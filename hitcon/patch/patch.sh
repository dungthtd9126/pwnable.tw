#!/usr/bin/env bash
set -Eeuo pipefail

program=${0##*/}

usage() {
    cat >&2 <<USAGE
Usage:
  $program <binary> <libs_dir> [output]

Patch a dynamically linked ELF binary to use the loader and libraries from
libs_dir. The source binary is left unchanged unless output names the source.
The default output is <binary>_patched.

Examples:
  $program ./hitcon_ftp ./libs
  $program ./hitcon_ftp ./libs ./hitcon_ftp_patched

Optional environment variables:
  PATCH_LOADER=<path>  Select a loader when libs_dir contains more than one.
                       A relative path is resolved below libs_dir.
  PATCH_RPATH=<value>  Override the default absolute RPATH to libs_dir.

Requirements: bash, patchelf, python3, find, realpath, and coreutils.
USAGE
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
    usage
    exit 0
fi

if (( $# < 2 || $# > 3 )); then
    usage
    exit 1
fi

for command in patchelf python3 find realpath dirname mktemp cp mv chmod rm; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

source_arg=$1
libs_arg=$2
output_arg=${3:-"${source_arg}_patched"}

[[ -f $source_arg ]] || die "binary not found: $source_arg"
[[ -d $libs_arg ]] || die "library directory not found: $libs_arg"

source_path=$(realpath -e -- "$source_arg")
libs_path=$(realpath -e -- "$libs_arg")
output_path=$(realpath -m -- "$output_arg")
output_dir=$(dirname -- "$output_path")
[[ -d $output_dir ]] || die "output directory not found: $output_dir"

# Return ELF class, byte order, and machine as a stable identity. Matching all
# three prevents accidentally selecting (for example) an AArch64 loader for an
# x86-64 binary when a library bundle contains several architectures.
elf_identity() {
    python3 - "$1" <<'PY'
import struct
import sys

try:
    with open(sys.argv[1], "rb") as stream:
        header = stream.read(20)
except OSError:
    raise SystemExit(1)

if len(header) != 20 or header[:4] != b"\x7fELF":
    raise SystemExit(1)

elf_class = header[4]
byte_order = header[5]
if elf_class not in (1, 2) or byte_order not in (1, 2):
    raise SystemExit(1)

endian = "<" if byte_order == 1 else ">"
machine = struct.unpack_from(endian + "H", header, 18)[0]
print(f"{elf_class}:{byte_order}:{machine}")
PY
}

target_identity=$(elf_identity "$source_path") || die "not a supported ELF binary: $source_arg"

if ! original_interpreter=$(patchelf --print-interpreter "$source_path" 2>/dev/null); then
    die "binary has no program interpreter (it may be static): $source_arg"
fi
interpreter_name=${original_interpreter##*/}

validate_loader() {
    local candidate=$1
    local candidate_identity

    [[ -f $candidate ]] || die "loader not found: $candidate"
    candidate=$(realpath -e -- "$candidate")
    candidate_identity=$(elf_identity "$candidate") || die "loader is not an ELF file: $candidate"
    [[ $candidate_identity == "$target_identity" ]] || \
        die "loader architecture does not match the target binary: $candidate"
    printf '%s\n' "$candidate"
}

# Populate the global matches array with unique loaders matching the target.
# First search by the binary's original loader basename, then use common glibc
# and musl loader names as a fallback.
collect_loaders() {
    local mode=$1
    local candidate canonical candidate_identity
    local -A seen=()
    matches=()

    if [[ $mode == exact ]]; then
        while IFS= read -r -d '' candidate; do
            canonical=$(realpath -e -- "$candidate") || continue
            [[ -z ${seen[$canonical]+x} ]] || continue
            seen[$canonical]=1
            if candidate_identity=$(elf_identity "$canonical" 2>/dev/null) && \
                    [[ $candidate_identity == "$target_identity" ]]; then
                matches+=("$canonical")
            fi
        done < <(find -L "$libs_path" -maxdepth 4 -type f \
            -name "$interpreter_name" -print0 2>/dev/null)
    else
        while IFS= read -r -d '' candidate; do
            canonical=$(realpath -e -- "$candidate") || continue
            [[ -z ${seen[$canonical]+x} ]] || continue
            seen[$canonical]=1
            if candidate_identity=$(elf_identity "$canonical" 2>/dev/null) && \
                    [[ $candidate_identity == "$target_identity" ]]; then
                matches+=("$canonical")
            fi
        done < <(find -L "$libs_path" -maxdepth 4 -type f \
            \( -name 'ld-linux*.so*' -o -name 'ld-musl-*.so*' \
               -o -name 'ld-[0-9]*.so*' \) -print0 2>/dev/null)
    fi
}

if [[ -n ${PATCH_LOADER:-} ]]; then
    if [[ $PATCH_LOADER == /* ]]; then
        loader_candidate=$PATCH_LOADER
    else
        loader_candidate=$libs_path/$PATCH_LOADER
    fi
    loader_path=$(validate_loader "$loader_candidate")
else
    # The usual layout has a loader symlink at the root of libs_dir.
    loader_path=
    root_loader=$libs_path/$interpreter_name
    if [[ -f $root_loader ]]; then
        root_identity=$(elf_identity "$root_loader" 2>/dev/null || true)
        if [[ $root_identity == "$target_identity" ]]; then
            loader_path=$(realpath -e -- "$root_loader")
        fi
    fi

    if [[ -z $loader_path ]]; then
        collect_loaders exact
        if (( ${#matches[@]} == 1 )); then
            loader_path=${matches[0]}
        elif (( ${#matches[@]} > 1 )); then
            printf 'error: multiple matching loaders found; set PATCH_LOADER to one of:\n' >&2
            printf '  %s\n' "${matches[@]}" >&2
            exit 1
        fi
    fi

    if [[ -z $loader_path ]]; then
        collect_loaders fallback
        if (( ${#matches[@]} == 1 )); then
            loader_path=${matches[0]}
        elif (( ${#matches[@]} > 1 )); then
            printf 'error: multiple matching loaders found; set PATCH_LOADER to one of:\n' >&2
            printf '  %s\n' "${matches[@]}" >&2
            exit 1
        else
            die "no loader matching $interpreter_name and the target architecture was found in $libs_path"
        fi
    fi
fi

if [[ ! -x $loader_path ]]; then
    chmod a+x -- "$loader_path" || die "could not make loader executable: $loader_path"
fi

# Fail before modifying anything if a direct dependency is absent. DT_RPATH is
# used instead of DT_RUNPATH so the same directory also applies to transitive
# dependencies of libraries in the bundle.
missing=()
while IFS= read -r needed; do
    [[ -e $libs_path/$needed ]] || missing+=("$needed")
done < <(patchelf --print-needed "$source_path")

if (( ${#missing[@]} > 0 )); then
    printf 'error: direct dependencies missing from %s:\n' "$libs_path" >&2
    printf '  %s\n' "${missing[@]}" >&2
    exit 1
fi

rpath=${PATCH_RPATH:-$libs_path}
output_name=${output_path##*/}
temporary=$(mktemp "$output_dir/.${output_name}.tmp.XXXXXX")
cleanup() {
    [[ -z ${temporary:-} ]] || rm -f -- "$temporary"
}
trap cleanup EXIT INT TERM

cp -p -- "$source_path" "$temporary"
chmod a+x -- "$temporary"
patchelf --set-interpreter "$loader_path" \
    --force-rpath --set-rpath "$rpath" "$temporary"

patched_interpreter=$(patchelf --print-interpreter "$temporary")
patched_rpath=$(patchelf --print-rpath "$temporary")
[[ $patched_interpreter == "$loader_path" ]] || die "interpreter verification failed"
[[ $patched_rpath == "$rpath" ]] || die "RPATH verification failed"

mv -f -- "$temporary" "$output_path"
temporary=
trap - EXIT INT TERM

printf 'patched:     %s\n' "$output_path"
printf 'loader:      %s\n' "$loader_path"
printf 'RPATH:       %s\n' "$rpath"
