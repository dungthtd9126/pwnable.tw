# Binary patch helper notes

- Category: pwn / ELF runtime tooling.
- Scope: update `patch(1).sh`; this task does not attempt the challenge exploit.
- Weakness in the previous helper: its relative `PT_INTERP` depended on the
  caller's working directory, and `DT_RUNPATH` did not apply to transitive
  dependencies. In this bundle, `libbsd.so.0` consequently selected the host
  `librt.so.1` and produced a glibc version mismatch.
- Fix: auto-detect a loader with the same ELF class, endianness, and machine;
  patch an atomic copy with an absolute interpreter and forced `DT_RPATH`; and
  reject missing direct dependencies before writing the output.
- Run: `./patch(1).sh ./hitcon_ftp ./libs ./hitcon_ftp_patched`
- Verify: `libs/ld-linux-x86-64.so.2 --list ./hitcon_ftp_patched`
- Flag: not applicable to this tooling-only change.
