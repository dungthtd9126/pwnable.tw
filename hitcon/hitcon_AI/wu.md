# HITCON CTF — hitcon_AI (hitcon_ftp) writeup notes

## 1. Overview

- Target: `hitcon_ftp_patched` — ELF 64-bit PIE, **not stripped**, symbols present.
- Service: UDP TFTP-like file server, but requests are wrapped in **msgpack** encoding.
- Deployment (from `dockerfile`/`docker-compose.yml`): port 69, `CAP_NET_BIND_SERVICE` + `CAP_SYS_PTRACE`, runs as a simple user (no root). Server is **read-only** ("disable uploading" — WRQ always writes to `/dev/null`).
- Runtime: must be launched with the bundled glibc:
  `env LD_LIBRARY_PATH=/home/saitomu/Downloads/pwnable/hitcon/libs ./hitcon_ftp_patched 9999` (port from `argv[1]`).

## 2. Reverse engineering results

### 2.1 Key functions

| Function | Address | Role |
|---|---|---|
| `main` | `0x3dc1` | event loop: recvfrom (0xffc5 max) → unpack → dispatch opcode → process packet |
| `process_new` | `0x2fbb` | handle RRQ/WRQ; parse options (blksize/tsize/timeout); open file |
| `process_recv` | `0x2bf4` | handle DATA/ACK |
| `process_send` | `0x2db3` | handle RRQ/OACK/ERROR/ACK-send |
| `check_crc32` | `0x3b8e` | compares sent CRC against CRC of the *printed* (escaped) data |
| `send_data` | `0x257e` | send DATA block with CRC |
| `send_ack` / `send_err` / `send_oack` | `0x273a` / `0x2855` / `0x29af` | protocol replies |
| `add_oack_opt` | `0x247d` | build OACK option entries |
| `clean_req` | `0x2bac` | fclose + free request |
| `sandbox` | `0x2138` | seccomp filter + `setuid(1000)` |
| `handler` | `0x2f6a` | SIGALRM handler ("time's up!") |

### 2.2 msgpack object model

Custom msgpack-c-style `msgpack_object`:
- object stride **0x18** (type dword at `+0`, `via` union at `+8`, extra ptr at `+0x10`).
- array element `i` lives at `obj + i*0x18`; `via.array = {u32 size, object* ptr}`.
- **Type enum in this build** (verified via `msgpack_object_print_buffer` jump table at `.rodata:0xa89c`):

```
0 NIL      1 BOOL     2 INT      3 NEGINT   4 FLOAT
5 STR      6 ARRAY    7 MAP      8 BIN      9 EXT
```

- Protocol packet: array `[opcode, block, crc, payload]` (+ optional options map on WRQ/RRQ).
- opcodes: 1=RRQ, 2=WRQ, 3=DATA, 4=ACK, 5=ERROR, 6=OACK.

### 2.3 Packet parsing / flow

- `main`: `recvfrom(sockfd, datain, 0xffc5, 0, &localreq+0x128, &localreq+0x138)`.
- `localreq` = main stack buffer at `rbp-0x360`, **zeroed** with `memset(..., 0x340)` before each packet.
- `unpacker` parse result stored at `[rbp-0x458]` (array ptr) / `[rbp-0x460]` (array size).
- Dispatch in `main`:
  - `obj[0].type == 1` → RRQ → `process_new`; `== 2` → WRQ → `process_new`.
  - opcode `3` (DATA): checks `obj[1].type==2` (block u16), `obj[2].type==2` (crc u32), `obj[3].type ∈ {5 (STR), 8 (BIN)}` → calls `check_crc32(&localreq+0x13c, crc_value, type, size, ptr)` then `process_recv`.
- WRQ option handling: blksize (max 0xffb8), tsize, timeout parsed via a 0x30-stride kv loop. Server ACKs options via OACK.

## 3. THE BUG — stack buffer overflow in the DATA path

### 3.1 The vulnerable call chain

In `main` (DATA handler, ~`0x49bb`–`0x49f5`):

```
check_crc32( out  = &localreq + 0x13c  == main_rbp - 0x224,
             crc  = obj[2].via.u32,
             type = obj[3].type,          // 5 (STR) or 8 (BIN)
             size = obj[3].via.bin.size,  // fully attacker controlled
             ptr  = obj[3].via.bin.ptr )  // points into recv buffer (attacker data)
```

`check_crc32` (`0x3b8e`):

```c
void *addr = rdi;                       // rbp-0x224
u64 crc   = rsi;
int type  = rdx;
u64 size  = rcx;
u8  *ptr  = r8;

msgpack_object_print_buffer(addr, size + 1, type, size, ptr);  // <-- overflow
... crc over strlen(addr) bytes starting at index 1, compare with crc ...
```

`msgpack_object_print_buffer` for the **BIN** case (`0x690f`):

```
snprintf(out, rem, "\"")            // rem = size+1  ->  rem = size
msgpack_object_bin_print_buffer(out, rem, ptr, size);   // writes ESCAPED bytes
snprintf(out, rem, "\"")
```

`msgpack_object_bin_print_buffer` (`0x64a0`) iterates `i in 0..size-1` and, for any
printable non-`"` byte, does `*out++ = byte; rem--` **as long as rem != 0**. The only
limit is `rem`, which was set to `size` (attacker-chosen). For attacker data without
`"` (or `\`) it writes **all `size` raw bytes** and never stops early.

### 3.2 Overflow geometry

- Write starts at `main_rbp - 0x224`, goes **upward**.
- `size + 1` bytes are written (the leading `"` + up to `size` payload bytes).
- To reach main's **canary at `rbp-0x18`** you need `size + 1 > 0x20C`  (i.e. `size >= 0x20C`).
- To reach the **saved return address at `rbp+8`** you need `size + 1 > 0x22C`.

Written region for `size = 0x300`:  `rbp-0x224 .. rbp+0xDD`
→ covers canary (`rbp-0x18`), saved rbx/r12 (`rbp-0x10`/`rbp-0x8`), saved rbp (`rbp+0`), and return address (`rbp+8`).

### 3.3 Reachability

1. Default block size is 0x200. `main` rejects packets with `recvlen > blocksize + 13`.
   With `size=0x200` the write only reaches `rbp-0x224+0x201 = rbp-0x23`, i.e. it **never touches the canary**.
2. → Must negotiate a large `blksize` via WRQ option: max accepted is **0xffb8**.
   `recvlen <= 0xffb8+13` lets us pass `size` up to ~0xffc5.
3. Then send DATA block 1 with `obj[3]` = BIN (or STR) whose size is the overflow length.

### 3.4 CRC quirk (not required for the overflow)

- The CRC is computed over the **printed/escaped representation** starting at index 1
  (skipping the leading `"`), and it re-runs `strlen(buf)` on every loop iteration (O(n²)).
- For printable, quote-free data that is followed by a NUL on the stack, the printed form
  is exactly the raw payload, so sending `CRC32(payload)` passes the check
  (confirmed empirically with payload `ABCD`).
- `send_data` has a related off-by-one: it hashes `data[1:]` (skips the first byte),
  so a file's first byte is not covered by the sent CRC.
- The overflow happens **during the print**, i.e. before/independent of whether the CRC
  check passes, so no CRC bypass is needed to smash the stack.

### 3.5 Secondary (minor) bug

- Filename `strncpy(..., 0x100)` copies exactly 0x100 bytes with no NUL terminator
  → potential OOB read in `fopen`; not exploitable (server is read-only anyway).

## 4. Empirical verification

All tests: server launched with bundled libc on port 9999.

1. **RRQ** `test.txt` → server DATA block 1:
   payload `"est\n"` with CRC `0xd08d5bc8 = CRC32("est\n")` — confirms `send_data` CRC skips byte 0.
2. **WRQ** (no opts) → ACK `[4,0]`.
3. **WRQ** `{blksize: 0xffb8}` → OACK `[6,{blksize:0xffb8}]`
   (OACK bytes: `92 06 81 a7 62 6c 6b 73 69 7a 65 cd ff b8`).
4. **DATA** block 1 with 768 `B` bytes (bin16) → server replies
   `[5,4,"crc32 check failed"]` and **stays alive** (all its still-needed locals live below
   `rbp-0x224` or on the heap, so the corrupted frame doesn't break the loop yet).
5. ~60 s later `SIGALRM` → `"time's up!"` → `select()` returns `EINTR` → `"select failed. [Interrupted system call]"` → main epilogue → canary check **fires** → `__stack_chk_fail` → `abort` → `tgkill` **blocked by seccomp** → **SIGSYS, exit 159** (no "*** stack smashing detected ***" message — see §5).

### 4.1 Known type acceptance

DATA element 3 type tests (fresh server, WRQ blksize=0xffb8 first):
- STR `0xa4`   → `[5,4,"crc32 check failed"]` (processed)
- BIN8 `0xc4`  → `[5,4,"crc32 check failed"]` (processed)
- BIN16 `0xc5` → processed
- BIN32 `0xc6` → `[5,4,"crc32 check failed"]` (processed)
- ARRAY `0x94` → `[5,4,"illegal packet"]` (rejected at type check)
- MAP `0x84`   → unpacker error (payload too short)

## 5. Canary mystery — SOLVED (SIGSYS)

Capturing the server's exit code after the overflow + alarm:

```
SERVER_EXIT=159     (159 = 128 + 31 = killed by SIGSYS "Bad system call")
server.log: "time's up!" -> "select failed. [Interrupted system call]"
./serverw.sh: ... Bad system call (core dumped) env LD_LIBRARY_PATH=... ./hitcon_ftp_patched 9999
```

The process is killed by **SIGSYS** — a seccomp violation — which proves the canary
check fired exactly as predicted:

1. main epilogue (`0x4034`) loads `[rbp-0x18]` (overwritten with our bytes), XORs against
   `fs:0x28` → mismatch → `jmp 4dc5` → `call __stack_chk_fail@plt` (`0x4dc5`).
2. glibc `__stack_chk_fail` → `__fortify_fail` → `abort()` → `raise(SIGABRT)` → **`tgkill`**
   syscall (206 / 0xce).
3. `tgkill` is **NOT** in the seccomp allow-list → kernel delivers SIGSYS → process dies
   with exit 159 and **no** "*** stack smashing detected ***" message (message write to
   stderr is attempted but the abort path is killed before/independently; only stderr text
   is "time's up!" / "select failed").

A clean (non-overflowed) run would exit 255 (`main` returns -1 → `exit(60)`, which IS
allowed) — so SIGSYS is a positive, definitive confirmation that the canary was smashed.

### 5.1 Seccomp filter (`sandbox` @ `0x2138`)

45-instruction BPF program copied from `.rodata:0xa3c0`, jumps resolved by
`bpf_resolve_jumps` (`0x4dd3`), installed via
`prctl(PR_SET_NO_NEW_PRIVS,1)` + `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)`.
Allow-list (x86_64):

```
read(0) write(1) open(2) close(3) stat(4) fstat(5) lseek(8) mmap(9) mprotect(10)
brk(12) rt_sigreturn(15) ioctl(16) setuid(23) socket(41) sendto(44) recvfrom(45)
bind(49) exit(60) exit_group(231) openat(257)
```

Notably **blocked**: `tgkill`/`kill` (abort), `writev`, `poll`, `connect`, `fork`/`clone`,
`execve`, `getpid`. So:
- No shellcode / `execve` — RCE must use ROP with the allowed syscalls (e.g.
  `open`/`openat` + `read` + `write`/`sendto` to exfil a flag).
- `__stack_chk_fail` always dies via SIGSYS, so the canary can never be brute-forced
  through retries on the same process; it must be **leaked** or the exit canary check must
  be **avoided**.
- `sandbox()` runs `setuid(1000)` too, so the flag file must be world-readable.

## 6. Exploitation status / open items

The overflow is **fully confirmed and reachable**, but **RCE is not yet achieved**.
Constraints:

1. Canary at `rbp-0x18` sits in the middle of the contiguous write → it is always
   overwritten → main's exit canary check always fires → SIGSYS death.
2. The server only checks the canary when `main` exits (i.e. after the 60 s `SIGALRM`),
   so there is a ~60 s window where the corrupted frame persists while the loop keeps
   processing new UDP packets (`select` → `recvfrom`).
3. Corrupted locals above `rbp-0x224` (sockaddr `[rbp-0x238]`, socklen `[rbp-0x228]`,
   padding to `rbp-0x20`) are not dereferenced as pointers during the loop; the useful
   pointers (unpacker `[rbp-0x458]`, req `[rbp-0x480]`, fd_set `[rbp-0x3e0]`) are all
   **below** the write range, so no in-loop function-pointer hijack is directly available
   from this overflow alone.
4. Bonus primitive: `recvfrom(sockfd, datain=rbp-0x360, 0xffc5, ...)` can itself write up
   to `0xffc5` bytes into the stack frame (far past `rbp+0x8`) for any packet shorter than
   `blocksize+13` — a second, even larger overflow, but same canary problem.

Candidate paths to code execution (open):
- **Canary leak** via `process_new`'s unterminated 0x100-byte `strncpy` filename that is
  later `strlen`/`fopen`/printed (verify whether any print re-echoes the filename buffer).
- **Avoid the exit path**: if `main` can be made to longjmp/loop without ever returning,
  the canary check never runs (currently blocked by the 60 s `SIGALRM`).
- **Overwrite the saved `rbp`/`rsp` such that a later stack write re-maps the canary**.
- Corrupt the **heap request** indirectly (e.g. via the fd_set/sockfd if a second bug is
  found).

## 7. Files

- `hitcon_ftp_patched` — target binary.
- `client.py` — RRQ test client (port 9999).
- `test_data.py` — WRQ+DATA client; proves `CRC32(printable data)` is accepted.
- `dockerfile`, `docker-compose.yml` — deployment context.
- `/home/saitomu/Downloads/pwnable/hitcon/libs/` — bundled glibc needed to run.
- `/tmp/opencode/ftp/t1.py` — WRQ/OACK verification.
- `/tmp/opencode/ftp/t2.py` / `t4.py` — overflow probes (WRQ blksize=0xffb8 + DATA block 1, 0x300 bytes).
- `/tmp/opencode/ftp/t3.py` — DATA element-3 type fuzz.
- `/tmp/opencode/ftp/server.log`, `server_exit.log` — runtime logs.