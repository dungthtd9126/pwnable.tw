#!/usr/bin/env python3
import socket, struct, binascii, sys

HOST = "127.0.0.1"
PORT = 9999

def pstr(s):
    n = len(s)
    if n <= 31: return bytes([0xa0|n]) + s
    if n <= 0xff: return b"\xd9" + bytes([n]) + s
    return b"\xda" + struct.pack(">H", n) + s

def mk_wrq(filename):
    return b"\x93" + b"\x02" + pstr(filename) + pstr(b"octet")

def mk_data(block, crc, data, typ=b"\xc4"):
    out = b"\x94" + b"\x03"
    out += b"\xcd" + struct.pack(">H", block)
    out += b"\xce" + struct.pack(">I", crc & 0xffffffff)
    if len(data) <= 0xff:
        out += b"\xc4" + bytes([len(data)]) + data
    else:
        out += b"\xc5" + struct.pack(">H", len(data)) + data
    return out

def isprint(c):
    return 0x20 <= c <= 0x7e

def bin_print(data):
    out = b'"'
    for c in data:
        if c == 0x22:
            out += b'\\"'
        elif isprint(c):
            out += bytes([c])
        else:
            out += b"\\x%02x" % c
    out += b'"'
    return out

def str_print(data):
    # "%.*s" with precision=size, stops at NUL
    out = b'"' + data.split(b"\x00")[0] + b'"'
    return out

def recv_pkt(s, timeout=3):
    s.settimeout(timeout)
    try:
        data, addr = s.recvfrom(65536)
        return data
    except socket.timeout:
        return None

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print("port", s.getsockname()[1])

pkt = mk_wrq(b"x")
s.sendto(pkt, (HOST, PORT))
d = recv_pkt(s)
print("recv:", d.hex())

# send DATA block 1 with bin type
data = b"ABCD"
crc = binascii.crc32(data) & 0xffffffff
print("printed:", bin_print(data), "crc:", hex(crc))
pkt = mk_data(1, crc, data)
s.sendto(pkt, (HOST, PORT))
d = recv_pkt(s)
print("recv:", d.hex())
import msgpack
print("decoded:", msgpack.unpackb(d, raw=True))