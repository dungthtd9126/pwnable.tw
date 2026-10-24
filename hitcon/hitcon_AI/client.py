#!/usr/bin/env python3
import socket, struct, sys, binascii

HOST = "127.0.0.1"
PORT = 9999

def pstr(s):
    return b"\xa5" + s if len(s) == 5 else bytes([0xa0 | len(s)]) + s

def mk_rrq(filename, mode=b"octet", opts=None):
    # array header
    n = 3 if opts is None else 4
    if n == 3:
        body = b"\x93" + b"\x01" + pstr(filename) + pstr(mode)
    else:
        body = b"\x94" + b"\x01" + pstr(filename) + pstr(mode) + pack_map(opts)
    return body

def pack_map(opts):
    # opts: list of (key_str, int_value)
    out = bytes([0x80 | len(opts)])
    for k, v in opts:
        k = k.encode()
        out += bytes([0xa0 | len(k)]) + k
        if v < 0x80:
            out += bytes([v])
        else:
            out += b"\xcd" + struct.pack(">H", v)
    return out

def mk_wrq(filename, mode=b"octet", opts=None):
    body = b"\x93" + b"\x02" + pstr(filename) + pstr(mode)
    if opts:
        body = b"\x94" + b"\x02" + pstr(filename) + pstr(mode) + pack_map(opts)
    return body

def mk_data(block, crc, data):
    # [3, block, crc, bin(data)]
    out = b"\x94" + b"\x03"
    out += b"\xcd" + struct.pack(">H", block)
    out += b"\xce" + struct.pack(">I", crc & 0xffffffff)
    out += bytes([0xc4]) + bytes([len(data)]) + data if len(data) < 0x100 else b"\xc5" + struct.pack(">H", len(data)) + data
    return out

def crc32_std(data):
    return binascii.crc32(data) & 0xffffffff

def print_pkt(data):
    try:
        import msgpack
        print("decoded:", msgpack.unpackb(data, raw=True))
    except Exception as e:
        print("raw:", data[:80])

def recv_pkt(s, timeout=3):
    s.settimeout(timeout)
    try:
        data, addr = s.recvfrom(65536)
        return data
    except socket.timeout:
        return None

def main():
    op = sys.argv[1]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    print("client port:", s.getsockname()[1])
    if op == "rrq":
        pkt = mk_rrq(sys.argv[2].encode())
        print("sending", pkt.hex())
        s.sendto(pkt, (HOST, PORT))
        while True:
            d = recv_pkt(s)
            if d is None:
                break
            print("recv:", d.hex())
            import msgpack
            print("decoded:", msgpack.unpackb(d, raw=True))
            obj = msgpack.unpackb(d, raw=True)
            if obj[0] == 3:
                block, crc, data = obj[1], obj[2], obj[3]
                print("DATA block", block, "crc", crc, "data", data[:80])
                ack = b"\x92" + b"\x04" + b"\xcd" + struct.pack(">H", block)
                s.sendto(ack, (HOST, PORT))
            if obj[0] == 5:
                break
    elif op == "wrq":
        fn = sys.argv[2].encode()
        opts = None
        if len(sys.argv) > 3:
            opts = []
            for kv in sys.argv[3:]:
                k, v = kv.split("=")
                opts.append((k, int(v)))
        pkt = mk_wrq(fn, opts=opts)
        print("sending", pkt.hex())
        s.sendto(pkt, (HOST, PORT))
        while True:
            d = recv_pkt(s)
            if d is None:
                break
            print("recv:", d.hex())
            import msgpack
            print("decoded:", msgpack.unpackb(d, raw=True))

main()