#!/usr/bin/env python

import socket
import struct

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 4000))

name = "jeztek".encode('utf-8')
pkt = struct.pack("!cIB", '\xde', len(name)+1, 2) + name
print ' '.join(p.encode('hex') for p in pkt)
sock.send(pkt)

msg = "Hello".encode('utf-8')
pkt = struct.pack("!cIB", '\xde', len(msg)+1, 0) + msg
print ' '.join(p.encode('hex') for p in pkt)
sock.send(pkt)
sock.close()
