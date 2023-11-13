# Assemblky x86

## Flags
**ZF**: set when the result of an operation is equal to zero; otherwise, it is cleared.
**CF**: set when the result of an operation is too large or too small for the destination operand; otherwise, it is cleared.
**SF**: set when the result of an operation is negative or cleared when the result is positive. Also set when the most significant bit is set after an arithmetic operation.
**TF**: The trap flag is used for debugging. The x86 processor will execute only one instruction at a time if this flag is set.

## Instruction
### mov
The mov instruction can move data into registers or RAM. The format is mov destination, source. Operands surrounded
by brackets are treated as memory references to data. For example, [ ebx ] references the data at the memory address EBX

Performing calculations such as this within an instruction is not possible unless you are calculating a memory address. For example, mov eax, ebx+esi*4 (without the brackets) is an invalid instruction.
Ex:
- mov eax, ebx
- mov eax, 0x42
- mov eax, [ 0x4037C4 ]
- mov eax, [ ebx ]
- mov eax, [ ebx+esi*4 ]

### lea
The format of the instruction is lea destination, source. The lea instruction is used to put a memory address into the destination. For example, lea eax, [ ebx+8 ] will put EBX+8 into EAX. In contrast, mov eax, [ ebx+8 ] loads the data at the memory address specified by EBX+8.

### Arithmetic
- The sub instruction modifies two important flags: the zero flag (ZF) and carry flag (CF). The ZF is set if the result is zero, and CF is set if the destination is less than the value subtracted.

- The mul value instruction always multiplies eax by value. The result is stored as a 64-bit value across two registers: EDX and EAX. EDX stores the most significant 32 bits of the operations, and EAX stores the least significant 32 bits.

- div instruction divides the 64 bits across EDX and EAX by value. The result of the division operation is stored in EAX, and the across EDX and EAX registers remainder is stored in EDX.

Ex:
- **mul 0x50** : Multiplies EAX by 0x50 and stores the result in EDX:EAX
- **div 0x75** : Divides EDX:EAX by 0x75 and stores the result in EAX and the remainder in EDX

- The shr and shl instructions shift the bits in the destination operand to the right and left, respectively, by the number of bits specified in the count operand. Bits shifted beyond the destination boundary are first shifted into the CF flag. Zero bits are filled in during the shift.

- ror and rol, are similar to the shift instructions, except the shifted bits that “fall off” with the shift operation are rotated to the other end.

EX: 
mov eax, 0xA (00001010)
shl eax, 2
will perfom the following transformations:
00010100
00101000


mov bl, 0xA (00001010)
ror bl, 2
will perfom the following transformations:
00000101
10000010

## Conditionals
- The **test** instruction is identical to the **and** instruction; however, the operands involved are not modified by the instruction. The test instruction only sets the flags. The zero flag (ZF) will be set is the result of the and operation is 0.

- The **cmp** instruction is identical to the sub instruction; however, the operands are not affected. The cmp instruction is used only to set the flags. The zero flag and carry flag (CF) may be changed as a result of the cmp instruction.

dst = src => ZF=1 CF=0
dst < src => ZF=0 CF=1
dst > src => ZF=0 CF=0

## Branching

| Instruction  | Description  | 
|---|---|
| jz loc  |  Jump to specified location if ZF = 1. |
| jnz loc  | Jump to specified location if ZF = 0.  |
| je loc |  Same as jz, but commonly used after a cmp instruction. Jump will occur if the destination operand equals the source operand. |
| jne loc |  Same as jnz, but commonly used after a cmp. Jump will occur if the destination operand is not equal to the source operand. |
| jg loc |  Performs signed comparison jump after a cmp if the destination operand is greater than the source operand. |
| jge loc |  Performs signed comparison jump after a cmp if the destination operand is greater than or equal to the source operand. |
| ja loc |  Same as jg, but an unsigned comparison is performed. |
| jae loc |  Same as jge, but an unsigned comparison is performed. |
| jl loc |  Performs signed comparison jump after a cmp if the destination operand is less than the source operand. |
| jle loc | Performs signed comparison jump after a cmp if the destination operand is less than or equal to the source operand. |
| jb loc | Same as jl, but an unsigned comparison is performed. |
| jbe loc | Same as jle, but an unsigned comparison is performed. |
| jo loc | Jump if the previous instruction set the overflow flag (OF = 1). |
| js loc | Jump if the sign flag is set (SF = 1). |
| jecxz loc | Jump to location if ECX = 0. |

## Rep Instructions
The most common data buffer manipulation instructions are movsx, cmpsx, stosx, and scasx, where x = b, w, or d for byte, word, or double word, respectively.

The ESI and EDI registers are used as source index register, and EDI is the destination index register respectively. ECX is used as the counting variable.
| Instruction  | Description  | 
|---|---|
| rep  |  Repeat until ECX = 0 |
| repe, repz  |  Repeat until ECX = 0 or ZF = 0 |
| repne, repnz  |  Repeat until ECX = 0 or ZF = 1 |

The **movsb** instruction is used to move a sequence of bytes from one location to another. The rep prefix is commonly used with movsb to copy a sequence of bytes, with size defined by ECX.

The **rep movsb** instruction is the logical equivalent of the C memcpy function. The movsb instruction grabs the byte at address ESI, stores it at address EDI, and then increments or decrements the ESI and EDI registers by one according to the setting of the direction flag (DF). If DF = 0, they are incremented; otherwise, they are decremented.

The **cmpsb** instruction obtains the byte at address ESI, compares the value at location EDI to set the flags, and then increments the ESI and EDI registers by one. If the repe prefix is present, ECX is checked and the flags are also checked, but if ECX = 0 or ZF = 0, the operation will stop repeating. This is equivalent to the C function memcmp.

The **scasb** instruction is used to search for a single value in a sequence of bytes. The value is defined by the AL register. This works in the same way as cmpsb, but it compares the byte located at address ESI to AL, rather than to EDI. The repe operation will continue until the byte is found or ECX = 0. If the value is found in the sequence of bytes, ESI stores the location of that value.

The **stosb** instruction is used to store values in a location specified by EDI. This is identical to scasb, but instead of being searched for, the specified byte is placed in the location specified by EDI. The rep prefix is used with scasb to initialize a buffer of memory, wherein every byte contains the same value. This is equivalent to the C function memset.

| Instruction  | Description  | 
|---|---|
| repe cmpsb  |  Used to compare two data buffers. EDI and ESI must be set to the two buffer locations, and ECX must be set to the buffer length. The comparison will continue until ECX = 0 or the buffers are not equal. |
| rep stosb  |  Used to initialize all bytes of a buffer to a certain value. EDI will contain the buffer location, and AL must contain the initialization value. This instruction is often seen used with xor eax, eax. |
| rep movsb  |  Typically used to copy a buffer of bytes. ESI must be set to the source buffer address, EDI must be set to the destination buffer address, and ECX must contain the length to copy. Byte-by-byte copy will continue until ECX = 0. |
| repne scasb  |  Used for searching a data buffer for a single byte. EDI must contain the address of the buffer, AL must contain the byte you are looking for, and ECX must be set to the buffer length. The comparison will continue until ECX = 0 or until the byte is found. |