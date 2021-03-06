# Notes

Hex and ASCII output: https://stackoverflow.com/questions/25786982/how-can-gdb-show-both-hex-and-ascii-when-examing-memory

### Service
```
$ docker run --rm -d --name pwnable -p 10000:10000 pwnable:start
```

## References
### Syscalls

See: [syscall reference](https://syscalls.kernelgrok.com/).

 * 0x01: `sys_exit` `eax:1, ebx:<int error code>`
 * 0x03: `sys_read` `eax:3, ebx:<unsigned int fd>, ecx:<char __user *buf>, edx:<size_t count>`
 * 0x04: `sys_write` `eax:4, ebx:<unsigned int fd>, ecx:<const char __user *buf>, edx:<size_t count>`

## Analysis
### Disassembly
```
        ; Section .text
        ; Range: [0x8048060; 0x80480a3[ (67 bytes)
        ; File offset : [96; 163[ (67 bytes)
        ; Flags: 0x6
        ;   SHT_PROGBITS
        ;   SHF_ALLOC
        ;   SHF_EXECINSTR



        ; ================ B E G I N N I N G   O F   P R O C E D U R E ================

        ; Variables:
        ;    : void *, 4


             _start:
08048060         push       esp
08048061         push       _exit
08048066         xor        eax, eax        ; eax = 0
08048068         xor        ebx, ebx        ; ebx = 0
0804806a         xor        ecx, ecx        ; ecx = 0
0804806c         xor        edx, edx        ; edx = 0
0804806e         push       0x3a465443      ; "CTF:"
08048073         push       0x20656874      ; "the "
08048078         push       0x20747261      ; "art "
0804807d         push       0x74732073      ; "s st"
08048082         push       0x2774654c      ; "Let'"
08048087         mov        ecx, esp        ; ecx = esp
08048089         mov        dl, 0x14        ; edx = 20 (size_t count)
0804808b         mov        bl, 0x1         ; ebx = 1  (unsigned int fd => stdout)
0804808d         mov        al, 0x4         ; eax = 4  (0x04 => sys_write)
0804808f         int        0x80            ;
08048091         xor        ebx, ebx        ; ebx = 0 (unsigned int fd => stdin)
08048093         mov        dl, 0x3c        ; edx = 60 (size_t count)
08048095         mov        al, 0x3         ; eax = 3 (0x03 => sys_read)
08048097         int        0x80
08048099         add        esp, 0x14
0804809c         ret
                        ; endp


        ; ================ B E G I N N I N G   O F   P R O C E D U R E ================


             _exit:
0804809d         pop        esp                                                 ; DATA XREF=_start+1
0804809e         xor        eax, eax    ; eax = 0
080480a0         inc        eax         ; eax = 1 (0x01 => sys_exit)
080480a1         int        0x80
                        ; endp
```

### Stack frame
```
          +--------------------+
          | saved esp          |  esp + 24  -- saved $esp
          +--------------------+
          | _exit 0x0804809d   |  esp + 20  -- ret addr [_exit] ($esp before ret)
          +--------------------+
          | "CTF:"             |  esp + 16
          +--------------------+
          | "the "             |  esp + 12
          +--------------------+
          | "art "             |  esp + 8
          +--------------------+
          | "s st"             |  esp + 4
          +--------------------+
  esp --> | "Let'"             |
          +--------------------+
```

## Exploitation
### RET instruction
Transfers program control to a return address located on the top of the stack. The address is usually placed on the stack by a CALL instruction, and the return is made to the instruction that follows the CALL instruction.

([source](https://c9x.me/x86/html/file_module_x86_id_280.html)).

### JMP instruction
Transfers program control to a different point in the instruction stream without recording return information. The destination (target) operand specifies the address of the instruction being jumped to. This operand can be an immediate value, a general-purpose register, or a memory location. This instruction can be used to execute four different types of jumps:

 * *Near jump* A jump to an instruction within the current code segment (the segment currently pointed to by the CS register), sometimes referred to as an intrasegment jump.
 * *Short jump* A near jump where the jump range is limited to -128 to +127 from the current EIP value.

([source](https://c9x.me/x86/html/file_module_x86_id_147.html))

### Buffer Overflow
```
          +--------------------+
  esp --> | saved esp          |
          +--------------------+
          | 0x0804809c         |  <-- saved esp
          +---------+----------+
 start -> | jmp -16 | padding  |
          +---------+----------+
          |      padding       |  <-- start - 4
          +--------------------+
          |     shellcode      |  <-- start - 8
          +--------------------+
          |     shellcode      |  <-- start - 12
          +--------------------+
          |     shellcode      |  <-- start - 16
          +--------------------+
```
