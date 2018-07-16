```
; ================ B E G I N N I N G   O F   P R O C E D U R E ================

; Variables:
;    arg_0: int, 4


     main:
08048548         lea        ecx, dword [esp+arg_0]                              ; End of unwind block (FDE at 0x804872c), Begin of unwind block (FDE at 0x8048758), DATA XREF=_start+23
0804854c         and        esp, 0xfffffff0
0804854f         push       dword [ecx-4]
08048552         push       ebp
08048553         mov        ebp, esp
08048555         push       ecx
08048556         sub        esp, 0x4
08048559         call       orw_seccomp                                         ; orw_seccomp
0804855e         sub        esp, 0xc
08048561         push       aGiveMyYourShel                                     ; argument "__format" for method j_printf, "Give my your shellcode:"
08048566         call       j_printf                                            ; printf
0804856b         add        esp, 0x10
0804856e         sub        esp, 0x4
08048571         push       0xc8                                                ; argument "__nbytes" for method j_read (200)
08048576         push       shellcode                                           ; argument "__buf" for method j_read
0804857b         push       0x0                                                 ; argument "__fd" for method j_read
0804857d         call       j_read                                              ; read
08048582         add        esp, 0x10
08048585         mov        eax, shellcode
0804858a         call       eax                                                 ; shellcode
0804858c         mov        eax, 0x0
08048591         mov        ecx, dword [ebp-4]
08048594         leave
08048595         lea        esp, dword [ecx-4]
08048598         ret
                ; endp
08048599         align      32                                                  ; End of unwind block (FDE at 0x8048758)

; ================ B E G I N N I N G   O F   P R O C E D U R E ================

; Variables:
;    var_C: int8_t, -12
;    var_1C: int32_t, -28
;    var_7C: int8_t, -124
;    var_80: int32_t, -128
;    var_84: int16_t, -132


     orw_seccomp:
080484cb         push       ebp                                                 ; Begin of unwind block (FDE at 0x804872c), CODE XREF=main+17
080484cc         mov        ebp, esp
080484ce         push       edi
080484cf         push       esi
080484d0         push       ebx
080484d1         sub        esp, 0x7c                                           ; 124 bytes on stack
080484d4         mov        eax, dword [gs:0x14]
080484da         mov        dword [ebp+var_1C], eax                             ; vac_1C = *gs:0x14
080484dd         xor        eax, eax
080484df         lea        eax, dword [ebp+var_7C]                             ;
080484e2         mov        ebx, 0x8048640
080484e7         mov        edx, 0x18
080484ec         mov        edi, eax                                            ; edi = &var_7C (byte array?)
080484ee         mov        esi, ebx                                            ; esi = 0x08048640
080484f0         mov        ecx, edx                                            ; ecx = 24
080484f2         rep movsd  dword [edi], dword [esi]
080484f4         mov        word [ebp+var_84], 0xc                              ; *var_84 = 12 // nr of bpf rules
080484fd         lea        eax, dword [ebp+var_7C]
08048500         mov        dword [ebp+var_80], eax                             ; *var_80 = &var_7c // ptr to struct sock_fprog
08048503         sub        esp, 0xc                                            ; 12 additional bytes on stack
08048506         push       0x0
08048508         push       0x0
0804850a         push       0x0
0804850c         push       0x1
0804850e         push       0x26                                                ; argument "__option" for method j_prctl
08048510         call       j_prctl                                             ; prctl(PR_SET_NO_NEW_PRIVS, 1)
08048515         add        esp, 0x20
08048518         sub        esp, 0x4
0804851b         lea        eax, dword [ebp+var_84]                             ; pointer to struct sock_fprog
08048521         push       eax
08048522         push       0x2
08048524         push       0x16                                                ; argument "__option" for method j_prctl
08048526         call       j_prctl                                             ; prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, *(struct sock_fprog))
0804852b         add        esp, 0x10
0804852e         nop
0804852f         mov        eax, dword [ebp+var_1C]
08048532         xor        eax, dword [gs:0x14]
08048539         je         loc_8048540

0804853b         call       j___stack_chk_fail                                  ; __stack_chk_fail
                ; endp

     loc_8048540:
08048540         lea        esp, dword [ebp+var_C]                              ; CODE XREF=orw_seccomp+110
08048543         pop        ebx
08048544         pop        esi
08048545         pop        edi
08048546         pop        ebp
08048547         ret
                ; endp
```

```
08048640         db  0x20 ; ' '                                                 ; DATA XREF=orw_seccomp+23
08048641         db  0x00 ; '.'
08048642         db  0x00 ; '.'
08048643         db  0x00 ; '.'
08048644         db  0x04 ; '.'
08048645         db  0x00 ; '.'
08048646         db  0x00 ; '.'
08048647         db  0x00 ; '.'
08048648         db  0x15 ; '.'
08048649         db  0x00 ; '.'
0804864a         db  0x00 ; '.'
0804864b         db  0x09 ; '.'
0804864c         db  0x03 ; '.'
0804864d         db  0x00 ; '.'
0804864e         db  0x00 ; '.'
0804864f         db  0x40 ; '@'
08048650         db  0x20 ; ' '
08048651         db  0x00 ; '.'
08048652         db  0x00 ; '.'
08048653         db  0x00 ; '.'
08048654         db  0x00 ; '.'
08048655         db  0x00 ; '.'
08048656         db  0x00 ; '.'
08048657         db  0x00 ; '.'
```


## seccomp
 * https://en.wikipedia.org/wiki/Seccomp
 * https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt
 * http://man7.org/linux/man-pages/man2/prctl.2.html
 * https://www.youtube.com/watch?v=1XEUVerosgU
 * https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h
 * https://github.com/torvalds/linux/blob/master/include/uapi/linux/seccomp.h
 * https://blog.cloudflare.com/bpf-the-forgotten-bytecode/
 * https://kitctf.de/writeups/32c3ctf/ranger
 * https://github.com/unixist/seccomp-bypass
```
 prctl(0x26, 0x1, 0x0, 0x0, 0x0);       // prctl(PR_SET_NO_NEW_PRIVS, 1)
 prctl(0x16, 0x2, addr);                // prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, *(struct sock_fprog))

```


## Solution

```
# gdb orw
gdb-peda$ b *0x08048526
Breakpoint 1 at 0x8048526
gdb-peda$ r
Starting program: /opt/pwnable/orw
Breakpoint 1, 0x08048526 in orw_seccomp ()
gdb-peda$ dump binary memory bpf_bytecode $eax+8 $eax+108
gdb-peda$ quit

root@515dd04d2df7:/opt/pwnable# hexdump -C bpf_bytecode
00000000  20 00 00 00 04 00 00 00  15 00 00 09 03 00 00 40  | ..............@|
00000010  20 00 00 00 00 00 00 00  15 00 07 00 ad 00 00 00  | ...............|
00000020  15 00 06 00 77 00 00 00  15 00 05 00 fc 00 00 00  |....w...........|
00000030  15 00 04 00 01 00 00 00  15 00 03 00 05 00 00 00  |................|
00000040  15 00 02 00 03 00 00 00  15 00 01 00 04 00 00 00  |................|
00000050  06 00 00 00 26 00 05 00  06 00 00 00 00 00 ff 7f  |....&...........|
00000060  00 21 73 c6                                       |.!s.|
00000064

# cat bpf_bytecode| ~/git/libseccomp/tools/scmp_bpf_disasm
 line  OP   JT   JF   K
=================================
 0000: 0x20 0x00 0x00 0x00000004   ld  $data[4]
 0001: 0x15 0x00 0x09 0x40000003   jeq 1073741827 true:0002 false:0011
 0002: 0x20 0x00 0x00 0x00000000   ld  $data[0]
 0003: 0x15 0x07 0x00 0x000000ad   jeq 173  true:0011 false:0004                ; sys_rt_sigreturn
 0004: 0x15 0x06 0x00 0x00000077   jeq 119  true:0011 false:0005                ; sys_sigreturn
 0005: 0x15 0x05 0x00 0x000000fc   jeq 252  true:0011 false:0006                ; sys_exit_group
 0006: 0x15 0x04 0x00 0x00000001   jeq 1    true:0011 false:0007                ; sys_exit
 0007: 0x15 0x03 0x00 0x00000005   jeq 5    true:0011 false:0008                ; sys_open
 0008: 0x15 0x02 0x00 0x00000003   jeq 3    true:0011 false:0009                ; sys_read
 0009: 0x15 0x01 0x00 0x00000004   jeq 4    true:0011 false:0010                ; sys_write
 0010: 0x06 0x00 0x00 0x00050026   ret ERRNO(38)
 0011: 0x06 0x00 0x00 0x7fff0000   ret ALLOW
 ```
