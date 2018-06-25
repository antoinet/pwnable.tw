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
08048571         push       0xc8                                                ; argument "__nbytes" for method j_read
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
080484d1         sub        esp, 0x7c
080484d4         mov        eax, dword [gs:0x14]
080484da         mov        dword [ebp+var_1C], eax
080484dd         xor        eax, eax
080484df         lea        eax, dword [ebp+var_7C]
080484e2         mov        ebx, 0x8048640
080484e7         mov        edx, 0x18
080484ec         mov        edi, eax
080484ee         mov        esi, ebx
080484f0         mov        ecx, edx
080484f2         rep movsd  dword [edi], dword [esi]
080484f4         mov        word [ebp+var_84], 0xc
080484fd         lea        eax, dword [ebp+var_7C]
08048500         mov        dword [ebp+var_80], eax
08048503         sub        esp, 0xc
08048506         push       0x0
08048508         push       0x0
0804850a         push       0x0
0804850c         push       0x1
0804850e         push       0x26                                                ; argument "__option" for method j_prctl
08048510         call       j_prctl                                             ; prctl
08048515         add        esp, 0x20
08048518         sub        esp, 0x4
0804851b         lea        eax, dword [ebp+var_84]
08048521         push       eax
08048522         push       0x2
08048524         push       0x16                                                ; argument "__option" for method j_prctl
08048526         call       j_prctl                                             ; prctl
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
