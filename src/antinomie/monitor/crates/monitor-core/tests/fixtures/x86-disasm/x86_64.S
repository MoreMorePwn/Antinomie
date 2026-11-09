// SPDX-License-Identifier: GPL-3.0-only
// Benign x86-64 fixture: exit(0).
        .text
        .globl _start
_start:
        push    %rbp
        mov     %rsp, %rbp
        call    done
        xor     %edi, %edi
        mov     $60, %eax
        syscall
done:
        ret
