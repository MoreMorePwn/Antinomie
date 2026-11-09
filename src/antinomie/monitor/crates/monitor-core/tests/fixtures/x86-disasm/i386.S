// SPDX-License-Identifier: GPL-3.0-only
// Benign ia32 fixture: exit(0).
        .text
        .globl _start
_start:
        push    %ebp
        mov     %esp, %ebp
        call    done
        xor     %ebx, %ebx
        mov     $1, %eax
        int     $0x80
done:
        ret
