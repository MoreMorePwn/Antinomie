// SPDX-License-Identifier: GPL-3.0-only
// Benign AArch64 fixture: exit(0) after a little arithmetic.
        .text
        .globl _start
        .type _start, %function
_start:
        mov     x1, x0
        add     x0, x1, x1, lsl #1
        bl      done
        .size _start, .-_start
        .type done, %function
done:
        mov     x8, #93
        mov     x0, #0
        svc     #0
        ret
        .size done, .-done
