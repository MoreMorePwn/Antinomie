// SPDX-License-Identifier: GPL-3.0-only
// Benign ARM32 fixture: an ARM function that calls a Thumb function.
        .syntax unified
        .text
        .globl _start
        .type _start, %function
_start:
        .arm
        mov     r1, r0
        add     r0, r1, r1, lsl #1
        blx     thumbed
        mov     r7, #1
        svc     #0
        .size _start, .-_start
        .thumb_func
        .type thumbed, %function
thumbed:
        .thumb
        movs    r2, #7
        adds    r0, r0, r2
        bx      lr
        .size thumbed, .-thumbed
