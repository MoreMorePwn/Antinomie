// SPDX-License-Identifier: GPL-3.0-only
void _start(void){ register long r0 __asm__("r0")=1; register long r1 __asm__("r1")=(long)"benign tiny program\n"; register long r2 __asm__("r2")=20; register long r7 __asm__("r7")=4; __asm__ volatile("svc 0":"+r"(r0):"r"(r1),"r"(r2),"r"(r7):"memory"); r7=1; r0=0; __asm__ volatile("svc 0"::"r"(r0),"r"(r7)); for(;;); }
