// SPDX-License-Identifier: GPL-3.0-only
static long sys(long n,long a,long b,long c){ register long x0 __asm__("x0")=a; register long x1 __asm__("x1")=b; register long x2 __asm__("x2")=c; register long x8 __asm__("x8")=n; __asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x8):"memory"); return x0; }
void _start(void){ sys(64,1,(long)"benign tiny program\n",20); sys(93,0,0,0); for(;;); }
