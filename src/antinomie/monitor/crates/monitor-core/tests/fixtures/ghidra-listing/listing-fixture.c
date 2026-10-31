/* SPDX-License-Identifier: GPL-3.0-only */
/* Benign freestanding program: a few functions, a loop, a call chain, a jump
 * table and a read-only string, so a disassembler has calls, branches and data
 * references to list. It makes no system calls and is never run. */
volatile int sink;
const char greeting[] = "antinomie";

static int __attribute__((noinline)) square(int x) { return x * x; }

int __attribute__((noinline)) sum_squares(int n) {
    int total = 0;
    for (int i = 0; i < n; i++)
        total += square(i);
    return total;
}

int __attribute__((noinline)) pick(int v) {
    switch (v) {
    case 0: return 3;
    case 1: return 7;
    case 2: return 11;
    case 3: return 13;
    case 4: return greeting[1];
    default: return sum_squares(v);
    }
}

void _start(void) {
    sink = pick(sink) + sum_squares(10);
    for (;;)
        ;
}
