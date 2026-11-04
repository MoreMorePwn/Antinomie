/* Benign test program: the Thumb function stores through a null pointer. */
#include <stdio.h>
volatile int *volatile null_ptr = 0;
__attribute__((target("arm"), noinline)) int arm_fn(int x) { return x * 3 + 1; }
__attribute__((target("thumb"), noinline)) int thumb_fn(int x) { null_ptr[0] = x; return x + 5; }
int main(void) { printf("%d\n", arm_fn(2)); return thumb_fn(4); }
