// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
/* Debug-engine fixture for the disposable BusyBox qualifier. Build statically
 * and not position independent so a host debugger can read its symbols:
 *   gcc -O1 -static -no-pie -pthread -o debug-fixture debug-fixture.c
 *
 * usage: debug-fixture [ticks [workers [mode]]]
 *   mode churn   every tenth round a new thread calls hot() and exits
 *   mode exec    at round 8 the process executes /bin/sh (the image is replaced)
 *   mode vfork   at round 8 the process vforks; the child sleeps 6 s, so the
 *                parent cannot park for that long
 * Prints "symbols ..." once, then a "tick" line every fourth 50 ms round with
 * the state an anti-debug check would look at, and "done" before it exits 0.
 *   tracer      TracerPid from /proc/self/status (must stay 0)
 *   traceme     result of the one PTRACE_TRACEME at round 40 (0 means it worked)
 *   sigtrap     SIGTRAPs the sample received (engine breakpoints must add none)
 *   int3_mem    0xCC bytes seen in hot() through /proc/self/mem
 *   int3_direct 0xCC bytes seen in hot() by loading them directly
 *   tf          TF as pushfq in tf_probe() reports it
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_WORKERS 64
volatile unsigned long counters[MAX_WORKERS];
volatile long magic = 0x1111;
volatile int sigtrap_count;
volatile long hot_result;
static volatile int stop_workers;

/* hot(x) = 3 * x + magic. A plain asm body gives a fixed instruction sequence
 * the qualifier can place a breakpoint on and step through. */
__asm__(".text\n"
        ".globl hot\n.type hot,@function\nhot:\n"
        "  mov %rdi,%rax\n"
        "  lea (%rax,%rax,2),%rax\n"
        "  add magic(%rip),%rax\n"
        "  ret\n"
        ".size hot,.-hot\n"
        ".globl tf_probe\n.type tf_probe,@function\ntf_probe:\n"
        "  pushfq\n"
        "  pop %rax\n"
        "  ret\n"
        ".size tf_probe,.-tf_probe\n");
extern long hot(long x);
extern unsigned long tf_probe(void);

static void on_sigtrap(int sig)
{
    (void)sig;
    sigtrap_count++;
}

static void *churn_thread(void *round)
{
    hot_result += hot((long)round);
    return NULL;
}

static void *worker(void *index)
{
    unsigned long slot = (unsigned long)index;
    while (!stop_workers) {
        counters[slot]++;
        usleep(1000);
    }
    return NULL;
}

static long tracer_pid(void)
{
    char line[256];
    long value = -1;
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) return -1;
    while (fgets(line, sizeof(line), status))
        if (!strncmp(line, "TracerPid:", 10)) value = strtol(line + 10, NULL, 10);
    fclose(status);
    return value;
}

static int int3_through_mem(void)
{
    unsigned char code[32];
    int fd = open("/proc/self/mem", O_RDONLY), count = 0;
    if (fd < 0) return -1;
    if (pread(fd, code, sizeof(code), (off_t)(unsigned long)hot) != (ssize_t)sizeof(code)) count = -1;
    else for (unsigned i = 0; i < sizeof(code); i++) count += code[i] == 0xcc;
    close(fd);
    return count;
}

static int int3_direct(void)
{
    const volatile unsigned char *code = (const volatile unsigned char *)hot;
    int count = 0;
    for (unsigned i = 0; i < 32; i++) count += code[i] == 0xcc;
    return count;
}

int main(int argc, char **argv)
{
    long ticks = argc > 1 ? strtol(argv[1], NULL, 10) : 300;
    int workers = argc > 2 ? atoi(argv[2]) : 2, traceme = -9;
    const char *mode = argc > 3 ? argv[3] : "";
    pthread_t threads[MAX_WORKERS];
    (void)mode;
    struct sigaction action = { .sa_handler = on_sigtrap };
    if (workers < 0 || workers > MAX_WORKERS) workers = MAX_WORKERS;
    sigaction(SIGTRAP, &action, NULL);
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("symbols hot=0x%lx tf_probe=0x%lx counters=0x%lx magic=0x%lx pid=%d\n",
           (unsigned long)hot, (unsigned long)tf_probe, (unsigned long)counters,
           (unsigned long)&magic, getpid());
    for (long i = 0; i < workers; i++)
        pthread_create(&threads[i], NULL, worker, (void *)i);
    for (long round = 0; round < ticks; round++) {
        long value = hot(round);
        hot_result += value;
        if (!strcmp(mode, "churn") && round % 10 == 5) {
            pthread_t extra;
            if (!pthread_create(&extra, NULL, churn_thread, (void *)round))
                pthread_join(extra, NULL);
        }
        if (!strcmp(mode, "exec") && round == 8)
            execl("/bin/sh", "sh", "-c", "echo execd; sleep 2", (char *)NULL);
        if (!strcmp(mode, "vfork") && round == 8) {
            pid_t child = vfork();
            if (child == 0) {
                usleep(6000000);
                _exit(0);
            }
        }
        if (round == 40) traceme = (int)ptrace(PTRACE_TRACEME, 0, 0, 0);
        if (round % 4 == 0 || value != 3 * round + 0x1111)
            printf("tick %ld hot=%ld magic=0x%lx c0=%lu c1=%lu sigtrap=%d tracer=%ld "
                   "traceme=%d int3_mem=%d int3_direct=%d tf=%lu\n",
                   round, value, magic, counters[0], counters[1], sigtrap_count,
                   tracer_pid(), traceme, int3_through_mem(), int3_direct(),
                   (tf_probe() >> 8) & 1);
        usleep(50000);
    }
    stop_workers = 1;
    for (long i = 0; i < workers; i++) pthread_join(threads[i], NULL);
    printf("done sigtrap=%d\n", sigtrap_count);
    return 0;
}
