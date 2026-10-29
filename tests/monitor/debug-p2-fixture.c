// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
/* Debugger phase 2 fixture for the disposable BusyBox qualifier. One binary, a
 * mode per behavior. Build it statically or position independent:
 *   gcc -O1 -static -no-pie -pthread -o debug-p2-fixture debug-p2-fixture.c
 *   gcc -O1 -static-pie -pthread -o debug-p2-pie debug-p2-fixture.c
 *   gcc -O1 -pthread -Wl,--dynamic-linker=/tmp/dbgroot/ld.so -Wl,-rpath,/tmp/dbgroot \
 *       -o debug-p2-dyn debug-p2-fixture.c        (the host's ld.so and libc beside it)
 *
 * usage: debug-p2-fixture MODE [ROUNDS [WORKERS [gate]]]
 * With "gate" the sample waits after the symbols line, before round 0, until a
 * debugger stores a nonzero value in `go`: a test that counts rounds starts from
 * round 0 however long its attach took.
 * Every mode prints "symbols name=0xaddr ..." first (runtime addresses, so a
 * position independent build is visible), then "start" and then "tick" lines
 * about every 50 ms, and "done" before it exits 0.
 *   threads  WORKERS named threads (dbgwork-N), each counting in its own function
 *   signal   SIGUSR1 to itself every round, a handled SIGSEGV every tenth round
 *   fatal    SIGUSR2 with the default action at round 5 (the process dies)
 *   step     step_syscall() and step_rep(): a syscall and a rep movsb to step over
 *   hw       hw_code() writes then reads the global `watched` every round
 *   smc      rewrites and calls a function in a read-write-execute page
 *   anti     the usual anti-debug probes, one line per round
 *   start    prints "main reached" first thing in main (debug on start stops before)
 *   fork     forks a child every fifth round that runs hw_code() and exits
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_WORKERS 64
volatile unsigned long counters[MAX_WORKERS];
volatile long watched, round_now;
volatile long watched_other;
volatile long go;
volatile int got_usr1, got_segv, sigtrap_count, tf_in_frame;
static pthread_t main_thread;
char srcbuf[4096], dstbuf[4096];
static volatile int stop_workers;
static sigjmp_buf segv_jump;

/* Fixed instruction sequences: a stepper can predict every address. */
__asm__(".text\n"
        ".globl step_syscall\n.type step_syscall,@function\nstep_syscall:\n"
        "  mov $39,%eax\n"            /* getpid */
        ".globl step_syscall_insn\nstep_syscall_insn:\n"
        "  syscall\n"
        ".globl step_after_syscall\nstep_after_syscall:\n"
        "  mov %eax,%ecx\n"
        "  nop\n"
        "  ret\n"
        ".size step_syscall,.-step_syscall\n"
        ".globl step_rep\n.type step_rep,@function\nstep_rep:\n"
        "  lea srcbuf(%rip),%rsi\n"
        "  lea dstbuf(%rip),%rdi\n"
        "  mov $4096,%ecx\n"
        ".globl step_rep_insn\nstep_rep_insn:\n"
        "  rep movsb\n"
        ".globl step_after_rep\nstep_after_rep:\n"
        "  nop\n"
        "  ret\n"
        ".size step_rep,.-step_rep\n"
        ".globl hw_code\n.type hw_code,@function\nhw_code:\n"
        "  mov %rdi,watched(%rip)\n"
        ".globl hw_after_write\nhw_after_write:\n"
        "  mov watched(%rip),%rax\n"
        ".globl hw_after_read\nhw_after_read:\n"
        "  add $1,%rax\n"
        "  ret\n"
        ".size hw_code,.-hw_code\n"
        ".globl tf_probe\n.type tf_probe,@function\ntf_probe:\n"
        "  pushfq\n"
        "  pop %rax\n"
        "  ret\n"
        ".size tf_probe,.-tf_probe\n");
extern long step_syscall(void);
extern void step_rep(void);
extern long hw_code(long value);
extern unsigned long tf_probe(void);
extern char step_syscall_insn[], step_after_syscall[], step_rep_insn[], step_after_rep[];
extern char hw_after_write[], hw_after_read[];

#include <ucontext.h>
/* The handler looks at the trap flag the frame saved: a debugger's single step
 * must never leave its own TF there. */
void on_usr1(int sig, siginfo_t *info, void *context)
{
    (void)sig; (void)info;
    got_usr1++;
    if (((ucontext_t *)context)->uc_mcontext.gregs[REG_EFL] & 0x100) tf_in_frame++;
}
static void on_segv(int sig, siginfo_t *info, void *context)
{
    (void)sig; (void)info; (void)context;
    got_segv++;
    siglongjmp(segv_jump, 1);
}
static void on_trap(int sig) { (void)sig; sigtrap_count++; }

static void *pinger(void *unused)
{
    (void)unused;
    prctl(PR_SET_NAME, "dbgping");
    while (!stop_workers) {
        pthread_kill(main_thread, SIGUSR1);
        usleep(1500);
    }
    return NULL;
}

static void *worker(void *index)
{
    unsigned long slot = (unsigned long)index;
    char name[16];
    snprintf(name, sizeof(name), "dbgwork-%lu", slot);
    prctl(PR_SET_NAME, name);
    while (!stop_workers) {
        counters[slot]++;
        usleep(2000);
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

static int int3_in(const void *code_address, int direct)
{
    unsigned char code[32];
    int count = 0;
    if (direct) {
        const volatile unsigned char *code_bytes = code_address;
        for (unsigned i = 0; i < sizeof(code); i++) count += code_bytes[i] == 0xcc;
        return count;
    } else {
        int fd = open("/proc/self/mem", O_RDONLY);
        if (fd < 0) return -1;
        if (pread(fd, code, sizeof(code), (off_t)(unsigned long)code_address) != (ssize_t)sizeof(code))
            count = -1;
        else
            for (unsigned i = 0; i < sizeof(code); i++) count += code[i] == 0xcc;
        close(fd);
        return count;
    }
}

/* A traced child's debug registers as its tracer sees them (the kernel's
 * virtual view). The sample cannot read its own; this is the only way a program
 * looks at debug registers on Linux. */
static void dr_probe(void)
{
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
    long dr7 = ptrace(PTRACE_PEEKUSER, child, offsetof(struct user, u_debugreg[7]), 0);
    long dr6 = ptrace(PTRACE_PEEKUSER, child, offsetof(struct user, u_debugreg[6]), 0);
    printf("dr child_dr7=0x%lx child_dr6=0x%lx\n", dr7, dr6);
    ptrace(PTRACE_CONT, child, 0, 0);
    waitpid(child, &status, 0);
}

static __attribute__((noinline)) void fault_once(void)
{
    if (!sigsetjmp(segv_jump, 1)) *(volatile int *)0 = 1;
}

static void smc_round(unsigned char *page, int version)
{
    /* mov $version,%eax ; ret */
    unsigned char code[6] = { 0xb8, (unsigned char)version, 0, 0, 0, 0xc3 };
    memcpy(page, code, sizeof(code));
    __builtin___clear_cache((char *)page, (char *)page + sizeof(code));
    int result = ((int (*)(void))page)();
    if (result != version) printf("smc MISMATCH version=%d result=%d\n", version, result);
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "threads";
    long rounds = argc > 2 ? strtol(argv[2], NULL, 10) : 200;
    int workers = argc > 3 ? atoi(argv[3]) : 3;
    pthread_t threads[MAX_WORKERS];
    unsigned char *smc = NULL;
    int traceme = -9;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!strcmp(mode, "start")) printf("main reached\n");
    if (workers < 0 || workers > MAX_WORKERS) workers = MAX_WORKERS;
    struct sigaction usr1 = { .sa_sigaction = on_usr1, .sa_flags = SA_SIGINFO };
    struct sigaction segv = { .sa_sigaction = on_segv, .sa_flags = SA_SIGINFO | SA_NODEFER };
    struct sigaction trap = { .sa_handler = on_trap };
    sigaction(SIGSEGV, &segv, NULL);
    sigaction(SIGTRAP, &trap, NULL);
    if (!strcmp(mode, "signal")) sigaction(SIGUSR1, &usr1, NULL);
    if (!strcmp(mode, "smc")) {
        smc = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (smc == MAP_FAILED) { printf("smc mmap failed\n"); return 1; }
    }
    printf("symbols step_syscall=0x%lx step_syscall_insn=0x%lx step_after_syscall=0x%lx "
           "step_rep=0x%lx step_rep_insn=0x%lx step_after_rep=0x%lx hw_code=0x%lx "
           "hw_after_write=0x%lx hw_after_read=0x%lx watched=0x%lx watched_other=0x%lx "
           "counters=0x%lx smc=0x%lx tf_probe=0x%lx worker=0x%lx main=0x%lx on_usr1=0x%lx round_now=0x%lx go=0x%lx pid=%d\n",
           (unsigned long)step_syscall, (unsigned long)step_syscall_insn,
           (unsigned long)step_after_syscall, (unsigned long)step_rep,
           (unsigned long)step_rep_insn, (unsigned long)step_after_rep,
           (unsigned long)hw_code, (unsigned long)hw_after_write,
           (unsigned long)hw_after_read, (unsigned long)&watched,
           (unsigned long)&watched_other, (unsigned long)counters, (unsigned long)smc,
           (unsigned long)tf_probe, (unsigned long)worker, (unsigned long)main,
           (unsigned long)on_usr1, (unsigned long)&round_now, (unsigned long)&go, getpid());
    if (argc > 4 && !strcmp(argv[4], "gate"))
        while (!go) usleep(1000);
    main_thread = pthread_self();
    if (!strcmp(mode, "threads"))
        for (long i = 0; i < workers; i++) pthread_create(&threads[i], NULL, worker, (void *)i);
    if (!strcmp(mode, "signal") && workers > 0) pthread_create(&threads[0], NULL, pinger, NULL);
    printf("start\n");
    for (long round = 0; round < rounds; round++) {
        round_now = round;
        if (!strcmp(mode, "signal")) {
            kill(getpid(), SIGUSR1);
            if (round % 10 == 5) fault_once();
            printf("tick %ld usr1=%d segv=%d tf_in_frame=%d\n", round, got_usr1, got_segv,
                   tf_in_frame);
        } else if (!strcmp(mode, "fatal")) {
            if (round == 5) raise(SIGUSR2);
            printf("tick %ld\n", round);
        } else if (!strcmp(mode, "step")) {
            long pid = step_syscall();
            step_rep();
            printf("tick %ld pid=%ld\n", round, pid);
        } else if (!strcmp(mode, "hw")) {
            long value = hw_code(round);
            watched_other = value;
            printf("tick %ld watched=%ld\n", round, watched);
        } else if (!strcmp(mode, "smc")) {
            smc_round(smc, (int)(round % 200) + 1);
            printf("tick %ld smc=%02x\n", round, smc[1]);
        } else if (!strcmp(mode, "anti")) {
            if (round == 20) traceme = (int)ptrace(PTRACE_TRACEME, 0, 0, 0);
            if (round == 10) dr_probe();
            printf("tick %ld tracer=%ld traceme=%d sigtrap=%d int3_mem=%d int3_direct=%d tf=%lu\n",
                   round, tracer_pid(), traceme, sigtrap_count,
                   int3_in((const void *)step_syscall, 0), int3_in((const void *)step_syscall, 1),
                   (tf_probe() >> 8) & 1);
        } else if (!strcmp(mode, "fork")) {
            if (round % 5 == 4) {
                pid_t child = fork();
                if (child == 0) {
                    for (int i = 0; i < 3; i++) hw_code(i);
                    _exit(0);
                }
                int status = 0;
                if (child > 0 && waitpid(child, &status, 0) == child)
                    printf("child exit=%d sig=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                           WIFSIGNALED(status) ? WTERMSIG(status) : 0);
            }
            hw_code(round);
            printf("tick %ld watched=%ld\n", round, watched);
        } else {
            hw_code(round);
            printf("tick %ld\n", round);
        }
        usleep(50000);
    }
    stop_workers = 1;
    if (!strcmp(mode, "threads"))
        for (long i = 0; i < workers; i++) pthread_join(threads[i], NULL);
    if (!strcmp(mode, "signal") && workers > 0) pthread_join(threads[0], NULL);
    printf("done usr1=%d segv=%d sigtrap=%d tf_in_frame=%d\n", got_usr1, got_segv, sigtrap_count,
           tf_in_frame);
    return 0;
}
