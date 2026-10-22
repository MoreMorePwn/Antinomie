// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
/* Debugger phase 3 fixture for the disposable BusyBox qualifier: processes that
 * fork, vfork and exec, and threads that run on their own. One binary, a mode
 * per behavior; build it statically:
 *   gcc -O1 -static -no-pie -pthread -o p3fix debug-p3-fixture.c
 * The guest runs it as /tmp/p3fix.
 *
 * usage: p3fix MODE [ROUNDS [WORKERS [LEAD_MS]]]
 * LEAD_MS sleeps after "start" before the first round: a debugger that connects
 * then finds the program idle, not in the middle of a fork.
 * Every mode prints "symbols name=0xaddr ..." first, then "start". Lines of
 * the form "child ..." come from a forked child, "leaf ..." from an exec'd one.
 *   fork     every third round forks a child that calls child_site() twice and
 *            exits 7; the parent calls parent_site() every round and reports
 *            the child's exit status ("child exit=7")
 *   vfork    every third round vforks a child that execs this program in mode
 *            leaf; the parent reports "vfork child exit=5"
 *   exec     calls parent_site() ROUNDS times, then execs this program in mode
 *            leaf (the same PID, the other threads of WORKERS gone)
 *   leaf     prints "leaf pid=N", calls leaf_site() three times, exits 5
 *   nonstop  WORKERS threads, each calling work(slot) in a loop with its own
 *            counter; the main thread ticks
 *   system   every third round runs system("echo spawned") (clone with CLONE_VM
 *            and CLONE_VFORK, then an exec of the shell)
 *   spawn    WORKERS threads are created and joined every round, each writing
 *            the global `watched` once (hardware breakpoints in new threads)
 *   chld     blocks SIGCHLD, forks a child that exits at once, waits for it and
 *            unblocks: the queued SIGCHLD is delivered then, every round (the
 *            window glibc's fork() opens by itself when the child is quick)
 *   stopself ignores SIGTERM, starts a watchdog child that sends SIGCONT after
 *            6 s, and stops the whole process with SIGSTOP in round 3 (job
 *            control: no thread can park). After SIGCONT it calls
 *            child_site() and prints "child_site survived": a program that
 *            lived through Stop must not find an engine breakpoint byte there
 *   killtimer arms a timer that sends the process SIGKILL after ROUNDS ms and
 *            calls parent_site() every 50 ms until then (a group killed while
 *            the debugger holds it stopped)
 *   exitstep a second thread reaches exit_syscall, a SYS_exit system call
 *            instruction of its own, after LEAD_MS (6000 by default); the main
 *            thread ticks
 *   vforkstep in round 2 runs a raw SYS_vfork at vfork_syscall; the child execs
 *            this program in mode leaf; the parent reports "vfork child exit=5"
 *   pausestep in round 2 runs a raw SYS_pause at pause_syscall (blocks until a
 *            signal)
 *   vforknovm every third round clones a child with CLONE_VFORK and no
 *            CLONE_VM (its own copy of memory; the parent waits for it); the
 *            child calls child_site() twice and exits 7
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_WORKERS 64
volatile unsigned long counters[MAX_WORKERS];
volatile long watched;
volatile int stop_workers;
static char self_path[256];

#define SITE(name)                                                                     \
    __attribute__((noinline, used)) long name(long value)                              \
    {                                                                                  \
        __asm__ volatile("" ::: "memory");                                             \
        return value + 1;                                                              \
    }
SITE(parent_site)
SITE(child_site)
SITE(leaf_site)
SITE(grandchild_site)

__attribute__((noinline, used)) long work(long slot)
{
    counters[slot]++;
    return counters[slot];
}

/* A thread's own exit, at a known system call instruction. */
__attribute__((noinline, used)) void exit_now(void)
{
    __asm__ volatile(".globl exit_syscall\nexit_syscall:\n\tsyscall"
                     : : "a"((long)SYS_exit), "D"(0L) : "rcx", "r11", "memory");
    __builtin_unreachable();
}
extern char exit_syscall[];

__attribute__((noinline, used)) long pause_now(void)
{
    long ret;
    __asm__ volatile(".globl pause_syscall\npause_syscall:\n\tsyscall"
                     : "=a"(ret) : "0"((long)SYS_pause) : "rcx", "r11", "memory");
    return ret;
}
extern char pause_syscall[];
extern char vfork_syscall[];

static long exit_lead_ms;
static void *exiter(void *unused)
{
    (void)unused;
    usleep((useconds_t)exit_lead_ms * 1000);
    exit_now();
    return NULL;
}

static void *worker(void *index)
{
    unsigned long slot = (unsigned long)index;
    char name[16];
    snprintf(name, sizeof(name), "p3work-%lu", slot);
    prctl(PR_SET_NAME, name);
    while (!stop_workers) {
        work((long)slot);
        usleep(1000 + 700 * slot);
    }
    return NULL;
}

static void *spawned(void *unused)
{
    (void)unused;
    watched = 1;
    return NULL;
}

static void print_symbols(void)
{
    printf("symbols parent_site=%p child_site=%p leaf_site=%p grandchild_site=%p work=%p"
           " watched=%p counters=%p exit_syscall=%p pause_syscall=%p vfork_syscall=%p\n",
           (void *)parent_site, (void *)child_site, (void *)leaf_site, (void *)grandchild_site,
           (void *)work, (void *)&watched, (void *)counters, (void *)exit_syscall,
           (void *)pause_syscall, (void *)vfork_syscall);
    fflush(stdout);
}

static int leaf(void)
{
    printf("leaf pid=%d\n", (int)getpid());
    fflush(stdout);
    for (int i = 0; i < 3; i++) {
        leaf_site(i);
        usleep(20000);
    }
    return 5;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "fork";
    long rounds = argc > 2 ? strtol(argv[2], NULL, 10) : 60;
    long workers = argc > 3 ? strtol(argv[3], NULL, 10) : 0;
    pthread_t threads[MAX_WORKERS];

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (workers > MAX_WORKERS) workers = MAX_WORKERS;
    ssize_t length = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    self_path[length > 0 ? length : 0] = 0;
    if (!strcmp(mode, "leaf")) return leaf();
    print_symbols();
    printf("start\n");
    fflush(stdout);
    if (!strcmp(mode, "nonstop") || !strcmp(mode, "exec"))
        for (long i = 0; i < workers; i++) pthread_create(&threads[i], NULL, worker, (void *)i);
    long lead = argc > 4 ? strtol(argv[4], NULL, 10) : 0;
    if (!strcmp(mode, "exitstep")) {
        pthread_t exiting;
        exit_lead_ms = lead > 0 ? lead : 6000;
        pthread_create(&exiting, NULL, exiter, NULL);
        lead = 0;
    }
    if (lead > 0) usleep((useconds_t)lead * 1000);
    if (!strcmp(mode, "killtimer")) {
        struct sigevent event = { .sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGKILL };
        struct itimerspec when = { .it_value = { rounds / 1000, (rounds % 1000) * 1000000 } };
        timer_t timer;
        if (timer_create(CLOCK_MONOTONIC, &event, &timer) || timer_settime(timer, 0, &when, NULL))
            printf("timer failed %d\n", errno);
        rounds = 1000000;
    }
    if (!strcmp(mode, "stopself")) {
        signal(SIGTERM, SIG_IGN);
        pid_t watchdog = fork();
        if (watchdog == 0) {
            sleep(6);
            kill(getppid(), SIGCONT);
            _exit(0);
        }
    }
    for (long round = 0; round < rounds; round++) {
        parent_site(round);
        if (!strcmp(mode, "fork") && round % 3 == 2) {
            pid_t child = fork();
            if (child == 0) {
                printf("child pid=%d\n", (int)getpid());
                fflush(stdout);
                for (int i = 0; i < 2; i++) {
                    child_site(i);
                    usleep(10000);
                }
                _exit(7);
            }
            int status = 0;
            if (child > 0 && waitpid(child, &status, 0) == child)
                printf("child exit=%d sig=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                       WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        } else if (!strcmp(mode, "vfork") && round % 3 == 2) {
            pid_t child = vfork();
            if (child == 0) {
                char *args[] = { self_path, "leaf", NULL };
                execv(self_path, args);
                _exit(99);
            }
            int status = 0;
            if (child > 0 && waitpid(child, &status, 0) == child)
                printf("vfork child exit=%d sig=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                       WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        } else if (!strcmp(mode, "vforkstep") && round == 2) {
            /* Inline: the child returns into this frame, as from vfork(). */
            long child;
            __asm__ volatile(".globl vfork_syscall\nvfork_syscall:\n\tsyscall"
                             : "=a"(child) : "0"((long)SYS_vfork) : "rcx", "r11", "memory");
            if (child == 0) {
                char *args[] = { self_path, "leaf", NULL };
                execv(self_path, args);
                _exit(99);
            }
            int status = 0;
            if (child > 0 && waitpid((pid_t)child, &status, 0) == child)
                printf("vfork child exit=%d sig=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                       WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        } else if (!strcmp(mode, "pausestep") && round == 2) {
            printf("pausing\n");
            fflush(stdout);
            pause_now();
            printf("paused\n");
        } else if (!strcmp(mode, "vforknovm") && round % 3 == 2) {
            long child = syscall(SYS_clone, (long)(CLONE_VFORK | SIGCHLD), 0L, 0L, 0L, 0L);
            if (child == 0) {
                printf("child pid=%d\n", (int)getpid());
                fflush(stdout);
                for (int i = 0; i < 2; i++) {
                    child_site(i);
                    usleep(10000);
                }
                _exit(7);
            }
            int status = 0;
            if (child > 0 && waitpid((pid_t)child, &status, 0) == child)
                printf("child exit=%d sig=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                       WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        } else if (!strcmp(mode, "system") && round % 3 == 2) {
            int status = system("echo spawned");
            printf("system status=%d\n", status);
        } else if (!strcmp(mode, "exec") && round == rounds - 1) {
            printf("exec now pid=%d\n", (int)getpid());
            fflush(stdout);
            char *args[] = { self_path, "leaf", NULL };
            execv(self_path, args);
            printf("exec failed %d\n", errno);
        } else if (!strcmp(mode, "spawn")) {
            for (long i = 0; i < workers; i++) pthread_create(&threads[i], NULL, spawned, NULL);
            for (long i = 0; i < workers; i++) pthread_join(threads[i], NULL);
        } else if (!strcmp(mode, "chld")) {
            sigset_t chld, old;
            sigemptyset(&chld);
            sigaddset(&chld, SIGCHLD);
            sigprocmask(SIG_BLOCK, &chld, &old);
            pid_t child = fork();
            if (child == 0) _exit(0);
            int status;
            if (child > 0) waitpid(child, &status, 0);
            sigprocmask(SIG_SETMASK, &old, NULL);
            printf("chld reaped\n");
        } else if (!strcmp(mode, "stopself") && round == 3) {
            printf("stopping myself\n");
            fflush(stdout);
            raise(SIGSTOP);
            printf("continued\n");
            child_site(1);
            printf("child_site survived\n");
            fflush(stdout);
        }
        printf("tick %ld\n", round);
        usleep(50000);
    }
    stop_workers = 1;
    if (!strcmp(mode, "nonstop") || !strcmp(mode, "exec"))
        for (long i = 0; i < workers; i++) pthread_join(threads[i], NULL);
    printf("done\n");
    return 0;
}
