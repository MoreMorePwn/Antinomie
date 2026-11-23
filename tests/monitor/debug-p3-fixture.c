// SPDX-License-Identifier: GPL-3.0-only
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
 *            the child's exit status ("child exit=7"); on aarch64 from round
 *            30 (FORK_FIRST_ROUND)
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
 *            6 s, and stops the whole process with SIGSTOP in round 30
 *            (job control: no thread can park). After SIGCONT it calls
 *            child_site() and prints "child_site survived": a program that
 *            lived through Stop must not find an engine breakpoint byte there
 *   killtimer arms a timer that sends the process SIGKILL after ROUNDS ms and
 *            calls parent_site() every 50 ms until then (a group killed while
 *            the debugger holds it stopped)
 *   exec-gated waits for a 'g' line on stdin after printing its identity,
 *            then runs exec mode (attach to the old image before releasing it)
 *   exitstep a second thread reaches exit_syscall, a SYS_exit system call
 *            instruction of its own, after LEAD_MS (6000 by default); the main
 *            thread ticks
 *   vforkstep in round 20 (a second in, after the debugger attached) runs a raw
 *            SYS_vfork at vfork_syscall; the child execs this program in mode
 *            leaf; the parent reports "vfork child exit=5"
 *   pausestep in round 20 runs a raw SYS_pause at pause_syscall (blocks until a
 *            signal)
 *   vforknovm every third round clones a child with CLONE_VFORK and no
 *            CLONE_VM (its own copy of memory; the parent waits for it); the
 *            child calls child_site() twice and exits 7
 *   churn    prints "churn ready" and waits for a 'g' line, then starts and
 *            joins ROUNDS threads one after another; thread N calls
 *            churn_site(N) when N is CHURN_FIRST_HIT (1100, past the engine's
 *            1024 thread records) or a multiple of CHURN_EVERY (100) past it,
 *            and after joining such a thread the main thread prints
 *            "churn joined N" and waits for a 'g' line again; "churn done
 *            ROUNDS" at the end, exit 0
 *   exec-chld waits for a 'g' line after printing its identity, then execs
 *            this program in mode leafchld
 *   leafchld prints "leafchld pid=N", handles SIGCHLD, forks a child that
 *            exits after 200 ms, waits for the signal, reaps the child, prints
 *            "leafchld reaped" and exits 5
 *   forkfill waits for a 'g' line, then forks ROUNDS children (24 by
 *            default) at once, each calling child_site() and exiting 7, and
 *            reaps what ends within FORKFILL_MS: "forkfill exits=E traps=T
 *            other=O" (children still parked in a debug session are not
 *            waited for), exit 0
 *   vforksig handles SIGUSR1 and waits for a 'g' line, then vforks a child
 *            that sends itself SIGUSR1 (in the parent's memory) and execs this
 *            program in mode leafread; the parent reports "vfork child
 *            exit=5"
 *   leafread prints "leafread pid=N", reads stdin up to a line that starts with
 *            'x' (the end of the parent's 'g' line is skipped) and exits 5
 *   uringfifo makes a FIFO and submits an io_uring OPENAT of it for reading
 *            on an io-wq worker (IOSQE_ASYNC: it blocks there until a writer
 *            comes), prints "uring waiting", waits for a 'g' line, opens the
 *            FIFO for writing and prints "uring openat res=R" with the
 *            request's result, exit 0
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
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
SITE(churn_site)

__attribute__((noinline, used)) long work(long slot)
{
    counters[slot]++;
    return counters[slot];
}

/* A thread's own exit, at a known system call instruction. */
__attribute__((noinline, used)) void exit_now(void)
{
#if defined(__aarch64__)
    register long nr __asm__("x8") = SYS_exit, code __asm__("x0") = 0;
    __asm__ volatile(".globl exit_syscall\nexit_syscall:\n\tsvc #0"
                     : : "r"(nr), "r"(code) : "memory");
#else
    __asm__ volatile(".globl exit_syscall\nexit_syscall:\n\tsyscall"
                     : : "a"((long)SYS_exit), "D"(0L) : "rcx", "r11", "memory");
#endif
    __builtin_unreachable();
}
extern char exit_syscall[];

__attribute__((noinline, used)) long pause_now(void)
{
#if defined(__aarch64__)
    /* No pause on arm64: ppoll with no descriptors and no timeout blocks the same way. */
    register long nr __asm__("x8") = SYS_ppoll;
    register long ret __asm__("x0") = 0;
    register long a1 __asm__("x1") = 0, a2 __asm__("x2") = 0, a3 __asm__("x3") = 0,
                  a4 __asm__("x4") = 0;
    __asm__ volatile(".globl pause_syscall\npause_syscall:\n\tsvc #0"
                     : "+r"(ret) : "r"(nr), "r"(a1), "r"(a2), "r"(a3), "r"(a4) : "memory");
    return ret;
#else
    long ret;
    __asm__ volatile(".globl pause_syscall\npause_syscall:\n\tsyscall"
                     : "=a"(ret) : "0"((long)SYS_pause) : "rcx", "r11", "memory");
    return ret;
#endif
}
extern char pause_syscall[];

/* The round in which stopself stops itself: after the debugger attached and
 * stopped it once (1.5 s in; round 3, 150 ms, lost that race on a loaded
 * x86-64 host as on an emulated arm64 guest), and before its watchdog's 6 s. */
#define STOPSELF_ROUND 30
/* The first round fork may fork in: an emulated (TCG) arm64 guest's debugger
 * may attach and set its fork option only after round 2 (100 ms), and a child
 * forked before that exits and stops the program with a SIGCHLD where a test
 * expects the fork. */
#if defined(__aarch64__)
#define FORK_FIRST_ROUND 30
#else
#define FORK_FIRST_ROUND 0
#endif
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

#define CHURN_FIRST_HIT 1100
#define CHURN_EVERY 100

static int churn_hit(long index)
{
    return index >= CHURN_FIRST_HIT && (index - CHURN_FIRST_HIT) % CHURN_EVERY == 0;
}

static void *churner(void *index)
{
    if (churn_hit((long)index)) churn_site((long)index);
    return NULL;
}

static volatile sig_atomic_t chld_seen;
static void on_chld(int signal)
{
    (void)signal;
    chld_seen = 1;
}

static void print_symbols(void)
{
    printf("symbols parent_site=%p child_site=%p leaf_site=%p grandchild_site=%p work=%p"
           " watched=%p counters=%p exit_syscall=%p pause_syscall=%p vfork_syscall=%p"
           " churn_site=%p\n",
           (void *)parent_site, (void *)child_site, (void *)leaf_site, (void *)grandchild_site,
           (void *)work, (void *)&watched, (void *)counters, (void *)exit_syscall,
           (void *)pause_syscall, (void *)vfork_syscall, (void *)churn_site);
    fflush(stdout);
}

/* A 'g' on stdin (the line ends of earlier gates are skipped): the debugger
 * is ready for what comes next. 0 at the end of input.
 */
static int gate(void)
{
    char byte = 0;
    ssize_t count;
    for (;;) {
        count = read(STDIN_FILENO, &byte, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count != 1) return 0;
        if (byte == 'g') return 1;
        if (byte != '\n') return 0;
    }
}

/* How long forkfill waits for its children to end. */
#define FORKFILL_MS 6000

static int forkfill(long children)
{
    int exits = 0, traps = 0, other = 0, left = 0;

    if (!gate()) return 98;
    for (long i = 0; i < children; i++) {
        pid_t child = fork();
        if (child == 0) {
            child_site(i);
            _exit(7);
        }
        if (child > 0) left++;
    }
    for (int waited = 0; left > 0 && waited < FORKFILL_MS; ) {
        int status = 0;
        pid_t done = waitpid(-1, &status, WNOHANG);
        if (done > 0) {
            left--;
            if (WIFEXITED(status) && WEXITSTATUS(status) == 7) exits++;
            else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGTRAP) traps++;
            else other++;
            continue;
        }
        usleep(20000);
        waited += 20;
    }
    printf("forkfill exits=%d traps=%d other=%d\n", exits, traps, other);
    fflush(stdout);
    return 0;
}

static volatile sig_atomic_t usr1_seen;
static void on_usr1(int signal)
{
    (void)signal;
    usr1_seen = 1;
}

static int vforksig(void)
{
    int status = 0;
    pid_t child;

    signal(SIGUSR1, on_usr1);
    if (!gate()) return 98;
    child = vfork();
    if (child == 0) {
        char *args[] = { self_path, "leafread", NULL };
        kill(getpid(), SIGUSR1);
        execv(self_path, args);
        _exit(99);
    }
    if (child > 0 && waitpid(child, &status, 0) == child)
        printf("vfork child exit=%d sig=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1,
               WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    return 0;
}

static int leafread(void)
{
    char line[64];

    printf("leafread pid=%d\n", (int)getpid());
    fflush(stdout);
    do {
        if (!fgets(line, sizeof(line), stdin)) return 1;
    } while (line[0] != 'x');
    return 5;
}

/* One io_uring request, raw system calls: an OPENAT of a FIFO for reading,
 * pushed onto an io-wq worker, where it blocks until a writer opens the FIFO.
 */
static int uringfifo(void)
{
    struct io_uring_params params;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
    unsigned char *ring;
    unsigned *tail, *mask, *array, *cq_head, *cq_tail, *cq_mask;
    size_t size;
    char path[64];
    int fd, writer;

    snprintf(path, sizeof(path), "/tmp/p3fifo.%d", (int)getpid());
    unlink(path);
    if (mkfifo(path, 0600)) return 2;
    memset(&params, 0, sizeof(params));
    fd = (int)syscall(__NR_io_uring_setup, 4, &params);
    if (fd < 0) {
        printf("uring unavailable %d\n", errno);
        return 2;
    }
    size = params.sq_off.array + params.sq_entries * sizeof(unsigned);
    if (params.cq_off.cqes + params.cq_entries * sizeof(*cqes) > size)
        size = params.cq_off.cqes + params.cq_entries * sizeof(*cqes);
    ring = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
                IORING_OFF_SQ_RING);
    sqes = mmap(NULL, params.sq_entries * sizeof(*sqes), PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
    if (ring == MAP_FAILED || sqes == MAP_FAILED) return 2;
    tail = (unsigned *)(ring + params.sq_off.tail);
    mask = (unsigned *)(ring + params.sq_off.ring_mask);
    array = (unsigned *)(ring + params.sq_off.array);
    cq_head = (unsigned *)(ring + params.cq_off.head);
    cq_tail = (unsigned *)(ring + params.cq_off.tail);
    cq_mask = (unsigned *)(ring + params.cq_off.ring_mask);
    cqes = (struct io_uring_cqe *)(ring + params.cq_off.cqes);
    memset(&sqes[0], 0, sizeof(sqes[0]));
    sqes[0].opcode = IORING_OP_OPENAT;
    sqes[0].fd = AT_FDCWD;
    sqes[0].addr = (unsigned long)path;
    sqes[0].open_flags = O_RDONLY | O_CLOEXEC;
    sqes[0].flags = IOSQE_ASYNC;
    sqes[0].user_data = 1;
    array[*tail & *mask] = 0;
    __atomic_store_n(tail, *tail + 1, __ATOMIC_RELEASE);
    if (syscall(__NR_io_uring_enter, fd, 1, 0, 0, NULL, 0) != 1) return 2;
    usleep(100000);
    printf("uring waiting\n");
    fflush(stdout);
    if (!gate()) return 98;
    /* A reader is waiting in the worker, so a non-blocking writer opens. */
    writer = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (writer < 0) printf("uring writer open failed %d\n", errno);
    while (__atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == *cq_head)
        if (syscall(__NR_io_uring_enter, fd, 0, 1, IORING_ENTER_GETEVENTS, NULL, 0) < 0 &&
            errno != EINTR)
            return 2;
    printf("uring openat res=%d\n", cqes[*cq_head & *cq_mask].res);
    fflush(stdout);
    unlink(path);
    return 0;
}

static int churn(long threads)
{
    printf("churn ready\n");
    fflush(stdout);
    if (!gate()) return 98;
    for (long i = 0; i < threads; i++) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, churner, (void *)i)) {
            printf("churn create failed at %ld\n", i);
            return 1;
        }
        pthread_join(thread, NULL);
        if (churn_hit(i)) {
            printf("churn joined %ld\n", i);
            fflush(stdout);
            if (!gate()) return 98;
        }
    }
    printf("churn done %ld\n", threads);
    return 0;
}

/* The image an unfollowed exec leaves: its first signal (SIGCHLD, handled)
 * must be delivered, not held by a debug session that is over.
 */
static int leafchld(void)
{
    struct sigaction action;
    sigset_t chld, old;
    int status = 0;

    memset(&action, 0, sizeof(action));
    action.sa_handler = on_chld;
    sigemptyset(&action.sa_mask);
    sigaction(SIGCHLD, &action, NULL);
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, &old);
    printf("leafchld pid=%d\n", (int)getpid());
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        usleep(200000);
        _exit(0);
    }
    if (child < 0) return 1;
    while (!chld_seen) sigsuspend(&old);
    sigprocmask(SIG_SETMASK, &old, NULL);
    if (waitpid(child, &status, 0) != child) return 1;
    printf("leafchld reaped\n");
    fflush(stdout);
    return 5;
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
    int exec_gate = !strcmp(mode, "exec-gated");
    if (exec_gate) mode = "exec";
    int exec_chld = !strcmp(mode, "exec-chld");
    long rounds = argc > 2 ? strtol(argv[2], NULL, 10) : 60;
    long workers = argc > 3 ? strtol(argv[3], NULL, 10) : 0;
    pthread_t threads[MAX_WORKERS];

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (workers > MAX_WORKERS) workers = MAX_WORKERS;
    ssize_t length = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    self_path[length > 0 ? length : 0] = 0;
    if (!strcmp(mode, "leaf")) return leaf();
    if (!strcmp(mode, "leafchld")) return leafchld();
    if (!strcmp(mode, "leafread")) return leafread();
    print_symbols();
    printf("start\n");
    fflush(stdout);
    if (!strcmp(mode, "churn")) return churn(rounds);
    if (!strcmp(mode, "forkfill")) return forkfill(argc > 2 ? rounds : 24);
    if (!strcmp(mode, "vforksig")) return vforksig();
    if (!strcmp(mode, "uringfifo")) return uringfifo();
    if (exec_chld) {
        char *args[] = { self_path, "leafchld", NULL };
        if (!gate()) return 98;
        printf("exec now pid=%d\n", (int)getpid());
        fflush(stdout);
        execv(self_path, args);
        printf("exec failed %d\n", errno);
        return 1;
    }
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
    if (exec_gate) {
        /* The debugger must attach to the old image before the exec. */
        char gate = 0;
        ssize_t count;
        do {
            count = read(STDIN_FILENO, &gate, 1);
        } while (count < 0 && errno == EINTR);
        if (count != 1 || gate != 'g') return 98;
    }
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
        if (!strcmp(mode, "fork") && round % 3 == 2 && round >= FORK_FIRST_ROUND) {
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
        } else if (!strcmp(mode, "vforkstep") && round == 20) {
            /* Inline: the child returns into this frame, as from vfork(). */
#if defined(__aarch64__)
            /* No vfork on arm64: clone(CLONE_VM | CLONE_VFORK | SIGCHLD) on the same stack. */
            register long nr __asm__("x8") = SYS_clone;
            register long child __asm__("x0") = CLONE_VM | CLONE_VFORK | SIGCHLD;
            register long a1 __asm__("x1") = 0, a2 __asm__("x2") = 0, a3 __asm__("x3") = 0,
                          a4 __asm__("x4") = 0;
            __asm__ volatile(".globl vfork_syscall\nvfork_syscall:\n\tsvc #0"
                             : "+r"(child) : "r"(nr), "r"(a1), "r"(a2), "r"(a3), "r"(a4)
                             : "memory");
#else
            long child;
            __asm__ volatile(".globl vfork_syscall\nvfork_syscall:\n\tsyscall"
                             : "=a"(child) : "0"((long)SYS_vfork) : "rcx", "r11", "memory");
#endif
            if (child == 0) {
                char *args[] = { self_path, "leaf", NULL };
                execv(self_path, args);
                _exit(99);
            }
            int status = 0;
            if (child > 0 && waitpid((pid_t)child, &status, 0) == child)
                printf("vfork child exit=%d sig=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                       WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        } else if (!strcmp(mode, "pausestep") && round == 20) {
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
        } else if (!strcmp(mode, "stopself") && round == STOPSELF_ROUND) {
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
