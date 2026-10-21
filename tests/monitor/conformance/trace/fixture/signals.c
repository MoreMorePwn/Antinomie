// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// signals.c — dispositions, masks, queued signals, alternate stacks, timers
// that deliver signals, and the calls the kernel makes on the program's behalf
// (rt_sigreturn through the handler trampoline, restart_syscall after a stop).
//
// Slots: rt_sigaction rt_sigprocmask rt_sigreturn rt_sigpending rt_sigtimedwait
// rt_sigqueueinfo rt_tgsigqueueinfo rt_sigsuspend sigaltstack pause alarm
// getitimer setitimer restart_syscall.
//
// rt_sigaction goes through the raw system call, so the act/oldact structure is
// the kernel's struct sigaction {handler, flags, restorer, mask} (32 bytes) with
// sigsetsize 8, and the handlers installed that way return through this file's
// own SA_RESTORER trampoline. Child process indices: 500-502.
#include "areas.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>

#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif

// The kernel's x86-64 struct sigaction, as rt_sigaction reads and writes it.
struct ksigaction {
    void *handler;
    unsigned long flags;
    void (*restorer)(void);
    uint64_t mask;
};

#define KSIGSET 8
#define SIGBIT(sig) (1ULL << ((sig) - 1))

// The signal trampoline: what glibc's __restore_rt does, for handlers this
// file installs through the raw system call.
__asm__(".pushsection .text\n"
        ".p2align 4\n"
        ".globl ant_fixture_signals_restore_rt\n"
        ".hidden ant_fixture_signals_restore_rt\n"
        ".type ant_fixture_signals_restore_rt,@function\n"
        "ant_fixture_signals_restore_rt:\n"
        "\tmovq $15, %rax\n"
        "\tsyscall\n"
        "\thlt\n"
        ".size ant_fixture_signals_restore_rt,.-ant_fixture_signals_restore_rt\n"
        ".popsection\n");
extern void ant_fixture_signals_restore_rt(void);

static volatile sig_atomic_t hits;
static volatile int last_signo, last_code, last_value;
static volatile uintptr_t handler_sp;
static unsigned char alt_stack[65536];

static void on_signal(int sig, siginfo_t *info, void *context)
{
    volatile char local = 0;
    (void)context;
    hits++;
    last_signo = sig;
    if (info) {
        last_code = info->si_code;
        last_value = info->si_value.sival_int;
    }
    handler_sp = (uintptr_t)&local;
}

static struct ksigaction handler_action(unsigned long flags)
{
    struct ksigaction act;
    memset(&act, 0, sizeof act);
    act.handler = (void *)on_signal;
    act.flags = flags | SA_SIGINFO | SA_RESTORER;
    act.restorer = ant_fixture_signals_restore_rt;
    act.mask = 0;
    return act;
}

static void queued_info(siginfo_t *info, int sig, int value)
{
    memset(info, 0, sizeof *info);
    info->si_signo = sig;
    info->si_code = SI_QUEUE;
    info->si_pid = getpid();
    info->si_uid = getuid();
    info->si_value.sival_int = value;
}

// ---------------------------------------------------------------------------
// Children: a forked child that tells the parent, through a pipe, that it is
// about to make the call the parent then interrupts.

static pid_t start_child(unsigned index, void (*body)(int ready_fd))
{
    int ready[2];
    if (pipe2(ready, O_CLOEXEC) != 0) {
        ora_fail("signals: ready pipe");
        return -1;
    }
    ora_flush();
    pid_t child = fork();
    if (child < 0) {
        ora_fail("signals: fork");
        close(ready[0]);
        close(ready[1]);
        return -1;
    }
    if (child == 0) {
        close(ready[0]);
        ora_child(index);
        alarm(5); // a child that is never woken ends instead of hanging
        body(ready[1]);
        _exit(ora_failures() ? 3 : 0);
    }
    close(ready[1]);
    char byte;
    ssize_t got;
    do
        got = read(ready[0], &byte, 1);
    while (got < 0 && errno == EINTR);
    close(ready[0]);
    return child;
}

static void say_ready(int fd)
{
    if (write(fd, "r", 1) != 1)
        ora_fail("signals: child ready");
    close(fd);
}

static void pause_ms(long ms)
{
    struct timespec delay = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR)
        ;
}

// Wait until task `tid` sleeps inside system call `nr` (/proc/PID/syscall
// shows the number only while the task is blocked). Returns 0 on timeout or
// when the file cannot be read; the caller then relies on a fixed delay.
static int wait_in_syscall(const char *path, long nr)
{
    for (int round = 0; round < 1000; round++) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return 0;
        char text[64] = {0};
        ssize_t got = read(fd, text, sizeof text - 1);
        close(fd);
        if (got > 0 && strtol(text, NULL, 10) == nr && text[0] >= '0' && text[0] <= '9')
            return 1;
        pause_ms(2);
    }
    return 0;
}

// Reap `child`, sending `sig` again every 100 ms until it exits (a signal
// that arrived before the child blocked is handled and does not wake it).
// Bounded: after 5 s the child is killed and the case fails.
static void reap_signalling(pid_t child, int sig, const char *what)
{
    int status = 0;
    for (int round = 0; round < 1000; round++) {
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child) {
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                char text[160];
                snprintf(text, sizeof text, "%s: child status %#x", what, status);
                ora_fail(text);
            }
            return;
        }
        if (got < 0 && errno != EINTR)
            break;
        if (sig && round % 20 == 19)
            kill(child, sig);
        pause_ms(5);
    }
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    ora_fail(what);
}

static void sigsuspend_body(int ready_fd)
{
    sigset_t block;
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = on_signal;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &block, NULL) != 0 || sigaction(SIGUSR1, &action, NULL) != 0)
        ora_fail("rt_sigsuspend: child setup");
    hits = 0;
    say_ready(ready_fd);
    uint64_t none = 0;
    uint64_t t0 = ora_now();
    CALL("rt_sigsuspend.woken", rt_sigsuspend, EINTR, &none, KSIGSET);
    uint64_t t1 = ora_now();
    in_buf(0, &none, sizeof none);
    why("SIGUSR1 from the parent is blocked until rt_sigsuspend installs the empty mask, so "
        "it always interrupts the call; the recorded exit may carry ERESTARTNOHAND, the "
        "program sees EINTR after the handler");
    DONE();
    implicit_case("rt_sigreturn.after_sigsuspend", "rt_sigreturn", SYS_rt_sigreturn, t0, t1,
                  -EINTR);
    if (hits != 1 || last_signo != SIGUSR1)
        ora_fail("rt_sigsuspend: handler did not run once");
}

static void pause_body(int ready_fd)
{
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = on_signal;
    action.sa_flags = SA_SIGINFO;
    if (sigaction(SIGUSR1, &action, NULL) != 0)
        ora_fail("pause: child setup");
    hits = 0;
    say_ready(ready_fd);
    CALL0("pause.woken", pause, EINTR);
    why("the parent sends SIGUSR1 once the child sleeps in pause (and again until it exits)");
    DONE();
    if (hits < 1)
        ora_fail("pause: handler did not run");
}

static void restart_body(int ready_fd)
{
    struct timespec request = {0, 300000000L}, remain;
    memset(&remain, 0, sizeof remain);
    say_ready(ready_fd);
    uint64_t t0 = ora_now();
    CALL("clock_nanosleep.stopped_and_continued", clock_nanosleep, WANT_OK, CLOCK_MONOTONIC, 0,
         &request, &remain);
    uint64_t t1 = ora_now();
    in_buf(2, &request, sizeof request);
    why("the parent stops and continues the child during the 300 ms sleep; no handler runs, so "
        "the kernel resumes the sleep through restart_syscall and the program sees 0 (the "
        "recorded clock_nanosleep exit may carry ERESTART_RESTARTBLOCK)");
    DONE();
    implicit_case("restart_syscall.after_sigcont", "restart_syscall", SYS_restart_syscall, t0, t1,
                  0);
}

static void child_cases(void)
{
    char path[64];

    // rt_sigsuspend: the signal waits, blocked, until the call unblocks it.
    pid_t child = start_child(500, sigsuspend_body);
    if (child > 0) {
        kill(child, SIGUSR1);
        reap_signalling(child, SIGUSR1, "rt_sigsuspend child");
    }

    // pause: SIGUSR1 once the child sleeps in the call.
    child = start_child(501, pause_body);
    if (child > 0) {
        snprintf(path, sizeof path, "/proc/%d/syscall", (int)child);
        if (!wait_in_syscall(path, SYS_pause))
            pause_ms(100);
        kill(child, SIGUSR1);
        reap_signalling(child, SIGUSR1, "pause child");
    }

    // restart_syscall: SIGSTOP and SIGCONT during a relative clock_nanosleep.
    child = start_child(502, restart_body);
    if (child > 0) {
        snprintf(path, sizeof path, "/proc/%d/syscall", (int)child);
        if (!wait_in_syscall(path, SYS_clock_nanosleep))
            pause_ms(50);
        int status = 0;
        kill(child, SIGSTOP);
        pid_t got;
        do
            got = waitpid(child, &status, WUNTRACED);
        while (got < 0 && errno == EINTR);
        if (got != child || !WIFSTOPPED(status)) {
            ora_fail("restart_syscall: child did not stop in its sleep");
            if (got == child)
                return; // already reaped
        }
        pause_ms(20);
        kill(child, SIGCONT);
        reap_signalling(child, 0, "restart_syscall child");
    }
}

// ---------------------------------------------------------------------------

static void action_cases(struct ksigaction *saved_usr1)
{
    struct ksigaction act = handler_action(SA_RESTART), old, query;
    memset(&old, 0, sizeof old);
    CALL("rt_sigaction.install_siginfo_restart", rt_sigaction, WANT_OK, SIGUSR1, &act, &old,
         KSIGSET);
    in_buf(1, &act, sizeof act);
    out_buf(2, &old, sizeof old);
    DONE();
    *saved_usr1 = old;

    memset(&query, 0, sizeof query);
    CALL("rt_sigaction.query", rt_sigaction, WANT_OK, SIGUSR1, NULL, &query, KSIGSET);
    out_buf(2, &query, sizeof query);
    why("a NULL act only reads the disposition; the decoder records no field for it");
    DONE();
    if (query.handler != (void *)on_signal)
        ora_fail("rt_sigaction: query did not return the installed handler");

    struct ksigaction ignore;
    memset(&ignore, 0, sizeof ignore);
    ignore.handler = (void *)SIG_IGN;
    ignore.flags = SA_RESTORER;
    ignore.restorer = ant_fixture_signals_restore_rt;
    ignore.mask = SIGBIT(SIGUSR1);
    struct ksigaction old_usr2;
    memset(&old_usr2, 0, sizeof old_usr2);
    CALL("rt_sigaction.ignore", rt_sigaction, WANT_OK, SIGUSR2, &ignore, &old_usr2, KSIGSET);
    in_buf(1, &ignore, sizeof ignore);
    out_buf(2, &old_usr2, sizeof old_usr2);
    DONE();
    CALL("rt_sigaction.restore_usr2", rt_sigaction, WANT_OK, SIGUSR2, &old_usr2, NULL, KSIGSET);
    in_buf(1, &old_usr2, sizeof old_usr2);
    DONE();

    CALL("rt_sigaction.bad_sigsetsize", rt_sigaction, EINVAL, SIGUSR1, &act, &query, 4);
    want_status(1, "in", "INVALID_EXTENT");
    why("sigsetsize must be 8: the kernel rejects it and the recorder marks the extent invalid");
    DONE();
    CALL("rt_sigaction.sigkill", rt_sigaction, EINVAL, SIGKILL, &act, NULL, KSIGSET);
    in_buf(1, &act, sizeof act);
    DONE();
    CASE("rt_sigaction.bad_signal", rt_sigaction, EINVAL, 65, NULL, &query, KSIGSET);
    CALL("rt_sigaction.fault", rt_sigaction, EFAULT, SIGUSR1, 1, NULL, KSIGSET);
    want_status(1, "in", "COPY_FAULT");
    why("an address in the first page is never mapped");
    DONE();
}

static void sigreturn_and_queue_cases(void)
{
    siginfo_t info;
    queued_info(&info, SIGUSR1, 0x414e54);
    hits = 0;
    uint64_t t0 = ora_now();
    CALL("rt_sigqueueinfo.self_handled", rt_sigqueueinfo, WANT_OK, getpid(), SIGUSR1, &info);
    in_buf(2, &info, sizeof info);
    volatile_case();
    why("si_code SI_QUEUE to the caller itself; the handler runs on the way out of the call");
    DONE();
    uint64_t t1 = ora_now();
    implicit_case("rt_sigreturn.after_sigqueueinfo", "rt_sigreturn", SYS_rt_sigreturn, t0, t1, 0);
    if (hits != 1 || last_code != SI_QUEUE || last_value != 0x414e54)
        ora_fail("rt_sigqueueinfo: handler did not see the queued value");

    CALL("rt_sigqueueinfo.bad_signal", rt_sigqueueinfo, EINVAL, getpid(), 65, &info);
    in_buf(2, &info, sizeof info);
    volatile_case();
    DONE();
    CALL("rt_sigqueueinfo.fault", rt_sigqueueinfo, EFAULT, getpid(), SIGUSR1, 1);
    want_status(2, "in", "COPY_FAULT");
    volatile_case();
    DONE();
}

static void mask_cases(void)
{
    uint64_t set = SIGBIT(SIGUSR1) | SIGBIT(SIGUSR2), initial = 0, query = 0, after = 0;
    CALL("rt_sigprocmask.block", rt_sigprocmask, WANT_OK, SIG_BLOCK, &set, &initial, KSIGSET);
    in_buf(1, &set, sizeof set);
    out_buf(2, &initial, sizeof initial);
    DONE();
    CALL("rt_sigprocmask.query", rt_sigprocmask, WANT_OK, SIG_BLOCK, NULL, &query, KSIGSET);
    out_buf(2, &query, sizeof query);
    why("a NULL set only reads the mask; the decoder records no field for it");
    DONE();
    if ((query & set) != set)
        ora_fail("rt_sigprocmask: signals not blocked");

    // Blocked signals wait: queue them, look at them, take them.
    siginfo_t first, second, taken;
    queued_info(&first, SIGUSR1, 0x4f4e45);
    queued_info(&second, SIGUSR2, 0x54574f);
    CALL("rt_sigqueueinfo.self_blocked", rt_sigqueueinfo, WANT_OK, getpid(), SIGUSR1, &first);
    in_buf(2, &first, sizeof first);
    volatile_case();
    DONE();
    CALL("rt_tgsigqueueinfo.self_thread", rt_tgsigqueueinfo, WANT_OK, getpid(), gettid(), SIGUSR2,
         &second);
    in_buf(3, &second, sizeof second);
    volatile_case();
    DONE();
    CALL("rt_tgsigqueueinfo.bad_tid", rt_tgsigqueueinfo, EINVAL, getpid(), 0, SIGUSR2, &second);
    in_buf(3, &second, sizeof second);
    volatile_case();
    why("tid 0 is rejected before any lookup");
    DONE();

    uint64_t pending = 0;
    CALL("rt_sigpending.two", rt_sigpending, WANT_OK, &pending, KSIGSET);
    out_buf(0, &pending, sizeof pending);
    DONE();
    if ((pending & set) != set)
        ora_fail("rt_sigpending: queued signals not pending");
    uint32_t low = 0;
    CALL("rt_sigpending.short_size", rt_sigpending, WANT_OK, &low, 4);
    out_buf(0, &low, sizeof low);
    why("a sigsetsize below 8 writes only that many bytes");
    DONE();
    CASE("rt_sigpending.bad_size", rt_sigpending, EINVAL, &pending, 16);

    uint64_t wait_usr1 = SIGBIT(SIGUSR1), wait_usr2 = SIGBIT(SIGUSR2);
    struct timespec second_timeout = {1, 0}, zero = {0, 0};
    memset(&taken, 0, sizeof taken);
    CALL("rt_sigtimedwait.pending", rt_sigtimedwait, WANT_OK, &wait_usr1, &taken, &second_timeout,
         KSIGSET);
    in_buf(0, &wait_usr1, sizeof wait_usr1);
    in_buf(2, &second_timeout, sizeof second_timeout);
    out_buf(1, &taken, sizeof taken);
    volatile_case();
    DONE();
    if (taken.si_signo != SIGUSR1 || taken.si_code != SI_QUEUE || taken.si_value.sival_int != 0x4f4e45)
        ora_fail("rt_sigtimedwait: wrong siginfo");
    CALL("rt_sigtimedwait.null_info", rt_sigtimedwait, WANT_OK, &wait_usr2, NULL, &second_timeout,
         KSIGSET);
    in_buf(0, &wait_usr2, sizeof wait_usr2);
    in_buf(2, &second_timeout, sizeof second_timeout);
    why("SIGUSR2 is pending; a NULL info pointer records no field");
    DONE();
    CALL("rt_sigtimedwait.zero_timeout", rt_sigtimedwait, EAGAIN, &wait_usr1, &taken, &zero,
         KSIGSET);
    in_buf(0, &wait_usr1, sizeof wait_usr1);
    in_buf(2, &zero, sizeof zero);
    DONE();
    CALL("rt_sigtimedwait.bad_size", rt_sigtimedwait, EINVAL, &wait_usr1, &taken, &zero, 4);
    want_status(0, "in", "INVALID_EXTENT");
    in_buf(2, &zero, sizeof zero);
    DONE();

    CALL("rt_sigpending.empty", rt_sigpending, WANT_OK, &pending, KSIGSET);
    out_buf(0, &pending, sizeof pending);
    DONE();
    if (pending & set) {
        // A queued signal was not taken: drain it before SIGUSR2 is unblocked
        // with its default (terminating) disposition.
        sigset_t drain;
        struct timespec now = {0, 0};
        sigemptyset(&drain);
        sigaddset(&drain, SIGUSR1);
        sigaddset(&drain, SIGUSR2);
        while (sigtimedwait(&drain, NULL, &now) > 0)
            ;
        ora_fail("rt_sigtimedwait: queued signals left pending");
    }

    uint64_t usr2 = SIGBIT(SIGUSR2);
    CALL("rt_sigprocmask.unblock", rt_sigprocmask, WANT_OK, SIG_UNBLOCK, &usr2, &after, KSIGSET);
    in_buf(1, &usr2, sizeof usr2);
    out_buf(2, &after, sizeof after);
    DONE();
    CALL("rt_sigprocmask.bad_how", rt_sigprocmask, EINVAL, 7, &set, NULL, KSIGSET);
    in_buf(1, &set, sizeof set);
    DONE();
    CALL("rt_sigprocmask.bad_size", rt_sigprocmask, EINVAL, SIG_BLOCK, &set, NULL, 4);
    want_status(1, "in", "INVALID_EXTENT");
    DONE();
    CALL("rt_sigprocmask.setmask_restore", rt_sigprocmask, WANT_OK, SIG_SETMASK, &initial, &after,
         KSIGSET);
    in_buf(1, &initial, sizeof initial);
    out_buf(2, &after, sizeof after);
    DONE();

    uint64_t none = 0;
    CALL("rt_sigsuspend.bad_size", rt_sigsuspend, EINVAL, &none, 4);
    want_status(0, "in", "INVALID_EXTENT");
    DONE();
}

static void altstack_cases(void)
{
    stack_t initial, set, old, query, small, bad, off;
    memset(alt_stack, 0x5a, sizeof alt_stack);
    memset(&initial, 0, sizeof initial);
    CALL("sigaltstack.query_initial", sigaltstack, WANT_OK, NULL, &initial);
    out_buf(1, &initial, sizeof initial);
    DONE();

    memset(&set, 0, sizeof set);
    set.ss_sp = alt_stack;
    set.ss_flags = 0;
    set.ss_size = sizeof alt_stack;
    memset(&old, 0, sizeof old);
    CALL("sigaltstack.set", sigaltstack, WANT_OK, &set, &old);
    in_buf(0, &set, sizeof set);
    out_buf(1, &old, sizeof old);
    DONE();
    memset(&query, 0, sizeof query);
    CALL("sigaltstack.query", sigaltstack, WANT_OK, NULL, &query);
    out_buf(1, &query, sizeof query);
    DONE();

    memcpy(&small, &set, sizeof small);
    small.ss_size = 1024;
    CALL("sigaltstack.too_small", sigaltstack, ENOMEM, &small, NULL);
    in_buf(0, &small, sizeof small);
    DONE();
    memcpy(&bad, &set, sizeof bad);
    bad.ss_flags = 0x1234;
    CALL("sigaltstack.bad_flags", sigaltstack, EINVAL, &bad, NULL);
    in_buf(0, &bad, sizeof bad);
    DONE();
    CALL("sigaltstack.fault", sigaltstack, EFAULT, 1, NULL);
    want_status(0, "in", "COPY_FAULT");
    DONE();

    // A handler with SA_ONSTACK runs on the alternate stack.
    struct ksigaction onstack = handler_action(SA_ONSTACK), previous;
    memset(&previous, 0, sizeof previous);
    CALL("rt_sigaction.install_onstack", rt_sigaction, WANT_OK, SIGUSR2, &onstack, &previous,
         KSIGSET);
    in_buf(1, &onstack, sizeof onstack);
    out_buf(2, &previous, sizeof previous);
    DONE();
    hits = 0;
    handler_sp = 0;
    raise(SIGUSR2);
    if (hits != 1 || handler_sp < (uintptr_t)alt_stack ||
        handler_sp >= (uintptr_t)alt_stack + sizeof alt_stack)
        ora_fail("sigaltstack: SA_ONSTACK handler did not run on the alternate stack");
    CALL("rt_sigaction.restore_onstack", rt_sigaction, WANT_OK, SIGUSR2, &previous, NULL,
         KSIGSET);
    in_buf(1, &previous, sizeof previous);
    DONE();

    memset(&off, 0, sizeof off);
    off.ss_flags = SS_DISABLE;
    memset(&old, 0, sizeof old);
    CALL("sigaltstack.disable", sigaltstack, WANT_OK, &off, &old);
    in_buf(0, &off, sizeof off);
    out_buf(1, &old, sizeof old);
    DONE();
    if (!(initial.ss_flags & SS_DISABLE) && sigaltstack(&initial, NULL) != 0)
        ora_fail("sigaltstack: restore the initial stack");
}

static void timer_cases(void)
{
    // main's watchdog is alarm(240); every change to ITIMER_REAL puts it back.
    long previous = CALL("alarm.set", alarm, WANT_OK, 30);
    volatile_case();
    why("returns what is left of main's 240 s watchdog, which the area restores");
    DONE();
    CALL("alarm.cancel", alarm, WANT_OK, 0);
    volatile_case();
    DONE();
    // The watchdog starts again at its full length: a fixed argument keeps
    // the golden file stable, and the run stays bounded.
    (void)previous;
    CALL("alarm.restore", alarm, WANT_OK, 240);
    volatile_case();
    why("main's watchdog is restarted at its full 240 s");
    DONE();

    struct itimerval current, value, old, zero;
    memset(&current, 0, sizeof current);
    memset(&zero, 0, sizeof zero);
    CALL("getitimer.real", getitimer, WANT_OK, ITIMER_REAL, &current);
    out_any(1);
    volatile_case();
    DONE();
    memset(&value, 0, sizeof value);
    value.it_value.tv_sec = 50;
    memset(&old, 0, sizeof old);
    CALL("setitimer.real", setitimer, WANT_OK, ITIMER_REAL, &value, &old);
    in_buf(1, &value, sizeof value);
    out_any(2);
    why("the old value is main's watchdog; it is put back by setitimer.real_restore");
    DONE();
    struct itimerval restore = old;
    CALL("setitimer.real_restore", setitimer, WANT_OK, ITIMER_REAL, &restore, NULL);
    in_buf(1, &restore, sizeof restore);
    want_status(2, "any", "NULL_POINTER");
    volatile_case();
    DONE();

    static const int which[2] = {ITIMER_VIRTUAL, ITIMER_PROF};
    static const char *const set_label[2] = {"setitimer.virtual", "setitimer.prof"};
    static const char *const get_label[2] = {"getitimer.virtual", "getitimer.prof"};
    static const char *const cancel_label[2] = {"setitimer.virtual_cancel",
                                                "setitimer.prof_cancel"};
    for (int i = 0; i < 2; i++) {
        memset(&value, 0, sizeof value);
        value.it_value.tv_sec = 10;
        value.it_interval.tv_usec = 500000;
        memset(&old, 0, sizeof old);
        CALL(set_label[i], setitimer, WANT_OK, which[i], &value, &old);
        in_buf(1, &value, sizeof value);
        out_buf(2, &old, sizeof old);
        why("the timer was not armed before: the old value is zero");
        DONE();
        memset(&current, 0, sizeof current);
        CALL(get_label[i], getitimer, WANT_OK, which[i], &current);
        out_any(1);
        DONE();
        memset(&old, 0, sizeof old);
        CALL(cancel_label[i], setitimer, WANT_OK, which[i], &zero, &old);
        in_buf(1, &zero, sizeof zero);
        out_any(2);
        DONE();
    }
    CASE("getitimer.bad_which", getitimer, EINVAL, 5, &current);
    CALL("setitimer.bad_which", setitimer, EINVAL, 5, &zero, NULL);
    in_buf(1, &zero, sizeof zero);
    why("which is checked after the new value was read; the old value is recorded only on "
        "success, so the NULL pointer leaves no field");
    DONE();
    CALL("getitimer.fault", getitimer, EFAULT, ITIMER_PROF, 1);
    why("the value is computed, then the copy to the unmapped first page fails");
    DONE();
}

void area_signals(void)
{
    // Snapshot what this area touches; everything is put back at the end.
    struct sigaction saved_usr1, saved_usr2;
    sigset_t saved_mask;
    sigaction(SIGUSR1, NULL, &saved_usr1);
    sigaction(SIGUSR2, NULL, &saved_usr2);
    sigprocmask(SIG_SETMASK, NULL, &saved_mask);

    struct ksigaction kernel_usr1;
    action_cases(&kernel_usr1);
    sigreturn_and_queue_cases();
    mask_cases();
    altstack_cases();
    CALL("rt_sigaction.restore_usr1", rt_sigaction, WANT_OK, SIGUSR1, &kernel_usr1, NULL,
         KSIGSET);
    in_buf(1, &kernel_usr1, sizeof kernel_usr1);
    DONE();
    timer_cases();
    child_cases();

    sigaction(SIGUSR1, &saved_usr1, NULL);
    sigaction(SIGUSR2, &saved_usr2, NULL);
    sigprocmask(SIG_SETMASK, &saved_mask, NULL);
}
