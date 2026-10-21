// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// time.c — sleeping, reading and (refused) setting of clocks, and POSIX
// per-process timers.
//
// Slots: nanosleep clock_nanosleep clock_gettime clock_getres clock_settime
// settimeofday clock_adjtime adjtimex gettimeofday time timer_create
// timer_settime timer_gettime timer_getoverrun timer_delete.
//
// Every call goes through the raw system call (never the vDSO). Setting the
// clock is refused as UID 1000 (EPERM); the values passed are the current time,
// so even a privileged run would not move the clock noticeably.
#include "areas.h"

#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <time.h>

#define BAD_CLOCK 99
#define TIMER_SIGNAL 40 // a real-time signal glibc leaves to applications

static volatile sig_atomic_t timer_hits;

static void on_timer(int sig, siginfo_t *info, void *context)
{
    (void)sig;
    (void)info;
    (void)context;
    timer_hits++;
}

static void sleep_cases(void)
{
    struct timespec short_sleep = {0, 1000000L}, remain, bad;
    CALL("nanosleep.short", nanosleep, WANT_OK, &short_sleep, NULL);
    in_buf(0, &short_sleep, sizeof short_sleep);
    why("the remaining time is written only when a signal interrupts the sleep");
    DONE();
    memset(&remain, 0, sizeof remain);
    CALL("nanosleep.with_remain", nanosleep, WANT_OK, &short_sleep, &remain);
    in_buf(0, &short_sleep, sizeof short_sleep);
    DONE();
    memset(&bad, 0, sizeof bad);
    bad.tv_nsec = 1000000000L;
    CALL("nanosleep.bad_nsec", nanosleep, EINVAL, &bad, NULL);
    in_buf(0, &bad, sizeof bad);
    DONE();
    memset(&bad, 0, sizeof bad);
    bad.tv_sec = -1;
    CALL("nanosleep.negative", nanosleep, EINVAL, &bad, NULL);
    in_buf(0, &bad, sizeof bad);
    DONE();
    CALL("nanosleep.null_request", nanosleep, EFAULT, NULL, NULL);
    want_status(0, "in", "NULL_POINTER");
    DONE();

    CALL("clock_nanosleep.monotonic_relative", clock_nanosleep, WANT_OK, CLOCK_MONOTONIC, 0,
         &short_sleep, NULL);
    in_buf(2, &short_sleep, sizeof short_sleep);
    DONE();
    CALL("clock_nanosleep.realtime_relative", clock_nanosleep, WANT_OK, CLOCK_REALTIME, 0,
         &short_sleep, &remain);
    in_buf(2, &short_sleep, sizeof short_sleep);
    DONE();
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_nsec += 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    CALL("clock_nanosleep.monotonic_abstime", clock_nanosleep, WANT_OK, CLOCK_MONOTONIC,
         TIMER_ABSTIME, &deadline, &remain);
    in_any(2);
    why("an absolute deadline 1 ms ahead; remain is never written for TIMER_ABSTIME");
    DONE();
    struct timespec past = {1, 0};
    CALL("clock_nanosleep.abstime_past", clock_nanosleep, WANT_OK, CLOCK_BOOTTIME, TIMER_ABSTIME,
         &past, NULL);
    in_buf(2, &past, sizeof past);
    why("a deadline in the past returns at once");
    DONE();
    CALL("clock_nanosleep.bad_clock", clock_nanosleep, EINVAL, BAD_CLOCK, 0, &short_sleep, NULL);
    in_buf(2, &short_sleep, sizeof short_sleep);
    DONE();
    CALL("clock_nanosleep.thread_cputime", clock_nanosleep, EOPNOTSUPP, CLOCK_THREAD_CPUTIME_ID,
         0, &short_sleep, NULL);
    in_buf(2, &short_sleep, sizeof short_sleep);
    why("the thread CPU clock has no nsleep: refused before the request is read (glibc's "
        "wrapper would turn this into EINVAL; the raw call returns EOPNOTSUPP)");
    DONE();
    memset(&bad, 0, sizeof bad);
    bad.tv_nsec = -1;
    CALL("clock_nanosleep.bad_nsec", clock_nanosleep, EINVAL, CLOCK_MONOTONIC, 0, &bad, NULL);
    in_buf(2, &bad, sizeof bad);
    DONE();
}

static void clock_read_cases(void)
{
    static const clockid_t clocks[] = {CLOCK_REALTIME,       CLOCK_MONOTONIC,
                                       CLOCK_BOOTTIME,       CLOCK_PROCESS_CPUTIME_ID,
                                       CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW,
                                       CLOCK_REALTIME_COARSE, CLOCK_TAI};
    static const char *const get_labels[] = {
        "clock_gettime.realtime",       "clock_gettime.monotonic",
        "clock_gettime.boottime",       "clock_gettime.process_cputime",
        "clock_gettime.thread_cputime", "clock_gettime.monotonic_raw",
        "clock_gettime.realtime_coarse", "clock_gettime.tai"};
    static const char *const res_labels[] = {
        "clock_getres.realtime",       "clock_getres.monotonic",
        "clock_getres.boottime",       "clock_getres.process_cputime",
        "clock_getres.thread_cputime", "clock_getres.monotonic_raw",
        "clock_getres.realtime_coarse", "clock_getres.tai"};
    struct timespec value;
    for (size_t i = 0; i < sizeof clocks / sizeof clocks[0]; i++) {
        memset(&value, 0, sizeof value);
        CALL(get_labels[i], clock_gettime, WANT_OK, clocks[i], &value);
        out_any(1);
        DONE();
        memset(&value, 0, sizeof value);
        CALL(res_labels[i], clock_getres, WANT_OK, clocks[i], &value);
        out_any(1);
        why("the resolution depends on the guest's clocksource and tick");
        DONE();
    }
    clockid_t own_cpu;
    if (clock_getcpuclockid(getpid(), &own_cpu) == 0) {
        memset(&value, 0, sizeof value);
        CALL("clock_gettime.pid_cpu_clock", clock_gettime, WANT_OK, own_cpu, &value);
        out_any(1);
        volatile_case();
        why("a process CPU clock id encodes the pid");
        DONE();
    } else {
        ora_fail("clock_getcpuclockid");
    }
    CASE("clock_gettime.bad_clock", clock_gettime, EINVAL, BAD_CLOCK, &value);
    CALL("clock_gettime.fault", clock_gettime, EFAULT, CLOCK_MONOTONIC, 1);
    why("the time is read, then the copy to the unmapped first page fails; no output field");
    DONE();
    CALL("clock_getres.null_result", clock_getres, WANT_OK, CLOCK_MONOTONIC, NULL);
    want_status(1, "any", "NULL_POINTER");
    why("a NULL result only validates the clock id");
    DONE();
    CASE("clock_getres.bad_clock", clock_getres, EINVAL, BAD_CLOCK, &value);

    struct timeval tv;
    struct timezone tz;
    memset(&tv, 0, sizeof tv);
    memset(&tz, 0, sizeof tz);
    CALL("gettimeofday.with_timezone", gettimeofday, WANT_OK, &tv, &tz);
    out_any(0);
    out_buf(1, &tz, sizeof tz);
    DONE();
    memset(&tv, 0, sizeof tv);
    CALL("gettimeofday.no_timezone", gettimeofday, WANT_OK, &tv, NULL);
    out_any(0);
    want_status(1, "any", "NULL_POINTER");
    DONE();
    CALL("gettimeofday.timezone_only", gettimeofday, WANT_OK, NULL, &tz);
    want_status(0, "any", "NULL_POINTER");
    out_buf(1, &tz, sizeof tz);
    DONE();
    CALL("gettimeofday.fault", gettimeofday, EFAULT, 1, NULL);
    why("the copy to the unmapped first page fails; outputs are recorded only on success");
    DONE();

    time_t now = 0;
    CALL("time.pointer", time, WANT_OK, &now);
    out_any(0);
    volatile_case();
    DONE();
    CALL("time.null", time, WANT_OK, NULL);
    want_status(0, "any", "NULL_POINTER");
    volatile_case();
    DONE();
}

static void clock_set_cases(void)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    CALL("clock_settime.realtime", clock_settime, EPERM, CLOCK_REALTIME, &now);
    in_any(1);
    why("setting the clock needs CAP_SYS_TIME: refused as UID 1000 (the value is the current "
        "time)");
    DONE();
    CALL("clock_settime.monotonic", clock_settime, EINVAL, CLOCK_MONOTONIC, &now);
    in_any(1);
    why("CLOCK_MONOTONIC cannot be set by anyone");
    DONE();
    CALL("clock_settime.bad_clock", clock_settime, EINVAL, BAD_CLOCK, &now);
    in_any(1);
    DONE();
    CALL("clock_settime.fault", clock_settime, EFAULT, CLOCK_REALTIME, 1);
    want_status(1, "in", "COPY_FAULT");
    why("the new time cannot be read: refused before any permission check");
    DONE();

    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    CALL("settimeofday.time", settimeofday, EPERM, &tv, NULL);
    in_any(0);
    want_status(1, "any", "NULL_POINTER");
    why("needs CAP_SYS_TIME: refused as UID 1000 (the value is the current time)");
    DONE();
    CALL("settimeofday.time_and_zone", settimeofday, EPERM, &tv, &tz);
    in_any(0);
    in_buf(1, &tz, sizeof tz);
    why("needs CAP_SYS_TIME: refused as UID 1000 (the values are the current ones)");
    DONE();
    struct timeval bad = tv;
    bad.tv_usec = 2000000;
    CALL("settimeofday.bad_usec", settimeofday, EINVAL, &bad, NULL);
    in_any(0);
    want_status(1, "any", "NULL_POINTER");
    why("an out-of-range tv_usec is rejected before the permission check");
    DONE();

    struct timex tx, before;
    memset(&tx, 0, sizeof tx);
    memcpy(&before, &tx, sizeof before);
    CALL("adjtimex.read", adjtimex, WANT_OK, &tx);
    in_buf(0, &before, sizeof before);
    out_any(0);
    why("modes 0 only reads the clock state; the result is the clock state (TIME_OK...)");
    DONE();
    struct timex change;
    memcpy(&change, &tx, sizeof change);
    change.modes = ADJ_FREQUENCY;
    memcpy(&before, &change, sizeof before);
    CALL("adjtimex.set_frequency", adjtimex, EPERM, &change);
    in_buf(0, &before, sizeof before);
    volatile_case();
    why("any mode bit needs CAP_SYS_TIME: refused as UID 1000 (the frequency is unchanged)");
    DONE();
    CALL("adjtimex.fault", adjtimex, EFAULT, 1);
    want_status(0, "in", "COPY_FAULT");
    DONE();

    memset(&tx, 0, sizeof tx);
    memcpy(&before, &tx, sizeof before);
    CALL("clock_adjtime.realtime_read", clock_adjtime, WANT_OK, CLOCK_REALTIME, &tx);
    in_buf(1, &before, sizeof before);
    out_any(1);
    DONE();
    memcpy(&change, &tx, sizeof change);
    change.modes = ADJ_FREQUENCY;
    memcpy(&before, &change, sizeof before);
    CALL("clock_adjtime.realtime_set", clock_adjtime, EPERM, CLOCK_REALTIME, &change);
    in_buf(1, &before, sizeof before);
    volatile_case();
    why("needs CAP_SYS_TIME: refused as UID 1000 (the frequency is unchanged)");
    DONE();
    memset(&tx, 0, sizeof tx);
    memcpy(&before, &tx, sizeof before);
    CALL("clock_adjtime.monotonic", clock_adjtime, EOPNOTSUPP, CLOCK_MONOTONIC, &tx);
    in_buf(1, &before, sizeof before);
    why("only CLOCK_REALTIME can be adjusted");
    DONE();
    CALL("clock_adjtime.bad_clock", clock_adjtime, EINVAL, BAD_CLOCK, &tx);
    in_buf(1, &before, sizeof before);
    DONE();
}

static void posix_timer_cases(void)
{
    struct sigevent none, sig, thread;
    int timer_none = -1, timer_signal = -1, timer_thread = -1, timer_default = -1;

    memset(&none, 0, sizeof none);
    none.sigev_notify = SIGEV_NONE;
    CALL("timer_create.sigev_none", timer_create, WANT_OK, CLOCK_MONOTONIC, &none, &timer_none);
    in_buf(1, &none, sizeof none);
    out_buf(2, &timer_none, sizeof timer_none);
    volatile_case();
    why("timer ids are allocated per process; their values depend on earlier areas");
    DONE();

    struct itimerspec arm, old, current, zero;
    memset(&arm, 0, sizeof arm);
    arm.it_value.tv_sec = 10;
    arm.it_interval.tv_sec = 1;
    memset(&old, 0, sizeof old);
    memset(&zero, 0, sizeof zero);
    CALL("timer_settime.relative", timer_settime, WANT_OK, timer_none, 0, &arm, &old);
    in_buf(2, &arm, sizeof arm);
    out_buf(3, &old, sizeof old);
    volatile_case();
    why("a fresh timer is disarmed: the old value is zero");
    DONE();
    memset(&current, 0, sizeof current);
    CALL("timer_gettime.armed", timer_gettime, WANT_OK, timer_none, &current);
    out_any(1);
    volatile_case();
    DONE();
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    struct itimerspec absolute;
    memset(&absolute, 0, sizeof absolute);
    absolute.it_value.tv_sec = now.tv_sec + 20;
    CALL("timer_settime.abstime", timer_settime, WANT_OK, timer_none, TIMER_ABSTIME, &absolute,
         NULL);
    in_any(2);
    want_status(3, "any", "NULL_POINTER");
    volatile_case();
    DONE();
    struct itimerspec bad;
    memset(&bad, 0, sizeof bad);
    bad.it_value.tv_nsec = 1000000000L;
    CALL("timer_settime.bad_nsec", timer_settime, EINVAL, timer_none, 0, &bad, NULL);
    in_buf(2, &bad, sizeof bad);
    volatile_case();
    DONE();
    CASE("timer_getoverrun.none", timer_getoverrun, WANT_OK, timer_none);
    memset(&old, 0, sizeof old);
    CALL("timer_settime.disarm", timer_settime, WANT_OK, timer_none, 0, &zero, &old);
    in_buf(2, &zero, sizeof zero);
    out_any(3);
    volatile_case();
    DONE();

    // SIGEV_SIGNAL with a handled real-time signal: a 1 ms one-shot fires.
    struct sigaction action, saved;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = on_timer;
    action.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(TIMER_SIGNAL, &action, &saved);
    memset(&sig, 0, sizeof sig);
    sig.sigev_notify = SIGEV_SIGNAL;
    sig.sigev_signo = TIMER_SIGNAL;
    sig.sigev_value.sival_int = 0x54494d;
    CALL("timer_create.sigev_signal", timer_create, WANT_OK, CLOCK_MONOTONIC, &sig, &timer_signal);
    in_buf(1, &sig, sizeof sig);
    out_buf(2, &timer_signal, sizeof timer_signal);
    volatile_case();
    DONE();
    struct itimerspec once;
    memset(&once, 0, sizeof once);
    once.it_value.tv_nsec = 1000000L;
    timer_hits = 0;
    CALL("timer_settime.one_shot", timer_settime, WANT_OK, timer_signal, 0, &once, NULL);
    in_buf(2, &once, sizeof once);
    want_status(3, "any", "NULL_POINTER");
    volatile_case();
    DONE();
    for (int i = 0; i < 2000 && !timer_hits; i++) {
        struct timespec tick = {0, 1000000L};
        nanosleep(&tick, NULL);
    }
    if (!timer_hits)
        ora_fail("timer_settime: the one-shot timer never fired");
    memset(&current, 0, sizeof current);
    CALL("timer_gettime.expired", timer_gettime, WANT_OK, timer_signal, &current);
    out_buf(1, &current, sizeof current);
    volatile_case();
    why("a fired one-shot timer is disarmed: all zero");
    DONE();
    CASE("timer_getoverrun.fired", timer_getoverrun, WANT_OK, timer_signal);
    CASE("timer_delete.sigev_signal", timer_delete, WANT_OK, timer_signal);

    // SIGEV_THREAD_ID: the signal goes to this thread. Never armed.
    memset(&thread, 0, sizeof thread);
    thread.sigev_notify = SIGEV_THREAD_ID;
    thread.sigev_signo = TIMER_SIGNAL;
    thread._sigev_un._tid = gettid();
    CALL("timer_create.sigev_thread_id", timer_create, WANT_OK, CLOCK_REALTIME, &thread,
         &timer_thread);
    in_buf(1, &thread, sizeof thread);
    out_buf(2, &timer_thread, sizeof timer_thread);
    volatile_case();
    DONE();
    CASE("timer_delete.sigev_thread_id", timer_delete, WANT_OK, timer_thread);
    sigaction(TIMER_SIGNAL, &saved, NULL);

    // A NULL sigevent means SIGEV_SIGNAL with SIGALRM; never armed.
    CALL("timer_create.null_sigevent", timer_create, WANT_OK, CLOCK_BOOTTIME, NULL, &timer_default);
    want_status(1, "any", "NULL_POINTER");
    out_buf(2, &timer_default, sizeof timer_default);
    volatile_case();
    DONE();
    CASE("timer_delete.null_sigevent", timer_delete, WANT_OK, timer_default);

    int unused = -1;
    CALL("timer_create.bad_clock", timer_create, EINVAL, BAD_CLOCK, &none, &unused);
    in_buf(1, &none, sizeof none);
    DONE();
    struct sigevent bad_notify;
    memset(&bad_notify, 0, sizeof bad_notify);
    bad_notify.sigev_notify = 99;
    CALL("timer_create.bad_notify", timer_create, EINVAL, CLOCK_MONOTONIC, &bad_notify, &unused);
    in_buf(1, &bad_notify, sizeof bad_notify);
    DONE();

    CASE("timer_delete.sigev_none", timer_delete, WANT_OK, timer_none);
    CALL("timer_settime.bad_id", timer_settime, EINVAL, 9999, 0, &arm, NULL);
    in_buf(2, &arm, sizeof arm);
    why("timer 9999 was never created; the entry still records the new value");
    DONE();
    CASE("timer_gettime.bad_id", timer_gettime, EINVAL, 9999, &current);
    CASE("timer_getoverrun.bad_id", timer_getoverrun, EINVAL, 9999);
    CASE("timer_delete.bad_id", timer_delete, EINVAL, 9999);
    CASE("timer_delete.deleted", timer_delete, EINVAL, timer_none);
}

void area_time(void)
{
    sleep_cases();
    clock_read_cases();
    clock_set_cases();
    posix_timer_cases();
}
