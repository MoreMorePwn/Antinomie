// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// threads.c — concurrency: many threads and short-lived processes at once.
//
// Slots (exercised concurrently, owned by other areas): sched_getaffinity
// sched_setaffinity getpid gettid getppid sched_yield pipe2 write read
// clock_gettime openat close.
//
// 32 child processes are forked first (while this process has one thread, so
// no lock is copied held) and run their calls while 8 threads of the parent,
// each pinned to its own CPU when there are enough, run theirs. Every thread
// and child uses private descriptors and files and labels
// "threads.t<N>.<call>.<i>" / "threads.c<N>.<call>.<i>", unique per process.
// Every thread is joined and every child reaped; a child ends itself after
// 10 s should it ever hang.
#include "areas.h"

#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>

#define THREADS 8
#define CHILDREN 32
#define THREAD_ROUNDS 28
#define CHILD_ROUNDS 4

struct worker {
    int index;
    int cpu; // -1: not pinned
    pthread_t thread;
    int started;
};

// One labeled call: CALL/CALL0 with a label built in `label`.
#define LABEL(buffer, fmt, ...) (snprintf(buffer, sizeof buffer, fmt, __VA_ARGS__), buffer)

static void timed_calls(const char *who, int index, int round)
{
    char label[80];
    struct timespec now;

    memset(&now, 0, sizeof now);
    CALL(LABEL(label, "threads.%s%d.clock_gettime.%d", who, index, round), clock_gettime, WANT_OK,
         CLOCK_MONOTONIC, &now);
    out_any(1);
    volatile_case();
    DONE();
}

static void pipe_round(const char *who, int index, int round, const int fds[2])
{
    char label[80];
    unsigned char out[16], in[16];

    pattern(out, sizeof out, (unsigned)(index * 100 + round));
    memset(in, 0, sizeof in);
    CALL(LABEL(label, "threads.%s%d.write.%d", who, index, round), write, WANT_OK, fds[1], out,
         sizeof out);
    in_buf(1, out, sizeof out);
    volatile_case();
    DONE();
    long got = CALL(LABEL(label, "threads.%s%d.read.%d", who, index, round), read, WANT_OK, fds[0],
                    in, sizeof in);
    if (got > 0)
        out_buf(1, in, (size_t)got);
    volatile_case();
    DONE();
    if (got != (long)sizeof in || memcmp(in, out, sizeof in) != 0)
        ora_fail("threads pipe round trip");
}

static void file_round(const char *who, int index, int round, const char *name)
{
    char label[80];

    long fd = CALL(LABEL(label, "threads.%s%d.openat.%d", who, index, round), openat, WANT_OK,
                   AT_FDCWD, name, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    in_str(1, name);
    if (fd >= 0)
        file_fd("OPEN", (int)fd);
    volatile_case();
    DONE();
    if (fd >= 0) {
        CALL(LABEL(label, "threads.%s%d.close.%d", who, index, round), close, WANT_OK, fd);
        volatile_case();
        DONE();
    }
}

static int make_pipe(const char *who, int index, int fds[2])
{
    char label[80];

    long ret = CALL(LABEL(label, "threads.%s%d.pipe2", who, index), pipe2, WANT_OK, fds,
                    O_CLOEXEC);
    if (ret == 0)
        out_buf(0, fds, 2 * sizeof fds[0]);
    volatile_case();
    DONE();
    return ret == 0 ? 0 : -1;
}

static void close_pipe(const char *who, int index, const int fds[2])
{
    char label[80];

    for (int end = 0; end < 2; end++) {
        CALL(LABEL(label, "threads.%s%d.close_pipe.%d", who, index, end), close, WANT_OK,
             fds[end]);
        volatile_case();
        DONE();
    }
}

static void *thread_body(void *arg)
{
    struct worker *w = arg;
    char label[80], name[32];
    int fds[2];

    role("worker", syscall(SYS_gettid));
    if (w->cpu >= 0) {
        unsigned long mask = 1UL << w->cpu;
        CALL(LABEL(label, "threads.t%d.sched_setaffinity", w->index), sched_setaffinity, WANT_OK,
             0, sizeof mask, &mask);
        in_key("arg2.cpu_mask", &mask, sizeof mask);
        why("pins this thread only; the thread's affinity ends with it");
        volatile_case();
        DONE();
    }
    if (make_pipe("t", w->index, fds) != 0)
        return NULL;
    snprintf(name, sizeof name, "thr-t%d", w->index);
    for (int i = 0; i < THREAD_ROUNDS; i++) {
        CALL0(LABEL(label, "threads.t%d.getpid.%d", w->index, i), getpid, WANT_OK);
        volatile_case();
        DONE();
        CALL0(LABEL(label, "threads.t%d.gettid.%d", w->index, i), gettid, WANT_OK);
        volatile_case();
        DONE();
        pipe_round("t", w->index, i, fds);
        timed_calls("t", w->index, i);
        file_round("t", w->index, i, name);
    }
    close_pipe("t", w->index, fds);
    unlink(name);
    return NULL;
}

static void child_body(int index)
{
    char label[80], name[32];
    int fds[2];

    alarm(10);
    role("child", getpid());
    CALL0(LABEL(label, "threads.c%d.getpid", index), getpid, WANT_OK);
    volatile_case();
    DONE();
    CALL0(LABEL(label, "threads.c%d.getppid", index), getppid, WANT_OK);
    volatile_case();
    DONE();
    CALL0(LABEL(label, "threads.c%d.gettid", index), gettid, WANT_OK);
    volatile_case();
    DONE();
    CALL0(LABEL(label, "threads.c%d.sched_yield", index), sched_yield, WANT_OK);
    volatile_case();
    DONE();
    if (make_pipe("c", index, fds) != 0)
        return;
    for (int i = 0; i < CHILD_ROUNDS; i++)
        pipe_round("c", index, i, fds);
    timed_calls("c", index, 0);
    timed_calls("c", index, 1);
    snprintf(name, sizeof name, "thr-c%d", index);
    file_round("c", index, 0, name);
    CALL(LABEL(label, "threads.c%d.openat_missing", index), openat, ENOENT, AT_FDCWD,
         "thr-missing/none", O_RDONLY | O_CLOEXEC, 0);
    in_str(1, "thr-missing/none");
    volatile_case();
    DONE();
    close_pipe("c", index, fds);
    unlink(name);
    alarm(0);
}

// The CPUs this process may run on (the first 64), lowest first.
static int usable_cpus(int *cpus, int max)
{
    unsigned long mask = 0;
    int count = 0;

    long ret = CALL("threads.main.sched_getaffinity", sched_getaffinity, WANT_ANY, 0, sizeof mask,
                    &mask);
    if (ret > 0)
        out_key("arg2.cpu_mask", &mask, (size_t)ret);
    why("an 8-byte mask: fails with EINVAL only on a machine with more than 64 CPU ids, then the "
        "threads run unpinned");
    volatile_case();
    DONE();
    if (ret <= 0)
        return 0;
    for (int cpu = 0; cpu < 64 && count < max; cpu++)
        if (mask & (1UL << cpu))
            cpus[count++] = cpu;
    return count;
}

void area_threads(void)
{
    struct worker workers[THREADS];
    pid_t children[CHILDREN];
    int cpus[THREADS], count;

    // Children first: forking while this process has a single thread.
    for (int i = 0; i < CHILDREN; i++) {
        ora_flush();
        children[i] = fork();
        if (children[i] == 0) {
            ora_child(1000 + (unsigned)i);
            child_body(i);
            _exit(ora_failures() ? 3 : 0);
        }
        if (children[i] < 0)
            ora_fail("threads fork");
    }

    count = usable_cpus(cpus, THREADS);
    for (int i = 0; i < THREADS; i++) {
        workers[i].index = i;
        // Distinct CPUs when there are enough; otherwise share them round robin.
        workers[i].cpu = count > 0 ? cpus[i % count] : -1;
        workers[i].started = pthread_create(&workers[i].thread, NULL, thread_body, &workers[i]) == 0;
        if (!workers[i].started)
            ora_fail("threads pthread_create");
    }
    for (int i = 0; i < THREADS; i++)
        if (workers[i].started && pthread_join(workers[i].thread, NULL) != 0)
            ora_fail("threads pthread_join");

    for (int i = 0; i < CHILDREN; i++) {
        char what[32];
        if (children[i] <= 0)
            continue;
        snprintf(what, sizeof what, "threads child %d", i);
        ora_wait(children[i], what);
    }
}
