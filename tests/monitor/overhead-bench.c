// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// Phase 3 overhead workload: four threads pinned to CPUs 0-3 run the same
// syscall loops; each loop reports aggregate throughput and per-call latency.
// As PID 1 (initramfs /init) it powers the machine off when done, so the same
// binary measures a kernel without Antinomie, with it idle, and recording.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define THREADS 4
#define SAMPLES 20000

enum workload { NULL_CALL, PIPE_4K, OPEN_CLOSE, WORKLOADS };
static const char *const names[] = {"getppid", "pipe_write_read_4k", "openat_close"};

struct worker {
    pthread_t thread;
    int cpu, pipe[2];
    enum workload workload;
    uint64_t latency[SAMPLES];
    uint64_t elapsed_ns;
    int failed;
};

static struct worker workers[THREADS];
static pthread_barrier_t start, stop;

static uint64_t now(void)
{
    struct timespec time;

    clock_gettime(CLOCK_MONOTONIC, &time);
    return (uint64_t)time.tv_sec * 1000000000 + time.tv_nsec;
}

/* One operation; the clock is the vDSO, so timing adds no syscall. */
static int operation(struct worker *worker, char *buffer)
{
    int fd;

    switch (worker->workload) {
    case NULL_CALL:
        return syscall(SYS_getppid) < 0;
    case PIPE_4K:
        return write(worker->pipe[1], buffer, 4096) != 4096 ||
               read(worker->pipe[0], buffer, 4096) != 4096;
    case OPEN_CLOSE:
        fd = openat(AT_FDCWD, "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        return fd < 0 || close(fd) != 0;
    default:
        return 1;
    }
}

static void *run(void *arg)
{
    struct worker *worker = arg;
    static __thread char buffer[4096];
    cpu_set_t set;
    uint64_t begin;

    CPU_ZERO(&set);
    CPU_SET(worker->cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set))
        worker->failed = 1;
    memset(buffer, 'B', sizeof(buffer));
    for (int i = 0; i < 256; i++)
        worker->failed |= operation(worker, buffer);
    pthread_barrier_wait(&start);
    begin = now();
    for (int i = 0; i < SAMPLES; i++) {
        uint64_t before = now();
        worker->failed |= operation(worker, buffer);
        worker->latency[i] = now() - before;
    }
    worker->elapsed_ns = now() - begin;
    pthread_barrier_wait(&stop);
    return NULL;
}

static int compare(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

    return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
    static uint64_t all[THREADS * SAMPLES];
    const char *label = argc > 1 ? argv[1] : "unlabeled";
    int failed = 0;

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("BENCH START label=%s cpus=%ld\n", label, sysconf(_SC_NPROCESSORS_ONLN));
    for (int workload = 0; workload < WORKLOADS; workload++) {
        uint64_t slowest = 0;

        pthread_barrier_init(&start, NULL, THREADS);
        pthread_barrier_init(&stop, NULL, THREADS);
        for (int i = 0; i < THREADS; i++) {
            workers[i].cpu = i;
            workers[i].workload = workload;
            workers[i].failed = 0;
            if (pipe2(workers[i].pipe, O_CLOEXEC))
                failed = 1;
            if (pthread_create(&workers[i].thread, NULL, run, &workers[i]))
                failed = 1;
        }
        for (int i = 0; i < THREADS; i++) {
            pthread_join(workers[i].thread, NULL);
            close(workers[i].pipe[0]);
            close(workers[i].pipe[1]);
            failed |= workers[i].failed;
            if (workers[i].elapsed_ns > slowest)
                slowest = workers[i].elapsed_ns;
            memcpy(all + i * SAMPLES, workers[i].latency, sizeof(workers[i].latency));
        }
        pthread_barrier_destroy(&start);
        pthread_barrier_destroy(&stop);
        qsort(all, THREADS * SAMPLES, sizeof(all[0]), compare);
        /* Throughput is all operations over the slowest thread's time. */
        printf("BENCH {\"label\":\"%s\",\"workload\":\"%s\",\"threads\":%d,\"ops\":%d,"
               "\"ops_per_s\":%.0f,\"p50_ns\":%llu,\"p99_ns\":%llu,\"max_ns\":%llu}\n",
               label, names[workload], THREADS, THREADS * SAMPLES,
               THREADS * SAMPLES * 1e9 / (double)slowest,
               (unsigned long long)all[THREADS * SAMPLES / 2],
               (unsigned long long)all[THREADS * SAMPLES * 99 / 100],
               (unsigned long long)all[THREADS * SAMPLES - 1]);
    }
    printf("BENCH DONE failures=%d\n", failed);
    if (getpid() == 1) {
        sync();
        reboot(RB_POWER_OFF);
    }
    return failed;
}
