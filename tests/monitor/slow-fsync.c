// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
/* Test shim: delays fsync/fdatasync by SLOW_FSYNC_MS (default 187, the median
 * measured under WSL) to reproduce a slow host disk. With
 * SLOW_FSYNC_LOG set it logs time, thread name and file for each call.
 *
 *   cc -shared -fPIC -O2 tests/monitor/slow-fsync.c -o slow-fsync.so -ldl
 *   LD_PRELOAD=$PWD/slow-fsync.so headless BUNDLE DATA PROBE
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

static void slow(int fd)
{
    const char *value = getenv("SLOW_FSYNC_MS");
    long ms = value ? atol(value) : 187;
    struct timespec delay = {ms / 1000, (ms % 1000) * 1000000L}, now;

    if (getenv("SLOW_FSYNC_LOG")) {
        char name[17] = {0}, link[64], target[512] = {0};

        prctl(PR_GET_NAME, name);
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        if (readlink(link, target, sizeof(target) - 1) < 0) target[0] = '?';
        clock_gettime(CLOCK_MONOTONIC, &now);
        fprintf(stderr, "FSYNC %ld.%03ld %s %s\n", (long)now.tv_sec,
                now.tv_nsec / 1000000, name, target);
    }
    nanosleep(&delay, NULL);
}

int fsync(int fd)
{
    static int (*real)(int);
    if (!real) real = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
    slow(fd);
    return real(fd);
}

int fdatasync(int fd)
{
    static int (*real)(int);
    if (!real) real = (int (*)(int))dlsym(RTLD_NEXT, "fdatasync");
    slow(fd);
    return real(fd);
}
