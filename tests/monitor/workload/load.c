// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// load.c — volume: syscall rate, long sessions, captured buffers, terminal
// output and short-lived runs.
#include "workload.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// ---------------------------------------------------------------- syscall-load

static atomic_ullong flood_calls;
static atomic_int flood_stop;

static void *flood_worker(void *unused)
{
    (void)unused;
    int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
    char byte;
    struct timespec ts;
    unsigned long long local = 0;
    while (!atomic_load_explicit(&flood_stop, memory_order_relaxed)) {
        for (int i = 0; i < 256; i++) {
            syscall(SYS_getppid);
            syscall(SYS_read, null, &byte, 0);
            syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
        }
        local += 768;
    }
    close(null);
    atomic_fetch_add(&flood_calls, local);
    return NULL;
}

MODULE(syscall_load)
{
    const char *name = "syscall-load";
    int wanted = seconds(options, 5, 15, 30);
    int duration = wanted > CAP_FLOOD_SECONDS ? CAP_FLOOD_SECONDS : wanted;
    if (duration < wanted)
        limit(name, "flood shortened from %d s to the %d s cap", wanted, CAP_FLOOD_SECONDS);
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus < 1)
        cpus = 1;
    long threads = options->level == LEVEL_LIGHT ? 1 : options->level == LEVEL_HEAVY ? cpus : cpus * 2;
    if (threads > 64)
        threads = 64;
    pthread_t workers[64];
    atomic_store(&flood_stop, 0);
    atomic_store(&flood_calls, 0);
    double started = now();
    long made = 0;
    for (long i = 0; i < threads; i++)
        if (pthread_create(&workers[made], NULL, flood_worker, NULL) == 0)
            made++;
    struct timespec pause = {.tv_sec = duration};
    nanosleep(&pause, NULL);
    atomic_store(&flood_stop, 1);
    for (long i = 0; i < made; i++)
        pthread_join(workers[i], NULL);
    double elapsed = now() - started;
    unsigned long long calls = atomic_load(&flood_calls);
    count("syscalls (flood)", calls);
    pass(name, "%llu syscalls from %ld threads in %.1f s (%.0f per second)", calls, made, elapsed,
         (double)calls / elapsed);
    note(name, "compare with the run's call count and the TRL / shedding status");
    return 0;
}

// ---------------------------------------------------------------- long-run

MODULE(long_run)
{
    const char *name = "long-run";
    int duration = seconds(options, 60, 600, 1800);
    char path[512];
    unsigned long long operations = 0;
    double started = now(), next_report = started;
    int tick = 0;
    while (now() - started < duration) {
        snprintf(path, sizeof path, "%s/rotating-%d.log", options->workdir, tick % 16);
        char text[128];
        int len = snprintf(text, sizeof text, "tick %d at %.3f\n", tick, now() - started);
        if (write_file(path, text, (size_t)len, 0600) == 0)
            operations += 3;
        struct stat st;
        if (stat(path, &st) == 0)
            operations++;
        if (now() >= next_report) {
            printf("long-run: %5.0f s of %d s, %llu operations\n", now() - started, duration,
                   operations);
            next_report += 10;
        }
        struct timespec pause = {.tv_nsec = 100 * 1000 * 1000};
        nanosleep(&pause, NULL);
        tick++;
        operations++;
    }
    count("operations (long-run)", operations);
    pass(name, "%llu operations over %d s; check that STL stayed 0 and the run finalized",
         operations, duration);
    return 0;
}

// ---------------------------------------------------------------- object-capture

MODULE(object_capture)
{
    const char *name = "object-capture";
    size_t largest = options->level == LEVEL_LIGHT ? 64 << 10 : options->level == LEVEL_HEAVY ? 1 << 20 : 4 << 20;
    long repeats = scaled(options, 32);
    unsigned char *buffer = malloc(largest);
    if (!buffer) {
        fail(name, "allocating %zu bytes", largest);
        return 1;
    }
    char path[512];
    snprintf(path, sizeof path, "%s/objects.bin", options->workdir);
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    int pair[2];
    if (fd < 0 || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0) {
        fail(name, "setup: %s", strerror(errno));
        free(buffer);
        return 1;
    }
    unsigned long long bytes = 0, calls = 0;
    unsigned seed = 0x5eed;
    for (size_t size = 1; size <= largest; size *= 2) {
        // Unique contents: each buffer is a new object.
        for (size_t i = 0; i < size; i++)
            buffer[i] = (unsigned char)(rand_r(&seed) & 0xff);
        if (pwrite(fd, buffer, size, 0) == (ssize_t)size)
            bytes += size, calls++;
        if (pread(fd, buffer, size, 0) == (ssize_t)size)
            bytes += size, calls++;
        size_t chunk = size < 65536 ? size : 65536;
        if (send(pair[0], buffer, chunk, MSG_DONTWAIT) > 0) {
            recv(pair[1], buffer, chunk, 0);
            bytes += 2 * chunk, calls += 2;
        }
    }
    // Identical contents, written again and again: one stored copy is enough.
    memset(buffer, 'A', 4096);
    for (long i = 0; i < repeats * 16; i++)
        if (pwrite(fd, buffer, 4096, 0) == 4096)
            bytes += 4096, calls++;
    // Many small pieces in one call.
    struct iovec pieces[512];
    for (int i = 0; i < 512; i++) {
        pieces[i].iov_base = buffer + (i % 64);
        pieces[i].iov_len = 1 + (size_t)(i % 7);
    }
    for (long i = 0; i < repeats; i++) {
        ssize_t written = writev(fd, pieces, 512);
        if (written > 0)
            bytes += (unsigned long long)written, calls++;
    }
    close(fd);
    close(pair[0]);
    close(pair[1]);
    free(buffer);
    count("captured buffer bytes", bytes);
    pass(name, "%llu calls moved %llu bytes in buffers of 1 byte to %zu KiB", calls, bytes,
         largest >> 10);
    note(name, "check that objects/ holds a few pack files, not one file per buffer");
    return 0;
}

// ---------------------------------------------------------------- terminal-load

static void out(const char *text, size_t len)
{
    while (len > 0) {
        ssize_t written = write(1, text, len);
        if (written <= 0)
            return;
        text += written;
        len -= (size_t)written;
    }
}

MODULE(terminal_load)
{
    const char *name = "terminal-load";
    long lines = scaled(options, 2000);
    size_t long_line = (size_t)scaled(options, 16 << 10);
    unsigned long long bytes = 0;
    char row[256];
    double started = now();
    for (long i = 0; i < lines; i++) {
        int len = snprintf(row, sizeof row, "\033[38;5;%ldmline %06ld\033[0m the quick brown fox %ld\n",
                           i % 256, i, i * 7919);
        out(row, (size_t)len);
        bytes += (unsigned long long)len;
    }
    char *wide = malloc(long_line + 2);
    if (wide) {
        for (size_t i = 0; i < long_line; i++)
            wide[i] = (char)('a' + i % 26);
        wide[long_line] = '\n';
        out(wide, long_line + 1);
        bytes += long_line + 1;
        free(wide);
    }
    // Colors, cursor moves, a progress bar redrawn in place, UTF-8 and
    // combining marks, then raw control and high bytes.
    for (int color = 0; color < 256; color++) {
        int len = snprintf(row, sizeof row, "\033[48;5;%dm  ", color);
        out(row, (size_t)len);
    }
    out("\033[0m\n", 5);
    for (int step = 0; step <= 100; step += 5) {
        int len = snprintf(row, sizeof row, "\r[%-20.*s] %3d%%", step / 5,
                           "####################", step);
        out(row, (size_t)len);
    }
    out("\n\033[2A\033[10C\033[K\033[2B\n", 15);
    const char utf8[] = "UTF-8: café ñ 日本語 한국어 ελληνικά 🙂👍 e\xcc\x81 a\xcc\x8a\n";
    out(utf8, sizeof utf8 - 1);
    unsigned char raw[256];
    for (int i = 0; i < 256; i++)
        raw[i] = (unsigned char)i;
    out((const char *)raw, sizeof raw);
    out("\033[0m\n", 5);
    bytes += 4096;
    double elapsed = now() - started;
    count("terminal bytes", bytes);
    pass(name, "%ld lines, a %zu KiB line and escape sequences: %llu bytes in %.2f s", lines,
         long_line >> 10, bytes, elapsed);
    note(name, "the run should not slow to the terminal drain rate (about 200 KB/s before)");
    return 0;
}

// ---------------------------------------------------------------- timing

MODULE(timing)
{
    const char *name = "timing";
    long runs = scaled(options, 50);
    char self[4096];
    ssize_t len = readlink("/proc/self/exe", self, sizeof self - 1);
    if (len <= 0) {
        unavailable(name, "cannot find its own executable");
        return 0;
    }
    self[len] = 0;
    long done = 0;
    double started = now();
    for (long i = 0; i < runs; i++) {
        char *role = i % 2 ? "burst-exit" : "instant-exit";
        char *argv[] = {self, "--child", role, NULL};
        if (run_wait(argv) == 0)
            done++;
    }
    count("short-lived processes", (unsigned long long)done);
    pass(name, "%ld of %ld children exited at once or after a 10,000-call burst in %.2f s", done,
         runs, now() - started);
    return 0;
}
