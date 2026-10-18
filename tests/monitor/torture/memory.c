// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// memory.c — process cores and memory dumps, suspicious memory use, and the
// three YARA targets (the executable, a dropped file, memory only).
#include "torture.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static void hold(int seconds)
{
    struct timespec pause = {.tv_sec = seconds};
    nanosleep(&pause, NULL);
}

// Fill `mib` MiB with one recognizable line per 4 KiB page, and the
// memory-only indicator at the start of every MiB: a public YARA rule then
// reports a core or memory dump that holds the heap.
static unsigned char *patterned_heap(long mib)
{
    if ((unsigned long long)mib << 20 > CAP_MEMORY_BYTES)
        mib = (long)(CAP_MEMORY_BYTES >> 20);
    size_t size = (size_t)mib << 20;
    unsigned char *heap = malloc(size);
    char *indicator = memory_indicator_text();
    if (!heap || !indicator) {
        free(heap);
        free(indicator);
        return NULL;
    }
    size_t indicator_len = strlen(indicator) + 1;
    for (size_t page = 0; page < size; page += 4096) {
        size_t at = 0;
        if (page % (1 << 20) == 0) {
            memcpy(heap + page, indicator, indicator_len);
            at = indicator_len;
        }
        int len = snprintf((char *)heap + page + at, 4096 - at,
                           "ANTINOMIE-CORE-PATTERN page %zu of %zu MiB\n", page / 4096, (size_t)mib);
        memset(heap + page + at + (size_t)len, (int)(page / 4096 & 0x7f), 4096 - at - (size_t)len);
    }
    free(indicator);
    return heap;
}

int crash_role(const char *kind, long mib)
{
    struct rlimit core = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_CORE, &core);
    volatile unsigned char *heap = patterned_heap(mib);
    (void)heap;
    if (!strcmp(kind, "abort"))
        abort();
    volatile int *nowhere = NULL;
    *nowhere = 1;
    return 0;
}

// ---------------------------------------------------------------- crash-core

MODULE(crash_core)
{
    const char *name = "crash-core";
    long mib = options->level == LEVEL_LIGHT ? 32 : options->level == LEVEL_HEAVY ? 128 : 500;
    char self[4096];
    ssize_t len = readlink("/proc/self/exe", self, sizeof self - 1);
    if (len <= 0) {
        unavailable(name, "cannot find its own executable");
        return 0;
    }
    self[len] = 0;
    const char *kinds[] = {"segv", "abort"};
    char size[16];
    snprintf(size, sizeof size, "%ld", mib / 4 > 0 ? mib / 4 : 1);
    for (int i = 0; i < 2; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            char *argv[] = {self, "--child", "crash", (char *)kinds[i], size, NULL};
            execv(self, argv);
            _exit(127);
        }
        int status = 0;
        if (pid > 0)
            waitpid(pid, &status, 0);
        if (WIFSIGNALED(status))
            pass(name, "child %d crashed with signal %d after filling %s MiB%s", pid,
                 WTERMSIG(status), size, WCOREDUMP(status) ? " (kernel core written)" : "");
        else
            fail(name, "child %d was expected to crash", pid);
    }
#ifdef SINGLE_MODULE
    // The run's root process: hold a large heap for a live core, then crash
    // so the core on exit has the whole heap to capture.
    unsigned char *heap = patterned_heap(mib);
    if (!heap) {
        fail(name, "could not allocate %ld MiB", mib);
        return 1;
    }
    int wait = seconds(options, 10, 30, 60);
    note(name, "root process %d holds %ld MiB of ANTINOMIE-CORE-PATTERN pages for %d s:", getpid(),
         mib, wait);
    note(name, "take a live core now (Dump core), then it crashes for the core on exit");
    note(name, "a complete core is about %ld MiB; check it is not cut short", mib);
    hold(wait);
    printf("crash-core: crashing now with SIGSEGV\n");
    fflush(stdout);
    crash_role("segv", 0);
#endif
    return 0;
}

// ---------------------------------------------------------------- memory-tricks

MODULE(memory_tricks)
{
    const char *name = "memory-tricks";
    // Executable memory written at run time: mov eax, 42; ret.
    unsigned char *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code != MAP_FAILED) {
        static const unsigned char mov_ret[] = {0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3};
        memcpy(code, mov_ret, sizeof mov_ret);
        int result = ((int (*)(void))code)();
        pass(name, "RWX page executed generated code (returned %d)", result);
        munmap(code, 4096);
    } else {
        unavailable(name, "RWX mapping refused: %s", strerror(errno));
    }
    long flips = scaled(options, 100);
    unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    long flipped = 0;
    if (page != MAP_FAILED) {
        for (long i = 0; i < flips; i++)
            flipped += mprotect(page, 4096, i % 2 ? PROT_READ | PROT_WRITE : PROT_READ | PROT_EXEC) == 0;
        munmap(page, 4096);
    }
    pass(name, "%ld mprotect flips between writable and executable", flipped);
    // A copy of this program in a memfd, executed from there.
    int memfd = (int)syscall(SYS_memfd_create, "antinomie-torture", MFD_CLOEXEC);
    int self = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (memfd >= 0 && self >= 0) {
        char chunk[65536];
        ssize_t got;
        while ((got = read(self, chunk, sizeof chunk)) > 0)
            if (write(memfd, chunk, (size_t)got) != got)
                break;
        pid_t pid = fork();
        if (pid == 0) {
            char *argv[] = {"[ant-memfd]", "--child", "instant-exit", NULL};
            fexecve(memfd, argv, environ);
            _exit(127);
        }
        int status = 1;
        if (pid > 0)
            waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
            pass(name, "fexecve of a memfd copy of itself");
        else
            unavailable(name, "memfd execution failed (noexec?)");
    }
    if (memfd >= 0)
        close(memfd);
    if (self >= 0)
        close(self);
    // A large anonymous region with a marker that exists only in memory.
    long mib = scaled(options, 16);
    if ((unsigned long long)mib << 20 > CAP_MEMORY_BYTES)
        mib = (long)(CAP_MEMORY_BYTES >> 20);
    size_t size = (size_t)mib << 20;
    char *region = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *marker = memory_indicator_text();
    if (region != MAP_FAILED && marker) {
        for (size_t at = 0; at + 4096 <= size; at += 1 << 20)
            memcpy(region + at, marker, strlen(marker) + 1);
        int wait = seconds(options, 5, 20, 60);
        note(name, "%ld MiB region with the memory-only indicator held %d s for a memory dump", mib,
             wait);
        hold(wait);
        pass(name, "memory-only indicator (ESET_Kobalos_Ssh_Credential_Stealer) in %ld MiB", mib);
        munmap(region, size);
    }
    free(marker);
    count("memory held (MiB)", (unsigned long long)mib);
    return 0;
}

// ---------------------------------------------------------------- detect-yara

MODULE(detect_yara)
{
    const char *name = "detect-yara";
    note(name, "install YARA-Forge Core in the Rule manager; turn on memory and recovered-file "
               "scanning for all three targets");
    size_t in_executable = executable_indicator_count();
    if (in_executable)
        pass(name, "executable carries %zu bytes of SOLOSHRED and ORCSHRED indicator text",
             in_executable);
    else
        unavailable(name, "this build carries no executable indicators (only ant-detect-yara "
                          "and ant-torture do)");
    size_t len = 0;
    char *dropped = dropped_indicator_text(&len);
    const char *path = "/tmp/antinomie-torture-yara-dropped.txt";
    if (dropped && write_file(path, dropped, len, 0600) == 0)
        pass(name, "dropped %s with the Mozi kill-switch text (kept for recovery)", path);
    else
        fail(name, "could not write %s", path);
    free(dropped);
    char *memory = memory_indicator_text();
    if (memory) {
        int wait = seconds(options, 5, 20, 60);
        note(name, "memory-only Kobalos format string held for %d s", wait);
        hold(wait);
        pass(name, "memory-only indicator was held in memory");
        free(memory);
    }
    return 0;
}
