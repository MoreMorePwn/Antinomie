// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// file_mmap.c — a file edited through a shared mapping (contract revision 18:
// lifecycle.file_mapped, and the hash of a file at its last close).
//
// A store into a shared file mapping is no system call. The guest copies the
// pages when a call writes them back (msync) or drops them dirty (munmap, the
// exit of the process): only the pages stored to since their last writeback,
// as they are at that moment. The cases store into chosen pages and check
// that exactly those come back, with their bytes, then read the file back and
// check the guest's hash at its last close, which the munmap or the exit
// makes because the mapping holds the open file. A large mapping goes past
// the guest's copy budget: the range is listed whole, its tail not copied.
// The exit child keeps a shared anonymous mapping dirty too: memory with no
// file must not be reported.
#include "areas.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define PAGE 4096
#define EDIT_SIZE (3 * PAGE + 100)
#define EXIT_SIZE (PAGE + 10)
#define BUDGET_COPY (4 << 20)
#define BIG_SIZE (BUDGET_COPY + 2 * PAGE)

static unsigned char edit_expected[EDIT_SIZE];
static unsigned char exit_expected[EXIT_SIZE];
static unsigned char final_read[EDIT_SIZE];

// Store `len` pattern bytes at `at` of the mapping, and in the copy of what
// the file must hold.
static void store(unsigned char *map, unsigned char *expected, size_t at, size_t len,
                  unsigned seed)
{
    unsigned char bytes[PAGE];
    pattern(bytes, len, seed);
    memcpy(map + at, bytes, len);
    memcpy(expected + at, bytes, len);
}

static void read_back(const char *label, const char *name, const unsigned char *expected,
                      size_t size)
{
    int fd = open(name, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        ora_fail("mmap read back open");
        return;
    }
    memset(final_read, 0, sizeof final_read);
    CALL(label, pread64, WANT_OK, fd, final_read, size, 0);
    out_buf(1, expected, size);
    why("the file as the mappings left it, for the last-close hash");
    DONE();
    close(fd);
}

static void writeback_then_unmap(void)
{
    struct stat st;
    long fd = CALL("openat.mmap_edit", openat, WANT_OK, AT_FDCWD, "mmap-edit",
                   O_CREAT | O_RDWR | O_TRUNC, 0600);
    in_str(1, "mmap-edit");
    file_fd("OPEN", (int)fd);
    DONE();
    pattern(edit_expected, sizeof edit_expected, 90);
    if (fd < 0 || write((int)fd, edit_expected, sizeof edit_expected) != EDIT_SIZE ||
        fstat((int)fd, &st) != 0) {
        ora_fail("mmap edit setup");
        return;
    }
    unsigned char *map = mmap(NULL, EDIT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, (int)fd, 0);
    if (map == MAP_FAILED) {
        ora_fail("mmap edit mapping");
        close((int)fd);
        return;
    }
    // Pages 0 and 2 stored to; 1 and the short page 3 not.
    store(map, edit_expected, 100, 100, 91);
    store(map, edit_expected, 2 * PAGE, 50, 92);
    CALL("msync.mmap_writeback", msync, WANT_OK, map, EDIT_SIZE, MS_SYNC);
    file_mapped("WRITEBACK", &st, 0, PAGE, PAGE, NULL, edit_expected);
    file_mapped("WRITEBACK", &st, 2 * PAGE, PAGE, PAGE, NULL, edit_expected + 2 * PAGE);
    why("msync writes back the pages stored to through the mapping, as they are then");
    DONE();
    // After the writeback only page 1 is stored to; the descriptor is closed
    // first, so the munmap drops the last reference to the open file.
    store(map, edit_expected, PAGE, 10, 93);
    close((int)fd);
    CALL("munmap.mmap_dirty", munmap, WANT_OK, map, EDIT_SIZE);
    file_mapped("UNMAP", &st, PAGE, PAGE, PAGE, NULL, edit_expected + PAGE);
    file_hash_of(&st, "pread64.mmap_edit_final");
    why("the unmap drops page 1 dirty; pages 0 and 2 are clean since the msync");
    DONE();
    read_back("pread64.mmap_edit_final", "mmap-edit", edit_expected, EDIT_SIZE);
}

struct exit_slot {
    long pid, tid;
    uint64_t t0;
};

// The child maps the file, stores and exits with the mapping in place.
static void exit_with_mapping(void)
{
    struct stat st;
    struct exit_slot *slot = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                                  -1, 0);
    pattern(exit_expected, sizeof exit_expected, 94);
    int fd = open("mmap-exit", O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
    if (slot == MAP_FAILED || fd < 0 ||
        write(fd, exit_expected, sizeof exit_expected) != EXIT_SIZE || fstat(fd, &st) != 0) {
        ora_fail("mmap exit setup");
        if (fd >= 0)
            close(fd);
        return;
    }
    close(fd);
    // What the child stores, computed here as well.
    unsigned char bytes[16];
    pattern(bytes, 8, 95);
    memcpy(exit_expected + 8, bytes, 8);
    pattern(bytes, 10, 96);
    memcpy(exit_expected + PAGE, bytes, 10);
    ora_flush();
    pid_t pid = fork();
    if (pid == 0) {
        int child_fd = open("mmap-exit", O_RDWR);
        unsigned char *map = child_fd < 0 ? MAP_FAILED :
            mmap(NULL, EXIT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, child_fd, 0);
        if (map == MAP_FAILED)
            _exit(97);
        close(child_fd);
        memcpy(map + 8, exit_expected + 8, 8);
        memcpy(map + PAGE, exit_expected + PAGE, 10);
        // Shared memory with no file, dirty as well.
        slot->pid = getpid();
        slot->tid = syscall(SYS_gettid);
        slot->t0 = ora_now();
        syscall(SYS_exit_group, 0);
        _exit(98);
    }
    int status = -1;
    if (pid < 0 || waitpid(pid, &status, 0) != pid)
        ora_fail("mmap exit child");
    remote_begin("exit_group.mmap_child", "exit_group", SYS_exit_group, slot->pid, slot->tid,
                 slot->t0, ora_now(), 1, (long[6]){0}, 0);
    remote_noreturn(status);
    // Both pages are one range: page 0 whole, page 1 up to the end of the file.
    file_mapped("UNMAP", &st, 0, EXIT_SIZE, EXIT_SIZE, NULL, exit_expected);
    file_hash_of(&st, "pread64.mmap_exit_final");
    why("exit drops the address space with the file's pages dirty; the shared anonymous page is no file");
    volatile_case();
    DONE();
    munmap(slot, PAGE);
    read_back("pread64.mmap_exit_final", "mmap-exit", exit_expected, EXIT_SIZE);
}

// Every page of a mapping larger than the guest's per-call copy budget.
static void past_the_budget(void)
{
    struct stat st;
    int fd = open("mmap-big", O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || ftruncate(fd, BIG_SIZE) != 0 || fstat(fd, &st) != 0) {
        ora_fail("mmap budget setup");
        if (fd >= 0)
            close(fd);
        return;
    }
    unsigned char *map = mmap(NULL, BIG_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    unsigned char *big = malloc(BIG_SIZE);
    close(fd);
    if (map == MAP_FAILED || !big) {
        ora_fail("mmap budget mapping");
        free(big);
        return;
    }
    for (size_t at = 0; at < BIG_SIZE; at += PAGE)
        pattern(big + at, PAGE, 100 + (unsigned)(at / PAGE));
    memcpy(map, big, BIG_SIZE);
    CALL("munmap.mmap_budget", munmap, WANT_OK, map, BIG_SIZE);
    file_mapped("UNMAP", &st, 0, BIG_SIZE, BUDGET_COPY, "BUDGET", big);
    why("4 MiB are copied per call; the range is listed whole and its tail is not copied");
    DONE();
    free(big);
}

void area_file_mmap(void)
{
    writeback_then_unmap();
    exit_with_mapping();
    past_the_budget();
}
