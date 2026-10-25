// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// memory.c — mappings, protection, locking, NUMA policy, protection keys and
// cross-process memory access.
//
// Slots: mmap mprotect munmap brk mremap msync mincore madvise mlock munlock
// mlockall munlockall mlock2 remap_file_pages mbind set_mempolicy
// get_mempolicy migrate_pages move_pages set_mempolicy_home_node
// pkey_mprotect pkey_alloc pkey_free process_madvise process_mrelease
// memfd_secret mseal map_shadow_stack membarrier process_vm_readv
// process_vm_writev.
//
// Children: 300 mlockall, 301 mseal, 302 membarrier registration, 303 the
// cross-process target, 304 the zombie for process_mrelease.
#include "areas.h"

#include <fcntl.h>
#include <linux/membarrier.h>
#include <linux/mempolicy.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/wait.h>

#define PAGE 4096UL

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef MAP_SHARED_VALIDATE
#define MAP_SHARED_VALIDATE 0x03
#endif
#ifndef MAP_SYNC
#define MAP_SYNC 0x80000
#endif
#ifndef MAP_DROPPABLE
#define MAP_DROPPABLE 0x08
#endif
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif
#ifndef MLOCK_ONFAULT
#define MLOCK_ONFAULT 1U
#endif
#ifndef MCL_ONFAULT
#define MCL_ONFAULT 4
#endif
#ifndef MADV_COLD
#define MADV_COLD 20
#endif
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif
#ifndef MADV_POPULATE_READ
#define MADV_POPULATE_READ 22
#endif
#ifndef MADV_POPULATE_WRITE
#define MADV_POPULATE_WRITE 23
#endif
#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif
#ifndef SHADOW_STACK_SET_TOKEN
#define SHADOW_STACK_SET_TOKEN 0x1
#endif
#ifndef MEMBARRIER_CMD_GET_REGISTRATIONS
#define MEMBARRIER_CMD_GET_REGISTRATIONS (1 << 9)
#endif
#ifndef MEMBARRIER_CMD_FLAG_CPU
#define MEMBARRIER_CMD_FLAG_CPU (1 << 0)
#endif

// A node mask of 64 bits: maxnode 65 makes the kernel (and the recorder)
// read exactly one unsigned long.
#define MAXNODE 65UL
#define NO_SUCH_PID 0x3fffffff

static long membarrier_mask;

// A private anonymous read-write region filled with a pattern (setup only).
static char *anon(size_t pages, unsigned seed)
{
    char *p = mmap(NULL, pages * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                   -1, 0);
    if (p == MAP_FAILED) {
        ora_fail("memory setup mapping");
        return NULL;
    }
    pattern(p, pages * PAGE, seed);
    return p;
}

// An address range that is not mapped right now. Use it before any other
// mapping is made: the kernel may hand the gap out again.
static char *hole(size_t pages)
{
    char *p = mmap(NULL, pages * PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        ora_fail("memory setup hole");
        return NULL;
    }
    munmap(p, pages * PAGE);
    return p;
}

// Whether RLIMIT_MEMLOCK lets an unprivileged process lock `bytes` more.
static int memlock_allows(size_t bytes)
{
    struct rlimit limit;
    if (getrlimit(RLIMIT_MEMLOCK, &limit) != 0)
        return 0;
    return limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur >= bytes + 64 * 1024;
}

static int pidfd_of(pid_t pid)
{
    return (int)syscall(SYS_pidfd_open, pid, 0);
}

static void mmap_cases(void)
{
    char path[300];
    long p;

    p = CALL("mmap.anon_private", mmap, WANT_OK, 0, 2 * PAGE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    volatile_case();
    DONE();
    if (p > 0) {
        pattern((void *)p, 2 * PAGE, 1);
        CALL("munmap.anon_private", munmap, WANT_OK, p, 2 * PAGE);
        volatile_case();
        DONE();
    }
    p = CALL("mmap.anon_shared", mmap, WANT_OK, 0, PAGE, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    volatile_case();
    DONE();
    if (p > 0) {
        pattern((void *)p, PAGE, 2);
        CALL("madvise.remove_shared", madvise, WANT_OK, p, PAGE, MADV_REMOVE);
        volatile_case();
        why("MADV_REMOVE punches a hole in the shmem object behind a shared anonymous mapping");
        DONE();
        if (((char *)p)[0] != 0)
            ora_fail("MADV_REMOVE left data behind");
        CALL("munmap.anon_shared", munmap, WANT_OK, p, PAGE);
        volatile_case();
        DONE();
    }
    p = CALL("mmap.populate_noreserve", mmap, WANT_OK, 0, 4 * PAGE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_NORESERVE, -1, 0);
    volatile_case();
    DONE();
    if (p > 0)
        munmap((void *)p, 4 * PAGE);
    p = CALL("mmap.prot_none", mmap, WANT_OK, 0, PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);
    volatile_case();
    DONE();
    if (p > 0)
        munmap((void *)p, PAGE);
    p = CALL("mmap.stack_growsdown", mmap, WANT_OK, 0, 2 * PAGE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_GROWSDOWN, -1, 0);
    volatile_case();
    DONE();
    if (p > 0)
        munmap((void *)p, 2 * PAGE);
    p = CALL("mmap.droppable", mmap, WANT_OK, 0, PAGE, PROT_READ | PROT_WRITE, MAP_DROPPABLE |
             MAP_ANONYMOUS, -1, 0);
    volatile_case();
    why("MAP_DROPPABLE (Linux 6.11) is a private anonymous mapping type on 64-bit kernels");
    DONE();
    if (p > 0)
        munmap((void *)p, PAGE);
    CASE("mmap.no_type", mmap, EINVAL, 0, PAGE, PROT_READ, MAP_ANONYMOUS, -1, 0);
    CASE("mmap.zero_length", mmap, EINVAL, 0, 0, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CASE("mmap.anon_shared_validate", mmap, EINVAL, 0, PAGE, PROT_READ,
         MAP_SHARED_VALIDATE | MAP_ANONYMOUS, -1, 0);
    CASE("mmap.bad_fd", mmap, EBADF, 0, PAGE, PROT_READ, MAP_PRIVATE, 999, 0);

    // File-backed mappings of a two-page file in the work directory.
    static char file_data[2 * PAGE];
    pattern(file_data, sizeof file_data, 3);
    int fd = open(work_path(path, sizeof path, "mem-file"), O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0 || write(fd, file_data, sizeof file_data) != (ssize_t)sizeof file_data) {
        ora_fail("memory file setup");
        if (fd >= 0)
            close(fd);
        return;
    }
    p = CALL("mmap.file_shared", mmap, WANT_OK, 0, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
             fd, 0);
    volatile_case();
    DONE();
    if (p > 0) {
        if (memcmp((void *)p, file_data, sizeof file_data))
            ora_fail("shared file mapping content");
        munmap((void *)p, 2 * PAGE);
    }
    p = CALL("mmap.file_private_offset", mmap, WANT_OK, 0, PAGE, PROT_READ, MAP_PRIVATE, fd,
             PAGE);
    volatile_case();
    DONE();
    if (p > 0) {
        if (memcmp((void *)p, file_data + PAGE, PAGE))
            ora_fail("private file mapping at an offset");
        munmap((void *)p, PAGE);
    }
    p = CALL("mmap.shared_validate", mmap, WANT_OK, 0, PAGE, PROT_READ, MAP_SHARED_VALIDATE, fd,
             0);
    volatile_case();
    DONE();
    if (p > 0)
        munmap((void *)p, PAGE);
    CALL("mmap.map_sync_unsupported", mmap, EOPNOTSUPP, 0, PAGE, PROT_READ | PROT_WRITE,
         MAP_SHARED_VALIDATE | MAP_SYNC, fd, 0);
    why("MAP_SYNC is only offered by DAX files; MAP_SHARED_VALIDATE rejects it elsewhere");
    DONE();
    CASE("mmap.unaligned_offset", mmap, EINVAL, 0, PAGE, PROT_READ, MAP_PRIVATE, fd, 100);
    int ro = open(path, O_RDONLY);
    if (ro >= 0) {
        CASE("mmap.shared_write_rdonly_fd", mmap, EACCES, 0, PAGE, PROT_READ | PROT_WRITE,
             MAP_SHARED, ro, 0);
        close(ro);
    } else {
        ora_fail("read-only open of the memory file");
    }
    close(fd);

    // MAP_FIXED_NOREPLACE into a gap between two mapped pages.
    char *base = anon(3, 4);
    if (!base)
        return;
    munmap(base + PAGE, PAGE);
    p = CALL("mmap.fixed_noreplace", mmap, WANT_OK, base + PAGE, PAGE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    volatile_case();
    DONE();
    if (p > 0 && (char *)p != base + PAGE)
        ora_fail("MAP_FIXED_NOREPLACE placed the mapping elsewhere");
    CALL("mmap.fixed_noreplace_taken", mmap, EEXIST, base + PAGE, PAGE, PROT_READ,
         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    volatile_case();
    DONE();
    p = CALL("mmap.fixed_replace", mmap, WANT_OK, base, PAGE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    volatile_case();
    why("MAP_FIXED over the fixture's own page replaces it");
    DONE();
    CALL("munmap.three_pages", munmap, WANT_OK, base, 3 * PAGE);
    volatile_case();
    DONE();
}

static void protect_cases(void)
{
    char *region = anon(2, 5);
    if (!region)
        return;
    CALL("mprotect.read_only", mprotect, WANT_OK, region, 2 * PAGE, PROT_READ);
    volatile_case();
    DONE();
    CALL("mprotect.read_exec", mprotect, WANT_OK, region, PAGE, PROT_READ | PROT_EXEC);
    volatile_case();
    DONE();
    CALL("mprotect.read_write", mprotect, WANT_OK, region, 2 * PAGE, PROT_READ | PROT_WRITE);
    volatile_case();
    DONE();
    CALL("mprotect.unaligned", mprotect, EINVAL, region + 1, PAGE, PROT_READ);
    volatile_case();
    DONE();
    CALL("mprotect.bad_prot", mprotect, EINVAL, region, PAGE, 0x80);
    volatile_case();
    DONE();
    CALL("mprotect.both_grows", mprotect, EINVAL, region, PAGE,
         PROT_READ | PROT_GROWSDOWN | PROT_GROWSUP);
    volatile_case();
    DONE();
    char *gap = hole(1);
    CALL("mprotect.unmapped", mprotect, ENOMEM, gap, PAGE, PROT_READ);
    volatile_case();
    DONE();
    gap = hole(1);
    CALL("munmap.unmapped_is_ok", munmap, WANT_OK, gap, PAGE);
    volatile_case();
    why("unmapping a range with nothing mapped succeeds");
    DONE();
    CALL("munmap.unaligned", munmap, EINVAL, region + 1, PAGE);
    volatile_case();
    DONE();
    CALL("munmap.zero_length", munmap, EINVAL, region, 0);
    volatile_case();
    DONE();
    munmap(region, 2 * PAGE);

    // The program break: query, grow, shrink back to where it was.
    long current = CALL("brk.query", brk, WANT_OK, 0);
    volatile_case();
    DONE();
    if (current > 0) {
        long grown = CALL("brk.grow", brk, WANT_OK, current + 16 * PAGE);
        volatile_case();
        DONE();
        if (grown != current + (long)(16 * PAGE))
            ora_fail("brk did not grow");
        else
            memset((void *)current, 0x5a, 16 * PAGE);
        long back = CALL("brk.shrink", brk, WANT_OK, current);
        volatile_case();
        DONE();
        if (back != current)
            ora_fail("brk did not shrink back");
        CALL("brk.below_start", brk, WANT_OK, 1);
        volatile_case();
        why("brk reports a refused change by returning the unchanged break, not an error");
        DONE();
    }
}

static void remap_cases(void)
{
    char *a = anon(1, 6);
    if (!a)
        return;
    static char expect[PAGE];
    pattern(expect, PAGE, 6);
    long b = CALL("mremap.grow_maymove", mremap, WANT_OK, a, PAGE, 4 * PAGE, MREMAP_MAYMOVE, 0);
    volatile_case();
    DONE();
    if (b <= 0)
        return;
    if (memcmp((void *)b, expect, PAGE))
        ora_fail("mremap lost the data");
    long c = CALL("mremap.shrink", mremap, WANT_OK, b, 4 * PAGE, 2 * PAGE, 0, 0);
    volatile_case();
    DONE();
    if (c != b)
        ora_fail("mremap shrink moved the mapping");
    char *target = hole(2);
    long d = CALL("mremap.fixed", mremap, WANT_OK, b, 2 * PAGE, 2 * PAGE,
                  MREMAP_MAYMOVE | MREMAP_FIXED, target);
    volatile_case();
    DONE();
    if (d != (long)target) {
        ora_fail("mremap fixed target");
        if (d < 0)
            munmap((void *)b, 2 * PAGE);
        return;
    }
    long e = CALL("mremap.dontunmap", mremap, WANT_OK, target, 2 * PAGE, 2 * PAGE,
                  MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0);
    volatile_case();
    why("MREMAP_DONTUNMAP moves the pages and leaves the old range mapped and empty");
    DONE();
    if (e > 0) {
        if (memcmp((void *)e, expect, PAGE))
            ora_fail("mremap DONTUNMAP lost the data");
        munmap((void *)e, 2 * PAGE);
    }
    CALL("mremap.fixed_without_maymove", mremap, EINVAL, target, PAGE, PAGE, MREMAP_FIXED,
         target + 4 * PAGE);
    volatile_case();
    DONE();
    CALL("mremap.bad_flags", mremap, EINVAL, target, PAGE, 2 * PAGE, 0x80, 0);
    volatile_case();
    DONE();
    CALL("mremap.zero_new_length", mremap, EINVAL, target, PAGE, 0, MREMAP_MAYMOVE, 0);
    volatile_case();
    DONE();
    munmap(target, 2 * PAGE);
    char *gap = hole(1);
    CALL("mremap.unmapped", mremap, EFAULT, gap, PAGE, 2 * PAGE, MREMAP_MAYMOVE, 0);
    volatile_case();
    DONE();
    char *three = anon(3, 7);
    if (three) {
        CALL("mremap.grow_in_place_blocked", mremap, ENOMEM, three, PAGE, 2 * PAGE, 0, 0);
        volatile_case();
        why("the first page cannot grow in place over the rest of its own mapping");
        DONE();
        munmap(three, 3 * PAGE);
    }
}

static void sync_cases(void)
{
    char path[300];
    static char data[2 * PAGE];
    pattern(data, sizeof data, 8);
    int fd = open(work_path(path, sizeof path, "mem-sync"), O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0 || write(fd, data, sizeof data) != (ssize_t)sizeof data) {
        ora_fail("msync file setup");
        if (fd >= 0)
            close(fd);
        return;
    }
    char *map = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        ora_fail("msync mapping");
        close(fd);
        return;
    }
    memcpy(map, "MSYNC", 5);
    CALL("msync.sync", msync, WANT_OK, map, 2 * PAGE, MS_SYNC);
    volatile_case();
    DONE();
    CALL("msync.async", msync, WANT_OK, map, PAGE, MS_ASYNC);
    volatile_case();
    DONE();
    CALL("msync.invalidate", msync, WANT_OK, map, PAGE, MS_INVALIDATE);
    volatile_case();
    DONE();
    CALL("msync.sync_and_async", msync, EINVAL, map, PAGE, MS_SYNC | MS_ASYNC);
    volatile_case();
    DONE();
    CALL("msync.unaligned", msync, EINVAL, map + 1, PAGE, MS_SYNC);
    volatile_case();
    DONE();

    // remap_file_pages: show file page 1 in the mapping's first page.
    CALL("remap_file_pages.shared", remap_file_pages, WANT_OK, map, PAGE, 0, 1, 0);
    volatile_case();
    why("deprecated: emulated with a fixed shared mapping of the same file at the new offset");
    DONE();
    if (memcmp(map, data + PAGE, PAGE))
        ora_fail("remap_file_pages content");
    CALL("remap_file_pages.prot", remap_file_pages, EINVAL, map, PAGE, PROT_READ, 1, 0);
    volatile_case();
    DONE();
    char *private = anon(1, 9);
    if (private) {
        CALL("remap_file_pages.private", remap_file_pages, EINVAL, private, PAGE, 0, 0, 0);
        volatile_case();
        DONE();
        munmap(private, PAGE);
    }
    munmap(map, 2 * PAGE);
    close(fd);
    char *gap = hole(1);
    CALL("msync.unmapped", msync, ENOMEM, gap, PAGE, MS_SYNC);
    volatile_case();
    DONE();

    // mincore: pages 0 and 2 touched, page 1 never.
    char *three = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (three == MAP_FAILED) {
        ora_fail("mincore mapping");
        return;
    }
    three[0] = 1;
    three[2 * PAGE] = 1;
    unsigned char vec[3];
    memset(vec, 0xee, sizeof vec);
    CALL("mincore.partly_resident", mincore, WANT_OK, three, 3 * PAGE, vec);
    out_buf(2, vec, sizeof vec);
    volatile_case();
    DONE();
    if ((vec[0] & 1) != 1 || (vec[1] & 1) != 0 || (vec[2] & 1) != 1)
        ora_fail("mincore residency");
    CALL("mincore.unaligned", mincore, EINVAL, three + 1, PAGE, vec);
    volatile_case();
    DONE();
    CALL("mincore.bad_vector", mincore, EFAULT, three, PAGE, 1);
    volatile_case();
    why("the kernel faults writing the vector; nothing is recorded for a failed call");
    DONE();
    munmap(three, 3 * PAGE);
    gap = hole(1);
    CALL("mincore.unmapped", mincore, ENOMEM, gap, PAGE, vec);
    volatile_case();
    DONE();
}

static void advise_cases(void)
{
    static const struct {
        const char *label;
        int advice;
    } advices[] = {
        {"madvise.normal", MADV_NORMAL},
        {"madvise.random", MADV_RANDOM},
        {"madvise.sequential", MADV_SEQUENTIAL},
        {"madvise.willneed", MADV_WILLNEED},
        {"madvise.dontfork", MADV_DONTFORK},
        {"madvise.dofork", MADV_DOFORK},
        {"madvise.dontdump", MADV_DONTDUMP},
        {"madvise.dodump", MADV_DODUMP},
        {"madvise.wipeonfork", MADV_WIPEONFORK},
        {"madvise.keeponfork", MADV_KEEPONFORK},
        {"madvise.cold", MADV_COLD},
        {"madvise.pageout", MADV_PAGEOUT},
        {"madvise.populate_read", MADV_POPULATE_READ},
        {"madvise.populate_write", MADV_POPULATE_WRITE},
        {"madvise.free", MADV_FREE},
    };
    static const struct {
        const char *label;
        int advice;
        const char *why;
    } maybe[] = {
        {"madvise.mergeable", MADV_MERGEABLE, "KSM may be compiled out (EINVAL)"},
        {"madvise.unmergeable", MADV_UNMERGEABLE, "KSM may be compiled out (EINVAL)"},
        {"madvise.hugepage", MADV_HUGEPAGE, "transparent huge pages may be compiled out"},
        {"madvise.nohugepage", MADV_NOHUGEPAGE, "transparent huge pages may be compiled out"},
        {"madvise.collapse", MADV_COLLAPSE,
         "a four-page range cannot hold a huge page; the error depends on THP support"},
    };
    char *region = anon(4, 10);
    if (!region)
        return;
    for (size_t i = 0; i < sizeof advices / sizeof advices[0]; i++) {
        CALL(advices[i].label, madvise, WANT_OK, region, 4 * PAGE, advices[i].advice);
        volatile_case();
        DONE();
    }
    for (size_t i = 0; i < sizeof maybe / sizeof maybe[0]; i++) {
        CALL(maybe[i].label, madvise, WANT_ANY, region, 4 * PAGE, maybe[i].advice);
        volatile_case();
        why(maybe[i].why);
        DONE();
    }
    pattern(region, 4 * PAGE, 10);
    CALL("madvise.dontneed", madvise, WANT_OK, region, 2 * PAGE, MADV_DONTNEED);
    volatile_case();
    DONE();
    if (region[0] != 0 || region[2 * PAGE] == 0)
        ora_fail("MADV_DONTNEED content");
    CALL("madvise.zero_length", madvise, WANT_OK, region, 0, MADV_NORMAL);
    volatile_case();
    DONE();
    CALL("madvise.bad_advice", madvise, EINVAL, region, PAGE, 999);
    volatile_case();
    DONE();
    CALL("madvise.unaligned", madvise, EINVAL, region + 1, PAGE, MADV_NORMAL);
    volatile_case();
    DONE();
    munmap(region, 4 * PAGE);
    char *gap = hole(1);
    CALL("madvise.unmapped", madvise, ENOMEM, gap, PAGE, MADV_WILLNEED);
    volatile_case();
    DONE();
}

static void mlockall_child(void *unused)
{
    (void)unused;
    int ok = memlock_allows(0);
    CALL("mlockall.future", mlockall, ok ? WANT_OK : WANT_ANY, MCL_FUTURE);
    why("MCL_FUTURE alone needs a nonzero RLIMIT_MEMLOCK (EPERM otherwise)");
    DONE();
    CASE0("munlockall.after_future", munlockall, WANT_OK);
    CALL("mlockall.current_onfault", mlockall, WANT_ANY, MCL_CURRENT | MCL_ONFAULT);
    why("MCL_CURRENT fails with ENOMEM when the whole address space exceeds RLIMIT_MEMLOCK");
    DONE();
    CASE0("munlockall.after_current", munlockall, WANT_OK);
    CASE("mlockall.zero", mlockall, EINVAL, 0);
    CASE("mlockall.onfault_alone", mlockall, EINVAL, MCL_ONFAULT);
    CASE("mlockall.bad_flags", mlockall, EINVAL, MCL_CURRENT | 0x100);
}

static void lock_cases(void)
{
    char *region = anon(2, 11);
    if (!region)
        return;
    long want = memlock_allows(2 * PAGE) ? WANT_OK : WANT_ANY;
    const char *limit_why = "RLIMIT_MEMLOCK below 128 KiB: the lock may be refused";
    CALL("mlock.two_pages", mlock, want, region, 2 * PAGE);
    volatile_case();
    if (want == WANT_ANY)
        why(limit_why);
    DONE();
    CALL("munlock.two_pages", munlock, WANT_OK, region, 2 * PAGE);
    volatile_case();
    DONE();
    CALL("mlock2.onfault", mlock2, want, region, 2 * PAGE, MLOCK_ONFAULT);
    volatile_case();
    if (want == WANT_ANY)
        why(limit_why);
    DONE();
    CALL("mlock2.plain", mlock2, want, region, PAGE, 0);
    volatile_case();
    if (want == WANT_ANY)
        why(limit_why);
    DONE();
    CALL("munlock.onfault", munlock, WANT_OK, region, 2 * PAGE);
    volatile_case();
    DONE();
    CALL("mlock2.bad_flags", mlock2, EINVAL, region, PAGE, 0x10);
    volatile_case();
    DONE();
    munmap(region, 2 * PAGE);
    char *gap = hole(1);
    CALL("mlock.unmapped", mlock, want == WANT_OK ? ENOMEM : WANT_ANY, gap, PAGE);
    volatile_case();
    if (want == WANT_ANY)
        why(limit_why);
    DONE();
    gap = hole(1);
    CALL("munlock.unmapped", munlock, ENOMEM, gap, PAGE);
    volatile_case();
    DONE();
    // mlockall changes the whole address space: a child does it.
    in_child(300, "mlockall child", mlockall_child, NULL);
}

static void numa_cases(void)
{
    unsigned long node0 = 1, node5 = 1UL << 5, node63 = 1UL << 63, mask = 0;
    unsigned long nodes_in;
    int policy = -1;

    nodes_in = node0;
    CALL("set_mempolicy.bind_node0", set_mempolicy, WANT_OK, MPOL_BIND, &node0, MAXNODE);
    in_buf(1, &nodes_in, sizeof nodes_in);
    DONE();
    mask = 0;
    policy = -1;
    CALL("get_mempolicy.current", get_mempolicy, WANT_OK, &policy, &mask, MAXNODE, 0, 0);
    out_buf(0, &policy, sizeof policy);
    out_buf(1, &mask, sizeof mask);
    DONE();
    CALL("set_mempolicy.preferred", set_mempolicy, WANT_OK, MPOL_PREFERRED, &node0, MAXNODE);
    in_buf(1, &nodes_in, sizeof nodes_in);
    DONE();
    CALL("set_mempolicy.interleave_static", set_mempolicy, WANT_OK,
         MPOL_INTERLEAVE | MPOL_F_STATIC_NODES, &node0, MAXNODE);
    in_buf(1, &nodes_in, sizeof nodes_in);
    DONE();
    CALL("set_mempolicy.weighted_interleave", set_mempolicy, WANT_OK, MPOL_WEIGHTED_INTERLEAVE,
         &node0, MAXNODE);
    in_buf(1, &nodes_in, sizeof nodes_in);
    why("MPOL_WEIGHTED_INTERLEAVE exists since Linux 6.9");
    DONE();
    CALL("set_mempolicy.local", set_mempolicy, WANT_OK, MPOL_LOCAL, NULL, 0);
    why("a NULL node mask is not decoded: no field");
    DONE();
    CALL("set_mempolicy.offline_node", set_mempolicy, EINVAL, MPOL_BIND, &node63, MAXNODE);
    in_buf(1, &(unsigned long){1UL << 63}, sizeof(unsigned long));
    why("node 63 is never online in the guest: the bind mask becomes empty");
    DONE();
    CASE("set_mempolicy.bad_mode", set_mempolicy, EINVAL, 99, NULL, 0);
    CASE("set_mempolicy.default", set_mempolicy, WANT_OK, MPOL_DEFAULT, NULL, 0);

    char *region = anon(4, 12);
    if (!region)
        return;
    mask = 0;
    policy = -1;
    CALL("get_mempolicy.mems_allowed", get_mempolicy, WANT_OK, &policy, &mask, MAXNODE, 0,
         MPOL_F_MEMS_ALLOWED);
    out_buf(0, &policy, sizeof policy);
    out_buf(1, &mask, sizeof mask);
    DONE();
    policy = -1;
    CALL("get_mempolicy.addr_node", get_mempolicy, WANT_OK, &policy, NULL, 0, region,
         MPOL_F_NODE | MPOL_F_ADDR);
    out_buf(0, &policy, sizeof policy);
    volatile_case();
    DONE();
    CASE("get_mempolicy.small_maxnode", get_mempolicy, EINVAL, &policy, &mask, 0, 0, 0);
    CASE("get_mempolicy.bad_flags", get_mempolicy, EINVAL, &policy, NULL, 0, 0, 0x100);

    CALL("mbind.bind_node0", mbind, WANT_OK, region, 2 * PAGE, MPOL_BIND, &node0, MAXNODE, 0);
    in_buf(3, &nodes_in, sizeof nodes_in);
    volatile_case();
    DONE();
    CALL("mbind.preferred_move", mbind, WANT_OK, region + 2 * PAGE, 2 * PAGE, MPOL_PREFERRED,
         &node0, MAXNODE, MPOL_MF_MOVE);
    in_buf(3, &nodes_in, sizeof nodes_in);
    volatile_case();
    DONE();
    CALL("mbind.move_all", mbind, EPERM, region, PAGE, MPOL_BIND, &node0, MAXNODE,
         MPOL_MF_MOVE_ALL);
    in_buf(3, &nodes_in, sizeof nodes_in);
    volatile_case();
    why("MPOL_MF_MOVE_ALL needs CAP_SYS_NICE");
    DONE();
    CALL("mbind.bad_mode", mbind, EINVAL, region, PAGE, 99, NULL, 0, 0);
    volatile_case();
    DONE();
    CALL("mbind.unaligned", mbind, EINVAL, region + 1, PAGE, MPOL_BIND, &node0, MAXNODE, 0);
    in_buf(3, &nodes_in, sizeof nodes_in);
    volatile_case();
    DONE();

    CALL("set_mempolicy_home_node.bind_range", set_mempolicy_home_node, WANT_OK, region,
         2 * PAGE, 0, 0);
    volatile_case();
    DONE();
    CALL("set_mempolicy_home_node.preferred_range", set_mempolicy_home_node, EOPNOTSUPP,
         region + 2 * PAGE, 2 * PAGE, 0, 0);
    volatile_case();
    why("a home node applies only to MPOL_BIND and MPOL_PREFERRED_MANY ranges");
    DONE();
    char *plain = anon(1, 13);
    if (plain) {
        CALL("set_mempolicy_home_node.no_policy", set_mempolicy_home_node, ENOENT, plain, PAGE,
             0, 0);
        volatile_case();
        why("a range without any VMA policy leaves the initial -ENOENT");
        DONE();
    }
    CALL("set_mempolicy_home_node.offline_node", set_mempolicy_home_node, EINVAL, region,
         2 * PAGE, 63, 0);
    volatile_case();
    DONE();
    CALL("set_mempolicy_home_node.bad_flags", set_mempolicy_home_node, EINVAL, region, 2 * PAGE,
         0, 1);
    volatile_case();
    DONE();
    CALL("set_mempolicy_home_node.unaligned", set_mempolicy_home_node, EINVAL, region + 1, PAGE,
         0, 0);
    volatile_case();
    DONE();

    CALL("migrate_pages.self", migrate_pages, WANT_OK, 0, MAXNODE, &node0, &node0);
    in_buf(2, &nodes_in, sizeof nodes_in);
    in_buf(3, &nodes_in, sizeof nodes_in);
    DONE();
    CALL("migrate_pages.foreign_node", migrate_pages, EPERM, 0, MAXNODE, &node0, &node5);
    in_buf(2, &nodes_in, sizeof nodes_in);
    in_buf(3, &(unsigned long){1UL << 5}, sizeof(unsigned long));
    why("a target node outside the task's cpuset needs CAP_SYS_NICE");
    DONE();
    CALL("migrate_pages.no_such_pid", migrate_pages, ESRCH, NO_SUCH_PID, MAXNODE, &node0,
         &node0);
    in_buf(2, &nodes_in, sizeof nodes_in);
    in_buf(3, &nodes_in, sizeof nodes_in);
    DONE();

    void *pages[2] = {region, region + PAGE};
    int status[2] = {-1, -1}, targets[2] = {0, 0};
    CALL("move_pages.query", move_pages, WANT_OK, 0, 2, pages, NULL, status, 0);
    in_buf(2, pages, sizeof pages);
    out_buf(4, status, sizeof status);
    volatile_case();
    why("a NULL node array asks where the pages are; it is not decoded");
    DONE();
    status[0] = status[1] = -1;
    CALL("move_pages.to_node0", move_pages, WANT_OK, 0, 2, pages, targets, status, MPOL_MF_MOVE);
    in_buf(2, pages, sizeof pages);
    in_buf(3, targets, sizeof targets);
    out_buf(4, status, sizeof status);
    volatile_case();
    DONE();
    CALL("move_pages.bad_flags", move_pages, EINVAL, 0, 2, pages, NULL, status, MPOL_MF_STRICT);
    in_buf(2, pages, sizeof pages);
    volatile_case();
    DONE();
    CALL("move_pages.move_all", move_pages, EPERM, 0, 2, pages, targets, status,
         MPOL_MF_MOVE_ALL);
    in_buf(2, pages, sizeof pages);
    in_buf(3, targets, sizeof targets);
    volatile_case();
    why("MPOL_MF_MOVE_ALL needs CAP_SYS_NICE");
    DONE();
    CALL("move_pages.no_such_pid", move_pages, ESRCH, NO_SUCH_PID, 2, pages, NULL, status, 0);
    in_buf(2, pages, sizeof pages);
    volatile_case();
    DONE();

    CALL("mbind.default", mbind, WANT_OK, region, 4 * PAGE, MPOL_DEFAULT, NULL, 0, 0);
    volatile_case();
    DONE();
    munmap(region, 4 * PAGE);
    if (plain)
        munmap(plain, PAGE);
}

static void pkey_secret_cases(void)
{
    char *region = anon(1, 14);
    if (!region)
        return;
    long pkey = CALL("pkey_alloc.default", pkey_alloc, WANT_ANY, 0, 0);
    why("ENOSPC when the CPU or hypervisor offers no protection keys (PKU)");
    DONE();
    if (pkey >= 0) {
        CALL("pkey_mprotect.allocated", pkey_mprotect, WANT_OK, region, PAGE,
             PROT_READ | PROT_WRITE, pkey);
        volatile_case();
        DONE();
        CASE("pkey_free.allocated", pkey_free, WANT_OK, pkey);
    }
    CALL("pkey_mprotect.no_key", pkey_mprotect, WANT_OK, region, PAGE, PROT_READ, -1);
    volatile_case();
    why("pkey -1 is plain mprotect");
    DONE();
    CALL("pkey_mprotect.unallocated", pkey_mprotect, EINVAL, region, PAGE, PROT_READ, 15);
    volatile_case();
    DONE();
    CASE("pkey_alloc.bad_flags", pkey_alloc, EINVAL, 1, 0);
    CASE("pkey_alloc.bad_rights", pkey_alloc, EINVAL, 0, 4);
    CASE("pkey_free.unallocated", pkey_free, EINVAL, 15);
    CASE("pkey_free.negative", pkey_free, EINVAL, -1);
    munmap(region, PAGE);

    long secret = CALL("memfd_secret.cloexec", memfd_secret, WANT_ANY, O_CLOEXEC);
    why("ENOSYS when secretmem is disabled or the direct map cannot be changed");
    DONE();
    int secret_error = secret < 0 ? errno : 0;
    if (secret >= 0) {
        if (ftruncate((int)secret, PAGE) != 0)
            ora_fail("memfd_secret size");
        long map = CALL("mmap.secret", mmap, WANT_ANY, 0, PAGE, PROT_READ | PROT_WRITE,
                        MAP_SHARED, secret, 0);
        volatile_case();
        why("secret memory is locked memory: RLIMIT_MEMLOCK may refuse it (EAGAIN)");
        DONE();
        if (map > 0) {
            memset((void *)map, 0x5c, PAGE);
            munmap((void *)map, PAGE);
        }
        close((int)secret);
    }
    CALL("memfd_secret.bad_flags", memfd_secret, secret >= 0 ? EINVAL : secret_error, 1);
    why("flags are checked after the secretmem availability check");
    DONE();

    long stack = CALL("map_shadow_stack.token", map_shadow_stack, WANT_ANY, 0, PAGE,
                      SHADOW_STACK_SET_TOKEN);
    volatile_case();
    why("needs user shadow stacks (CET): EOPNOTSUPP without the CPU feature, ENOSYS when "
        "compiled out");
    DONE();
    int stack_error = stack < 0 ? errno : 0;
    if (stack > 0)
        munmap((void *)stack, PAGE);
    CALL("map_shadow_stack.bad_flags", map_shadow_stack, stack > 0 ? EINVAL : stack_error, 0,
         PAGE, 0x80);
    why("flags are checked after the CPU feature check");
    DONE();
}

static void mseal_child(void *unused)
{
    (void)unused;
    char *m = anon(3, 16);
    if (!m)
        return;
    CALL("mseal.middle", mseal, WANT_OK, m + PAGE, PAGE, 0);
    volatile_case();
    why("sealed in a child: the sealed page goes away with the child");
    DONE();
    CALL("munmap.sealed", munmap, EPERM, m + PAGE, PAGE);
    volatile_case();
    DONE();
    CALL("mprotect.sealed", mprotect, EPERM, m + PAGE, PAGE, PROT_READ);
    volatile_case();
    DONE();
    CALL("mremap.sealed", mremap, EPERM, m + PAGE, PAGE, 2 * PAGE, MREMAP_MAYMOVE, 0);
    volatile_case();
    DONE();
    CALL("mseal.again", mseal, WANT_OK, m + PAGE, PAGE, 0);
    volatile_case();
    DONE();
    CALL("mseal.zero_length", mseal, WANT_OK, m, 0, 0);
    volatile_case();
    DONE();
    CALL("mseal.bad_flags", mseal, EINVAL, m, PAGE, 1);
    volatile_case();
    DONE();
    CALL("mseal.unaligned", mseal, EINVAL, m + 1, PAGE, 0);
    volatile_case();
    DONE();
    munmap(m, PAGE);
    munmap(m + 2 * PAGE, PAGE);
    char *gap = hole(1);
    CALL("mseal.unmapped", mseal, ENOMEM, gap, PAGE, 0);
    volatile_case();
    DONE();
}

static long membarrier_want(long command, long success)
{
    return membarrier_mask >= 0 && (membarrier_mask & command) ? success : EINVAL;
}

static void membarrier_child(void *unused)
{
    (void)unused;
    CALL("membarrier.private_unregistered", membarrier,
         membarrier_want(MEMBARRIER_CMD_PRIVATE_EXPEDITED, EPERM),
         MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0);
    why("registration happens in this child only; before it the command is refused");
    DONE();
    CASE("membarrier.register_private", membarrier,
         membarrier_want(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, WANT_OK),
         MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0);
    CASE("membarrier.private", membarrier,
         membarrier_want(MEMBARRIER_CMD_PRIVATE_EXPEDITED, WANT_OK),
         MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0);
    CASE("membarrier.register_sync_core", membarrier,
         membarrier_want(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, WANT_OK),
         MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
    CASE("membarrier.sync_core", membarrier,
         membarrier_want(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, WANT_OK),
         MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
    CASE("membarrier.register_rseq", membarrier,
         membarrier_want(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ, WANT_OK),
         MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ, 0, 0);
    CASE("membarrier.rseq_cpu0", membarrier,
         membarrier_want(MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ, WANT_OK),
         MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ, MEMBARRIER_CMD_FLAG_CPU, 0);
    CASE("membarrier.register_global", membarrier,
         membarrier_want(MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, WANT_OK),
         MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, 0, 0);
    CASE("membarrier.global_expedited", membarrier,
         membarrier_want(MEMBARRIER_CMD_GLOBAL_EXPEDITED, WANT_OK),
         MEMBARRIER_CMD_GLOBAL_EXPEDITED, 0, 0);
    CASE("membarrier.get_registrations", membarrier,
         membarrier_want(MEMBARRIER_CMD_GET_REGISTRATIONS, WANT_OK),
         MEMBARRIER_CMD_GET_REGISTRATIONS, 0, 0);
    CALL("membarrier.cpu_flag_not_rseq", membarrier, EINVAL, MEMBARRIER_CMD_PRIVATE_EXPEDITED,
         MEMBARRIER_CMD_FLAG_CPU, 0);
    why("MEMBARRIER_CMD_FLAG_CPU is only accepted with the RSEQ command");
    DONE();
}

static void membarrier_cases(void)
{
    membarrier_mask = CASE("membarrier.query", membarrier, WANT_OK, MEMBARRIER_CMD_QUERY, 0, 0);
    CASE("membarrier.query_flags", membarrier, EINVAL, MEMBARRIER_CMD_QUERY, 1, 0);
    CALL("membarrier.global", membarrier, membarrier_want(MEMBARRIER_CMD_GLOBAL, WANT_OK),
         MEMBARRIER_CMD_GLOBAL, 0, 0);
    why("MEMBARRIER_CMD_GLOBAL is refused only with nohz_full; the query says which");
    DONE();
    CASE("membarrier.unknown", membarrier, EINVAL, 1 << 20, 0, 0);
    in_child(302, "membarrier child", membarrier_child, NULL);
}

// Process memory of other processes: process_madvise, process_mrelease,
// process_vm_readv/writev.
static char remote_source[32];
static char remote_target[32];

static void remote_iov_status(int count)
{
    static const char *keys[] = {"arg3.remote_iov[0].data", "arg3.remote_iov[1].data"};
    for (int i = 0; i < count && i < 2; i++)
        want_key_status(keys[i], "ADDRESS_ONLY");
}

static void process_vm_self_cases(void)
{
    char a[8], b[8], src1[10], src2[6], all[16];
    pattern(src1, sizeof src1, 20);
    pattern(src2, sizeof src2, 21);
    memset(a, 0, sizeof a);
    memset(b, 0, sizeof b);
    struct iovec local[2] = {{a, sizeof a}, {b, sizeof b}};
    struct iovec remote[2] = {{src1, sizeof src1}, {src2, sizeof src2}};
    long got = CALL("process_vm_readv.self", process_vm_readv, WANT_OK, getpid(), local, 2,
                    remote, 2, 0);
    in_key("arg1.iov", local, sizeof local);
    out_key("arg1.iov[0].data", a, sizeof a);
    out_key("arg1.iov[1].data", b, got > 8 ? (size_t)got - 8 : 0);
    in_key("arg3.remote_iov", remote, sizeof remote);
    remote_iov_status(2);
    volatile_case();
    why("the remote side is recorded by address only");
    DONE();
    memcpy(all, src1, sizeof src1);
    memcpy(all + sizeof src1, src2, sizeof src2);
    if (got != 16 || memcmp(a, all, 8) || memcmp(b, all + 8, 8))
        ora_fail("process_vm_readv self copy");

    char one[9], two[3], target[12];
    memcpy(one, "WRITE-ONE", sizeof one);
    memcpy(two, "TWO", sizeof two);
    memset(target, 0, sizeof target);
    struct iovec wlocal[2] = {{one, sizeof one}, {two, sizeof two}};
    struct iovec wremote[1] = {{target, sizeof target}};
    got = CALL("process_vm_writev.self", process_vm_writev, WANT_OK, getpid(), wlocal, 2,
               wremote, 1, 0);
    in_key("arg1.iov", wlocal, sizeof wlocal);
    in_key("arg1.iov[0].data", one, sizeof one);
    in_key("arg1.iov[1].data", two, sizeof two);
    in_key("arg3.remote_iov", wremote, sizeof wremote);
    remote_iov_status(1);
    volatile_case();
    DONE();
    if (got != 12 || memcmp(target, "WRITE-ONETWO", 12))
        ora_fail("process_vm_writev self copy");

    struct iovec fault[1] = {{(void *)1, 16}};
    CALL("process_vm_readv.remote_fault", process_vm_readv, EFAULT, getpid(), local, 1, fault, 1,
         0);
    in_key("arg1.iov", local, sizeof local[0]);
    in_key("arg3.remote_iov", fault, sizeof fault);
    remote_iov_status(1);
    volatile_case();
    DONE();
    CALL("process_vm_readv.bad_flags", process_vm_readv, EINVAL, getpid(), local, 2, remote, 2,
         1);
    in_key("arg1.iov", local, sizeof local);
    in_key("arg3.remote_iov", remote, sizeof remote);
    remote_iov_status(2);
    volatile_case();
    DONE();
    CALL("process_vm_readv.no_such_pid", process_vm_readv, ESRCH, NO_SUCH_PID, local, 2, remote,
         2, 0);
    in_key("arg1.iov", local, sizeof local);
    in_key("arg3.remote_iov", remote, sizeof remote);
    remote_iov_status(2);
    volatile_case();
    DONE();
    CALL("process_vm_writev.too_many_local", process_vm_writev, EINVAL, getpid(), wlocal, 1025,
         wremote, 1, 0);
    want_key_status("arg1.iov", "INVALID_EXTENT");
    in_key("arg3.remote_iov", wremote, sizeof wremote);
    remote_iov_status(1);
    volatile_case();
    DONE();
}

static void madvise_mrelease_self_cases(void)
{
    int self = pidfd_of(getpid());
    if (self < 0) {
        ora_fail("pidfd_open self");
        return;
    }
    char *region = anon(4, 15);
    if (!region) {
        close(self);
        return;
    }
    struct iovec ranges[2] = {{region, PAGE}, {region + 2 * PAGE, 2 * PAGE}};
    long done = CALL("process_madvise.self_cold", process_madvise, WANT_OK, self, ranges, 2,
                     MADV_COLD, 0);
    in_key("arg1.remote_ranges", ranges, sizeof ranges);
    volatile_case();
    DONE();
    if (done != (long)(3 * PAGE))
        ora_fail("process_madvise advised length");
    CALL("process_madvise.self_willneed", process_madvise, WANT_OK, self, ranges, 1,
         MADV_WILLNEED, 0);
    in_key("arg1.remote_ranges", ranges, sizeof ranges[0]);
    volatile_case();
    DONE();
    CALL("process_madvise.self_pageout", process_madvise, WANT_OK, self, ranges + 1, 1,
         MADV_PAGEOUT, 0);
    in_key("arg1.remote_ranges", ranges + 1, sizeof ranges[1]);
    volatile_case();
    DONE();
    CALL("process_madvise.bad_advice", process_madvise, EINVAL, self, ranges, 2, MADV_DONTNEED,
         0);
    in_key("arg1.remote_ranges", ranges, sizeof ranges);
    volatile_case();
    why("only non-destructive hints are accepted");
    DONE();
    CALL("process_madvise.bad_flags", process_madvise, EINVAL, self, ranges, 2, MADV_COLD, 1);
    in_key("arg1.remote_ranges", ranges, sizeof ranges);
    volatile_case();
    DONE();
    CALL("process_madvise.badf", process_madvise, EBADF, 999, ranges, 2, MADV_COLD, 0);
    in_key("arg1.remote_ranges", ranges, sizeof ranges);
    volatile_case();
    DONE();
    CALL("process_madvise.too_many", process_madvise, EINVAL, self, ranges, 1025, MADV_COLD, 0);
    want_key_status("arg1.remote_ranges", "INVALID_EXTENT");
    volatile_case();
    DONE();
    munmap(region, 4 * PAGE);

    CALL("process_mrelease.self_live", process_mrelease, EINVAL, self, 0);
    why("a live process is not exiting: there is nothing to reap");
    DONE();
    CASE("process_mrelease.bad_flags", process_mrelease, EINVAL, self, 1);
    CASE("process_mrelease.badf", process_mrelease, EBADF, 999, 0);
    close(self);
}

// The cross-process target (303): it fills remote_source, signals ready,
// waits until the parent is done and checks what the parent wrote.
static void cross_process_cases(void)
{
    int ready[2], go[2];
    if (pipe(ready) != 0 || pipe(go) != 0) {
        ora_fail("cross-process pipes");
        return;
    }
    pattern(remote_source, sizeof remote_source, 31);
    memset(remote_target, 0, sizeof remote_target);
    ora_flush();
    pid_t child = fork();
    if (child < 0) {
        ora_fail("cross-process fork");
        return;
    }
    if (child == 0) {
        char byte = 'R', expect[32];
        ora_child(303);
        close(ready[0]);
        close(go[1]);
        pattern(remote_source, sizeof remote_source, 30);
        if (write(ready[1], &byte, 1) != 1)
            _exit(4);
        while (read(go[0], &byte, 1) < 0 && errno == EINTR)
            ;
        pattern(expect, sizeof expect, 32);
        _exit(memcmp(remote_target, expect, sizeof expect) ? 3 : 0);
    }
    close(ready[1]);
    close(go[0]);
    char byte;
    if (read(ready[0], &byte, 1) != 1)
        ora_fail("cross-process child ready");
    role("child", child);

    char local[32], expect[32];
    memset(local, 0, sizeof local);
    struct iovec liov[1] = {{local, sizeof local}};
    struct iovec riov[1] = {{remote_source, sizeof remote_source}};
    long got = CALL("process_vm_readv.child", process_vm_readv, WANT_OK, child, liov, 1, riov, 1,
                    0);
    in_key("arg1.iov", liov, sizeof liov);
    out_key("arg1.iov[0].data", local, got > 0 ? (size_t)got : 0);
    in_key("arg3.remote_iov", riov, sizeof riov);
    remote_iov_status(1);
    volatile_case();
    DONE();
    pattern(expect, sizeof expect, 30);
    if (got != 32 || memcmp(local, expect, sizeof expect))
        ora_fail("process_vm_readv child data");

    char data[32];
    pattern(data, sizeof data, 32);
    struct iovec wiov[1] = {{data, sizeof data}};
    struct iovec tiov[1] = {{remote_target, sizeof remote_target}};
    got = CALL("process_vm_writev.child", process_vm_writev, WANT_OK, child, wiov, 1, tiov, 1, 0);
    in_key("arg1.iov", wiov, sizeof wiov);
    in_key("arg1.iov[0].data", data, sizeof data);
    in_key("arg3.remote_iov", tiov, sizeof tiov);
    remote_iov_status(1);
    volatile_case();
    why("the child checks the bytes and exits nonzero when they differ");
    DONE();

    int pidfd = pidfd_of(child);
    if (pidfd >= 0) {
        char *region = anon(1, 17);
        if (region) {
            struct iovec range[1] = {{region, PAGE}};
            CALL("process_madvise.child", process_madvise, EPERM, pidfd, range, 1, MADV_COLD, 0);
            in_key("arg1.remote_ranges", range, sizeof range);
            volatile_case();
            why("advising another process needs CAP_SYS_NICE");
            DONE();
            munmap(region, PAGE);
        }
        CALL("process_mrelease.child_live", process_mrelease, EINVAL, pidfd, 0);
        volatile_case();
        DONE();
        close(pidfd);
    } else {
        ora_fail("pidfd_open child");
    }
    if (write(go[1], "D", 1) != 1)
        ora_fail("cross-process release");
    close(go[1]);
    close(ready[0]);
    ora_wait(child, "cross-process target");

    // A zombie has no memory left to release.
    int gate[2];
    if (pipe(gate) != 0) {
        ora_fail("zombie pipe");
        return;
    }
    ora_flush();
    child = fork();
    if (child < 0) {
        ora_fail("zombie fork");
        return;
    }
    if (child == 0) {
        ora_child(304);
        close(gate[1]);
        while (read(gate[0], &byte, 1) < 0 && errno == EINTR)
            ;
        _exit(0);
    }
    close(gate[0]);
    pidfd = pidfd_of(child);
    close(gate[1]);
    siginfo_t info;
    memset(&info, 0, sizeof info);
    if (waitid(P_PID, (id_t)child, &info, WEXITED | WNOWAIT) != 0)
        ora_fail("zombie wait");
    if (pidfd >= 0) {
        CALL("process_mrelease.zombie", process_mrelease, ESRCH, pidfd, 0);
        volatile_case();
        why("the exited, unreaped child has already dropped its address space");
        DONE();
        close(pidfd);
    } else {
        ora_fail("pidfd_open zombie");
    }
    ora_wait(child, "zombie child");
}

void area_memory(void)
{
    mmap_cases();
    protect_cases();
    remap_cases();
    sync_cases();
    advise_cases();
    lock_cases();
    numa_cases();
    pkey_secret_cases();
    in_child(301, "mseal child", mseal_child, NULL);
    membarrier_cases();
    process_vm_self_cases();
    madvise_mrelease_self_cases();
    cross_process_cases();
}
