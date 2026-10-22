// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// attribution.c — who wrote an io_uring entry, as the run status says it.
//
// Groups ring-private, ring-shared and ring-sqpoll, one run each, because the
// guest reports attribution per run (RUN_STATUS OBSERVATION_INCOMPLETE):
//   ring-private  one process makes a ring and submits through it: the entry
//                 was written by that process, so the run's async observation
//                 is complete (ASYNC_COMPLETE, no OBSERVATION_INCOMPLETE).
//   ring-shared   the ring's mapping is kept across a fork and the parent
//                 submits while the child holds it: either could have written
//                 the entry, so the observation stays incomplete.
//   ring-sqpoll   the ring's kernel thread submits (IORING_SETUP_SQPOLL): no
//                 task of the program does, so it stays incomplete.
// The calls are not described (no ANT_EXPECT); the suite checks the run's
// flags, notes and that every recorded call and request is whole.
#include "areas.h"

#include <fcntl.h>
#include <linux/io_uring.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct ring {
    int fd;
    unsigned *sq_tail, *sq_array, *sq_flags, sq_mask;
    unsigned *cq_head, *cq_tail, cq_mask;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
};

static int ring_open(struct ring *r, unsigned flags)
{
    struct io_uring_params p;
    unsigned char *sq;
    size_t sq_size, cq_size;

    memset(&p, 0, sizeof p);
    p.flags = flags;
    r->fd = (int)syscall(__NR_io_uring_setup, 8, &p);
    if (r->fd < 0)
        return -1;
    sq_size = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    cq_size = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    if (cq_size > sq_size)
        sq_size = cq_size;
    // One mapping for both rings (IORING_FEAT_SINGLE_MMAP, every 6.12 ring).
    sq = mmap(NULL, sq_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
              IORING_OFF_SQ_RING);
    r->sqes = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQES);
    if (sq == MAP_FAILED || r->sqes == MAP_FAILED)
        return -1;
    r->sq_tail = (unsigned *)(sq + p.sq_off.tail);
    r->sq_array = (unsigned *)(sq + p.sq_off.array);
    r->sq_flags = (unsigned *)(sq + p.sq_off.flags);
    r->sq_mask = *(unsigned *)(sq + p.sq_off.ring_mask);
    r->cq_head = (unsigned *)(sq + p.cq_off.head);
    r->cq_tail = (unsigned *)(sq + p.cq_off.tail);
    r->cq_mask = *(unsigned *)(sq + p.cq_off.ring_mask);
    r->cqes = (struct io_uring_cqe *)(sq + p.cq_off.cqes);
    return 0;
}

// Fill the entry, then publish it (an SQPOLL thread may take it at once).
static void ring_queue(struct ring *r, const struct io_uring_sqe *entry)
{
    unsigned tail = *r->sq_tail, index = tail & r->sq_mask;

    r->sqes[index] = *entry;
    r->sq_array[index] = index;
    __atomic_store_n(r->sq_tail, tail + 1, __ATOMIC_RELEASE);
}

// A NOP and a write of `text` to a file of the work directory, queued.
static void queue_work(struct ring *r, int fd, const char *text)
{
    struct io_uring_sqe entry;

    memset(&entry, 0, sizeof entry);
    entry.opcode = IORING_OP_NOP;
    entry.user_data = 1;
    ring_queue(r, &entry);
    memset(&entry, 0, sizeof entry);
    entry.opcode = IORING_OP_WRITE;
    entry.fd = fd;
    entry.addr = (unsigned long)text;
    entry.len = (unsigned)strlen(text);
    entry.user_data = 2;
    ring_queue(r, &entry);
}

// Wait (bounded) for `count` completions, waking an SQPOLL thread that sleeps;
// every one must have succeeded.
static void reap(struct ring *r, unsigned count, int sqpoll)
{
    unsigned head = *r->cq_head;
    struct timespec pause = {0, 10 * 1000 * 1000};

    for (int tries = 0; tries < 500 && count; tries++) {
        if (sqpoll && (__atomic_load_n(r->sq_flags, __ATOMIC_ACQUIRE) & IORING_SQ_NEED_WAKEUP))
            syscall(__NR_io_uring_enter, r->fd, 0, 0, IORING_ENTER_SQ_WAKEUP, NULL, 0);
        while (count && head != __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE)) {
            if (r->cqes[head & r->cq_mask].res < 0)
                ora_fail("attribution: a request failed");
            head++;
            count--;
        }
        if (count)
            nanosleep(&pause, NULL);
    }
    __atomic_store_n(r->cq_head, head, __ATOMIC_RELEASE);
    if (count)
        ora_fail("attribution: completions missing");
}

static int open_file(const char *name)
{
    char path[512];
    int fd = open(work_path(path, sizeof path, name), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                  0600);

    if (fd < 0)
        ora_fail("attribution: open the data file");
    return fd;
}

void area_ring_private(void)
{
    struct ring r;
    int fd = open_file("ring-private");

    if (ring_open(&r, 0) < 0) {
        ora_fail("ring-private: io_uring_setup");
        return;
    }
    queue_work(&r, fd, "written through a private ring\n");
    if (syscall(__NR_io_uring_enter, r.fd, 2, 2, IORING_ENTER_GETEVENTS, NULL, 0) != 2)
        ora_fail("ring-private: io_uring_enter");
    reap(&r, 2, 0);
    close(r.fd);
    close(fd);
}

void area_ring_shared(void)
{
    struct ring r;
    int fd = open_file("ring-shared"), done[2];
    pid_t child;
    char byte = 0;

    if (ring_open(&r, 0) < 0 || pipe(done) != 0) {
        ora_fail("ring-shared: io_uring_setup");
        return;
    }
    // The child keeps the ring's mapping (MAP_SHARED survives fork) until
    // the parent has submitted: it could have written the entries.
    child = fork();
    if (child == 0) {
        close(done[1]);
        if (read(done[0], &byte, 1) < 0)
            _exit(1);
        _exit(0);
    }
    close(done[0]);
    queue_work(&r, fd, "written through a ring two processes map\n");
    if (syscall(__NR_io_uring_enter, r.fd, 2, 2, IORING_ENTER_GETEVENTS, NULL, 0) != 2)
        ora_fail("ring-shared: io_uring_enter");
    reap(&r, 2, 0);
    if (write(done[1], &byte, 1) != 1)
        ora_fail("ring-shared: release the child");
    int status = 0;
    if (child < 0 || waitpid(child, &status, 0) != child || status != 0)
        ora_fail("ring-shared: the child");
    close(done[1]);
    close(r.fd);
    close(fd);
}

void area_ring_sqpoll(void)
{
    struct ring r;
    int fd = open_file("ring-sqpoll");

    if (ring_open(&r, IORING_SETUP_SQPOLL) < 0) {
        ora_fail("ring-sqpoll: io_uring_setup");
        return;
    }
    queue_work(&r, fd, "written by the ring's kernel thread\n");
    reap(&r, 2, 1);
    close(r.fd);
    close(fd);
}
