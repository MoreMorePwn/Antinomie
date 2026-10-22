// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// uring.c — io_uring rings, submission/completion and registration.
//
// Slots: io_uring_setup io_uring_enter io_uring_register.
//
// A minimal raw ring (no liburing). Every request carries a unique user_data
// 0xC0F0000000000000 + n and is reported on the io_uring_enter case that
// submitted it with async_req(user_data, opcode, result). The completion
// queue is shared memory: right after the enter call returns (before DONE)
// the case harvests the CQEs it can see without a system call and reports the
// result the CQE carries; a request that completes later (a canceled timeout)
// is reported with the result the case means and checked when it completes.
// Payload bytes the recorder captures are declared with async_data():
// "async.payload.input" (WRITE/WRITEV/SEND/WRITE_FIXED, the bytes handed to
// the kernel), "async.payload.output" (READ/READV/RECV/READ_FIXED, the bytes
// the completion produced), "async.payload.iov" (the kernel's copy of a
// multi-segment iovec array), and the typed operands "async.operand.path"
// (with its NUL, as the kernel copied it), "async.operand.statx" and
// "async.operand.timeout". Every wait is bounded: waiting enters pass a
// timeout through IORING_ENTER_EXT_ARG unless the request completes inline.
#include "areas.h"

#include <fcntl.h>
#include <linux/io_uring.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>

#define UD(n) (0xC0F0000000000000ULL + (n))
// No io_uring opcode: io_init_req() rejects it (6.12 has 59).
#define BAD_OPCODE 250
// No io_uring_register opcode (6.12 has fewer than 40).
#define BAD_REGISTER_OPCODE 200

struct ring {
    struct io_uring_params p;
    int fd;
    unsigned char *sq, *cq;
    size_t sq_size, cq_size;
    struct io_uring_sqe *sqes;
    size_t sqes_size;
    unsigned *sq_tail, *sq_array, sq_mask;
    unsigned *cq_head, *cq_tail, cq_mask;
    struct io_uring_cqe *cqes;
    unsigned queued;
};

// Completions seen but not yet asked for.
static struct {
    uint64_t user_data;
    int result;
} seen[64];
static unsigned seen_count;

// Requests reported before they completed: checked when they do.
static struct {
    uint64_t user_data;
    int result;
} later[8];
static unsigned later_count;

// The bounded wait of every waiting enter, and a short one that expires.
static struct __kernel_timespec wait_ts, short_ts;
static struct io_uring_getevents_arg wait_arg, short_arg;

static int data_file = -1;

static int ring_map(struct ring *r)
{
    r->sq_size = r->p.sq_off.array + r->p.sq_entries * sizeof(unsigned);
    r->cq_size = r->p.cq_off.cqes + r->p.cq_entries * sizeof(struct io_uring_cqe);
    if (r->p.features & IORING_FEAT_SINGLE_MMAP) {
        if (r->cq_size > r->sq_size)
            r->sq_size = r->cq_size;
        r->cq_size = r->sq_size;
    }
    r->sq = mmap(NULL, r->sq_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
                 IORING_OFF_SQ_RING);
    if (r->sq == MAP_FAILED)
        return -1;
    r->cq = r->sq;
    if (!(r->p.features & IORING_FEAT_SINGLE_MMAP)) {
        r->cq = mmap(NULL, r->cq_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                     r->fd, IORING_OFF_CQ_RING);
        if (r->cq == MAP_FAILED) {
            munmap(r->sq, r->sq_size);
            return -1;
        }
    }
    r->sqes_size = r->p.sq_entries * sizeof(struct io_uring_sqe);
    r->sqes = mmap(NULL, r->sqes_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
                   IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) {
        if (r->cq != r->sq)
            munmap(r->cq, r->cq_size);
        munmap(r->sq, r->sq_size);
        return -1;
    }
    r->sq_tail = (unsigned *)(r->sq + r->p.sq_off.tail);
    r->sq_array = (unsigned *)(r->sq + r->p.sq_off.array);
    r->sq_mask = *(unsigned *)(r->sq + r->p.sq_off.ring_mask);
    r->cq_head = (unsigned *)(r->cq + r->p.cq_off.head);
    r->cq_tail = (unsigned *)(r->cq + r->p.cq_off.tail);
    r->cq_mask = *(unsigned *)(r->cq + r->p.cq_off.ring_mask);
    r->cqes = (struct io_uring_cqe *)(r->cq + r->p.cq_off.cqes);
    r->queued = 0;
    return 0;
}

static void ring_unmap(struct ring *r)
{
    munmap(r->sqes, r->sqes_size);
    if (r->cq != r->sq)
        munmap(r->cq, r->cq_size);
    munmap(r->sq, r->sq_size);
}

// The next free SQE, cleared, with its opcode and user_data.
static struct io_uring_sqe *ring_sqe(struct ring *r, uint8_t opcode, uint64_t user_data)
{
    unsigned index = (*r->sq_tail + r->queued) & r->sq_mask;
    struct io_uring_sqe *sqe = &r->sqes[index];

    memset(sqe, 0, sizeof *sqe);
    sqe->opcode = opcode;
    sqe->user_data = user_data;
    r->sq_array[index] = index;
    r->queued++;
    return sqe;
}

// Make the queued SQEs visible to the next io_uring_enter.
static void ring_publish(struct ring *r)
{
    __atomic_store_n(r->sq_tail, *r->sq_tail + r->queued, __ATOMIC_RELEASE);
    r->queued = 0;
}

// Move every visible CQE into `seen` (memory only, no system call).
static void harvest(struct ring *r)
{
    unsigned head = *r->cq_head;
    while (head != __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE)) {
        const struct io_uring_cqe *cqe = &r->cqes[head & r->cq_mask];
        if (seen_count < sizeof seen / sizeof seen[0]) {
            seen[seen_count].user_data = cqe->user_data;
            seen[seen_count++].result = cqe->res;
        } else {
            ora_fail("io_uring completion stash full");
        }
        head++;
    }
    __atomic_store_n(r->cq_head, head, __ATOMIC_RELEASE);
}

static int take(struct ring *r, uint64_t user_data, int *result)
{
    harvest(r);
    for (unsigned i = 0; i < seen_count; i++) {
        if (seen[i].user_data == user_data) {
            *result = seen[i].result;
            seen[i] = seen[--seen_count];
            return 1;
        }
    }
    return 0;
}

// Inside a pending enter case: the request's completion as the CQE reports it.
static void request(struct ring *r, uint64_t user_data, int opcode, int expected)
{
    char text[160];
    int result;

    if (!take(r, user_data, &result)) {
        snprintf(text, sizeof text, "io_uring request %#llx has no completion",
                 (unsigned long long)user_data);
        ora_fail(text);
        async_req(user_data, opcode, expected);
        return;
    }
    if (result != expected) {
        snprintf(text, sizeof text, "io_uring request %#llx completed with %d, wanted %d",
                 (unsigned long long)user_data, result, expected);
        ora_fail(text);
    }
    async_req(user_data, opcode, result);
}

// Inside a pending enter case: a request that completes after this call.
static void request_later(uint64_t user_data, int opcode, int expected)
{
    async_req(user_data, opcode, expected);
    if (later_count < sizeof later / sizeof later[0]) {
        later[later_count].user_data = user_data;
        later[later_count++].result = expected;
    } else {
        ora_fail("io_uring later list full");
    }
}

static void check_later(struct ring *r)
{
    char text[160];
    for (unsigned i = 0; i < later_count; i++) {
        int result;
        if (!take(r, later[i].user_data, &result)) {
            snprintf(text, sizeof text, "io_uring request %#llx never completed",
                     (unsigned long long)later[i].user_data);
            ora_fail(text);
        } else if (result != later[i].result) {
            snprintf(text, sizeof text, "io_uring request %#llx completed with %d, wanted %d",
                     (unsigned long long)later[i].user_data, result, later[i].result);
            ora_fail(text);
        }
    }
    later_count = 0;
}

static void describe_wait(const struct io_uring_getevents_arg *arg,
                          const struct __kernel_timespec *ts)
{
    in_key("arg4.ext_arg", arg, sizeof *arg);
    in_key("arg4.timeout", ts, sizeof *ts);
}

// Submit what is queued and wait, at most 5 s, for `wait` completions. The
// case stays pending: the caller reports its requests and calls DONE().
static long enter_wait(const char *label, struct ring *r, unsigned submit, unsigned wait)
{
    ring_publish(r);
    long ret = CALL(label, io_uring_enter, WANT_OK, r->fd, submit, wait,
                    IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG, &wait_arg, sizeof wait_arg);
    describe_wait(&wait_arg, &wait_ts);
    volatile_case();
    if (ret != (long)submit)
        ora_fail("io_uring_enter submitted fewer requests than queued");
    return ret;
}

static long ring_setup(const char *label, struct ring *r, unsigned entries, unsigned flags,
                       unsigned cq_entries)
{
    struct io_uring_params before;

    memset(r, 0, sizeof *r);
    r->p.flags = flags;
    r->p.cq_entries = cq_entries;
    before = r->p;
    long fd = CALL(label, io_uring_setup, WANT_OK, entries, &r->p);
    in_key("arg1.params", &before, sizeof before);
    if (fd >= 0)
        out_key("arg1.params", &r->p, sizeof r->p);
    DONE();
    r->fd = (int)fd;
    if (fd < 0)
        return -1;
    if (ring_map(r) != 0) {
        ora_fail("io_uring ring mapping");
        CASE("close.unmapped_ring", close, WANT_OK, fd);
        r->fd = -1;
        return -1;
    }
    return fd;
}

static void setup_cases(void)
{
    struct io_uring_params p;
    struct ring small;

    memset(&p, 0, sizeof p);
    CALL("io_uring_setup.zero_entries", io_uring_setup, EINVAL, 0, &p);
    in_key("arg1.params", &p, sizeof p);
    DONE();
    memset(&p, 0, sizeof p);
    p.flags = 0x80000000U;
    CALL("io_uring_setup.bad_flags", io_uring_setup, EINVAL, 4, &p);
    in_key("arg1.params", &p, sizeof p);
    DONE();
    memset(&p, 0, sizeof p);
    p.flags = IORING_SETUP_CQSIZE;
    p.cq_entries = 4;
    CALL("io_uring_setup.cqsize_below_sq", io_uring_setup, EINVAL, 8, &p);
    in_key("arg1.params", &p, sizeof p);
    why("a completion queue smaller than the submission queue is refused");
    DONE();
    CALL("io_uring_setup.fault", io_uring_setup, EFAULT, 4, 1);
    want_key_status("arg1.params", "COPY_FAULT");
    why("an address in the first page is never mapped: the kernel and the recorder both fault");
    DONE();

    if (ring_setup("io_uring_setup.cqsize", &small, 4, IORING_SETUP_CQSIZE, 64) >= 0) {
        if (small.p.cq_entries != 64)
            ora_fail("io_uring CQSIZE ring has the wrong completion queue size");
        ring_unmap(&small);
        CASE("close.cqsize_ring", close, WANT_OK, small.fd);
    }
}

static void enter_cases(struct ring *r)
{
    uint64_t mask = 1ULL << (SIGUSR2 - 1);

    ring_sqe(r, IORING_OP_NOP, UD(1));
    ring_publish(r);
    CALL("io_uring_enter.submit_wait", io_uring_enter, WANT_OK, r->fd, 1, 1,
         IORING_ENTER_GETEVENTS, 0, 0);
    request(r, UD(1), IORING_OP_NOP, 0);
    why("a NOP completes inline during submission, so the wait cannot block");
    DONE();

    ring_sqe(r, IORING_OP_NOP, UD(2));
    ring_publish(r);
    CALL("io_uring_enter.sigmask", io_uring_enter, WANT_OK, r->fd, 1, 1, IORING_ENTER_GETEVENTS,
         &mask, sizeof mask);
    in_key("signal.mask", &mask, sizeof mask);
    request(r, UD(2), IORING_OP_NOP, 0);
    why("without EXT_ARG the fifth argument is the wait's signal mask (SIGUSR2 blocked)");
    DONE();

    ring_sqe(r, IORING_OP_NOP, UD(3));
    ring_publish(r);
    CALL("io_uring_enter.submit_only", io_uring_enter, WANT_OK, r->fd, 1, 0, 0, 0, 0);
    request_later(UD(3), IORING_OP_NOP, 0);
    DONE();
    CALL("io_uring_enter.getevents_only", io_uring_enter, WANT_OK, r->fd, 0, 1,
         IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG, &wait_arg, sizeof wait_arg);
    describe_wait(&wait_arg, &wait_ts);
    volatile_case();
    why("the NOP's completion is already queued; the wait is bounded by a 5 s timeout");
    DONE();
    check_later(r);

    harvest(r);
    CALL("io_uring_enter.wait_expires", io_uring_enter, ETIME, r->fd, 0, 1,
         IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG, &short_arg, sizeof short_arg);
    describe_wait(&short_arg, &short_ts);
    volatile_case();
    why("nothing is in flight: the 10 ms wait times out");
    DONE();
    CALL("io_uring_enter.ext_arg_bad_size", io_uring_enter, EINVAL, r->fd, 0, 1,
         IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG, &wait_arg, 8);
    want_key_status("arg4.ext_arg", "INVALID_EXTENT");
    why("EXT_ARG needs sizeof(struct io_uring_getevents_arg); the recorder keeps the bad size");
    volatile_case();
    DONE();
    CASE("io_uring_enter.badf", io_uring_enter, EBADF, 999, 0, 0, 0, 0, 0);
    CASE("io_uring_enter.bad_flags", io_uring_enter, EINVAL, r->fd, 0, 0, 0x80000000U, 0, 0);
}

static void file_cases(struct ring *r)
{
    static const char linked[] = "LINKED-PAIR-PAYLOAD!";
    unsigned char out[64], in[64], va[16], vb[24], ra[16], rb[24], both[40];
    unsigned char link_in[sizeof linked - 1];
    struct iovec wvec[2], rvec[2];
    struct statx stx;
    struct io_uring_sqe *sqe;
    long ret;
    int result;

    ret = CALL("openat.uring_file", openat, WANT_OK, AT_FDCWD, "uring-file",
               O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
    in_str(1, "uring-file");
    if (ret >= 0)
        file_fd("OPEN", (int)ret);
    DONE();
    if (ret < 0)
        return;
    data_file = (int)ret;
    CASE("io_uring_enter.not_a_ring", io_uring_enter, EOPNOTSUPP, data_file, 0, 0, 0, 0, 0);

    pattern(out, sizeof out, 11);
    sqe = ring_sqe(r, IORING_OP_WRITE, UD(4));
    sqe->fd = data_file;
    sqe->addr = (uintptr_t)out;
    sqe->len = sizeof out;
    sqe->off = 0;
    enter_wait("io_uring_enter.write", r, 1, 1);
    request(r, UD(4), IORING_OP_WRITE, sizeof out);
    async_data(UD(4), "async.payload.input", out, sizeof out);
    DONE();

    memset(in, 0, sizeof in);
    sqe = ring_sqe(r, IORING_OP_READ, UD(5));
    sqe->fd = data_file;
    sqe->addr = (uintptr_t)in;
    sqe->len = sizeof in;
    sqe->off = 0;
    enter_wait("io_uring_enter.read", r, 1, 1);
    request(r, UD(5), IORING_OP_READ, sizeof in);
    async_data(UD(5), "async.payload.output", in, sizeof in);
    DONE();
    if (memcmp(in, out, sizeof in) != 0)
        ora_fail("io_uring read output");

    pattern(va, sizeof va, 12);
    pattern(vb, sizeof vb, 13);
    memcpy(both, va, sizeof va);
    memcpy(both + sizeof va, vb, sizeof vb);
    wvec[0] = (struct iovec){va, sizeof va};
    wvec[1] = (struct iovec){vb, sizeof vb};
    sqe = ring_sqe(r, IORING_OP_WRITEV, UD(6));
    sqe->fd = data_file;
    sqe->addr = (uintptr_t)wvec;
    sqe->len = 2;
    sqe->off = 64;
    enter_wait("io_uring_enter.writev", r, 1, 1);
    request(r, UD(6), IORING_OP_WRITEV, sizeof both);
    async_data(UD(6), "async.payload.iov", wvec, sizeof wvec);
    async_data(UD(6), "async.payload.input", both, sizeof both);
    DONE();

    memset(ra, 0, sizeof ra);
    memset(rb, 0, sizeof rb);
    rvec[0] = (struct iovec){ra, sizeof ra};
    rvec[1] = (struct iovec){rb, sizeof rb};
    sqe = ring_sqe(r, IORING_OP_READV, UD(7));
    sqe->fd = data_file;
    sqe->addr = (uintptr_t)rvec;
    sqe->len = 2;
    sqe->off = 64;
    enter_wait("io_uring_enter.readv", r, 1, 1);
    request(r, UD(7), IORING_OP_READV, sizeof both);
    async_data(UD(7), "async.payload.iov", rvec, sizeof rvec);
    async_data(UD(7), "async.payload.output", both, sizeof both);
    why("the output is the file's bytes in iovec order; checked against the buffers below");
    DONE();
    if (memcmp(ra, va, sizeof ra) != 0 || memcmp(rb, vb, sizeof rb) != 0)
        ora_fail("io_uring readv output");

    sqe = ring_sqe(r, IORING_OP_FSYNC, UD(8));
    sqe->fd = data_file;
    enter_wait("io_uring_enter.fsync", r, 1, 1);
    request(r, UD(8), IORING_OP_FSYNC, 0);
    DONE();

    // A linked pair: the read starts only after the write completed.
    memset(link_in, 0, sizeof link_in);
    sqe = ring_sqe(r, IORING_OP_WRITE, UD(9));
    sqe->fd = data_file;
    sqe->addr = (uintptr_t)linked;
    sqe->len = sizeof linked - 1;
    sqe->off = 256;
    sqe->flags = IOSQE_IO_LINK;
    sqe = ring_sqe(r, IORING_OP_READ, UD(10));
    sqe->fd = data_file;
    sqe->addr = (uintptr_t)link_in;
    sqe->len = sizeof link_in;
    sqe->off = 256;
    enter_wait("io_uring_enter.linked_pair", r, 2, 2);
    request(r, UD(9), IORING_OP_WRITE, sizeof linked - 1);
    async_data(UD(9), "async.payload.input", linked, sizeof linked - 1);
    request(r, UD(10), IORING_OP_READ, sizeof link_in);
    async_data(UD(10), "async.payload.output", link_in, sizeof link_in);
    why("IOSQE_IO_LINK orders the read after the write");
    DONE();
    if (memcmp(link_in, linked, sizeof link_in) != 0)
        ora_fail("io_uring linked read output");

    // A request that fails at issue, and one the kernel refuses to accept.
    sqe = ring_sqe(r, IORING_OP_READ, UD(11));
    sqe->fd = 999;
    sqe->addr = (uintptr_t)in;
    sqe->len = sizeof in;
    enter_wait("io_uring_enter.read_badf", r, 1, 1);
    request(r, UD(11), IORING_OP_READ, -EBADF);
    why("descriptor 999 is closed: accepted, then completed with -EBADF");
    DONE();
    ring_sqe(r, BAD_OPCODE, UD(12));
    enter_wait("io_uring_enter.bad_opcode", r, 1, 1);
    request(r, UD(12), BAD_OPCODE, -EINVAL);
    why("an unknown opcode is rejected at submission (stage 3) and completed with -EINVAL");
    DONE();

    // OPENAT, then CLOSE of the descriptor it returned, then STATX.
    sqe = ring_sqe(r, IORING_OP_OPENAT, UD(13));
    sqe->fd = AT_FDCWD;
    sqe->addr = (uintptr_t) "uring-open";
    sqe->open_flags = O_CREAT | O_RDWR;
    sqe->len = 0600;
    enter_wait("io_uring_enter.openat", r, 1, 1);
    int opened = -1;
    if (take(r, UD(13), &result)) {
        opened = result;
        async_req(UD(13), IORING_OP_OPENAT, result);
        if (result < 0)
            ora_fail("io_uring openat");
    } else {
        ora_fail("io_uring openat has no completion");
    }
    async_data(UD(13), "async.operand.path", "uring-open", sizeof "uring-open");
    why("O_CREAT forces the open onto an io-wq worker; the result is the new descriptor");
    DONE();
    if (opened >= 0) {
        sqe = ring_sqe(r, IORING_OP_CLOSE, UD(14));
        sqe->fd = opened;
        enter_wait("io_uring_enter.close", r, 1, 1);
        request(r, UD(14), IORING_OP_CLOSE, 0);
        DONE();
    }

    memset(&stx, 0, sizeof stx);
    sqe = ring_sqe(r, IORING_OP_STATX, UD(15));
    sqe->fd = AT_FDCWD;
    sqe->addr = (uintptr_t) "uring-file";
    sqe->statx_flags = 0;
    sqe->len = STATX_BASIC_STATS;
    sqe->off = (uintptr_t)&stx;
    enter_wait("io_uring_enter.statx", r, 1, 1);
    request(r, UD(15), IORING_OP_STATX, 0);
    async_data(UD(15), "async.operand.path", "uring-file", sizeof "uring-file");
    async_data(UD(15), "async.operand.statx", &stx, sizeof stx);
    why("STATX runs on an io-wq worker of this process; its output is read there");
    DONE();
}

static void socket_cases(struct ring *r)
{
    int sv[2] = {-1, -1};
    unsigned char message[32], got[64];
    struct io_uring_sqe *sqe;

    long ret = CALL("socketpair.uring", socketpair, WANT_OK, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
                    0, sv);
    if (ret == 0)
        out_key("arg3.socketpair", sv, sizeof sv);
    DONE();
    if (ret != 0)
        return;
    pattern(message, sizeof message, 14);
    sqe = ring_sqe(r, IORING_OP_SEND, UD(16));
    sqe->fd = sv[0];
    sqe->addr = (uintptr_t)message;
    sqe->len = sizeof message;
    enter_wait("io_uring_enter.send", r, 1, 1);
    request(r, UD(16), IORING_OP_SEND, sizeof message);
    async_data(UD(16), "async.payload.input", message, sizeof message);
    DONE();

    memset(got, 0, sizeof got);
    sqe = ring_sqe(r, IORING_OP_RECV, UD(17));
    sqe->fd = sv[1];
    sqe->addr = (uintptr_t)got;
    sqe->len = sizeof got;
    enter_wait("io_uring_enter.recv", r, 1, 1);
    request(r, UD(17), IORING_OP_RECV, sizeof message);
    async_data(UD(17), "async.payload.output", got, sizeof message);
    why("the 32 queued bytes are ready, so the 64-byte receive returns them at once");
    DONE();
    if (memcmp(got, message, sizeof message) != 0)
        ora_fail("io_uring recv output");
    CASE("close.uring_socket0", close, WANT_OK, sv[0]);
    CASE("close.uring_socket1", close, WANT_OK, sv[1]);
}

static void timeout_cases(struct ring *r)
{
    struct __kernel_timespec expire = {0, 20 * 1000 * 1000}, ten = {10, 0};
    struct io_uring_sqe *sqe;

    sqe = ring_sqe(r, IORING_OP_TIMEOUT, UD(18));
    sqe->addr = (uintptr_t)&expire;
    sqe->len = 1;
    sqe->off = 0;
    enter_wait("io_uring_enter.timeout_expires", r, 1, 1);
    request(r, UD(18), IORING_OP_TIMEOUT, -ETIME);
    async_data(UD(18), "async.operand.timeout", &expire, sizeof expire);
    why("a pure 20 ms timeout completes with -ETIME");
    DONE();

    sqe = ring_sqe(r, IORING_OP_TIMEOUT, UD(19));
    sqe->addr = (uintptr_t)&ten;
    sqe->len = 1;
    ring_publish(r);
    CALL("io_uring_enter.submit_timeout", io_uring_enter, WANT_OK, r->fd, 1, 0, 0, 0, 0);
    request_later(UD(19), IORING_OP_TIMEOUT, -ECANCELED);
    async_data(UD(19), "async.operand.timeout", &ten, sizeof ten);
    why("a 10 s timeout, canceled by the next request (stage 5)");
    DONE();
    sqe = ring_sqe(r, IORING_OP_ASYNC_CANCEL, UD(20));
    sqe->addr = UD(19);
    enter_wait("io_uring_enter.async_cancel", r, 1, 2);
    request(r, UD(20), IORING_OP_ASYNC_CANCEL, 0);
    why("ASYNC_CANCEL by user_data finds the timeout; both complete before the wait ends");
    DONE();
    check_later(r);
}

static void poll_case(struct ring *r)
{
    int fds[2] = {-1, -1};
    struct io_uring_sqe *sqe;

    long ret = CALL("pipe2.uring_poll", pipe2, WANT_OK, fds, O_CLOEXEC);
    if (ret == 0)
        out_buf(0, fds, sizeof fds);
    DONE();
    if (ret != 0)
        return;
    CALL("write.uring_poll_pipe", write, WANT_OK, fds[1], "P", 1);
    in_buf(1, "P", 1);
    DONE();
    sqe = ring_sqe(r, IORING_OP_POLL_ADD, UD(21));
    sqe->fd = fds[0];
    sqe->poll32_events = POLLIN;
    enter_wait("io_uring_enter.poll_ready", r, 1, 1);
    request(r, UD(21), IORING_OP_POLL_ADD, POLLIN);
    why("the pipe holds a byte, so the poll completes at once with POLLIN");
    DONE();
    CASE("close.uring_pipe_read", close, WANT_OK, fds[0]);
    CASE("close.uring_pipe_write", close, WANT_OK, fds[1]);
}

static void register_cases(struct ring *r)
{
    unsigned char probe[sizeof(struct io_uring_probe) + 16 * sizeof(struct io_uring_probe_op)];
    unsigned char probe_in[sizeof probe];
    unsigned char fixed_out[8];
    struct io_uring_sqe *sqe;
    struct iovec registered;
    void *memory = NULL;
    int files[1];
    long ret;

    memset(probe, 0, sizeof probe);
    memcpy(probe_in, probe, sizeof probe);
    CALL("io_uring_register.probe", io_uring_register, WANT_OK, r->fd, IORING_REGISTER_PROBE,
         probe, 16);
    in_key("arg2.probe", probe_in, sizeof probe_in);
    out_key("arg2.probe", probe, sizeof probe);
    why("16 probe entries: the kernel fills the first 16 opcodes' support flags");
    DONE();
    CALL("io_uring_register.probe_fault", io_uring_register, EFAULT, r->fd, IORING_REGISTER_PROBE,
         1, 16);
    want_key_status("arg2.probe", "COPY_FAULT");
    why("an unmapped probe buffer: the kernel and the recorder both fault");
    DONE();

    if (posix_memalign(&memory, 4096, 4096) != 0) {
        ora_fail("io_uring registered buffer");
        return;
    }
    unsigned char *buffer = memory;
    pattern(buffer, 2048, 15);
    memset(buffer + 2048, 0, 2048);
    registered = (struct iovec){buffer, 4096};
    ret = CALL("io_uring_register.buffers", io_uring_register, WANT_OK, r->fd,
               IORING_REGISTER_BUFFERS, &registered, 1);
    in_key("arg2.register", &registered, sizeof registered);
    volatile_case();
    DONE();
    if (ret == 0) {
        CALL("io_uring_register.buffers_busy", io_uring_register, EBUSY, r->fd,
             IORING_REGISTER_BUFFERS, &registered, 1);
        in_key("arg2.register", &registered, sizeof registered);
        why("a ring holds one buffer table: a second registration is refused");
        volatile_case();
        DONE();

        sqe = ring_sqe(r, IORING_OP_WRITE_FIXED, UD(22));
        sqe->fd = data_file;
        sqe->addr = (uintptr_t)buffer;
        sqe->len = 2048;
        sqe->off = 4096;
        sqe->buf_index = 0;
        enter_wait("io_uring_enter.write_fixed", r, 1, 1);
        request(r, UD(22), IORING_OP_WRITE_FIXED, 2048);
        async_data(UD(22), "async.payload.input", buffer, 2048);
        DONE();
        sqe = ring_sqe(r, IORING_OP_READ_FIXED, UD(23));
        sqe->fd = data_file;
        sqe->addr = (uintptr_t)(buffer + 2048);
        sqe->len = 2048;
        sqe->off = 4096;
        sqe->buf_index = 0;
        enter_wait("io_uring_enter.read_fixed", r, 1, 1);
        request(r, UD(23), IORING_OP_READ_FIXED, 2048);
        async_data(UD(23), "async.payload.output", buffer + 2048, 2048);
        why("reads back the block the fixed write stored, into the buffer's second half");
        DONE();
        if (memcmp(buffer + 2048, buffer, 2048) != 0)
            ora_fail("io_uring fixed read output");
        CASE("io_uring_register.unregister_buffers", io_uring_register, WANT_OK, r->fd,
             IORING_UNREGISTER_BUFFERS, 0, 0);
    }
    free(memory);

    files[0] = data_file;
    ret = CALL("io_uring_register.files", io_uring_register, WANT_OK, r->fd, IORING_REGISTER_FILES,
               files, 1);
    in_key("arg2.register", files, sizeof files);
    DONE();
    if (ret == 0) {
        pattern(fixed_out, sizeof fixed_out, 16);
        sqe = ring_sqe(r, IORING_OP_WRITE, UD(24));
        sqe->fd = 0;
        sqe->flags = IOSQE_FIXED_FILE;
        sqe->addr = (uintptr_t)fixed_out;
        sqe->len = sizeof fixed_out;
        sqe->off = 8192;
        enter_wait("io_uring_enter.write_fixed_file", r, 1, 1);
        request(r, UD(24), IORING_OP_WRITE, sizeof fixed_out);
        async_data(UD(24), "async.payload.input", fixed_out, sizeof fixed_out);
        why("IOSQE_FIXED_FILE: sqe->fd 0 is slot 0 of the registered file table");
        DONE();
        CASE("io_uring_register.unregister_files", io_uring_register, WANT_OK, r->fd,
             IORING_UNREGISTER_FILES, 0, 0);
    }
    CASE("io_uring_register.unregister_files_none", io_uring_register, ENXIO, r->fd,
         IORING_UNREGISTER_FILES, 0, 0);

    unsigned char dummy[16];
    memset(dummy, 0, sizeof dummy);
    CALL("io_uring_register.bad_opcode", io_uring_register, EINVAL, r->fd, BAD_REGISTER_OPCODE,
         dummy, 0);
    want_key_status("arg2.register_variant", "NO_DECODER");
    why("an unknown register opcode: refused, recorded as an undecoded variant");
    DONE();
    CASE("io_uring_register.badf", io_uring_register, EBADF, 999, IORING_UNREGISTER_BUFFERS, 0,
         0);
}

void area_uring(void)
{
    struct ring r;

    seen_count = 0;
    later_count = 0;
    wait_ts = (struct __kernel_timespec){5, 0};
    short_ts = (struct __kernel_timespec){0, 10 * 1000 * 1000};
    memset(&wait_arg, 0, sizeof wait_arg);
    wait_arg.ts = (uintptr_t)&wait_ts;
    memset(&short_arg, 0, sizeof short_arg);
    short_arg.ts = (uintptr_t)&short_ts;

    setup_cases();
    if (ring_setup("io_uring_setup.default", &r, 16, 0, 0) < 0)
        return;
    enter_cases(&r);
    file_cases(&r);
    socket_cases(&r);
    timeout_cases(&r);
    poll_case(&r);
    if (data_file >= 0)
        register_cases(&r);
    ring_unmap(&r);
    CASE("close.ring", close, WANT_OK, r.fd);
    if (data_file >= 0)
        CASE("close.uring_file", close, WANT_OK, data_file);
    data_file = -1;
    unlink("uring-file");
    unlink("uring-open");
}
