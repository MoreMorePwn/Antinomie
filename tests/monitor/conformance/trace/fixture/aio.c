// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// aio.c — Linux native AIO: contexts, submission, completion, cancellation.
//
// Slots: io_setup io_destroy io_submit io_getevents io_pgetevents io_cancel.
//
// Async requests. Every request an io_submit case hands to the kernel is
// reported on that case with async_req(aio_data, opcode, result), where
// result is what the request's completion event reports (or the negative
// errno of a request the kernel rejected at submission). The completion is
// reaped later, by its own io_getevents/io_pgetevents case, so the result
// declared on the submission is the one the case means; the reaping code
// checks the event it received and fails the fixture on a mismatch. Payload
// bytes are declared with async_data(): "async.payload.input" for writes (the
// bytes handed to the kernel), "async.payload.output" for reads (the bytes
// the file holds, checked against the buffer after the reap). An O_DIRECT
// read on a block device completes in interrupt context; its output is then
// recorded at reap time (stage 7, contract 14.2) under the same key.
#include "areas.h"

#include <fcntl.h>
#include <linux/aio_abi.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>

#define AIO_UD(n) (0xA10F000000000000ULL + (n))
#define BLOCK 4096
#define BLOCKS 8

// struct __aio_sigset (fs/aio.c): the sixth io_pgetevents argument.
struct aio_sigset {
    const void *sigmask;
    size_t sigsetsize;
};

static aio_context_t context;
static int data_fd = -1;
static unsigned char *blocks;

static unsigned char *block(int index)
{
    return blocks + (size_t)index * BLOCK;
}

static void prep(struct iocb *cb, uint64_t user_data, int opcode, int fd, const void *buffer,
                 uint64_t length, int64_t offset)
{
    memset(cb, 0, sizeof *cb);
    cb->aio_data = user_data;
    cb->aio_lio_opcode = (uint16_t)opcode;
    cb->aio_fildes = (uint32_t)fd;
    cb->aio_buf = (uint64_t)(uintptr_t)buffer;
    cb->aio_nbytes = length;
    cb->aio_offset = offset;
}

// The recorder's io_submit capture (async_capture.c aio_submission): the
// pointer array, each pointer, each iocb, and per opcode its iovec array,
// its write payload, or an unobserved read destination.
static void describe_submit(long nr, struct iocb *const *list)
{
    char key[64];

    in_key("arg2.iocbpp", list, (size_t)nr * sizeof list[0]);
    for (long i = 0; i < nr; i++) {
        const struct iocb *cb = list[i];
        snprintf(key, sizeof key, "arg2.iocbpp[%ld]", i);
        in_key(key, &list[i], sizeof list[i]);
        snprintf(key, sizeof key, "arg2.iocb[%ld]", i);
        in_key(key, cb, sizeof *cb);
        switch (cb->aio_lio_opcode) {
        case IOCB_CMD_PREADV:
        case IOCB_CMD_PWRITEV:
            snprintf(key, sizeof key, "arg2.iocb[%ld].iov", i);
            in_key(key, (const void *)(uintptr_t)cb->aio_buf,
                   (size_t)cb->aio_nbytes * sizeof(struct iovec));
            break;
        case IOCB_CMD_PWRITE:
            snprintf(key, sizeof key, "arg2.iocb[%ld].input", i);
            in_key(key, (const void *)(uintptr_t)cb->aio_buf, (size_t)cb->aio_nbytes);
            break;
        case IOCB_CMD_PREAD:
            snprintf(key, sizeof key, "arg2.iocb[%ld].output", i);
            want_key_status(key, "ASYNC_UNOBSERVED");
            break;
        case IOCB_CMD_FSYNC:
        case IOCB_CMD_FDSYNC:
        case IOCB_CMD_POLL:
            break;
        default:
            snprintf(key, sizeof key, "arg2.iocb[%ld].variant", i);
            want_key_status(key, "NO_DECODER");
            break;
        }
    }
    // iocb pointers and buffer addresses differ between runs.
    volatile_case();
}

// The event for user_data among the reaped ones must report `result`.
static void check_event(const struct io_event *events, long count, uint64_t user_data,
                        long result)
{
    char text[160];
    for (long i = 0; i < count; i++) {
        if (events[i].data != user_data)
            continue;
        if (events[i].res != result) {
            snprintf(text, sizeof text, "aio request %#llx completed with %lld, wanted %ld",
                     (unsigned long long)user_data, (long long)events[i].res, result);
            ora_fail(text);
        }
        return;
    }
    snprintf(text, sizeof text, "aio request %#llx was not reaped", (unsigned long long)user_data);
    ora_fail(text);
}

static void check_bytes(const void *seen, const void *wanted, size_t len, const char *what)
{
    if (memcmp(seen, wanted, len) != 0)
        ora_fail(what);
}

// io_getevents bounded by a 5 s timeout; returns the number of events.
static long reap(const char *label, long min_nr, long nr, struct io_event *events)
{
    struct timespec timeout = {5, 0};
    memset(events, 0, (size_t)nr * sizeof *events);
    long got = CALL(label, io_getevents, WANT_OK, context, min_nr, nr, events, &timeout);
    in_key("arg4.timeout", &timeout, sizeof timeout);
    if (got > 0)
        out_key("arg3.events", events, (size_t)got * sizeof *events);
    volatile_case();
    DONE();
    if (got < min_nr)
        ora_fail("aio reap returned fewer events than it waited for");
    return got;
}

static int setup_cases(void)
{
    aio_context_t probe = 0;
    const aio_context_t zero = 0;

    CALL("io_setup.nr_zero", io_setup, EINVAL, 0, &probe);
    in_key("arg1.context_id", &zero, sizeof zero);
    DONE();
    probe = 1;
    CALL("io_setup.context_not_zero", io_setup, EINVAL, 4, &probe);
    in_key("arg1.context_id", &probe, sizeof probe);
    why("the context word must be zero on entry");
    DONE();
    CALL("io_setup.fault", io_setup, EFAULT, 4, 1);
    want_key_status("arg1.context_id", "COPY_FAULT");
    why("an address in the first page is never mapped: the kernel and the recorder both fault");
    DONE();

    context = 0;
    long ret = CALL("io_setup.sixteen", io_setup, WANT_OK, 16, &context);
    in_key("arg1.context_id", &zero, sizeof zero);
    if (ret == 0)
        out_key("arg1.context_id", &context, sizeof context);
    volatile_case();
    DONE();
    return ret == 0 ? 0 : -1;
}

static void open_data_file(void)
{
    long fd = CALL("openat.aio_direct", openat, WANT_ANY, AT_FDCWD, "aio-direct",
                   O_CREAT | O_RDWR | O_TRUNC | O_DIRECT | O_CLOEXEC, 0600);
    in_str(1, "aio-direct");
    why("O_DIRECT needs filesystem support (ext4 and tmpfs >= 6.6 have it); without it the "
        "area falls back to a buffered file");
    if (fd >= 0)
        file_fd("OPEN", (int)fd);
    DONE();
    if (fd < 0) {
        fd = CALL("openat.aio_buffered", openat, WANT_OK, AT_FDCWD, "aio-direct",
                  O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
        in_str(1, "aio-direct");
        if (fd >= 0)
            file_fd("OPEN", (int)fd);
        DONE();
    }
    data_fd = (int)fd;
}

// Submissions the kernel refuses, before or at the first request.
static void submit_failure_cases(void)
{
    struct iocb cb;
    struct iocb *list[1] = {&cb};

    prep(&cb, AIO_UD(0x80), IOCB_CMD_PWRITE, data_fd, block(0), BLOCK, 0);
    CALL("io_submit.bad_context", io_submit, EINVAL, 0, 1, list);
    describe_submit(1, list);
    why("context 0 is never a valid AIO context: no request reaches the kernel");
    DONE();

    CALL("io_submit.negative_nr", io_submit, EINVAL, context, -1, list);
    want_key_status("arg2.iocbpp", "INVALID_EXTENT");
    why("a negative count is rejected; the recorder cannot size the pointer array");
    DONE();

    CALL("io_submit.zero_nr", io_submit, WANT_OK, context, 0, list);
    describe_submit(0, list);
    DONE();

    CALL("io_submit.fault", io_submit, EFAULT, context, 1, 1);
    want_key_status("arg2.iocbpp", "COPY_FAULT");
    want_key_status("arg2.iocbpp[0]", "COPY_FAULT");
    why("an unmapped pointer array: the kernel and the recorder both fault");
    DONE();

    prep(&cb, AIO_UD(0x81), IOCB_CMD_FSYNC, 999, NULL, 0, 0);
    CALL("io_submit.badf", io_submit, EBADF, context, 1, list);
    describe_submit(1, list);
    async_req(AIO_UD(0x81), IOCB_CMD_FSYNC, -EBADF);
    why("descriptor 999 is closed: the request is rejected (stage 3) and io_submit returns its "
        "error because it is the first one; FSYNC carries no payload, so the rejection leaves no "
        "payload gap");
    DONE();

    prep(&cb, AIO_UD(0x82), 99, data_fd, block(0), BLOCK, 0);
    CALL("io_submit.bad_opcode", io_submit, EINVAL, context, 1, list);
    describe_submit(1, list);
    async_req(AIO_UD(0x82), 99, -EINVAL);
    why("opcode 99 is no IOCB_CMD: rejected at submission, recorded as an undecoded variant");
    DONE();
}

static void read_write_cases(void)
{
    struct iocb write_cb, read_cb, vector_cb, second_cb, readv_cb;
    struct iocb *list[2];
    struct io_event events[4];
    struct iovec out_vec[2], in_vec[2];
    uint64_t mask;
    struct aio_sigset sigset;
    struct timespec timeout = {5, 0};
    long got;

    // PWRITE of one block at offset 0.
    pattern(block(0), BLOCK, 1);
    prep(&write_cb, AIO_UD(1), IOCB_CMD_PWRITE, data_fd, block(0), BLOCK, 0);
    list[0] = &write_cb;
    CALL("io_submit.pwrite", io_submit, WANT_OK, context, 1, list);
    describe_submit(1, list);
    async_req(AIO_UD(1), IOCB_CMD_PWRITE, BLOCK);
    async_data(AIO_UD(1), "async.payload.input", block(0), BLOCK);
    DONE();
    got = reap("io_getevents.one", 1, 4, events);
    check_event(events, got, AIO_UD(1), BLOCK);

    // PREAD of that block, reaped with io_pgetevents and a signal mask.
    memset(block(1), 0, BLOCK);
    prep(&read_cb, AIO_UD(2), IOCB_CMD_PREAD, data_fd, block(1), BLOCK, 0);
    list[0] = &read_cb;
    CALL("io_submit.pread", io_submit, WANT_OK, context, 1, list);
    describe_submit(1, list);
    async_req(AIO_UD(2), IOCB_CMD_PREAD, BLOCK);
    async_data(AIO_UD(2), "async.payload.output", block(0), BLOCK);
    why("an O_DIRECT read may complete in interrupt context: its output is then recorded when "
        "io_pgetevents reaps it (stage 7)");
    DONE();
    mask = 1ULL << (SIGUSR2 - 1);
    sigset.sigmask = &mask;
    sigset.sigsetsize = sizeof mask;
    memset(events, 0, sizeof events);
    got = CALL("io_pgetevents.sigmask", io_pgetevents, WANT_OK, context, 1, 4, events, &timeout,
               &sigset);
    in_key("arg4.timeout", &timeout, sizeof timeout);
    in_key("arg5.sigset", &sigset, sizeof sigset);
    in_key("signal.mask", &mask, sizeof mask);
    if (got > 0)
        out_key("arg3.events", events, (size_t)got * sizeof events[0]);
    volatile_case();
    why("SIGUSR2 is blocked only for the duration of the wait");
    DONE();
    check_event(events, got, AIO_UD(2), BLOCK);
    check_bytes(block(1), block(0), BLOCK, "aio pread output");

    // Two requests in one call: a two-segment PWRITEV and a PWRITE.
    pattern(block(2), BLOCK, 2);
    pattern(block(3), BLOCK, 3);
    pattern(block(4), BLOCK, 4);
    out_vec[0] = (struct iovec){block(2), BLOCK};
    out_vec[1] = (struct iovec){block(3), BLOCK};
    prep(&vector_cb, AIO_UD(3), IOCB_CMD_PWRITEV, data_fd, out_vec, 2, 2 * BLOCK);
    prep(&second_cb, AIO_UD(4), IOCB_CMD_PWRITE, data_fd, block(4), BLOCK, 4 * BLOCK);
    list[0] = &vector_cb;
    list[1] = &second_cb;
    CALL("io_submit.pwritev_and_pwrite", io_submit, WANT_OK, context, 2, list);
    describe_submit(2, list);
    async_req(AIO_UD(3), IOCB_CMD_PWRITEV, 2 * BLOCK);
    async_data(AIO_UD(3), "async.payload.iov", out_vec, sizeof out_vec);
    async_data(AIO_UD(3), "async.payload.input", block(2), 2 * BLOCK);
    async_req(AIO_UD(4), IOCB_CMD_PWRITE, BLOCK);
    async_data(AIO_UD(4), "async.payload.input", block(4), BLOCK);
    why("two iocbs in one call; block(2) and block(3) are adjacent, so the vector input is one "
        "contiguous 8 KiB range");
    DONE();
    got = reap("io_getevents.two", 2, 4, events);
    check_event(events, got, AIO_UD(3), 2 * BLOCK);
    check_event(events, got, AIO_UD(4), BLOCK);

    // PREADV of the vector, in two segments.
    memset(block(5), 0, BLOCK);
    memset(block(6), 0, BLOCK);
    in_vec[0] = (struct iovec){block(5), BLOCK};
    in_vec[1] = (struct iovec){block(6), BLOCK};
    prep(&readv_cb, AIO_UD(5), IOCB_CMD_PREADV, data_fd, in_vec, 2, 2 * BLOCK);
    list[0] = &readv_cb;
    CALL("io_submit.preadv", io_submit, WANT_OK, context, 1, list);
    describe_submit(1, list);
    async_req(AIO_UD(5), IOCB_CMD_PREADV, 2 * BLOCK);
    async_data(AIO_UD(5), "async.payload.iov", in_vec, sizeof in_vec);
    async_data(AIO_UD(5), "async.payload.output", block(2), 2 * BLOCK);
    why("the output is the file's bytes in iovec order, at completion or at reap (contract "
        "15.3)");
    DONE();
    got = reap("io_getevents.preadv", 1, 4, events);
    check_event(events, got, AIO_UD(5), 2 * BLOCK);
    check_bytes(block(5), block(2), 2 * BLOCK, "aio preadv output");

    // FSYNC and FDSYNC: run on a kernel worker; refused on a filesystem
    // without fsync.
    struct iocb sync_cb, dsync_cb;
    prep(&sync_cb, AIO_UD(6), IOCB_CMD_FSYNC, data_fd, NULL, 0, 0);
    list[0] = &sync_cb;
    long fsync_ret = CALL("io_submit.fsync", io_submit, WANT_ANY, context, 1, list);
    int fsync_error = errno;
    describe_submit(1, list);
    async_req(AIO_UD(6), IOCB_CMD_FSYNC, fsync_ret == 1 ? 0 : -fsync_error);
    why("IOCB_CMD_FSYNC needs f_op->fsync (EINVAL without it); accepted, it completes with 0");
    DONE();
    prep(&dsync_cb, AIO_UD(7), IOCB_CMD_FDSYNC, data_fd, NULL, 0, 0);
    list[0] = &dsync_cb;
    long fdsync_ret = CALL("io_submit.fdsync", io_submit, WANT_ANY, context, 1, list);
    int fdsync_error = errno;
    describe_submit(1, list);
    async_req(AIO_UD(7), IOCB_CMD_FDSYNC, fdsync_ret == 1 ? 0 : -fdsync_error);
    why("IOCB_CMD_FDSYNC needs f_op->fsync (EINVAL without it); accepted, it completes with 0");
    DONE();
    long queued = (fsync_ret == 1) + (fdsync_ret == 1);
    if (queued) {
        got = reap("io_getevents.sync", queued, 4, events);
        if (fsync_ret == 1)
            check_event(events, got, AIO_UD(6), 0);
        if (fdsync_ret == 1)
            check_event(events, got, AIO_UD(7), 0);
    }

    // The completed PWRITE is no longer active: nothing to cancel.
    CALL("io_cancel.completed", io_cancel, EINVAL, context, &write_cb, events);
    in_key("arg1.iocb", &write_cb, sizeof write_cb);
    why("a request that already completed is not on the active list");
    DONE();
}

// A poll on an empty pipe stays pending until io_cancel removes it.
static void cancel_cases(void)
{
    int fds[2] = {-1, -1};
    struct iocb poll_cb;
    struct iocb *list[1] = {&poll_cb};
    struct io_event events[4], unused;

    long ret = CALL("pipe2.aio_poll", pipe2, WANT_OK, fds, O_CLOEXEC);
    if (ret == 0)
        out_buf(0, fds, sizeof fds);
    DONE();
    if (ret != 0)
        return;
    prep(&poll_cb, AIO_UD(8), IOCB_CMD_POLL, fds[0], (void *)(uintptr_t)POLLIN, 0, 0);
    CALL("io_submit.poll", io_submit, WANT_OK, context, 1, list);
    describe_submit(1, list);
    async_req(AIO_UD(8), IOCB_CMD_POLL, 0);
    why("the pipe is empty, so the poll stays pending; io_cancel ends it with an empty mask");
    DONE();
    memset(&unused, 0, sizeof unused);
    CALL("io_cancel.pending_poll", io_cancel, EINPROGRESS, context, &poll_cb, &unused);
    in_key("arg1.iocb", &poll_cb, sizeof poll_cb);
    why("a canceled poll is completed through the ring: io_cancel reports EINPROGRESS");
    DONE();
    long got = reap("io_getevents.canceled_poll", 1, 4, events);
    check_event(events, got, AIO_UD(8), 0);

    CALL("io_cancel.fault", io_cancel, EFAULT, context, 1, &unused);
    want_key_status("arg1.iocb", "COPY_FAULT");
    why("an unmapped iocb address: the kernel and the recorder both fault");
    DONE();

    CASE("close.aio_pipe_read", close, WANT_OK, fds[0]);
    CASE("close.aio_pipe_write", close, WANT_OK, fds[1]);
}

static void reap_variant_cases(void)
{
    struct io_event events[4];
    struct timespec timeout = {0, 1000000};
    uint64_t mask = 1ULL << (SIGUSR2 - 1);
    struct aio_sigset sigset = {&mask, 4};

    memset(events, 0, sizeof events);
    CALL("io_getevents.nonblocking", io_getevents, WANT_OK, context, 0, 4, events, NULL);
    why("min_nr 0 and no timeout: returns at once; nothing is in flight, so 0 events");
    DONE();
    CALL("io_getevents.bad_context", io_getevents, EINVAL, 0, 1, 4, events, &timeout);
    in_key("arg4.timeout", &timeout, sizeof timeout);
    DONE();
    CALL("io_getevents.min_above_nr", io_getevents, EINVAL, context, 4, 1, events, &timeout);
    in_key("arg4.timeout", &timeout, sizeof timeout);
    DONE();
    CALL("io_pgetevents.null_sigset", io_pgetevents, WANT_OK, context, 0, 4, events, &timeout,
         NULL);
    in_key("arg4.timeout", &timeout, sizeof timeout);
    why("no sigset: io_pgetevents behaves like io_getevents; nothing is in flight");
    DONE();
    CALL("io_pgetevents.bad_sigsetsize", io_pgetevents, EINVAL, context, 0, 4, events, &timeout,
         &sigset);
    in_key("arg4.timeout", &timeout, sizeof timeout);
    in_key("arg5.sigset", &sigset, sizeof sigset);
    want_key_status("signal.mask", "INVALID_EXTENT");
    why("sigsetsize 4 is not sizeof(sigset_t): the kernel refuses it and the recorder records "
        "the mask as an invalid extent");
    volatile_case();
    DONE();
}

void area_aio(void)
{
    void *memory = NULL;

    if (posix_memalign(&memory, BLOCK, (size_t)BLOCKS * BLOCK) != 0) {
        ora_fail("aio aligned buffers");
        return;
    }
    blocks = memory;
    memset(blocks, 0, (size_t)BLOCKS * BLOCK);
    if (setup_cases() == 0) {
        open_data_file();
        if (data_fd >= 0) {
            submit_failure_cases();
            read_write_cases();
            cancel_cases();
            reap_variant_cases();
        }
        CASE("io_destroy.context", io_destroy, WANT_OK, context);
        CASE("io_destroy.destroyed", io_destroy, EINVAL, context);
        if (data_fd >= 0)
            CASE("close.aio_direct", close, WANT_OK, data_fd);
        unlink("aio-direct");
    }
    CASE("io_destroy.bad_context", io_destroy, EINVAL, 0);
    free(blocks);
    blocks = NULL;
    data_fd = -1;
}
