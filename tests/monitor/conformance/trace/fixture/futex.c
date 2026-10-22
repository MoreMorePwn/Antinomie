// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// futex.c — the futex multiplexer and the futex2 calls.
//
// Slots: futex futex_waitv futex_wake futex_wait futex_requeue.
//
// Every wait is bounded by a timeout. Two real wait/wake pairs run across
// threads: the waiter blocks, the main thread sees it asleep in the call
// (/proc/self/task/TID/syscall) and then requeues or wakes it.
#include "areas.h"

#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef FUTEX2_SIZE_U32
#define FUTEX2_SIZE_U32 0x02
#endif
#ifndef FUTEX2_SIZE_U8
#define FUTEX2_SIZE_U8 0x00
#endif
#ifndef FUTEX2_PRIVATE
#define FUTEX2_PRIVATE FUTEX_PRIVATE_FLAG
#endif
#ifndef FUTEX_BITSET_MATCH_ANY
#define FUTEX_BITSET_MATCH_ANY 0xffffffffU
#endif

#define F2 (FUTEX2_SIZE_U32 | FUTEX2_PRIVATE)
#define UNMAPPED_WORD 0x1000 // aligned, below mmap_min_addr: never mapped

static uint32_t words[8] __attribute__((aligned(64)));

static struct timespec in_ms(clockid_t clock, long ms)
{
    struct timespec when;
    clock_gettime(clock, &when);
    when.tv_sec += ms / 1000;
    when.tv_nsec += (ms % 1000) * 1000000L;
    if (when.tv_nsec >= 1000000000L) {
        when.tv_sec++;
        when.tv_nsec -= 1000000000L;
    }
    return when;
}

static void sleep_ms(long ms)
{
    struct timespec delay = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR)
        ;
}

// Wait until thread `tid` of this process sleeps in system call `nr`.
static int wait_blocked(pid_t tid, long nr)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/self/task/%d/syscall", (int)tid);
    for (int round = 0; round < 1000; round++) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return 0;
        char text[64] = {0};
        ssize_t got = read(fd, text, sizeof text - 1);
        close(fd);
        if (got > 0 && text[0] >= '0' && text[0] <= '9' && strtol(text, NULL, 10) == nr)
            return 1;
        sleep_ms(2);
    }
    return 0;
}

static void classic_cases(void)
{
    uint32_t *word = &words[0], *second = &words[1];
    struct timespec ten_ms = {0, 10000000L}, bad = {0, 2000000000L};

    *word = 0;
    *second = 0;
    CALL("futex.wait_mismatch", futex, EAGAIN, word, FUTEX_WAIT, 1, NULL, NULL, 0);
    in_buf(0, word, sizeof *word);
    why("the word holds 0, the caller expects 1: no sleep");
    DONE();
    CALL("futex.wait_private_mismatch", futex, EAGAIN, word, FUTEX_WAIT_PRIVATE, 1, NULL, NULL,
         0);
    in_buf(0, word, sizeof *word);
    DONE();
    CALL("futex.wait_timeout", futex, ETIMEDOUT, word, FUTEX_WAIT, 0, &ten_ms, NULL, 0);
    in_buf(0, word, sizeof *word);
    in_buf(3, &ten_ms, sizeof ten_ms);
    why("nobody wakes the word: the relative 10 ms timeout expires");
    DONE();
    CALL("futex.wait_private_timeout", futex, ETIMEDOUT, word, FUTEX_WAIT_PRIVATE, 0, &ten_ms,
         NULL, 0);
    in_buf(0, word, sizeof *word);
    in_buf(3, &ten_ms, sizeof ten_ms);
    DONE();
    CALL("futex.wait_bad_timeout", futex, EINVAL, word, FUTEX_WAIT_PRIVATE, 0, &bad, NULL, 0);
    in_buf(0, word, sizeof *word);
    in_buf(3, &bad, sizeof bad);
    DONE();
    CALL("futex.wait_unaligned", futex, EINVAL, (char *)word + 1, FUTEX_WAIT_PRIVATE, 0, &ten_ms,
         NULL, 0);
    in_buf(0, (char *)word + 1, sizeof(uint32_t));
    in_buf(3, &ten_ms, sizeof ten_ms);
    why("a futex word must be 4-byte aligned; the recorder still reads the 4 bytes there");
    DONE();
    CALL("futex.wait_fault", futex, EFAULT, UNMAPPED_WORD, FUTEX_WAIT_PRIVATE, 0, &ten_ms, NULL,
         0);
    want_status(0, "in", "COPY_FAULT");
    in_buf(3, &ten_ms, sizeof ten_ms);
    DONE();

    CALL("futex.wake_none", futex, WANT_OK, word, FUTEX_WAKE, 1, NULL, NULL, 0);
    in_buf(0, word, sizeof *word);
    why("no waiter: wakes 0");
    DONE();
    CALL("futex.wake_private_all", futex, WANT_OK, word, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL,
         NULL, 0);
    in_buf(0, word, sizeof *word);
    DONE();
    CALL("futex.wake_clock_realtime", futex, ENOSYS, word, FUTEX_WAKE | FUTEX_CLOCK_REALTIME, 1,
         NULL, NULL, 0);
    in_buf(0, word, sizeof *word);
    why("FUTEX_CLOCK_REALTIME is accepted only with the waiting commands");
    DONE();

    // Bitset variants: absolute timeouts on CLOCK_MONOTONIC and CLOCK_REALTIME.
    struct timespec deadline = in_ms(CLOCK_MONOTONIC, 10);
    CALL("futex.wait_bitset_monotonic", futex, ETIMEDOUT, word, FUTEX_WAIT_BITSET_PRIVATE, 0,
         &deadline, NULL, 0x0f);
    in_buf(0, word, sizeof *word);
    in_any(3);
    why("an absolute CLOCK_MONOTONIC deadline 10 ms ahead");
    DONE();
    deadline = in_ms(CLOCK_REALTIME, 10);
    CALL("futex.wait_bitset_realtime", futex, ETIMEDOUT, word,
         FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME, 0, &deadline, NULL, FUTEX_BITSET_MATCH_ANY);
    in_buf(0, word, sizeof *word);
    in_any(3);
    why("an absolute CLOCK_REALTIME deadline 10 ms ahead");
    DONE();
    CALL("futex.wait_bitset_zero", futex, EINVAL, word, FUTEX_WAIT_BITSET_PRIVATE, 0, NULL, NULL,
         0);
    in_buf(0, word, sizeof *word);
    why("an empty bitset is rejected before any sleep");
    DONE();
    CALL("futex.wake_bitset", futex, WANT_OK, word, FUTEX_WAKE_BITSET_PRIVATE, 1, NULL, NULL,
         0xf0);
    in_buf(0, word, sizeof *word);
    DONE();

    // Requeue: no waiters, so nothing moves; the compare variant checks *word.
    CALL("futex.requeue", futex, WANT_OK, word, FUTEX_REQUEUE_PRIVATE, 1, 1, second, 0);
    in_buf(0, word, sizeof *word);
    in_buf(4, second, sizeof *second);
    why("arg3 is the requeue count, not a timeout");
    DONE();
    CALL("futex.cmp_requeue", futex, WANT_OK, word, FUTEX_CMP_REQUEUE, 1, 1, second, 0);
    in_buf(0, word, sizeof *word);
    in_buf(4, second, sizeof *second);
    DONE();
    CALL("futex.cmp_requeue_mismatch", futex, EAGAIN, word, FUTEX_CMP_REQUEUE_PRIVATE, 1, 1,
         second, 5);
    in_buf(0, word, sizeof *word);
    in_buf(4, second, sizeof *second);
    why("val3 5 does not match the word's 0");
    DONE();

    // WAKE_OP: *second += 1, then wake on the old value comparing equal to 0.
    uint32_t first_before = *word, second_before = *second;
    CALL("futex.wake_op_add", futex, WANT_OK, word, FUTEX_WAKE_OP_PRIVATE, 1, 1, second,
         FUTEX_OP(FUTEX_OP_ADD, 1, FUTEX_OP_CMP_EQ, 0));
    in_buf(0, &first_before, sizeof first_before);
    in_buf(4, &second_before, sizeof second_before);
    out_buf(0, word, sizeof *word);
    out_buf(4, second, sizeof *second);
    why("WAKE_OP writes the second word; both words are read back at exit");
    DONE();
    if (*second != second_before + 1)
        ora_fail("futex: WAKE_OP did not add to the second word");

    // Priority-inheritance lock on an unowned word, then errors on it.
    uint32_t *pi = &words[2];
    *pi = 0;
    CALL("futex.lock_pi_unowned", futex, WANT_OK, pi, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    in_buf(0, &(uint32_t){0}, sizeof(uint32_t));
    out_buf(0, pi, sizeof *pi);
    volatile_case();
    why("the kernel stores the caller's tid in the word");
    DONE();
    if ((*pi & FUTEX_TID_MASK) != (uint32_t)gettid())
        ora_fail("futex: LOCK_PI did not take the word");
    uint32_t owned = *pi;
    CALL("futex.lock_pi_deadlock", futex, EDEADLK, pi, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    in_buf(0, &owned, sizeof owned);
    volatile_case();
    DONE();
    CALL("futex.trylock_pi_deadlock", futex, EDEADLK, pi, FUTEX_TRYLOCK_PI, 0, NULL, NULL, 0);
    in_buf(0, &owned, sizeof owned);
    volatile_case();
    DONE();
    CALL("futex.unlock_pi", futex, WANT_OK, pi, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    in_buf(0, &owned, sizeof owned);
    out_buf(0, pi, sizeof *pi);
    volatile_case();
    DONE();
    CALL("futex.unlock_pi_unowned", futex, EPERM, pi, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    in_buf(0, pi, sizeof *pi);
    DONE();
    deadline = in_ms(CLOCK_REALTIME, 1000);
    CALL("futex.lock_pi_private_timeout", futex, WANT_OK, pi, FUTEX_LOCK_PI_PRIVATE, 0, &deadline,
         NULL, 0);
    in_buf(0, &(uint32_t){0}, sizeof(uint32_t));
    in_any(3);
    out_buf(0, pi, sizeof *pi);
    volatile_case();
    why("the word is free: taken at once, the absolute CLOCK_REALTIME timeout is unused");
    DONE();
    owned = *pi;
    CALL("futex.unlock_pi_private", futex, WANT_OK, pi, FUTEX_UNLOCK_PI_PRIVATE, 0, NULL, NULL,
         0);
    in_buf(0, &owned, sizeof owned);
    out_buf(0, pi, sizeof *pi);
    volatile_case();
    DONE();

    CALL("futex.bad_op", futex, ENOSYS, word, 0x7f, 0, NULL, NULL, 0);
    want_key_status("futex.unknown_selector", "NO_DECODER");
    why("an unknown command is recorded as an explicit selector gap");
    DONE();
}

static void futex2_cases(void)
{
    uint32_t *word = &words[4], *other = &words[5];
    *word = 0;
    *other = 0;
    struct futex_waitv one[1], two[2];
    struct timespec deadline;

    memset(one, 0, sizeof one);
    one[0].val = 1;
    one[0].uaddr = (uintptr_t)word;
    one[0].flags = F2;
    deadline = in_ms(CLOCK_MONOTONIC, 1000);
    CALL("futex_waitv.mismatch", futex_waitv, EAGAIN, one, 1, 0, &deadline, CLOCK_MONOTONIC);
    in_key("arg0.waiters", one, sizeof one);
    in_key("arg0.waiters.0.futex.observed", word, sizeof *word);
    in_any(3);
    why("the word holds 0, the waiter expects 1: no sleep");
    DONE();

    memset(two, 0, sizeof two);
    two[0].val = 0;
    two[0].uaddr = (uintptr_t)word;
    two[0].flags = F2;
    two[1].val = 0;
    two[1].uaddr = (uintptr_t)other;
    two[1].flags = F2;
    deadline = in_ms(CLOCK_MONOTONIC, 10);
    CALL("futex_waitv.timeout", futex_waitv, ETIMEDOUT, two, 2, 0, &deadline, CLOCK_MONOTONIC);
    in_key("arg0.waiters", two, sizeof two);
    in_key("arg0.waiters.0.futex.observed", word, sizeof *word);
    in_key("arg0.waiters.1.futex.observed", other, sizeof *other);
    in_any(3);
    why("both words match and nobody wakes them: the absolute 10 ms deadline expires");
    DONE();
    one[0].val = 0;
    deadline = in_ms(CLOCK_REALTIME, 10);
    CALL("futex_waitv.realtime_timeout", futex_waitv, ETIMEDOUT, one, 1, 0, &deadline,
         CLOCK_REALTIME);
    in_key("arg0.waiters", one, sizeof one);
    in_key("arg0.waiters.0.futex.observed", word, sizeof *word);
    in_any(3);
    DONE();
    CALL("futex_waitv.zero_count", futex_waitv, EINVAL, one, 0, 0, NULL, 0);
    want_status(0, "in", "INVALID_EXTENT");
    DONE();
    CALL("futex_waitv.bad_flags", futex_waitv, EINVAL, one, 1, 1, NULL, 0);
    in_key("arg0.waiters", one, sizeof one);
    in_key("arg0.waiters.0.futex.observed", word, sizeof *word);
    why("the syscall flags argument must be 0");
    DONE();
    deadline = in_ms(CLOCK_MONOTONIC, 10);
    CALL("futex_waitv.bad_clock", futex_waitv, EINVAL, one, 1, 0, &deadline,
         CLOCK_PROCESS_CPUTIME_ID);
    in_key("arg0.waiters", one, sizeof one);
    in_key("arg0.waiters.0.futex.observed", word, sizeof *word);
    in_any(3);
    DONE();
    struct futex_waitv reserved[1];
    memcpy(reserved, one, sizeof reserved);
    reserved[0].__reserved = 1;
    CALL("futex_waitv.reserved_set", futex_waitv, EINVAL, reserved, 1, 0, NULL, 0);
    in_key("arg0.waiters", reserved, sizeof reserved);
    want_key_status("arg0.waiters.0.futex.observed", "INVALID_EXTENT");
    why("a nonzero reserved word is rejected; the recorder does not read the futex word");
    DONE();
    struct futex_waitv unknown[1];
    memcpy(unknown, one, sizeof unknown);
    unknown[0].flags = F2 | 0x40;
    CALL("futex_waitv.unknown_waiter_flag", futex_waitv, EINVAL, unknown, 1, 0, NULL, 0);
    in_key("arg0.waiters", unknown, sizeof unknown);
    want_key_status("arg0.waiters.0.futex.observed", "NO_DECODER");
    DONE();

    CALL("futex_wake.none", futex_wake, WANT_OK, word, FUTEX_BITSET_MATCH_ANY, 1, F2);
    in_buf(0, word, sizeof *word);
    why("no waiter: wakes 0");
    DONE();
    CALL("futex_wake.shared", futex_wake, WANT_OK, word, 0x3, 0x7fffffff, FUTEX2_SIZE_U32);
    in_buf(0, word, sizeof *word);
    DONE();
    CALL("futex_wake.size_u8", futex_wake, EINVAL, word, FUTEX_BITSET_MATCH_ANY, 1,
         FUTEX2_SIZE_U8 | FUTEX2_PRIVATE);
    want_status(0, "in", "INVALID_EXTENT");
    why("only 32-bit futex words exist; the recorder marks the size invalid");
    DONE();
    CALL("futex_wake.zero_mask", futex_wake, EINVAL, word, 0, 1, F2);
    in_buf(0, word, sizeof *word);
    DONE();

    deadline = in_ms(CLOCK_MONOTONIC, 1000);
    CALL("futex_wait.mismatch", futex_wait, EAGAIN, word, 1, FUTEX_BITSET_MATCH_ANY, F2, &deadline,
         CLOCK_MONOTONIC);
    in_buf(0, word, sizeof *word);
    in_any(4);
    DONE();
    deadline = in_ms(CLOCK_MONOTONIC, 10);
    CALL("futex_wait.timeout", futex_wait, ETIMEDOUT, word, 0, FUTEX_BITSET_MATCH_ANY, F2,
         &deadline, CLOCK_MONOTONIC);
    in_buf(0, word, sizeof *word);
    in_any(4);
    why("an absolute CLOCK_MONOTONIC deadline 10 ms ahead");
    DONE();
    CALL("futex_wait.value_too_wide", futex_wait, EINVAL, word, 1ULL << 32, FUTEX_BITSET_MATCH_ANY,
         F2, NULL, 0);
    in_buf(0, word, sizeof *word);
    why("a value wider than the 32-bit word is rejected");
    DONE();
    CALL("futex_wait.unknown_flag", futex_wait, EINVAL, word, 0, FUTEX_BITSET_MATCH_ANY,
         F2 | 0x40, NULL, 0);
    in_buf(0, word, sizeof *word);
    DONE();

    memset(two, 0, sizeof two);
    two[0].val = 0;
    two[0].uaddr = (uintptr_t)word;
    two[0].flags = F2;
    two[1].val = 0;
    two[1].uaddr = (uintptr_t)other;
    two[1].flags = F2;
    CALL("futex_requeue.none", futex_requeue, WANT_OK, two, 0, 1, 1);
    in_key("arg0.waiters", two, sizeof two);
    in_key("arg0.waiters.0.futex.observed", word, sizeof *word);
    in_key("arg0.waiters.1.futex.observed", other, sizeof *other);
    why("no waiter: nothing woken or moved");
    DONE();
    two[0].val = 7;
    CALL("futex_requeue.mismatch", futex_requeue, EAGAIN, two, 0, 1, 1);
    in_key("arg0.waiters", two, sizeof two);
    in_key("arg0.waiters.0.futex.observed", word, sizeof *word);
    in_key("arg0.waiters.1.futex.observed", other, sizeof *other);
    why("waiters[0].val is compared with the first word");
    DONE();
    two[0].val = 0;
    CALL("futex_requeue.bad_flags", futex_requeue, EINVAL, two, 1, 1, 1);
    in_key("arg0.waiters", two, sizeof two);
    in_key("arg0.waiters.0.futex.observed", word, sizeof *word);
    in_key("arg0.waiters.1.futex.observed", other, sizeof *other);
    DONE();
}

// ---------------------------------------------------------------------------
// Real wait/wake pairs across two threads.

struct waiter {
    uint32_t *word;
    volatile pid_t tid;
    int kind; // 0: futex FUTEX_WAIT_PRIVATE, 1: futex_wait
};

static void *waiter_main(void *arg)
{
    struct waiter *w = arg;
    w->tid = gettid();
    if (w->kind == 0) {
        struct timespec bound = {3, 0};
        CALL("futex.wait_woken_by_requeue", futex, WANT_OK, w->word, FUTEX_WAIT_PRIVATE, 0, &bound,
             NULL, 0);
        in_buf(0, &(uint32_t){0}, sizeof(uint32_t));
        in_buf(3, &bound, sizeof bound);
        why("the main thread requeues this waiter to a second word and wakes it there; the 3 s "
            "timeout only bounds a failure");
        DONE();
    } else {
        struct timespec deadline = in_ms(CLOCK_MONOTONIC, 3000);
        CALL("futex_wait.woken", futex_wait, WANT_OK, w->word, 0, FUTEX_BITSET_MATCH_ANY, F2,
             &deadline, CLOCK_MONOTONIC);
        in_buf(0, &(uint32_t){0}, sizeof(uint32_t));
        in_any(4);
        why("the main thread wakes this waiter with futex_wake; the 3 s deadline only bounds a "
            "failure");
        DONE();
    }
    return NULL;
}

static void wait_wake_pairs(void)
{
    uint32_t *source = &words[6], *target = &words[7];
    *source = 0;
    *target = 0;

    struct waiter first = {.word = source, .tid = 0, .kind = 0};
    pthread_t thread;
    if (pthread_create(&thread, NULL, waiter_main, &first) != 0) {
        ora_fail("futex: waiter thread");
        return;
    }
    for (int i = 0; i < 1000 && !first.tid; i++)
        sleep_ms(1);
    if (!wait_blocked(first.tid, SYS_futex))
        sleep_ms(100);
    long moved = CALL("futex.cmp_requeue_waiter", futex, WANT_OK, source,
                      FUTEX_CMP_REQUEUE_PRIVATE, 0, 1, target, 0);
    in_buf(0, source, sizeof *source);
    in_buf(4, target, sizeof *target);
    why("wake none, move the blocked waiter to the target word: returns 1");
    DONE();
    long woken = CALL("futex.wake_requeued", futex, WANT_OK, target, FUTEX_WAKE_PRIVATE, 1, NULL,
                      NULL, 0);
    in_buf(0, target, sizeof *target);
    why("the requeued waiter now sleeps on the target word: returns 1");
    DONE();
    pthread_join(thread, NULL);
    if (moved != 1 || woken != 1)
        ora_fail("futex: requeue pair did not move and wake one waiter");

    *source = 0;
    struct waiter second = {.word = source, .tid = 0, .kind = 1};
    if (pthread_create(&thread, NULL, waiter_main, &second) != 0) {
        ora_fail("futex: futex2 waiter thread");
        return;
    }
    for (int i = 0; i < 1000 && !second.tid; i++)
        sleep_ms(1);
    if (!wait_blocked(second.tid, SYS_futex_wait))
        sleep_ms(100);
    woken = CALL("futex_wake.waiter", futex_wake, WANT_OK, source, FUTEX_BITSET_MATCH_ANY, 1, F2);
    in_buf(0, source, sizeof *source);
    why("one futex_wait waiter is blocked on the word: returns 1");
    DONE();
    pthread_join(thread, NULL);
    if (woken != 1)
        ora_fail("futex: futex_wake did not wake the futex_wait waiter");
}

void area_futex(void)
{
    memset(words, 0, sizeof words);
    classic_cases();
    futex2_cases();
    wait_wake_pairs();
}
