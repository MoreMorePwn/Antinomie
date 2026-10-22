// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// ipc.c — System V semaphores, message queues and shared memory, and POSIX
// message queues.
//
// Slots: semget semop semtimedop semctl msgget msgsnd msgrcv msgctl shmget
// shmat shmdt shmctl mq_open mq_unlink mq_timedsend mq_timedreceive
// mq_notify mq_getsetattr.
//
// Every object is IPC_PRIVATE or named after the fixture's pid, and every
// object is removed before the area returns. Children: 320 a semaphore
// waiter woken by IPC_RMID, 321 a message receiver woken by IPC_RMID.
#include "areas.h"

#include <fcntl.h>
#include <mqueue.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/resource.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <time.h>

#define PAGE 4096UL

#ifndef MSG_COPY
#define MSG_COPY 040000
#endif

// The glibc structures are the kernel's 64-bit layouts on x86-64; the
// recorder captures the kernel sizes.
_Static_assert(sizeof(struct semid_ds) == 104, "semid64_ds");
_Static_assert(sizeof(struct msqid_ds) == 120, "msqid64_ds");
_Static_assert(sizeof(struct shmid_ds) == 112, "shmid64_ds");
_Static_assert(sizeof(struct seminfo) == 40, "seminfo");
_Static_assert(sizeof(struct msginfo) == 32, "msginfo");
_Static_assert(sizeof(struct shminfo) == 72, "shminfo64");
_Static_assert(sizeof(struct shm_info) == 48, "shm_info");
_Static_assert(sizeof(struct sembuf) == 6, "sembuf");
_Static_assert(sizeof(struct mq_attr) == 64, "mq_attr");
_Static_assert(sizeof(struct sigevent) == 64, "sigevent");

struct message {
    long mtype;
    char mtext[64];
};

// A System V key no other program uses: the fixture's pid and a salt.
static key_t unique_key(int salt)
{
    return (key_t)(0x41000000 | ((getpid() & 0xffff) << 8) | (salt & 0xff));
}

static int memlock_allows(size_t bytes)
{
    struct rlimit limit;
    if (getrlimit(RLIMIT_MEMLOCK, &limit) != 0)
        return 0;
    return limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur >= bytes + 64 * 1024;
}

static void pause_briefly(void)
{
    struct timespec delay = {0, 2 * 1000 * 1000};
    nanosleep(&delay, NULL);
}

// Whether `pid` is blocked in system call `nr` (/proc/PID/syscall).
static int blocked_in(pid_t pid, int nr)
{
    char path[64], text[64];
    snprintf(path, sizeof path, "/proc/%d/syscall", (int)pid);
    FILE *file = fopen(path, "r");
    if (!file)
        return -1;
    int number = -2;
    if (fgets(text, sizeof text, file))
        sscanf(text, "%d", &number);
    fclose(file);
    return number == nr;
}

// --- System V semaphores ------------------------------------------------

static void sem_waiter(int semid)
{
    struct sembuf op = {0, -1, 0};
    struct sembuf op_in = op;
    struct timespec timeout = {5, 0};
    CALL("semtimedop.removed_while_waiting", semtimedop, EIDRM, semid, &op, 1, &timeout);
    in_buf(1, &op_in, sizeof op_in);
    in_buf(3, &timeout, sizeof timeout);
    volatile_case();
    why("the parent removes the set once GETNCNT shows this waiter");
    DONE();
}

static void sem_cases(void)
{
    long id = CALL("semget.private", semget, WANT_OK, IPC_PRIVATE, 3, IPC_CREAT | 0600);
    volatile_case();
    DONE();
    if (id < 0)
        return;
    key_t key = unique_key(1);
    long named = CALL("semget.named_create", semget, WANT_OK, key, 1, IPC_CREAT | IPC_EXCL | 0600);
    volatile_case();
    DONE();
    CALL("semget.named_exists", semget, EEXIST, key, 1, IPC_CREAT | IPC_EXCL | 0600);
    volatile_case();
    DONE();
    CALL("semget.named_open", semget, WANT_OK, key, 0, 0);
    volatile_case();
    DONE();
    CALL("semget.missing", semget, ENOENT, unique_key(2), 1, 0);
    volatile_case();
    DONE();
    CASE("semget.too_many_semaphores", semget, EINVAL, IPC_PRIVATE, 100000, IPC_CREAT | 0600);
    CASE("semget.create_zero", semget, EINVAL, IPC_PRIVATE, 0, IPC_CREAT | 0600);

    // semctl: values, arrays, status structures.
    CASE("semctl.setval", semctl, WANT_OK, id, 0, SETVAL, 2);
    long value = CASE("semctl.getval", semctl, WANT_OK, id, 0, GETVAL, 0);
    if (value != 2)
        ora_fail("semaphore value");
    CASE("semctl.setval_range", semctl, ERANGE, id, 0, SETVAL, 40000);
    CASE("semctl.getval_bad_index", semctl, EINVAL, id, 7, GETVAL, 0);
    unsigned short values[3] = {1, 2, 3}, values_in[3] = {1, 2, 3}, read_back[3] = {9, 9, 9};
    CALL("semctl.setall", semctl, WANT_OK, id, 0, SETALL, values);
    any_buf(3, values_in, sizeof values_in);
    why("the kernel hands over its own copy of the array (arg3.array, kernel-imported)");
    DONE();
    CALL("semctl.getall", semctl, WANT_OK, id, 0, GETALL, read_back);
    out_buf(3, read_back, sizeof read_back);
    why("the kernel hands over its own copy of the array (arg3.array, kernel-imported)");
    DONE();
    if (memcmp(values, read_back, sizeof values))
        ora_fail("semaphore array");
    unsigned short too_big[3] = {1, 40000, 1};
    CALL("semctl.setall_range", semctl, ERANGE, id, 0, SETALL, too_big);
    any_buf(3, too_big, sizeof too_big);
    why("the array is handed over before the SEMVMX check");
    DONE();
    struct semid_ds ds;
    memset(&ds, 0, sizeof ds);
    CALL("semctl.ipc_stat", semctl, WANT_OK, id, 0, IPC_STAT, &ds);
    out_buf(3, &ds, sizeof ds);
    volatile_case();
    DONE();
    if (ds.sem_nsems != 3)
        ora_fail("semaphore set size");
    ds.sem_perm.mode = 0640;
    struct semid_ds ds_in = ds;
    CALL("semctl.ipc_set", semctl, WANT_OK, id, 0, IPC_SET, &ds);
    in_buf(3, &ds_in, sizeof ds_in);
    volatile_case();
    DONE();
    struct seminfo info;
    memset(&info, 0, sizeof info);
    CALL("semctl.ipc_info", semctl, WANT_OK, 0, 0, IPC_INFO, &info);
    out_buf(3, &info, sizeof info);
    volatile_case();
    why("the result is the highest index in use, which depends on other IPC users");
    DONE();
    memset(&info, 0, sizeof info);
    CALL("semctl.sem_info", semctl, WANT_OK, 0, 0, SEM_INFO, &info);
    out_buf(3, &info, sizeof info);
    volatile_case();
    DONE();
    CALL("semctl.stat_fault", semctl, EFAULT, id, 0, IPC_STAT, 1);
    why("the kernel faults writing the result; nothing is recorded for a failed call");
    DONE();
    CALL("semctl.unknown_command", semctl, EINVAL, id, 0, 99, 0);
    want_key_status("ipc.unknown_selector", "NO_DECODER");
    why("an unknown command is recorded as an explicit selector gap");
    DONE();

    // semop and semtimedop.
    struct sembuf take = {0, -1, 0};
    struct sembuf take_in = take;
    CALL("semop.decrement", semop, WANT_OK, id, &take, 1);
    in_buf(1, &take_in, sizeof take_in);
    DONE();
    struct sembuf pair[2] = {{1, 1, SEM_UNDO}, {2, -1, IPC_NOWAIT}};
    struct sembuf pair_in[2];
    memcpy(pair_in, pair, sizeof pair);
    CALL("semop.two_ops_undo", semop, WANT_OK, id, pair, 2);
    in_buf(1, pair_in, sizeof pair_in);
    DONE();
    struct sembuf nowait = {0, -1, IPC_NOWAIT};
    struct sembuf nowait_in = nowait;
    CALL("semop.would_block", semop, EAGAIN, id, &nowait, 1);
    in_buf(1, &nowait_in, sizeof nowait_in);
    DONE();
    struct sembuf far = {7, 1, 0};
    struct sembuf far_in = far;
    CALL("semop.bad_index", semop, EFBIG, id, &far, 1);
    in_buf(1, &far_in, sizeof far_in);
    DONE();
    CALL("semop.zero_ops", semop, EINVAL, id, &take, 0);
    want_status(1, "in", "INVALID_EXTENT");
    DONE();
    CALL("semop.too_many_ops", semop, E2BIG, id, &take, 600);
    want_status(1, "in", "INVALID_EXTENT");
    why("more than SEMOPM (500) operations are refused before they are read");
    DONE();
    CALL("semop.bad_id", semop, EINVAL, -1, &take, 1);
    in_buf(1, &take_in, sizeof take_in);
    DONE();
    CALL("semop.fault", semop, EFAULT, id, 1, 1);
    want_status(1, "in", "COPY_FAULT");
    DONE();
    struct timespec short_wait = {0, 20 * 1000 * 1000};
    struct timespec short_in = short_wait;
    CALL("semtimedop.times_out", semtimedop, EAGAIN, id, &take, 1, &short_wait);
    in_buf(1, &take_in, sizeof take_in);
    in_buf(3, &short_in, sizeof short_in);
    why("semaphore 0 is zero: the 20 ms timeout expires");
    DONE();
    struct sembuf give = {1, -1, 0};
    struct sembuf give_in = give;
    CALL("semtimedop.immediate", semtimedop, WANT_OK, id, &give, 1, &short_wait);
    in_buf(1, &give_in, sizeof give_in);
    in_buf(3, &short_in, sizeof short_in);
    DONE();
    struct sembuf wait_zero = {0, 0, 0};
    struct sembuf wait_zero_in = wait_zero;
    CALL("semtimedop.null_timeout", semtimedop, WANT_OK, id, &wait_zero, 1, NULL);
    in_buf(1, &wait_zero_in, sizeof wait_zero_in);
    why("waiting for zero on a zero semaphore returns at once; a NULL timeout is not decoded");
    DONE();
    struct timespec bad_time = {0, 2000000000L};
    struct timespec bad_in = bad_time;
    CALL("semtimedop.bad_timeout", semtimedop, EINVAL, id, &take, 1, &bad_time);
    in_buf(1, &take_in, sizeof take_in);
    in_buf(3, &bad_in, sizeof bad_in);
    DONE();
    CALL("semctl.getpid", semctl, WANT_OK, id, 1, GETPID, 0);
    volatile_case();
    DONE();
    CASE("semctl.getncnt", semctl, WANT_OK, id, 0, GETNCNT, 0);
    CASE("semctl.getzcnt", semctl, WANT_OK, id, 0, GETZCNT, 0);

    // A waiter in another process is woken with EIDRM by IPC_RMID.
    ora_flush();
    pid_t child = fork();
    if (child < 0) {
        ora_fail("semaphore waiter fork");
    } else if (child == 0) {
        ora_child(320);
        sem_waiter((int)id);
        _exit(ora_failures() ? 3 : 0);
    } else {
        role("child", child);
        for (int i = 0; i < 1500 && semctl((int)id, 0, GETNCNT) < 1; i++)
            pause_briefly();
        CALL("semctl.rmid_with_waiter", semctl, WANT_OK, id, 0, IPC_RMID, 0);
        why("removing the set wakes the child's semtimedop with EIDRM");
        DONE();
        ora_wait(child, "semaphore waiter");
        id = -1;
    }
    if (id >= 0)
        semctl((int)id, 0, IPC_RMID);
    if (named >= 0) {
        CASE("semctl.rmid", semctl, WANT_OK, named, 0, IPC_RMID, 0);
        CALL("semctl.stat_removed", semctl, EINVAL, named, 0, IPC_STAT, &ds);
        why("the identifier no longer exists");
        DONE();
    }
}

// --- System V message queues --------------------------------------------

static void msg_receiver(int queue)
{
    struct message box;
    memset(&box, 0, sizeof box);
    CALL("msgrcv.removed_while_waiting", msgrcv, EIDRM, queue, &box, sizeof box.mtext, 0, 0);
    why("the parent removes the queue once /proc shows this receiver blocked in msgrcv");
    DONE();
}

static long send_message(const char *label, int queue, long type, size_t len, unsigned seed,
                         int flags, long want)
{
    struct message box;
    memset(&box, 0, sizeof box);
    box.mtype = type;
    pattern(box.mtext, len, seed);
    struct message box_in = box;
    long result = CALL(label, msgsnd, want, queue, &box, len, flags);
    in_buf(1, &box_in, sizeof box_in.mtype + len);
    return result;
}

static long receive_message(const char *label, int queue, size_t capacity, long type, int flags,
                            long want, struct message *box)
{
    memset(box, 0, sizeof *box);
    long got = CALL(label, msgrcv, want, queue, box, capacity, type, flags);
    if (got >= 0)
        out_buf(1, box, sizeof box->mtype + (size_t)got);
    return got;
}

static void msg_cases(void)
{
    long queue = CALL("msgget.private", msgget, WANT_OK, IPC_PRIVATE, IPC_CREAT | 0600);
    volatile_case();
    DONE();
    if (queue < 0)
        return;
    key_t key = unique_key(3);
    long named = CALL("msgget.named_create", msgget, WANT_OK, key, IPC_CREAT | IPC_EXCL | 0600);
    volatile_case();
    DONE();
    CALL("msgget.named_exists", msgget, EEXIST, key, IPC_CREAT | IPC_EXCL | 0600);
    volatile_case();
    DONE();
    CALL("msgget.missing", msgget, ENOENT, unique_key(4), 0);
    volatile_case();
    DONE();

    send_message("msgsnd.type1", (int)queue, 1, 20, 1, 0, WANT_OK);
    DONE();
    send_message("msgsnd.type2", (int)queue, 2, 10, 2, IPC_NOWAIT, WANT_OK);
    DONE();
    send_message("msgsnd.type3", (int)queue, 3, 40, 3, 0, WANT_OK);
    DONE();
    send_message("msgsnd.zero_type", (int)queue, 0, 4, 4, 0, EINVAL);
    DONE();
    send_message("msgsnd.bad_id", -1, 1, 4, 5, 0, EINVAL);
    DONE();
    struct message box;
    memset(&box, 0, sizeof box);
    box.mtype = 1;
    CALL("msgsnd.too_big", msgsnd, EINVAL, queue, &box, 100000, 0);
    want_status(1, "in", "INVALID_EXTENT");
    why("larger than MSGMAX: refused before the message is read");
    DONE();
    CALL("msgsnd.negative_size", msgsnd, EINVAL, queue, &box, -1L, 0);
    want_status(1, "in", "INVALID_EXTENT");
    DONE();

    struct msqid_ds ds;
    memset(&ds, 0, sizeof ds);
    CALL("msgctl.ipc_stat", msgctl, WANT_OK, queue, IPC_STAT, &ds);
    out_buf(2, &ds, sizeof ds);
    volatile_case();
    DONE();
    if (ds.msg_qnum != 3)
        ora_fail("message count");
    ds.msg_qbytes = 128;
    struct msqid_ds ds_in = ds;
    CALL("msgctl.ipc_set_qbytes", msgctl, WANT_OK, queue, IPC_SET, &ds);
    in_buf(2, &ds_in, sizeof ds_in);
    volatile_case();
    why("lowering the byte limit needs no privilege");
    DONE();
    send_message("msgsnd.full_nowait", (int)queue, 4, 64, 6, IPC_NOWAIT, EAGAIN);
    why("70 bytes queued plus 64 exceed the 128-byte limit");
    DONE();

    receive_message("msgrcv.type2", (int)queue, sizeof box.mtext, 2, 0, WANT_OK, &box);
    DONE();
    if (box.mtype != 2)
        ora_fail("msgrcv by type");
    receive_message("msgrcv.lowest_type", (int)queue, sizeof box.mtext, -3, 0, WANT_OK, &box);
    DONE();
    if (box.mtype != 1)
        ora_fail("msgrcv lowest type");
    receive_message("msgrcv.too_small", (int)queue, 10, 3, IPC_NOWAIT, E2BIG, &box);
    why("without MSG_NOERROR a longer message stays queued");
    DONE();
    long got = receive_message("msgrcv.noerror_truncates", (int)queue, 10, 3,
                               MSG_NOERROR | IPC_NOWAIT, WANT_OK, &box);
    DONE();
    if (got != 10)
        ora_fail("MSG_NOERROR truncation");
    receive_message("msgrcv.empty_nowait", (int)queue, sizeof box.mtext, 0, IPC_NOWAIT, ENOMSG,
                    &box);
    DONE();
    send_message("msgsnd.type5", (int)queue, 5, 8, 7, 0, WANT_OK);
    DONE();
    send_message("msgsnd.type6", (int)queue, 6, 8, 8, 0, WANT_OK);
    DONE();
    got = receive_message("msgrcv.copy", (int)queue, sizeof box.mtext, 0, MSG_COPY | IPC_NOWAIT,
                          WANT_ANY, &box);
    why("MSG_COPY needs CONFIG_CHECKPOINT_RESTORE; without it the flag is refused");
    DONE();
    receive_message("msgrcv.except", (int)queue, sizeof box.mtext, 5, MSG_EXCEPT, WANT_OK, &box);
    DONE();
    if (box.mtype != 6)
        ora_fail("MSG_EXCEPT");
    receive_message("msgrcv.any", (int)queue, sizeof box.mtext, 0, 0, WANT_OK, &box);
    DONE();
    receive_message("msgrcv.bad_id", -1, sizeof box.mtext, 0, IPC_NOWAIT, EINVAL, &box);
    DONE();
    receive_message("msgrcv.negative_size", (int)queue, (size_t)-1, 0, IPC_NOWAIT, EINVAL, &box);
    DONE();

    struct msginfo info;
    memset(&info, 0, sizeof info);
    CALL("msgctl.ipc_info", msgctl, WANT_OK, 0, IPC_INFO, &info);
    out_buf(2, &info, sizeof info);
    volatile_case();
    DONE();
    memset(&info, 0, sizeof info);
    CALL("msgctl.msg_info", msgctl, WANT_OK, 0, MSG_INFO, &info);
    out_buf(2, &info, sizeof info);
    volatile_case();
    DONE();
    CALL("msgctl.unknown_command", msgctl, EINVAL, queue, 99, &ds);
    want_key_status("ipc.unknown_selector", "NO_DECODER");
    DONE();
    CASE("msgctl.rmid", msgctl, WANT_OK, queue, IPC_RMID, 0);
    CALL("msgctl.stat_removed", msgctl, EINVAL, queue, IPC_STAT, &ds);
    why("the identifier no longer exists");
    DONE();

    // A blocked receiver in another process is woken with EIDRM.
    if (named < 0)
        return;
    ora_flush();
    pid_t child = fork();
    if (child < 0) {
        ora_fail("message receiver fork");
        msgctl((int)named, IPC_RMID, NULL);
        return;
    }
    if (child == 0) {
        ora_child(321);
        msg_receiver((int)named);
        _exit(ora_failures() ? 3 : 0);
    }
    role("child", child);
    int blocked = 0;
    for (int i = 0; i < 1500; i++) {
        int state = blocked_in(child, SYS_msgrcv);
        if (state != 0) {
            blocked = state;
            break;
        }
        pause_briefly();
    }
    if (blocked < 0) {
        struct timespec delay = {0, 300 * 1000 * 1000};
        nanosleep(&delay, NULL);
    }
    CALL("msgctl.rmid_with_receiver", msgctl, WANT_OK, named, IPC_RMID, 0);
    why("removing the queue wakes the child's msgrcv with EIDRM");
    DONE();
    ora_wait(child, "message receiver");
}

// --- System V shared memory ---------------------------------------------

static void shm_cases(void)
{
    long seg = CALL("shmget.private", shmget, WANT_OK, IPC_PRIVATE, PAGE, IPC_CREAT | 0600);
    volatile_case();
    DONE();
    if (seg < 0)
        return;
    key_t key = unique_key(5);
    long named = CALL("shmget.named_create_readonly", shmget, WANT_OK, key, PAGE,
                      IPC_CREAT | IPC_EXCL | 0400);
    volatile_case();
    DONE();
    CALL("shmget.named_exists", shmget, EEXIST, key, PAGE, IPC_CREAT | IPC_EXCL | 0600);
    volatile_case();
    DONE();
    CALL("shmget.larger_than_existing", shmget, EINVAL, key, 2 * PAGE, 0);
    volatile_case();
    DONE();
    CALL("shmget.missing", shmget, ENOENT, unique_key(6), PAGE, 0);
    volatile_case();
    DONE();
    CASE("shmget.zero_size", shmget, EINVAL, IPC_PRIVATE, 0, IPC_CREAT | 0600);

    long at = CALL("shmat.anywhere", shmat, WANT_OK, seg, NULL, 0);
    want_status(1, "in", "ADDRESS_ONLY");
    volatile_case();
    DONE();
    if (at < 0) {
        shmctl((int)seg, IPC_RMID, NULL);
        if (named >= 0)
            shmctl((int)named, IPC_RMID, NULL);
        return;
    }
    pattern((void *)at, PAGE, 40);
    long ro = CALL("shmat.readonly", shmat, WANT_OK, seg, NULL, SHM_RDONLY);
    want_status(1, "in", "ADDRESS_ONLY");
    volatile_case();
    DONE();
    if (ro > 0 && memcmp((void *)ro, (void *)at, PAGE))
        ora_fail("shared memory contents");
    char *gap = mmap(NULL, PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(gap, PAGE);
    long fixed = CALL("shmat.fixed", shmat, WANT_OK, seg, gap, 0);
    want_status(1, "in", "ADDRESS_ONLY");
    volatile_case();
    DONE();
    if (fixed > 0 && (char *)fixed != gap)
        ora_fail("shmat fixed address");
    gap = mmap(NULL, PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(gap, PAGE);
    long rounded = CALL("shmat.round_down", shmat, WANT_OK, seg, gap + 123, SHM_RND);
    want_status(1, "in", "ADDRESS_ONLY");
    volatile_case();
    DONE();
    if (rounded > 0 && (char *)rounded != gap)
        ora_fail("shmat SHM_RND address");
    CALL("shmat.unaligned", shmat, EINVAL, seg, gap + 123, 0);
    want_status(1, "in", "ADDRESS_ONLY");
    volatile_case();
    DONE();
    CALL("shmat.bad_id", shmat, EINVAL, -1, NULL, 0);
    want_status(1, "in", "ADDRESS_ONLY");
    DONE();
    if (named >= 0) {
        CALL("shmat.no_write_permission", shmat, EACCES, named, NULL, 0);
        want_status(1, "in", "ADDRESS_ONLY");
        volatile_case();
        why("the segment is mode 0400: the owner may only attach it read-only");
        DONE();
        long view = CALL("shmat.readonly_named", shmat, WANT_OK, named, NULL, SHM_RDONLY);
        want_status(1, "in", "ADDRESS_ONLY");
        volatile_case();
        DONE();
        if (view > 0) {
            CALL("shmdt.named", shmdt, WANT_OK, view);
            want_status(0, "in", "ADDRESS_ONLY");
            volatile_case();
            DONE();
        }
    }

    struct shmid_ds ds;
    memset(&ds, 0, sizeof ds);
    CALL("shmctl.ipc_stat", shmctl, WANT_OK, seg, IPC_STAT, &ds);
    out_buf(2, &ds, sizeof ds);
    volatile_case();
    DONE();
    if (ds.shm_nattch != 1u + (ro > 0) + (fixed > 0) + (rounded > 0))
        ora_fail("shared memory attach count");
    ds.shm_perm.mode = 0640;
    struct shmid_ds ds_in = ds;
    CALL("shmctl.ipc_set", shmctl, WANT_OK, seg, IPC_SET, &ds);
    in_buf(2, &ds_in, sizeof ds_in);
    volatile_case();
    DONE();
    struct shminfo limits;
    memset(&limits, 0, sizeof limits);
    CALL("shmctl.ipc_info", shmctl, WANT_OK, 0, IPC_INFO, &limits);
    out_buf(2, &limits, sizeof limits);
    volatile_case();
    DONE();
    struct shm_info usage;
    memset(&usage, 0, sizeof usage);
    CALL("shmctl.shm_info", shmctl, WANT_OK, 0, SHM_INFO, &usage);
    out_buf(2, &usage, sizeof usage);
    volatile_case();
    DONE();
    long lock_want = memlock_allows(PAGE) ? WANT_OK : WANT_ANY;
    CALL("shmctl.shm_lock", shmctl, lock_want, seg, SHM_LOCK, 0);
    if (lock_want == WANT_ANY)
        why("the owner may lock within RLIMIT_MEMLOCK, which is small here");
    DONE();
    CASE("shmctl.shm_unlock", shmctl, WANT_OK, seg, SHM_UNLOCK, 0);
    CALL("shmctl.stat_fault", shmctl, EFAULT, seg, IPC_STAT, 1);
    why("the kernel faults writing the result; nothing is recorded for a failed call");
    DONE();
    CALL("shmctl.unknown_command", shmctl, EINVAL, seg, 99, &ds);
    want_key_status("ipc.unknown_selector", "NO_DECODER");
    DONE();

    CALL("shmdt.anywhere", shmdt, WANT_OK, at);
    want_status(0, "in", "ADDRESS_ONLY");
    volatile_case();
    DONE();
    if (ro > 0) {
        CALL("shmdt.readonly", shmdt, WANT_OK, ro);
        want_status(0, "in", "ADDRESS_ONLY");
        volatile_case();
        DONE();
    }
    CASE("shmctl.rmid_attached", shmctl, WANT_OK, seg, IPC_RMID, 0);
    if (fixed > 0) {
        CALL("shmdt.fixed", shmdt, WANT_OK, fixed);
        want_status(0, "in", "ADDRESS_ONLY");
        volatile_case();
        why("the last detach of a removed segment destroys it");
        DONE();
    }
    if (rounded > 0)
        shmdt((void *)rounded);
    CALL("shmdt.not_attached", shmdt, EINVAL, at);
    want_status(0, "in", "ADDRESS_ONLY");
    volatile_case();
    DONE();
    if (named >= 0) {
        CASE("shmctl.rmid", shmctl, WANT_OK, named, IPC_RMID, 0);
        CALL("shmctl.stat_removed", shmctl, EINVAL, named, IPC_STAT, &ds);
        why("the identifier no longer exists");
        DONE();
    }
}

// --- POSIX message queues -------------------------------------------------

static void queue_send(const char *label, long mq, const char *text, size_t len, unsigned prio,
                    const struct timespec *timeout, long want)
{
    struct timespec timeout_in;
    if (timeout)
        timeout_in = *timeout;
    CALL(label, mq_timedsend, want, mq, text, len, prio, timeout);
    in_buf(1, text, len);
    if (timeout)
        in_buf(4, &timeout_in, sizeof timeout_in);
}

static void mq_cases(void)
{
    char name[64], other[64], bad[64];
    snprintf(name, sizeof name, "ant-mq-%d", (int)getpid());
    snprintf(other, sizeof other, "ant-mq-missing-%d", (int)getpid());
    snprintf(bad, sizeof bad, "ant-mq-bad-%d", (int)getpid());
    struct mq_attr attr, attr_in, old;
    memset(&attr, 0, sizeof attr);
    attr.mq_maxmsg = 4;
    attr.mq_msgsize = 64;
    attr_in = attr;

    long mq = CALL("mq_open.create", mq_open, WANT_OK, name, O_CREAT | O_EXCL | O_RDWR, 0600,
                   &attr);
    in_str(0, name);
    in_buf(3, &attr_in, sizeof attr_in);
    volatile_case();
    DONE();
    if (mq < 0)
        return;
    long mq2 = CALL("mq_open.existing_nonblock", mq_open, WANT_OK, name, O_RDWR | O_NONBLOCK, 0,
                    NULL);
    in_str(0, name);
    want_status(3, "in", "NULL_POINTER");
    volatile_case();
    DONE();
    CALL("mq_open.exists_excl", mq_open, EEXIST, name, O_CREAT | O_EXCL | O_RDWR, 0600, &attr);
    in_str(0, name);
    in_buf(3, &attr_in, sizeof attr_in);
    volatile_case();
    DONE();
    CALL("mq_open.missing", mq_open, ENOENT, other, O_RDONLY, 0, NULL);
    in_str(0, other);
    want_status(3, "in", "NULL_POINTER");
    volatile_case();
    DONE();
    struct mq_attr zero;
    memset(&zero, 0, sizeof zero);
    zero.mq_msgsize = 64;
    struct mq_attr zero_in = zero;
    CALL("mq_open.bad_attr", mq_open, EINVAL, bad, O_CREAT | O_EXCL | O_RDWR, 0600, &zero);
    in_str(0, bad);
    in_buf(3, &zero_in, sizeof zero_in);
    volatile_case();
    why("mq_maxmsg 0 is invalid");
    DONE();
    char slashed[] = "ant/mq";
    CALL("mq_open.slash_in_name", mq_open, EACCES, slashed, O_RDONLY, 0, NULL);
    in_str(0, slashed);
    want_status(3, "in", "NULL_POINTER");
    why("the kernel's name lookup refuses a slash inside the name");
    DONE();
    CALL("mq_open.null_name", mq_open, EFAULT, NULL, O_RDONLY, 0, NULL);
    want_status(0, "in", "NULL_POINTER");
    want_status(3, "in", "NULL_POINTER");
    DONE();

    memset(&old, 0xa5, sizeof old);
    CALL("mq_getsetattr.get", mq_getsetattr, WANT_OK, mq, NULL, &old);
    want_status(1, "in", "NULL_POINTER");
    out_buf(2, &old, sizeof old);
    DONE();
    if (old.mq_maxmsg != 4 || old.mq_msgsize != 64)
        ora_fail("mq attributes");

    char first[] = "first-message", second[] = "second-message";
    static char big[100];
    pattern(big, sizeof big, 41);
    struct timespec future;
    clock_gettime(CLOCK_REALTIME, &future);
    future.tv_sec += 5;
    queue_send("mq_timedsend.prio5", mq, first, sizeof first - 1, 5, NULL, WANT_OK);
    why("a NULL timeout is not decoded");
    DONE();
    queue_send("mq_timedsend.prio9_timeout", mq, second, sizeof second - 1, 9, &future, WANT_OK);
    volatile_case();
    DONE();
    queue_send("mq_timedsend.too_big", mq, big, sizeof big, 1, NULL, EMSGSIZE);
    why("longer than mq_msgsize (64)");
    DONE();
    queue_send("mq_timedsend.bad_priority", mq, first, 4, 40000, NULL, EINVAL);
    why("priorities stop below MQ_PRIO_MAX (32768)");
    DONE();
    struct timespec bad_time = {0, 2000000000L};
    queue_send("mq_timedsend.bad_timeout", mq, first, 4, 1, &bad_time, EINVAL);
    DONE();
    queue_send("mq_timedsend.badf", 999, first, 4, 1, NULL, EBADF);
    DONE();
    queue_send("mq_timedsend.fill_a", mq, first, 5, 1, NULL, WANT_OK);
    DONE();
    queue_send("mq_timedsend.fill_b", mq, first, 6, 1, NULL, WANT_OK);
    DONE();
    queue_send("mq_timedsend.full_nonblock", mq2, first, 4, 1, NULL, EAGAIN);
    why("four messages fill the queue; the second descriptor is nonblocking");
    DONE();

    char buffer[64];
    unsigned prio = 77;
    memset(buffer, 0, sizeof buffer);
    long got = CALL("mq_timedreceive.highest_priority", mq_timedreceive, WANT_OK, mq, buffer,
                    sizeof buffer, &prio, NULL);
    if (got >= 0) {
        out_buf(1, buffer, (size_t)got);
        out_buf(3, &prio, sizeof prio);
    }
    DONE();
    if (got != (long)sizeof second - 1 || prio != 9)
        ora_fail("mq priority order");
    CALL("mq_timedreceive.small_buffer", mq_timedreceive, EMSGSIZE, mq, buffer, 10, &prio, NULL);
    why("a buffer smaller than mq_msgsize is refused");
    DONE();
    memset(buffer, 0, sizeof buffer);
    struct timespec future_in = future;
    got = CALL("mq_timedreceive.with_timeout", mq_timedreceive, WANT_OK, mq, buffer,
               sizeof buffer, NULL, &future);
    in_buf(4, &future_in, sizeof future_in);
    if (got >= 0)
        out_buf(1, buffer, (size_t)got);
    volatile_case();
    why("a NULL priority pointer is not decoded");
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("mq_timedreceive.drain_a", mq_timedreceive, WANT_OK, mq2, buffer, sizeof buffer,
               &prio, NULL);
    if (got >= 0) {
        out_buf(1, buffer, (size_t)got);
        out_buf(3, &prio, sizeof prio);
    }
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("mq_timedreceive.drain_b", mq_timedreceive, WANT_OK, mq2, buffer, sizeof buffer,
               &prio, NULL);
    if (got >= 0) {
        out_buf(1, buffer, (size_t)got);
        out_buf(3, &prio, sizeof prio);
    }
    DONE();
    CALL("mq_timedreceive.empty_nonblock", mq_timedreceive, EAGAIN, mq2, buffer, sizeof buffer,
         &prio, NULL);
    DONE();

    struct mq_attr nonblock, nonblock_in;
    memset(&nonblock, 0, sizeof nonblock);
    nonblock.mq_flags = O_NONBLOCK;
    nonblock_in = nonblock;
    memset(&old, 0, sizeof old);
    CALL("mq_getsetattr.set_nonblock", mq_getsetattr, WANT_OK, mq, &nonblock, &old);
    in_buf(1, &nonblock_in, sizeof nonblock_in);
    out_buf(2, &old, sizeof old);
    DONE();
    struct mq_attr blocking, blocking_in;
    memset(&blocking, 0, sizeof blocking);
    blocking_in = blocking;
    CALL("mq_getsetattr.set_only", mq_getsetattr, WANT_OK, mq, &blocking, NULL);
    in_buf(1, &blocking_in, sizeof blocking_in);
    want_status(2, "out", "NULL_POINTER");
    DONE();
    struct mq_attr odd, odd_in;
    memset(&odd, 0, sizeof odd);
    odd.mq_flags = O_APPEND;
    odd_in = odd;
    CALL("mq_getsetattr.bad_flags", mq_getsetattr, EINVAL, mq, &odd, &old);
    in_buf(1, &odd_in, sizeof odd_in);
    why("only O_NONBLOCK can be changed");
    DONE();
    CALL("mq_getsetattr.badf", mq_getsetattr, EBADF, 999, NULL, &old);
    want_status(1, "in", "NULL_POINTER");
    DONE();
    struct timespec past = {1, 0}, past_in = {1, 0};
    CALL("mq_timedreceive.expired", mq_timedreceive, ETIMEDOUT, mq, buffer, sizeof buffer, &prio,
         &past);
    in_buf(4, &past_in, sizeof past_in);
    why("an absolute timeout in 1970 expires at once on an empty blocking queue");
    DONE();
    struct timespec bad_in = bad_time;
    CALL("mq_timedreceive.bad_timeout", mq_timedreceive, EINVAL, mq, buffer, sizeof buffer,
         &prio, &bad_time);
    in_buf(4, &bad_in, sizeof bad_in);
    DONE();

    struct sigevent event, event_in;
    memset(&event, 0, sizeof event);
    event.sigev_notify = SIGEV_NONE;
    event_in = event;
    CALL("mq_notify.register_none", mq_notify, WANT_OK, mq, &event);
    in_buf(1, &event_in, sizeof event_in);
    DONE();
    CALL("mq_notify.busy", mq_notify, EBUSY, mq2, &event);
    in_buf(1, &event_in, sizeof event_in);
    why("one registration per queue, even for the same process");
    DONE();
    CALL("mq_notify.unregister", mq_notify, WANT_OK, mq, NULL);
    why("a NULL notification unregisters; it is not decoded");
    DONE();
    memset(&event, 0, sizeof event);
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = 999;
    event_in = event;
    CALL("mq_notify.bad_signal", mq_notify, EINVAL, mq, &event);
    in_buf(1, &event_in, sizeof event_in);
    DONE();
    memset(&event, 0, sizeof event);
    event.sigev_notify = 99;
    event_in = event;
    CALL("mq_notify.bad_notify", mq_notify, EINVAL, mq, &event);
    in_buf(1, &event_in, sizeof event_in);
    DONE();
    static char cookie[32];
    pattern(cookie, sizeof cookie, 42);
    memset(&event, 0, sizeof event);
    event.sigev_notify = SIGEV_THREAD;
    event.sigev_signo = 999;
    event.sigev_value.sival_ptr = cookie;
    event_in = event;
    CALL("mq_notify.thread_bad_socket", mq_notify, EBADF, mq, &event);
    in_buf(1, &event_in, sizeof event_in);
    in_key("arg1.notification.cookie", cookie, sizeof cookie);
    volatile_case();
    why("SIGEV_THREAD names a netlink socket in sigev_signo; fd 999 is closed");
    DONE();
    int pipefd[2];
    if (pipe(pipefd) == 0) {
        memset(&event, 0, sizeof event);
        event.sigev_notify = SIGEV_NONE;
        event_in = event;
        CALL("mq_notify.not_a_queue", mq_notify, EBADF, pipefd[0], &event);
        in_buf(1, &event_in, sizeof event_in);
        DONE();
        close(pipefd[0]);
        close(pipefd[1]);
    }
    close((int)mq);
    if (mq2 >= 0)
        close((int)mq2);

    CALL("mq_unlink.named", mq_unlink, WANT_OK, name);
    in_str(0, name);
    volatile_case();
    DONE();
    CALL("mq_unlink.missing", mq_unlink, ENOENT, name);
    in_str(0, name);
    volatile_case();
    DONE();
    CALL("mq_unlink.null_name", mq_unlink, EFAULT, NULL);
    want_status(0, "in", "NULL_POINTER");
    DONE();
}

void area_ipc(void)
{
    sem_cases();
    msg_cases();
    shm_cases();
    mq_cases();
}
