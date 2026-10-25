// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// kernel.c — asynchronous requests (io_uring) and rare system calls with
// unusual arguments for the argument decoders.
#include "workload.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/io_uring.h>
#include <linux/keyctl.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// ---------------------------------------------------------------- async-io

struct ring {
    int fd;
    unsigned *sq_head, *sq_tail, *sq_mask, *sq_array;
    unsigned *cq_head, *cq_tail, *cq_mask;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
    unsigned entries;
};

static int ring_open(struct ring *ring, unsigned entries)
{
    struct io_uring_params params;
    memset(&params, 0, sizeof params);
    ring->fd = (int)syscall(__NR_io_uring_setup, entries, &params);
    if (ring->fd < 0)
        return -1;
    size_t sq_size = params.sq_off.array + params.sq_entries * sizeof(unsigned);
    size_t cq_size = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
    int single = params.features & IORING_FEAT_SINGLE_MMAP;
    if (single && cq_size > sq_size)
        sq_size = cq_size;
    char *sq = mmap(NULL, sq_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring->fd,
                    IORING_OFF_SQ_RING);
    if (sq == MAP_FAILED)
        return -1;
    char *cq = single ? sq
                      : mmap(NULL, cq_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                             ring->fd, IORING_OFF_CQ_RING);
    if (cq == MAP_FAILED)
        return -1;
    ring->sqes = mmap(NULL, params.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE, ring->fd, IORING_OFF_SQES);
    if (ring->sqes == MAP_FAILED)
        return -1;
    ring->sq_head = (unsigned *)(sq + params.sq_off.head);
    ring->sq_tail = (unsigned *)(sq + params.sq_off.tail);
    ring->sq_mask = (unsigned *)(sq + params.sq_off.ring_mask);
    ring->sq_array = (unsigned *)(sq + params.sq_off.array);
    ring->cq_head = (unsigned *)(cq + params.cq_off.head);
    ring->cq_tail = (unsigned *)(cq + params.cq_off.tail);
    ring->cq_mask = (unsigned *)(cq + params.cq_off.ring_mask);
    ring->cqes = (struct io_uring_cqe *)(cq + params.cq_off.cqes);
    ring->entries = params.sq_entries;
    return 0;
}

static struct io_uring_sqe *ring_next(struct ring *ring)
{
    unsigned tail = *ring->sq_tail;
    if (tail - __atomic_load_n(ring->sq_head, __ATOMIC_ACQUIRE) >= ring->entries)
        return NULL;
    unsigned index = tail & *ring->sq_mask;
    struct io_uring_sqe *sqe = &ring->sqes[index];
    memset(sqe, 0, sizeof *sqe);
    ring->sq_array[index] = index;
    __atomic_store_n(ring->sq_tail, tail + 1, __ATOMIC_RELEASE);
    return sqe;
}

// Submit what is queued and wait for `wait` completions; returns completions reaped.
static long ring_submit(struct ring *ring, unsigned submit, unsigned wait, long *errors)
{
    if (syscall(__NR_io_uring_enter, ring->fd, submit, wait, IORING_ENTER_GETEVENTS, NULL, 0) < 0)
        return -1;
    long reaped = 0;
    unsigned head = *ring->cq_head;
    while (head != __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE)) {
        if (ring->cqes[head & *ring->cq_mask].res < 0 && errors)
            (*errors)++;
        head++;
        reaped++;
    }
    __atomic_store_n(ring->cq_head, head, __ATOMIC_RELEASE);
    return reaped;
}

MODULE(async_io)
{
    const char *name = "async-io";
    unsigned depth = options->level == LEVEL_LIGHT ? 32 : options->level == LEVEL_HEAVY ? 128 : 256;
    long rounds = scaled(options, 20);
    struct ring ring;
    if (ring_open(&ring, depth) < 0) {
        unavailable(name, "io_uring is not available here (%s); kernel.io_uring_disabled?",
                    strerror(errno));
        return 0;
    }
    char path[512];
    snprintf(path, sizeof path, "%s/async.dat", options->workdir);
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    static char block[4096];
    memset(block, 'Q', sizeof block);
    long completions = 0, errors = 0;
    for (long round = 0; round < rounds; round++) {
        unsigned queued = 0;
        for (unsigned i = 0; i + 1 < ring.entries; i += 2) {
            struct io_uring_sqe *write_op = ring_next(&ring);
            struct io_uring_sqe *read_op = write_op ? ring_next(&ring) : NULL;
            if (!read_op)
                break;
            off_t offset = (off_t)((round * ring.entries + i) % 1024) * 4096;
            // A write linked to the read of the same block.
            write_op->opcode = IORING_OP_WRITE;
            write_op->fd = fd;
            write_op->addr = (unsigned long)block;
            write_op->len = sizeof block;
            write_op->off = (unsigned long long)offset;
            write_op->flags = IOSQE_IO_LINK;
            write_op->user_data = 1;
            read_op->opcode = IORING_OP_READ;
            read_op->fd = fd;
            read_op->addr = (unsigned long)block;
            read_op->len = sizeof block;
            read_op->off = (unsigned long long)offset;
            read_op->user_data = 2;
            queued += 2;
        }
        long reaped = ring_submit(&ring, queued, queued, &errors);
        if (reaped < 0)
            break;
        completions += reaped;
    }
    // A read that cannot finish (an empty pipe), then its cancellation.
    int pipefd[2];
    if (pipe(pipefd) == 0) {
        static char sink[16];
        struct io_uring_sqe *stuck = ring_next(&ring);
        if (stuck) {
            stuck->opcode = IORING_OP_READ;
            stuck->fd = pipefd[0];
            stuck->addr = (unsigned long)sink;
            stuck->len = sizeof sink;
            stuck->user_data = 0xdead;
            ring_submit(&ring, 1, 0, NULL);
            struct io_uring_sqe *cancel = ring_next(&ring);
            if (cancel) {
                cancel->opcode = IORING_OP_ASYNC_CANCEL;
                cancel->addr = 0xdead;
                cancel->user_data = 3;
                long reaped = ring_submit(&ring, 1, 2, NULL);
                if (reaped > 0)
                    completions += reaped;
                pass(name, "an endless pipe read was cancelled through the ring");
            }
        }
        close(pipefd[0]);
        close(pipefd[1]);
    }
    close(fd);
    close(ring.fd);
    count("async completions", (unsigned long long)completions);
    pass(name, "%ld completions (%ld errors) from linked write/read pairs, %u deep", completions,
         errors, depth);
    return 0;
}

// ---------------------------------------------------------------- decoder-variants

static unsigned long long decoded;
#define TRY(expr) ((void)(expr), decoded++)

static void sockets(void)
{
    int tcp = socket(AF_INET, SOCK_STREAM, 0), on = 1, ttl = 33, tos = 0x10, size = 1 << 18;
    struct linger linger = {.l_onoff = 1, .l_linger = 0};
    TRY(setsockopt(tcp, SOL_SOCKET, SO_RCVBUF, &size, sizeof size));
    TRY(setsockopt(tcp, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on));
    TRY(setsockopt(tcp, SOL_SOCKET, SO_LINGER, &linger, sizeof linger));
    TRY(setsockopt(tcp, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on));
    TRY(setsockopt(tcp, IPPROTO_TCP, TCP_KEEPIDLE, &ttl, sizeof ttl));
    TRY(setsockopt(tcp, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl));
    TRY(setsockopt(tcp, IPPROTO_IP, IP_TOS, &tos, sizeof tos));
    TRY(setsockopt(tcp, SOL_SOCKET, 0x7fff, &on, sizeof on)); // unknown option: ENOPROTOOPT
    close(tcp);
    int six = socket(AF_INET6, SOCK_DGRAM, 0);
    if (six >= 0) {
        TRY(setsockopt(six, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on));
        close(six);
    }
}

static void tracing(void)
{
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        _exit(0);
    }
    int status;
    if (child > 0 && waitpid(child, &status, 0) > 0 && WIFSTOPPED(status)) {
        struct user_regs_struct regs;
        TRY(ptrace(PTRACE_GETREGS, child, NULL, &regs));
        TRY(ptrace(PTRACE_PEEKDATA, child, (void *)&decoded, NULL));
        TRY(ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)PTRACE_O_TRACESYSGOOD));
        TRY(ptrace(PTRACE_CONT, child, NULL, NULL));
        waitpid(child, &status, 0);
    }
}

static void keys(void)
{
    long key = syscall(SYS_add_key, "user", "antinomie:workload", "benign payload", 14,
                       KEY_SPEC_PROCESS_KEYRING);
    decoded++;
    if (key >= 0) {
        char buffer[64];
        TRY(syscall(SYS_keyctl, KEYCTL_READ, key, buffer, sizeof buffer));
        TRY(syscall(SYS_keyctl, KEYCTL_DESCRIBE, key, buffer, sizeof buffer));
        TRY(syscall(SYS_keyctl, KEYCTL_REVOKE, key));
    }
}

static void controls(void)
{
    // In a child: no_new_privs and a seccomp filter must not reach the module.
    pid_t child = fork();
    if (child == 0) {
        char name[16];
        prctl(PR_SET_NAME, "ant-decoder");
        prctl(PR_GET_NAME, name);
        prctl(PR_SET_DUMPABLE, 1);
        prctl(PR_CAPBSET_READ, 0);
        prctl(PR_GET_SECCOMP);
        prctl(PR_SET_PDEATHSIG, 0);
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        struct sock_filter allow = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        struct sock_fprog program = {.len = 1, .filter = &allow};
        syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
        _exit(0);
    }
    if (child > 0)
        waitpid(child, NULL, 0);
    decoded += 9;
}

static void odd_arguments(const struct options *options)
{
    char buffer[64];
    TRY(read(-1, buffer, sizeof buffer));                       // EBADF
    TRY(syscall(SYS_write, 1, NULL, 10));                       // EFAULT
    TRY(mmap(NULL, (size_t)1 << 46, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)); // ENOMEM
    TRY(open("/nonexistent/antinomie/workload", O_RDONLY));      // ENOENT
    TRY(open(options->workdir, O_PATH | O_NOFOLLOW | O_DIRECTORY));
    TRY(ioctl(1, TIOCGWINSZ, buffer));
    TRY(ioctl(open("/dev/null", O_RDONLY), 0x5401feed, 0));     // ENOTTY
    int pipefd[2];
    if (pipe(pipefd) == 0) {
        int available;
        TRY(ioctl(pipefd[0], FIONREAD, &available));
        close(pipefd[0]);
        close(pipefd[1]);
    }
    int futex = 0;
    struct timespec zero = {0};
    TRY(syscall(SYS_futex, &futex, 0 /* FUTEX_WAIT */, 1, &zero, NULL, 0));
    struct statx info;
    TRY(statx(AT_FDCWD, options->workdir, AT_SYMLINK_NOFOLLOW, STATX_ALL, &info));
    // A semaphore set read and written as an array.
    int set = semget(IPC_PRIVATE, 4, IPC_CREAT | 0600);
    if (set >= 0) {
        unsigned short values[4] = {1, 2, 3, 4};
        TRY(semctl(set, 0, SETALL, values));
        TRY(semctl(set, 0, GETALL, values));
        TRY(semctl(set, 0, IPC_RMID));
    }
    // A queued signal with a value.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGRTMIN + 1);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    union sigval value = {.sival_int = 0x1234};
    TRY(sigqueue(getpid(), SIGRTMIN + 1, value));
    siginfo_t info_out;
    TRY(sigtimedwait(&mask, &info_out, &zero));
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

static void new_processes(void)
{
    struct clone_args args = {.exit_signal = SIGCHLD};
    long child = syscall(SYS_clone3, &args, sizeof args);
    if (child == 0)
        _exit(0);
    decoded++;
    if (child > 0)
        waitpid((pid_t)child, NULL, 0);
    char self[4096];
    ssize_t len = readlink("/proc/self/exe", self, sizeof self - 1);
    if (len > 0) {
        self[len] = 0;
        pid_t pid = fork();
        if (pid == 0) {
            int fd = open(self, O_RDONLY | O_CLOEXEC);
            char *argv[] = {self, "--child", "instant-exit", NULL};
            char *envp[] = {NULL};
            syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
            _exit(127);
        }
        if (pid > 0)
            waitpid(pid, NULL, 0);
        decoded++;
    }
}

static void privileged(const struct options *options, const char *name)
{
    if (need_root(options, name, "BPF program load")) {
        struct bpf_insn program[] = {
            {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
            {.code = BPF_JMP | BPF_EXIT},
        };
        union bpf_attr attr;
        memset(&attr, 0, sizeof attr);
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insns = (unsigned long)program;
        attr.insn_cnt = 2;
        attr.license = (unsigned long)"GPL";
        int fd = (int)syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof attr);
        decoded++;
        if (fd >= 0)
            close(fd);
    }
    if (need_root(options, name, "mount in a private namespace")) {
        pid_t child = fork();
        if (child == 0) {
            char target[512];
            snprintf(target, sizeof target, "%s/mnt", options->workdir);
            mkdir(target, 0700);
            if (unshare(CLONE_NEWNS) == 0 && mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0 &&
                mount("tmpfs", target, "tmpfs", MS_NOSUID | MS_NODEV, "size=1m,mode=0700") == 0)
                umount2(target, MNT_DETACH);
            _exit(0);
        }
        if (child > 0)
            waitpid(child, NULL, 0);
        decoded += 4;
    }
}

MODULE(decoder_variants)
{
    const char *name = "decoder-variants";
    long rounds = scaled(options, 1);
    decoded = 0;
    for (long i = 0; i < rounds; i++) {
        sockets();
        tracing();
        keys();
        controls();
        odd_arguments(options);
        new_processes();
    }
    privileged(options, name);
    count("decoder calls", decoded);
    pass(name, "%llu calls: socket options by level, ptrace, keyctl, prctl, seccomp, clone3, "
               "execveat, semctl arrays, queued signals, statx and failing arguments",
         decoded);
    return 0;
}
