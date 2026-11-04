// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// compat-calls-fixture.c — a benign 32-bit program (ia32 on x86-64 guests,
// AArch32 on arm64 guests) that makes the compat calls whose structures the
// recorder captures by their ILP32 layouts (contract revision 21, guest
// patches 49 and 50), each with raw system calls so that the compat (32-bit
// time, 32-bit pointer) variants are the ones called. Everything it touches
// is its own: a file and a directory under its work directory, a pipe, an
// AF_UNIX socket pair, a loopback UDP socket and a child that exits at once.
// It prints "compat calls done" and exits 0; tests/monitor/compat-calls-check.py
// checks the recording.
//
//   compat-calls-fixture [DIR]     work in DIR (default /tmp)
//
// Build: i686-linux-gnu-gcc -static -O1 -o compat-calls-fixture-ia32 compat-calls-fixture.c
//        arm-linux-gnueabihf-gcc -static -O1 -o compat-calls-fixture-arm compat-calls-fixture.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__i386__) && !defined(__arm__)
#error "a 32-bit x86 or ARM program"
#endif

// linux/net.h's socketcall numbers (i386 only).
#define CALL_SENDMSG 16
#define CALL_RECVMSG 17

static char work[256];

static void path(char *out, size_t size, const char *name)
{
    snprintf(out, size, "%s/%s", work, name);
}

// The patch 49 calls: the 32-bit time calls, rt_sigaction, the iovec calls,
// poll, _newselect, getdents and wait4.
static void structure_calls(void)
{
    struct { int32_t sec, nsec; } nap = {0, 1000000}, left = {0, 0}, now = {0, 0};
    struct { int32_t sec, usec; } tv = {0, 0};
    struct { uint32_t handler, flags, restorer, mask[2]; } act = {0, 0, 0, {0, 0}}, old;
    int pipefd[2], status = 0;
    char text[8] = "compat", back[8], dirents[1024];
    struct iovec out = {text, 6}, in = {back, sizeof back};
    struct pollfd ready;
    uint32_t readable[1] = {0};

    syscall(SYS_nanosleep, &nap, &left);
    syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &nap, &left);
    syscall(SYS_clock_gettime, CLOCK_REALTIME, &now);
    syscall(SYS_clock_getres, CLOCK_MONOTONIC, &now);
    syscall(SYS_gettimeofday, &tv, NULL);
    syscall(SYS_rt_sigaction, SIGUSR1, NULL, &old, 8);
    act.handler = 1; // SIG_IGN
    syscall(SYS_rt_sigaction, SIGUSR2, &act, &old, 8);
    if (pipe(pipefd) == 0) {
        syscall(SYS_writev, pipefd[1], &out, 1);
        ready.fd = pipefd[0];
        ready.events = POLLIN;
        ready.revents = 0;
        syscall(SYS_poll, &ready, 1, 0);
        readable[0] = 1u << pipefd[0];
        syscall(SYS__newselect, pipefd[0] + 1, readable, NULL, NULL, &tv);
        syscall(SYS_readv, pipefd[0], &in, 1);
        close(pipefd[0]);
        close(pipefd[1]);
    }
    int dir = open(work, O_RDONLY | O_DIRECTORY);
    if (dir >= 0) {
        syscall(SYS_getdents, dir, dirents, sizeof dirents);
        close(dir);
    }
    pid_t kid = fork();
    if (kid == 0)
        _exit(5);
    syscall(SYS_wait4, kid, &status, 0, NULL);
}

// The patch 50 file calls: the stat64 family, the old stat calls, statfs and
// statfs64, by path and by descriptor.
static void stat_calls(void)
{
    char file[300], buffer[256];
    int fd;

    path(file, sizeof file, "compat-stat");
    fd = open(file, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return;
    if (write(fd, "compat stat\n", 12) != 12)
        perror("write");
    syscall(SYS_stat64, file, buffer);
    syscall(SYS_lstat64, file, buffer);
    syscall(SYS_fstat64, fd, buffer);
    syscall(SYS_fstatat64, AT_FDCWD, file, buffer, 0);
    syscall(SYS_stat, file, buffer);
    syscall(SYS_lstat, file, buffer);
    syscall(SYS_fstat, fd, buffer);
    syscall(SYS_statfs, work, buffer);
    syscall(SYS_fstatfs, fd, buffer);
    syscall(SYS_statfs64, work, 84, buffer); // sizeof(struct statfs64) on both ABIs
    syscall(SYS_fstatfs64, fd, 84, buffer);
    close(fd);
    unlink(file);
}

// getitimer and setitimer of a timer that stays unarmed, and waitid.
static void timer_and_wait_calls(void)
{
    struct { int32_t interval_sec, interval_usec, value_sec, value_usec; } off = {0, 0, 0, 0}, old;
    char info[128], usage[72];

    syscall(SYS_getitimer, ITIMER_REAL, &old);
    syscall(SYS_setitimer, ITIMER_REAL, &off, &old);
    pid_t kid = fork();
    if (kid == 0)
        _exit(7);
    syscall(SYS_waitid, P_PID, kid, info, WEXITED, usage);
}

// sendmsg and recvmsg with a name (loopback UDP) and with control data
// (SCM_RIGHTS over an AF_UNIX pair), sendmmsg and recvmmsg (32- and 64-bit
// timeouts); on i386 also through socketcall.
static void message_calls(void)
{
    struct sockaddr_in to = {0}, from;
    socklen_t length = sizeof to;
    char payload[] = "compat-msg", back[32], control[CMSG_SPACE(sizeof(int))];
    struct iovec out = {payload, sizeof payload - 1}, in = {back, sizeof back};
    struct msghdr message;
    struct cmsghdr *header;
    int udp = socket(AF_INET, SOCK_DGRAM, 0), pair[2];

    if (udp < 0)
        return;
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(udp, (struct sockaddr *)&to, sizeof to) != 0 ||
        getsockname(udp, (struct sockaddr *)&to, &length) != 0) {
        close(udp);
        return;
    }
    memset(&message, 0, sizeof message);
    message.msg_name = &to;
    message.msg_namelen = sizeof to;
    message.msg_iov = &out;
    message.msg_iovlen = 1;
    syscall(SYS_sendmsg, udp, &message, 0);
    memset(&message, 0, sizeof message);
    message.msg_name = &from;
    message.msg_namelen = sizeof from;
    message.msg_iov = &in;
    message.msg_iovlen = 1;
    syscall(SYS_recvmsg, udp, &message, MSG_DONTWAIT);
#ifdef __i386__
    {
        unsigned long args[3] = {(unsigned long)udp, (unsigned long)&message, 0};

        memset(&message, 0, sizeof message);
        message.msg_name = &to;
        message.msg_namelen = sizeof to;
        message.msg_iov = &out;
        message.msg_iovlen = 1;
        syscall(SYS_socketcall, CALL_SENDMSG, args);
        memset(&message, 0, sizeof message);
        message.msg_name = &from;
        message.msg_namelen = sizeof from;
        message.msg_iov = &in;
        message.msg_iovlen = 1;
        args[2] = MSG_DONTWAIT;
        syscall(SYS_socketcall, CALL_RECVMSG, args);
    }
#endif
    {
        struct mmsghdr batch[2], received[2];
        struct iovec outs[2] = {{payload, 6}, {payload + 7, 3}}, ins[2] = {{back, 16}, {back + 16, 16}};
        struct { int32_t sec, nsec; } wait32 = {1, 0};
        struct { int64_t sec, nsec; } wait64 = {1, 0};

        memset(batch, 0, sizeof batch);
        memset(received, 0, sizeof received);
        for (int i = 0; i < 2; i++) {
            batch[i].msg_hdr.msg_name = &to;
            batch[i].msg_hdr.msg_namelen = sizeof to;
            batch[i].msg_hdr.msg_iov = &outs[i];
            batch[i].msg_hdr.msg_iovlen = 1;
            received[i].msg_hdr.msg_iov = &ins[i];
            received[i].msg_hdr.msg_iovlen = 1;
        }
        syscall(SYS_sendmmsg, udp, batch, 2, 0);
        syscall(SYS_recvmmsg, udp, received, 2, MSG_DONTWAIT, &wait32);
#ifdef SYS_recvmmsg_time64
        syscall(SYS_sendmmsg, udp, batch, 1, 0);
        syscall(SYS_recvmmsg_time64, udp, received, 1, MSG_DONTWAIT, &wait64);
#else
        (void)wait64;
#endif
    }
    close(udp);
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0)
        return;
    memset(&message, 0, sizeof message);
    memset(control, 0, sizeof control);
    message.msg_iov = &out;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &pair[0], sizeof(int));
    syscall(SYS_sendmsg, pair[1], &message, 0);
    memset(&message, 0, sizeof message);
    memset(control, 0, sizeof control);
    message.msg_iov = &in;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    if (syscall(SYS_recvmsg, pair[0], &message, MSG_DONTWAIT) >= 0) {
        header = CMSG_FIRSTHDR(&message);
        if (header && header->cmsg_type == SCM_RIGHTS) {
            int passed;

            memcpy(&passed, CMSG_DATA(header), sizeof passed);
            close(passed);
        }
    }
    close(pair[0]);
    close(pair[1]);
}

int main(int argc, char **argv)
{
    snprintf(work, sizeof work, "%s", argc > 1 ? argv[1] : "/tmp");
    structure_calls();
    stat_calls();
    timer_and_wait_calls();
    message_calls();
    printf("compat calls done\n");
    return 0;
}
