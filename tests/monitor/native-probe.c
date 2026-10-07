// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/sched.h>
#include <linux/dqblk_xfs.h>
#include <linux/io_uring.h>
#include <linux/kexec.h>
#include <linux/keyctl.h>
#include <linux/openat2.h>
#include <linux/perf_event.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <asm/ldt.h>
#include <asm/prctl.h>
#include <elf.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/quota.h>
#include <sys/sem.h>
#include <sys/rseq.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/times.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#ifndef PR_GET_AUXV
#define PR_GET_AUXV 0x41555856
#endif
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
#endif

#ifndef SYS_quotactl_fd
#define SYS_quotactl_fd 443
#endif

static const char marker[] = "ANTINOMIE-NATIVE-PAYLOAD";
static char mount_options[4096] __attribute__((aligned(4096))) = "size=1m,mode=0700";
static unsigned long ptrace_word = 0x414e54494e4f4d49UL;
static unsigned failures;
static unsigned case_count;
static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t monotonic_ns(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time)) abort();
    return (uint64_t)time.tv_sec * 1000000000 + time.tv_nsec;
}

/* Labeled cases are compared with tests/monitor/fixtures/native-schema. A
 * kernel-dependent value is printed as "observed" hex under its field key.
 */
static long observed_labeled(const char *label, const char *name, long nr, long value,
                             int expected_errno, uint64_t started_ns, uint64_t finished_ns,
                             const char *observed_members)
{
    int error = value < 0 ? errno : 0;
    const char *verdict = "PASS";

    if (value < 0) {
        if (error == expected_errno && expected_errno)
            verdict = "EXPECTED_REJECTION";
        else if (error == ENOSYS || error == EOPNOTSUPP || error == EPERM ||
                 error == EACCES || error == ENODEV)
            verdict = "SKIP";
        else
            verdict = "FAIL";
    } else if (expected_errno) {
        verdict = "FAIL";
    }
    pthread_mutex_lock(&output_lock);
    if (!strcmp(verdict, "FAIL"))
        failures++;
    printf("ANT_CASE {\"name\":\"%s\",\"number\":%ld,\"result\":%ld,"
           "\"errno\":%d,\"verdict\":\"%s\",\"case_id\":%u,\"tid\":%ld,"
           "\"started_ns\":%llu,\"finished_ns\":%llu", name, nr, value,
           error, verdict, ++case_count, syscall(SYS_gettid),
           (unsigned long long)started_ns, (unsigned long long)finished_ns);
    if (label)
        printf(",\"label\":\"%s\"", label);
    if (observed_members && *observed_members)
        printf(",\"observed\":{%s}", observed_members);
    puts("}");
    pthread_mutex_unlock(&output_lock);
    /* Functional coverage is paced; overflow is a separate lossy stress test. */
    struct timespec pause = {0, 2000000};
    nanosleep(&pause, NULL);
    errno = error;
    return value;
}

static void require(int condition, const char *what);

static long observed(const char *name, long nr, long value, int expected_errno,
                     uint64_t started_ns, uint64_t finished_ns)
{
    return observed_labeled(NULL, name, nr, value, expected_errno, started_ns,
                            finished_ns, NULL);
}

/* One labeled call at a time per thread: CALL records it, observe() adds the
 * bytes the program saw under a field key, and report() prints the case.
 */
struct pending_case {
    const char *label, *name;
    long nr, value;
    int expected, error;
    uint64_t started_ns, finished_ns;
    size_t used;
    char observed[65536];
};
static __thread struct pending_case pending;

static void observe(const char *key, const void *data, size_t length)
{
    size_t room = sizeof(pending.observed) - pending.used;
    int written = snprintf(pending.observed + pending.used, room, "%s\"%s\":\"",
                           pending.used ? "," : "", key);

    require(written > 0 && (size_t)written + 2 * length + 2 <= room, "observed buffer");
    pending.used += written;
    for (size_t i = 0; i < length; i++)
        pending.used += sprintf(pending.observed + pending.used, "%02x",
                                ((const unsigned char *)data)[i]);
    pending.used += sprintf(pending.observed + pending.used, "\"");
}

static long report(void)
{
    errno = pending.error;
    return observed_labeled(pending.label, pending.name, pending.nr, pending.value,
                            pending.expected, pending.started_ns, pending.finished_ns,
                            pending.observed);
}

#define OBSERVE(name, expected, ...) ({ \
    uint64_t ant_case_internal_start = monotonic_ns(); \
    long ant_case_internal_result = syscall(SYS_##name, __VA_ARGS__); \
    int ant_case_internal_errno = errno; \
    uint64_t ant_case_internal_end = monotonic_ns(); \
    errno = ant_case_internal_errno; \
    observed(#name, SYS_##name, ant_case_internal_result, expected, \
             ant_case_internal_start, ant_case_internal_end); \
})
#define CALL(case_label, sys, expected_errno, ...) ({ \
    pending.label = case_label; pending.name = #sys; pending.nr = SYS_##sys; \
    pending.expected = expected_errno; pending.used = 0; pending.observed[0] = 0; \
    pending.started_ns = monotonic_ns(); \
    pending.value = syscall(SYS_##sys, __VA_ARGS__); \
    pending.error = errno; \
    pending.finished_ns = monotonic_ns(); \
    pending.value; \
})
#define CASE(case_label, sys, expected_errno, ...) ({ \
    CALL(case_label, sys, expected_errno, __VA_ARGS__); \
    report(); \
})
#define SOCKSET(label, expected, fd, level, option, value, len) \
    CASE(label, setsockopt, expected, fd, level, option, value, len)
#define SOCKGET(label, expected, fd, level, option, buffer, len) ({ \
    CALL(label, getsockopt, expected, fd, level, option, buffer, len); \
    if (pending.value == 0) \
        observe("arg3.optval", buffer, *(len)); \
    report(); \
})
#define TEST(name, ...) OBSERVE(name, 0, __VA_ARGS__)
#define REJECT(name, error, ...) OBSERVE(name, error, __VA_ARGS__)

static void require(int condition, const char *what)
{
    if (!condition) {
        fprintf(stderr, "native probe invariant failed: %s\n", what);
        exit(2);
    }
}

static void file_cases(void)
{
    char data[128] = {0}, cwd[4096], names[4096];
    struct stat statbuf;
    struct statx statxbuf;
    struct statfs fsbuf;
    struct open_how how = {.flags = O_RDONLY | O_CLOEXEC};
    struct iovec iov[2] = {{(void *)marker, 8}, {(void *)marker + 8, sizeof(marker) - 8}};
    struct timespec timestamp[2] = {{0, UTIME_OMIT}, {0, UTIME_OMIT}};
    int fd = TEST(openat, AT_FDCWD, "payload", O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    int other;

    require(fd >= 0, "private file creation");
    require(TEST(write, fd, marker, sizeof(marker)) == sizeof(marker), "write");
    TEST(lseek, fd, 0, SEEK_SET);
    require(TEST(read, fd, data, sizeof(data)) == sizeof(marker), "read size");
    require(!memcmp(data, marker, sizeof(marker)), "read payload");
    TEST(pwrite64, fd, marker, sizeof(marker), 0);
    TEST(pread64, fd, data, sizeof(data), 0);
    TEST(lseek, fd, 0, SEEK_SET);
    TEST(writev, fd, iov, 2);
    iov[0] = (struct iovec){data, 8};
    iov[1] = (struct iovec){data + 8, sizeof(data) - 8};
    TEST(lseek, fd, 0, SEEK_SET);
    TEST(readv, fd, iov, 2);
    TEST(preadv, fd, iov, 2, 0UL, 0UL);
    TEST(pwritev, fd, iov, 2, 0UL, 0UL);
    TEST(fstat, fd, &statbuf);
    TEST(stat, "payload", &statbuf);
    TEST(lstat, "payload", &statbuf);
    TEST(newfstatat, AT_FDCWD, "payload", &statbuf, AT_SYMLINK_NOFOLLOW);
    TEST(statx, AT_FDCWD, "payload", 0, STATX_BASIC_STATS, &statxbuf);
    TEST(statfs, ".", &fsbuf);
    TEST(fstatfs, fd, &fsbuf);
    TEST(fsync, fd);
    TEST(fdatasync, fd);
    TEST(ftruncate, fd, sizeof(marker));
    TEST(fchmod, fd, 0600);
    TEST(chmod, "payload", 0600);
    TEST(access, "payload", R_OK);
    TEST(faccessat, AT_FDCWD, "payload", R_OK);
    TEST(faccessat2, AT_FDCWD, "payload", R_OK, AT_EACCESS);
    TEST(utimensat, AT_FDCWD, "payload", timestamp, 0);
    TEST(fcntl, fd, F_GETFL, 0);
    other = TEST(dup, fd);
    if (other >= 0) {
        TEST(dup2, fd, other);
        TEST(dup3, fd, other, O_CLOEXEC);
        TEST(close, other);
    }
    other = TEST(open, "payload", O_RDONLY, 0);
    if (other >= 0) TEST(close, other);
    other = TEST(openat2, AT_FDCWD, "payload", &how, sizeof(how));
    if (other >= 0) TEST(close, other);
    TEST(setxattr, "payload", "user.antinomie", marker, sizeof(marker), 0);
    TEST(getxattr, "payload", "user.antinomie", data, sizeof(data));
    TEST(listxattr, "payload", names, sizeof(names));
    TEST(removexattr, "payload", "user.antinomie");
    REJECT(write, EFAULT, fd, (void *)1, 32);
    TEST(getcwd, cwd, sizeof(cwd));
    TEST(link, "payload", "hardlink");
    TEST(unlink, "hardlink");
    TEST(symlink, "payload", "symlink");
    TEST(readlink, "symlink", data, sizeof(data));
    TEST(readlinkat, AT_FDCWD, "symlink", data, sizeof(data));
    TEST(unlinkat, AT_FDCWD, "symlink", 0);
    TEST(rename, "payload", "renamed");
    TEST(renameat, AT_FDCWD, "renamed", AT_FDCWD, "payload");
    TEST(mkdir, "child", 0700);
    TEST(rmdir, "child");
    TEST(mkdirat, AT_FDCWD, "child", 0700);
    TEST(unlinkat, AT_FDCWD, "child", AT_REMOVEDIR);
    other = TEST(openat, AT_FDCWD, ".", O_RDONLY | O_DIRECTORY, 0);
    if (other >= 0) {
        TEST(getdents64, other, names, sizeof(names));
        TEST(close, other);
    }
    TEST(close, fd);
    TEST(unlink, "payload");
}

static void descriptor_cases(void)
{
    int pipes[2], sockets[2], value = 0;
    uint64_t one = 1;
    char data[128] = {0}, ancillary[64];
    struct iovec iov = {data, sizeof(data)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = ancillary, .msg_controllen = sizeof(ancillary)};
    struct pollfd pollfd;
    struct epoll_event event = {.events = EPOLLIN}, ready;
    struct itimerspec timer = {{0}, {0, 1000000}}, old_timer;
    int epoll, eventfd, timerfd;

    require(TEST(pipe2, pipes, O_CLOEXEC | O_NONBLOCK) == 0, "pipe");
    TEST(write, pipes[1], marker, sizeof(marker));
    TEST(ioctl, pipes[0], FIONREAD, &value);
    require(value == sizeof(marker), "FIONREAD");
    pollfd = (struct pollfd){pipes[0], POLLIN, 0};
    TEST(poll, &pollfd, 1, 0);
    struct timespec zero = {0};
    TEST(ppoll, &pollfd, 1, &zero, NULL, 8);
    epoll = TEST(epoll_create1, EPOLL_CLOEXEC);
    if (epoll >= 0) {
        TEST(epoll_ctl, epoll, EPOLL_CTL_ADD, pipes[0], &event);
        TEST(epoll_wait, epoll, &ready, 1, 0);
        TEST(epoll_pwait, epoll, &ready, 1, 0, NULL, 8);
        TEST(close, epoll);
    }
    TEST(read, pipes[0], data, sizeof(data));
    TEST(close, pipes[0]); TEST(close, pipes[1]);
    eventfd = TEST(eventfd2, 0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (eventfd >= 0) {
        TEST(write, eventfd, &one, sizeof(one));
        TEST(read, eventfd, &one, sizeof(one));
        TEST(close, eventfd);
    }
    timerfd = TEST(timerfd_create, CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (timerfd >= 0) {
        TEST(timerfd_settime, timerfd, 0, &timer, &old_timer);
        TEST(timerfd_gettime, timerfd, &old_timer);
        TEST(close, timerfd);
    }
    require(TEST(socketpair, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sockets) == 0,
            "local socketpair");
    TEST(sendto, sockets[0], marker, sizeof(marker), MSG_NOSIGNAL, NULL, 0);
    TEST(recvfrom, sockets[1], data, sizeof(data), 0, NULL, NULL);
    iov = (struct iovec){(void *)marker, sizeof(marker)};
    message.msg_control = NULL; message.msg_controllen = 0;
    TEST(sendmsg, sockets[0], &message, MSG_NOSIGNAL);
    iov = (struct iovec){data, sizeof(data)};
    message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
    TEST(recvmsg, sockets[1], &message, 0);
    TEST(shutdown, sockets[0], SHUT_RDWR);
    TEST(close, sockets[0]); TEST(close, sockets[1]);
}

/* Slice 2A: never-connected sockets and a local pair; no network I/O. */
static void sockopt_cases(void)
{
    static const char unknown[] = "ANTINOMIE-SOCKOPT";
    struct sock_filter accept_all = BPF_STMT(BPF_RET | BPF_K, 0xffffffff);
    struct sock_fprog program = {1, &accept_all};
    struct linger linger = {1, 5};
    struct { long seconds, microseconds; } old_timeout = {2, 500000};
    struct { int64_t seconds, microseconds; } new_timeout = {3, 0};
    struct ip_mreqn group = {.imr_multiaddr.s_addr = htonl(0xef010203)};
    unsigned char buffer[512];
    int local[2], value;
    socklen_t length;
    int tcp4 = TEST(socket, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int tcp6 = TEST(socket, AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);

    require(tcp4 >= 0 && tcp6 >= 0, "unconnected TCP sockets");
    require(TEST(socketpair, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, local) == 0,
            "local stream pair");
    value = 65536;
    SOCKSET("sockopt.so_rcvbuf.set", 0, tcp4, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value));
    length = 4;
    SOCKGET("sockopt.so_rcvbuf.get", 0, tcp4, SOL_SOCKET, SO_RCVBUF, buffer, &length);
    length = 16;
    SOCKGET("sockopt.so_rcvbuf.get_oversize", 0, tcp4, SOL_SOCKET, SO_RCVBUF, buffer, &length);
    SOCKSET("sockopt.so_linger.set", 0, tcp4, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
    length = sizeof(linger);
    SOCKGET("sockopt.so_linger.get", 0, tcp4, SOL_SOCKET, SO_LINGER, buffer, &length);
    SOCKSET("sockopt.so_rcvtimeo_old.set", 0, tcp4, SOL_SOCKET, SO_RCVTIMEO_OLD,
            &old_timeout, sizeof(old_timeout));
    SOCKSET("sockopt.so_rcvtimeo_new.set", 0, tcp4, SOL_SOCKET, SO_RCVTIMEO_NEW,
            &new_timeout, sizeof(new_timeout));
    length = 12;
    SOCKGET("sockopt.so_peercred.get", 0, local[0], SOL_SOCKET, SO_PEERCRED, buffer, &length);
    SOCKSET("sockopt.so_attach_filter.set", 0, local[0], SOL_SOCKET, SO_ATTACH_FILTER,
            &program, sizeof(program));
    length = 1;
    SOCKGET("sockopt.so_get_filter.get", 0, local[0], SOL_SOCKET, SO_GET_FILTER, buffer, &length);
    SOCKSET("sockopt.so_bindtodevice.set", 0, tcp4, SOL_SOCKET, SO_BINDTODEVICE, "lo", 2);
    value = 1;
    SOCKSET("sockopt.tcp_nodelay.set", 0, tcp4, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
    length = 16;
    SOCKGET("sockopt.tcp_congestion.get", 0, tcp4, IPPROTO_TCP, TCP_CONGESTION, buffer, &length);
    length = 104;
    SOCKGET("sockopt.tcp_info.get", 0, tcp4, IPPROTO_TCP, TCP_INFO, buffer, &length);
    value = 64;
    SOCKSET("sockopt.ip_ttl.set", 0, tcp4, IPPROTO_IP, IP_TTL, &value, sizeof(value));
    value = 1;
    SOCKSET("sockopt.ipv6_v6only.set", 0, tcp6, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value));
    value = 0;
    SOCKSET("sockopt.ipv6_tclass.set", 0, tcp6, IPPROTO_IPV6, IPV6_TCLASS, &value, sizeof(value));
    SOCKSET("sockopt.ip_add_membership.set", EPROTO, tcp4, IPPROTO_IP, IP_ADD_MEMBERSHIP,
            &group, sizeof(group));
    SOCKSET("sockopt.unknown.set", ENOPROTOOPT, tcp4, SOL_SOCKET, 0x7fff,
            unknown, sizeof(unknown) - 1);
    length = 8;
    SOCKGET("sockopt.unknown.get", ENOPROTOOPT, tcp4, SOL_SOCKET, 0x7fff, buffer, &length);
    SOCKSET("sockopt.short_int.set", EINVAL, tcp4, SOL_SOCKET, SO_KEEPALIVE, &value, 2);
    SOCKSET("sockopt.fault.set", EFAULT, tcp4, SOL_SOCKET, SO_RCVBUF, (void *)1, 4);
    SOCKSET("sockopt.negative_optlen.set", EINVAL, tcp4, SOL_SOCKET, SO_RCVBUF, &value, -1);
    TEST(close, local[0]); TEST(close, local[1]); TEST(close, tcp6); TEST(close, tcp4);
}

/* Slice 2B: selector families. Every effect stays inside the probe or a child. */
/* A forked child inherits the case and failure counters; give each child its
 * own ID range and count only its own failures in its exit status.
 */
static void child_case_range(unsigned index)
{
    case_count = 100000 * index;
    failures = 0;
}

static void wait_child(pid_t child, const char *what)
{
    int status;

    require(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
            WEXITSTATUS(status) == 0, what);
}

static void prctl_cases(void)
{
    static volatile char selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    struct sock_filter allow = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog program = {1, &allow};
    unsigned long auxv[64], mm_auxv[2] = {1, 2}, tid_address;
    char original[16] = {0}, name[16];
    int value;
    long result;
    pid_t child;
    void *mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    require(mapping != MAP_FAILED, "prctl mapping");
    require(syscall(SYS_prctl, PR_GET_NAME, original, 0, 0, 0) == 0, "current thread name");
    CASE("prctl.set_name", prctl, 0, PR_SET_NAME, "antprobe", 0, 0, 0);
    CASE("prctl.get_name", prctl, 0, PR_GET_NAME, name, 0, 0, 0);
    TEST(prctl, PR_SET_NAME, original, 0, 0, 0);
    CASE("prctl.set_pdeathsig", prctl, 0, PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0);
    CASE("prctl.get_pdeathsig", prctl, 0, PR_GET_PDEATHSIG, &value, 0, 0, 0);
    TEST(prctl, PR_SET_PDEATHSIG, 0, 0, 0, 0);
    CALL("prctl.get_child_subreaper", prctl, 0, PR_GET_CHILD_SUBREAPER, &value, 0, 0, 0);
    observe("arg1.value", &value, sizeof(value));
    report();
    CASE("prctl.get_tsc", prctl, 0, PR_GET_TSC, &value, 0, 0, 0);
    CALL("prctl.get_tid_address", prctl, 0, PR_GET_TID_ADDRESS, &tid_address, 0, 0, 0);
    observe("arg1.tid_address", &tid_address, sizeof(tid_address));
    report();
    result = CALL("prctl.get_auxv", prctl, 0, PR_GET_AUXV, auxv, sizeof(auxv), 0, 0);
    if (result > 0)
        observe("arg1.auxv", auxv, (size_t)result < sizeof(auxv) ? (size_t)result : sizeof(auxv));
    report();
    CASE("prctl.set_mm_auxv", prctl, EPERM, PR_SET_MM, PR_SET_MM_AUXV, mm_auxv,
         sizeof(mm_auxv), 0);
    /* CONFIG_ANON_VMA_NAME differs by kernel profile; learn it first. */
    value = syscall(SYS_prctl, PR_SET_VMA, PR_SET_VMA_ANON_NAME, mapping, 4096, "probe") ?
        errno : 0;
    CASE("prctl.set_vma_anon_name", prctl, value, PR_SET_VMA, PR_SET_VMA_ANON_NAME,
         mapping, 4096, "ant-probe-vma");
    CASE("prctl.unknown", prctl, EINVAL, 0x7fffffff, 0, 0, 0, 0);
    child = fork();
    require(child >= 0, "seccomp child");
    if (!child) {
        child_case_range(1);
        CASE("prctl.set_no_new_privs", prctl, 0, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        CASE("prctl.set_seccomp_filter", prctl, 0, PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
             &program, 0, 0);
        _exit(failures ? 3 : 0);
    }
    wait_child(child, "seccomp child exit");
    child = fork();
    require(child >= 0, "dispatch child");
    if (!child) {
        child_case_range(2);
        CASE("prctl.set_syscall_user_dispatch", prctl, 0, PR_SET_SYSCALL_USER_DISPATCH,
             PR_SYS_DISPATCH_ON, 0, 0, &selector);
        _exit(failures ? 3 : 0);
    }
    wait_child(child, "dispatch child exit");
    TEST(munmap, mapping, 4096);
}

static void ptrace_cases(void)
{
    struct __ptrace_peeksiginfo_args peek = {0, 0, 1};
    struct user_regs_struct regs;
    struct user_fpregs_struct fpregs;
    struct user_desc desc;
    unsigned char regset[512], info[88];
    struct iovec iov = {regset, sizeof(regset)};
    unsigned long word = 0, message, fs;
    uint64_t mask;
    siginfo_t siginfo, peeked[1];
    sigset_t block;
    long result;
    pid_t child;
    int status;

    child = fork();
    require(child >= 0, "tracee");
    if (!child) {
        child_case_range(3);
        sigemptyset(&block);
        sigaddset(&block, SIGUSR1);
        sigprocmask(SIG_BLOCK, &block, NULL);
        CASE("ptrace.traceme", ptrace, 0, PTRACE_TRACEME, 0, 0, 0);
        raise(SIGUSR1);
        raise(SIGSTOP);
        _exit(failures ? 3 : 0);
    }
    require(waitpid(child, &status, 0) == child && WIFSTOPPED(status) &&
            WSTOPSIG(status) == SIGSTOP, "tracee stop");
    CASE("ptrace.peekdata", ptrace, 0, PTRACE_PEEKDATA, child, &ptrace_word, &word);
    require(word == 0x414e54494e4f4d49UL, "tracee word");
    CASE("ptrace.pokedata", ptrace, 0, PTRACE_POKEDATA, child, &ptrace_word,
         0x5345545345544553UL);
    CALL("ptrace.peekuser", ptrace, 0, PTRACE_PEEKUSER, child,
         offsetof(struct user, regs.orig_rax), &word);
    observe("arg3.word", &word, sizeof(word));
    report();
    CALL("ptrace.getregs", ptrace, 0, PTRACE_GETREGS, child, 0, &regs);
    observe("arg3.regs", &regs, sizeof(regs));
    report();
    CALL("ptrace.setregs", ptrace, 0, PTRACE_SETREGS, child, 0, &regs);
    observe("arg3.regs", &regs, sizeof(regs));
    report();
    CALL("ptrace.getfpregs", ptrace, 0, PTRACE_GETFPREGS, child, 0, &fpregs);
    observe("arg3.fpregs", &fpregs, sizeof(fpregs));
    report();
    CALL("ptrace.getregset", ptrace, 0, PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
    observe("arg3.iovec.data", regset, iov.iov_len);
    report();
    CALL("ptrace.setregset", ptrace, 0, PTRACE_SETREGSET, child, NT_PRSTATUS, &iov);
    observe("arg3.iovec.data", regset, iov.iov_len);
    report();
    CALL("ptrace.getsiginfo", ptrace, 0, PTRACE_GETSIGINFO, child, 0, &siginfo);
    observe("arg3.siginfo", &siginfo, sizeof(siginfo));
    report();
    CALL("ptrace.getsigmask", ptrace, 0, PTRACE_GETSIGMASK, child, sizeof(mask), &mask);
    observe("arg3.sigmask", &mask, sizeof(mask));
    report();
    CASE("ptrace.getsigmask_badsize", ptrace, EINVAL, PTRACE_GETSIGMASK, child, 4, &mask);
    result = CALL("ptrace.peeksiginfo", ptrace, 0, PTRACE_PEEKSIGINFO, child, &peek, peeked);
    if (result == 1)
        observe("arg3.siginfo", peeked, sizeof(peeked));
    report();
    CALL("ptrace.geteventmsg", ptrace, 0, PTRACE_GETEVENTMSG, child, 0, &message);
    observe("arg3.message", &message, sizeof(message));
    report();
    CASE("ptrace.setoptions", ptrace, 0, PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    result = CALL("ptrace.get_syscall_info", ptrace, 0, PTRACE_GET_SYSCALL_INFO, child,
                  sizeof(info), info);
    if (result > 0)
        observe("arg3.info", info, (size_t)result < sizeof(info) ? (size_t)result : sizeof(info));
    report();
    CALL("ptrace.arch_prctl_get_fs", ptrace, 0, PTRACE_ARCH_PRCTL, child, &fs, ARCH_GET_FS);
    observe("arg2.value", &fs, sizeof(fs));
    report();
    CALL("ptrace.get_thread_area", ptrace, 0, PTRACE_GET_THREAD_AREA, child, 12, &desc);
    observe("arg3.desc", &desc, sizeof(desc));
    report();
    CASE("ptrace.unknown", ptrace, EIO, 0x7fff, child, 0, 0);
    CASE("ptrace.cont", ptrace, 0, PTRACE_CONT, child, 0, 0);
    wait_child(child, "tracee exit");
}

static void keyctl_cases(void)
{
    char buffer[256];
    struct iovec iov = {"abc", 3};
    struct keyctl_pkey_query query;
    struct keyctl_dh_params dh;
    long key, result;

    key = TEST(add_key, "user", "ant:probe", "secret-payload", 14, KEY_SPEC_PROCESS_KEYRING);
    require(key > 0, "probe key");
    dh = (struct keyctl_dh_params){.private = key, .prime = key, .base = key};
    result = CALL("keyctl.describe", keyctl, 0, KEYCTL_DESCRIBE, key, buffer, sizeof(buffer));
    if (result > 0)
        observe("arg2.buffer", buffer,
                (size_t)result < sizeof(buffer) ? (size_t)result : sizeof(buffer));
    report();
    CASE("keyctl.read", keyctl, 0, KEYCTL_READ, key, buffer, 64);
    require(!memcmp(buffer, "secret-payload", 14), "key payload");
    CASE("keyctl.read_query", keyctl, 0, KEYCTL_READ, key, NULL, 0);
    CASE("keyctl.update", keyctl, 0, KEYCTL_UPDATE, key, "updated", 7);
    CASE("keyctl.search", keyctl, 0, KEYCTL_SEARCH, KEY_SPEC_PROCESS_KEYRING, "user",
         "ant:probe", 0);
    result = CALL("keyctl.capabilities", keyctl, 0, KEYCTL_CAPABILITIES, buffer, 16);
    if (result > 0)
        observe("arg1.buffer", buffer, result < 16 ? (size_t)result : 16);
    report();
    CALL("keyctl.dh_compute", keyctl, EINVAL, KEYCTL_DH_COMPUTE, &dh, buffer, 64, NULL);
    observe("arg1.params", &dh, sizeof(dh));
    report();
    CASE("keyctl.pkey_query", keyctl, EOPNOTSUPP, KEYCTL_PKEY_QUERY, key, 0, "enc=raw", &query);
    CASE("keyctl.instantiate_iov", keyctl, EPERM, KEYCTL_INSTANTIATE_IOV, key, &iov, 1,
         KEY_SPEC_PROCESS_KEYRING);
    CASE("keyctl.get_keyring_id", keyctl, 0, KEYCTL_GET_KEYRING_ID, KEY_SPEC_PROCESS_KEYRING, 0);
    CASE("keyctl.join_session", keyctl, 0, KEYCTL_JOIN_SESSION_KEYRING, "ant-session");
    CASE("keyctl.unknown", keyctl, EOPNOTSUPP, 0x7fff, 0, 0, 0, 0);
    CASE("keyctl.revoke", keyctl, 0, KEYCTL_REVOKE, key);
}

static void sysfs_cases(void)
{
    char buffer[256];
    long index = CASE("sysfs.index", sysfs, 0, 1, "proc");

    require(index >= 0, "proc filesystem index");
    CASE("sysfs.name", sysfs, 0, 2, index, buffer);
    require(!strcmp(buffer, "proc"), "proc filesystem name");
    CASE("sysfs.count", sysfs, 0, 3);
    CASE("sysfs.bad_index", sysfs, EINVAL, 2, 9999, buffer);
    CASE("sysfs.unknown", sysfs, EINVAL, 9);
}

/* Slice 2C: mount, quota control, kexec_load and rseq. */
static void *rseq_thread(void *unused)
{
    char *area = (char *)__builtin_thread_pointer() + __rseq_offset;

    /* A thread shares the process's case and failure counters. */
    (void)unused;
    CALL("rseq.unregister", rseq, 0, area, 32, RSEQ_FLAG_UNREGISTER, RSEQ_SIG);
    observe("arg0.rseq", area, 32);
    report();
    CASE("rseq.register", rseq, 0, area, 32, 0, RSEQ_SIG);
    return NULL;
}

static void slice_2c_cases(void)
{
    char *area = (char *)__builtin_thread_pointer() + __rseq_offset;
    struct kexec_segment segment = {"ANTINOMIE-KEXEC", 15, (void *)0x1000000, 4096};
    struct kexec_segment segments[17] = {0};
    struct fs_quota_statv statv = {.qs_version = FS_QSTATV_VERSION1};
    struct dqblk quota = {.dqb_bhardlimit = 1};
    unsigned int flags = 1, format;
    pthread_t thread;
    char *edge;
    int directory;
    pid_t child;

    require(mkdir("mnt", 0700) == 0, "private mount point");
    child = fork();
    require(child >= 0, "mount namespace child");
    if (!child) {
        child_case_range(5);
        require(unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0, "private user and mount namespace");
        /* A fresh child has not mapped .rodata yet and the recorder's no-fault
         * copy cannot page it in; touch the strings so this case tests decoding.
         */
        for (const char *const *text = (const char *const[]){"ant-tmpfs", "mnt", "tmpfs", NULL};
             *text; text++)
            for (const volatile char *byte = *text; *byte; byte++)
                ;
        CASE("mount.userns_tmpfs", mount, 0, "ant-tmpfs", "mnt", "tmpfs", MS_NOSUID | MS_NODEV,
             mount_options);
        TEST(umount2, "mnt", 0);
        _exit(failures ? 3 : 0);
    }
    wait_child(child, "mount namespace child exit");
    CASE("mount.unprivileged", mount, EPERM, "none", "mnt", "tmpfs", 0, NULL);
    edge = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(edge != MAP_FAILED && mprotect(edge + 4096, 4096, PROT_NONE) == 0, "edge page");
    memcpy(edge + 4096 - 16, "mode=0700", 9);
    CASE("mount.boundary_options", mount, EPERM, "none", "mnt", "tmpfs", 0, edge + 4096 - 16);
    CASE("mount.unknown_fstype", mount, EPERM, "none", "mnt", "ant-missingfs", 0, NULL);
    TEST(munmap, edge, 8192);
    require(rmdir("mnt") == 0, "mount point cleanup");

    CASE("quotactl.getfmt_missing_device", quotactl, ENOENT, QCMD(Q_GETFMT, USRQUOTA),
         "/dev/ant-missing", 0, &format);
    CASE("quotactl.quotaon_paths", quotactl, ENOENT, QCMD(Q_QUOTAON, USRQUOTA),
         "/dev/ant-missing", QFMT_VFS_V1, "aquota.user");
    CASE("quotactl.xquotaon_flags", quotactl, ENOENT, QCMD(Q_XQUOTAON, USRQUOTA),
         "/dev/ant-missing", 0, &flags);
    CASE("quotactl.xgetqstatv_version", quotactl, ENOENT, QCMD(Q_XGETQSTATV, USRQUOTA),
         "/dev/ant-missing", 0, &statv);
    directory = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(directory >= 0, "quota directory");
    CASE("quotactl_fd.getfmt_no_quota", quotactl_fd, ESRCH, directory, QCMD(Q_GETFMT, USRQUOTA),
         0, &format);
    CALL("quotactl_fd.setquota_input", quotactl_fd, EPERM, directory,
         QCMD(Q_SETQUOTA, USRQUOTA), 0, &quota);
    observe("arg3.dqblk", &quota, sizeof(quota));
    report();
    close(directory);

    CASE("kexec_load.unprivileged", kexec_load, EPERM, 0, 1, &segment, 0);
    CASE("kexec_load.too_many_segments", kexec_load, EPERM, 0, 17, segments, 0);

    require(__rseq_size > 0, "glibc rseq registration");
    CASE("rseq.register_again", rseq, EBUSY, area, 32, 0, RSEQ_SIG);
    CASE("rseq.unregister_badsig", rseq, EPERM, area, 32, RSEQ_FLAG_UNREGISTER, 0xdead);
    require(!pthread_create(&thread, NULL, rseq_thread, NULL) &&
            !pthread_join(thread, NULL), "rseq thread");
}

/* Slice 2H, unprivileged part: map creation and program load are refused, but
 * their attribute blocks and program inputs are still recorded.
 */
static const struct bpf_insn return_zero[2] = {
    {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
    {.code = BPF_JMP | BPF_EXIT},
};

#define BPF_CASE(label, expected, command, attr, size) ({ \
    union bpf_attr bpf_case_entry = (attr); \
    CALL(label, bpf, expected, command, &(attr), size); \
    observe("arg1.attr", &bpf_case_entry, size); \
    pending.value; \
})

static void bpf_unprivileged_cases(void)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 8;
    attr.max_entries = 4;
    strcpy(attr.map_name, "ant_array");
    BPF_CASE("bpf.map_create_unprivileged", EPERM, BPF_MAP_CREATE, attr, 72);
    report();
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = 2;
    attr.insns = (uintptr_t)return_zero;
    attr.license = (uintptr_t)"GPL";
    BPF_CASE("bpf.prog_load_unprivileged", EPERM, BPF_PROG_LOAD, attr, 40);
    report();
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = 0x414e5449;
    BPF_CASE("bpf.unknown", EINVAL, 0x7fff, attr, 16);
    report();
}

/* Slice 2E: the handler copies its signal frame and FPU state just before
 * returning through the trampoline's rt_sigreturn.
 */
static unsigned char signal_frame[440], signal_fx[512], signal_xstate[16384];
static size_t signal_xstate_len;

static void frame_handler(int signal, siginfo_t *info, void *context)
{
    ucontext_t *uc = context;
    const unsigned char *fp = (const unsigned char *)uc->uc_mcontext.fpregs;
    uint32_t sw[6];

    (void)signal; (void)info;
    memcpy(signal_frame, (const unsigned char *)uc - sizeof(long), sizeof(signal_frame));
    signal_xstate_len = 0;
    if (!fp)
        return;
    memcpy(signal_fx, fp, sizeof(signal_fx));
    memcpy(sw, fp + 464, sizeof(sw));          /* fxregs_state.sw_reserved */
    /* Mirror the kernel: below 512 + 64 bytes, or without FP_XSTATE_MAGIC2 at
     * the end, the extension is ignored and the legacy state is restored.
     */
    if (sw[0] == 0x46505853U && sw[4] >= 576 && sw[4] - 512 <= sizeof(signal_xstate) &&
        !memcmp(fp + sw[4], "\x45\x58\x50\x46", 4)) {
        signal_xstate_len = sw[4] - 512;
        memcpy(signal_xstate, fp + 512, signal_xstate_len);
    }
}

static void rt_sigreturn_case(void)
{
    struct sigaction action = {.sa_sigaction = frame_handler, .sa_flags = SA_SIGINFO};
    struct sigaction previous;

    require(sigaction(SIGUSR2, &action, &previous) == 0, "frame handler");
    pending = (struct pending_case){.label = "rt_sigreturn.handler_return",
                                    .name = "rt_sigreturn", .nr = SYS_rt_sigreturn};
    pending.started_ns = monotonic_ns();
    raise(SIGUSR2);
    pending.finished_ns = monotonic_ns();
    observe("context.rt_sigframe", signal_frame, sizeof(signal_frame));
    observe("context.fpstate", signal_fx, sizeof(signal_fx));
    if (signal_xstate_len)
        observe("context.fpstate.xstate", signal_xstate, signal_xstate_len);
    report();
    require(sigaction(SIGUSR2, &previous, NULL) == 0, "restore SIGUSR2");
}

/* Root run (--root-bpf): privileged bpf and a real uretprobe. Every map,
 * program, BTF object and perf event is closed before NATIVE PASS.
 */
__attribute__((noinline)) int ant_uretprobe_target(void)
{
    __asm__ volatile("" ::: "memory");
    return 42;
}

static int read_number(const char *path, const char *prefix)
{
    char text[64] = {0};
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    require(fd >= 0 && read(fd, text, sizeof(text) - 1) > 0, path);
    close(fd);
    require(!strncmp(text, prefix, strlen(prefix)), path);
    return atoi(text + strlen(prefix));
}

static uint64_t file_offset_of(const void *address)
{
    char line[512];
    FILE *maps = fopen("/proc/self/maps", "re");
    uint64_t start, end, offset, result = 0;

    require(maps != NULL, "process maps");
    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%lx-%lx %*s %lx", &start, &end, &offset) == 3 &&
            (uintptr_t)address >= start && (uintptr_t)address < end) {
            result = (uintptr_t)address - start + offset;
            break;
        }
    }
    fclose(maps);
    require(result != 0, "probe function mapping");
    return result;
}

static void uretprobe_case(void)
{
    struct perf_event_attr event;
    char path[256];
    ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
    int fd, value;

    require(length > 0, "probe path");
    path[length] = 0;
    memset(&event, 0, sizeof(event));
    event.size = sizeof(event);
    event.type = read_number("/sys/bus/event_source/devices/uprobe/type", "");
    event.config = 1ULL << read_number("/sys/bus/event_source/devices/uprobe/format/retprobe",
                                       "config:");
    event.config1 = (uintptr_t)path;
    event.config2 = file_offset_of((const void *)ant_uretprobe_target);
    fd = TEST(perf_event_open, &event, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    require(fd >= 0, "uprobe return probe");
    pending = (struct pending_case){.label = "uretprobe.return_value", .name = "uretprobe",
                                    .nr = 335};
    pending.started_ns = monotonic_ns();
    value = ant_uretprobe_target();
    pending.finished_ns = monotonic_ns();
    pending.value = value;
    require(value == 42, "probed function result");
    report();
    TEST(close, fd);
}

static unsigned possible_cpus(void)
{
    char text[64] = {0};
    unsigned first, last;
    int fd = open("/sys/devices/system/cpu/possible", O_RDONLY | O_CLOEXEC);

    require(fd >= 0 && read(fd, text, sizeof(text) - 1) > 0, "possible CPUs");
    close(fd);
    if (sscanf(text, "%u-%u", &first, &last) == 2)
        return last - first + 1;
    return 1;
}

static int root_bpf_mode(void)
{
    static const unsigned char btf_blob[45] = {
        0x9f, 0xeb, 1, 0, 24, 0, 0, 0,        /* magic, version, flags, hdr_len */
        0, 0, 0, 0, 16, 0, 0, 0,              /* type_off 0, type_len 16 */
        16, 0, 0, 0, 5, 0, 0, 0,              /* str_off 16, str_len 5 */
        1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0,   /* "int": BTF_KIND_INT, size 4 */
        32, 0, 0, 0,                          /* 32-bit signed encoding 0 */
        0, 'i', 'n', 't', 0,
    };
    static const struct bpf_insn lone_exit[1] = {{.code = BPF_JMP | BPF_EXIT}};
    unsigned char value[8], values[32], percpu[8 * 256], data_in[64] = {0}, data_out[128];
    unsigned char info[64];
    char log[4096];
    uint32_t key, next_key, batch_out, keys[4], data_size_out, info_len;
    union bpf_attr attr;
    int map, percpu_map, program, btf;
    unsigned cpus = possible_cpus();
    long result;

    require(getuid() == 0, "root run");
    require(cpus <= 256, "possible CPU bound");
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 8;
    attr.max_entries = 4;
    strcpy(attr.map_name, "ant_array");
    map = BPF_CASE("bpf.map_create_array", 0, BPF_MAP_CREATE, attr, 72);
    report();
    require(map >= 0, "array map");
    key = 1;
    memcpy(value, "ANTIMAP1", 8);
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map;
    attr.key = (uintptr_t)&key;
    attr.value = (uintptr_t)value;
    attr.flags = BPF_ANY;
    BPF_CASE("bpf.map_update", 0, BPF_MAP_UPDATE_ELEM, attr, 32);
    report();
    memset(value, 0, sizeof(value));
    BPF_CASE("bpf.map_lookup", 0, BPF_MAP_LOOKUP_ELEM, attr, 32);
    report();
    require(!memcmp(value, "ANTIMAP1", 8), "map lookup value");
    attr.next_key = (uintptr_t)&next_key;
    BPF_CASE("bpf.map_get_next_key", 0, BPF_MAP_GET_NEXT_KEY, attr, 32);
    report();
    attr.value = 0;
    BPF_CASE("bpf.map_delete_array", EINVAL, BPF_MAP_DELETE_ELEM, attr, 32);
    report();
    memset(&attr, 0, sizeof(attr));
    attr.batch.map_fd = map;
    attr.batch.out_batch = (uintptr_t)&batch_out;
    attr.batch.keys = (uintptr_t)keys;
    attr.batch.values = (uintptr_t)values;
    attr.batch.count = 4;
    result = BPF_CASE("bpf.map_lookup_batch", 0, BPF_MAP_LOOKUP_BATCH, attr, 56);
    if (result < 0 && pending.error == ENOENT)
        pending.expected = ENOENT;           /* end of map after copying all entries */
    observe("arg1.attr.out_batch", &batch_out, sizeof(batch_out));
    observe("arg1.attr.values", values, sizeof(values));
    report();

    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_PERCPU_ARRAY;
    attr.key_size = 4;
    attr.value_size = 8;
    attr.max_entries = 1;
    percpu_map = TEST(bpf, BPF_MAP_CREATE, &attr, 72);
    require(percpu_map >= 0, "per-CPU map");
    key = 0;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = percpu_map;
    attr.key = (uintptr_t)&key;
    attr.value = (uintptr_t)percpu;
    BPF_CASE("bpf.percpu_lookup", 0, BPF_MAP_LOOKUP_ELEM, attr, 32);
    observe("arg1.attr.value", percpu, 8 * cpus);
    report();

    memset(&attr, 0, sizeof(attr));
    memset(log, 0, sizeof(log));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = 2;
    attr.insns = (uintptr_t)return_zero;
    attr.license = (uintptr_t)"GPL";
    attr.log_level = 1;
    attr.log_size = sizeof(log);
    attr.log_buf = (uintptr_t)log;
    program = BPF_CASE("bpf.prog_load", 0, BPF_PROG_LOAD, attr, 40);
    observe("arg1.attr.log_buf", log, strlen(log) + 1);
    report();
    require(program >= 0, "socket filter");
    memset(log, 0, sizeof(log));
    attr.insn_cnt = 1;
    attr.insns = (uintptr_t)lone_exit;
    BPF_CASE("bpf.prog_load_rejected", EACCES, BPF_PROG_LOAD, attr, 40);
    observe("arg1.attr.log_buf", log, strlen(log) + 1);
    report();

    memset(&attr, 0, sizeof(attr));
    attr.test.prog_fd = program;
    attr.test.data_size_in = sizeof(data_in);
    attr.test.data_size_out = sizeof(data_out);
    attr.test.data_in = (uintptr_t)data_in;
    attr.test.data_out = (uintptr_t)data_out;
    BPF_CASE("bpf.prog_test_run", 0, BPF_PROG_TEST_RUN, attr, 32);
    observe("arg1.attr.data_in", data_in, sizeof(data_in));
    data_size_out = attr.test.data_size_out;
    observe("arg1.attr.data_size_out", &data_size_out, sizeof(data_size_out));
    observe("arg1.attr.data_out", data_out,
            data_size_out < sizeof(data_out) ? data_size_out : sizeof(data_out));
    report();

    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = map;
    attr.info.info_len = sizeof(info);
    attr.info.info = (uintptr_t)info;
    BPF_CASE("bpf.obj_get_info_map", 0, BPF_OBJ_GET_INFO_BY_FD, attr, 16);
    info_len = attr.info.info_len;
    observe("arg1.attr.info", info, info_len < sizeof(info) ? info_len : sizeof(info));
    report();

    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uintptr_t)"/sys/fs/bpf/ant-missing";
    BPF_CASE("bpf.obj_get_missing", ENOENT, BPF_OBJ_GET, attr, 16);
    report();
    memset(&attr, 0, sizeof(attr));
    attr.raw_tracepoint.name = (uintptr_t)"sched_switch";
    attr.raw_tracepoint.prog_fd = program;
    BPF_CASE("bpf.raw_tracepoint_bad_prog", EINVAL, BPF_RAW_TRACEPOINT_OPEN, attr, 12);
    report();
    memset(&attr, 0, sizeof(attr));
    attr.btf = (uintptr_t)btf_blob;
    attr.btf_size = sizeof(btf_blob);
    btf = BPF_CASE("bpf.btf_load", 0, BPF_BTF_LOAD, attr, 28);
    observe("arg1.attr.btf", btf_blob, sizeof(btf_blob));
    report();

    uretprobe_case();
    if (btf >= 0) TEST(close, btf);
    TEST(close, program); TEST(close, percpu_map); TEST(close, map);
    printf("NATIVE READY failures=%u\n", failures);
    if (failures)
        return 1;
    puts("NATIVE PASS");
    return 0;
}

/* Slice 2D: clone writes, semctl arrays, process_vm, deferred pointers. */
static void reap_clone(long child, const char *what)
{
    int status;

    require(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
            WEXITSTATUS(status) == 0, what);
}

static void slice_2d_cases(void)
{
    static const char remote[16] __attribute__((nonstring)) = "ANTINOMIE-REMOTE";
    static const char written[16] __attribute__((nonstring)) = "ANTINOMIE-WRITEV";
    struct clone_args args;
    struct robust_list_head head, *saved_head;
    unsigned short values[3] = {1, 2, 3}, read_back[3];
    char local[16], target[16];
    struct iovec local_iov, remote_iov;
    pid_t parent_tid = 0, child_tid = 0;
    int pidfd = -1, semid, entry_size;
    size_t saved_len;
    long child;

    child = CALL("clone.parent_and_child_tid", clone, 0,
                 CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | SIGCHLD, 0, &parent_tid,
                 &child_tid, 0);
    if (child == 0)
        _exit(0);
    observe("arg2.parent_tid", &parent_tid, sizeof(parent_tid));
    report();
    reap_clone(child, "clone settid child");
    child = CALL("clone.pidfd", clone, 0, CLONE_PIDFD | SIGCHLD, 0, &pidfd, 0, 0);
    if (child == 0)
        _exit(0);
    observe("arg2.pidfd", &pidfd, sizeof(pidfd));
    report();
    reap_clone(child, "clone pidfd child");
    close(pidfd);
    child = CALL("clone.clear_child_tid", clone, 0, CLONE_CHILD_CLEARTID | SIGCHLD, 0, 0,
                 &child_tid, 0);
    if (child == 0)
        _exit(0);
    report();
    reap_clone(child, "clone cleartid child");
    memset(&args, 0, sizeof(args));
    args.flags = CLONE_PIDFD | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
    args.pidfd = (uintptr_t)&pidfd;
    args.parent_tid = (uintptr_t)&parent_tid;
    args.child_tid = (uintptr_t)&child_tid;
    args.exit_signal = SIGCHLD;
    entry_size = 88;                         /* CLONE_ARGS_SIZE_VER2 */
    {
        struct clone_args entry = args;

        child = CALL("clone3.tids_and_pidfd", clone3, 0, &args, entry_size);
        if (child == 0)
            _exit(0);
        observe("arg0.clone_args", &entry, entry_size);
    }
    observe("arg0.clone_args.pidfd", &pidfd, sizeof(pidfd));
    observe("arg0.clone_args.parent_tid", &parent_tid, sizeof(parent_tid));
    report();
    reap_clone(child, "clone3 child");
    close(pidfd);

    semid = semget(IPC_PRIVATE, 3, IPC_CREAT | 0600);
    require(semid >= 0, "private semaphore set");
    CASE("semctl.setall", semctl, 0, semid, 0, SETALL, values);
    CASE("semctl.getall", semctl, 0, semid, 0, GETALL, read_back);
    require(!memcmp(values, read_back, sizeof(values)), "semaphore values");
    CASE("semctl.setall_bad_id", semctl, EINVAL, -1, 0, SETALL, values);
    TEST(semctl, semid, 0, IPC_RMID, 0);

    local_iov = (struct iovec){local, sizeof(local)};
    remote_iov = (struct iovec){(void *)remote, sizeof(remote)};
    CASE("process_vm_readv.self", process_vm_readv, 0, getpid(), &local_iov, 1, &remote_iov,
         1, 0);
    require(!memcmp(local, remote, sizeof(local)), "process_vm_readv copy");
    local_iov = (struct iovec){(void *)written, sizeof(written)};
    remote_iov = (struct iovec){target, sizeof(target)};
    CASE("process_vm_writev.self", process_vm_writev, 0, getpid(), &local_iov, 1, &remote_iov,
         1, 0);
    require(!memcmp(target, written, sizeof(target)), "process_vm_writev copy");

    child = fork();
    require(child >= 0, "set_tid_address child");
    if (!child) {
        child_case_range(6);
        CASE("set_tid_address.child", set_tid_address, 0, &child_tid);
        _exit(failures ? 3 : 0);
    }
    wait_child(child, "set_tid_address child exit");
    require(syscall(SYS_get_robust_list, 0, &saved_head, &saved_len) == 0, "glibc robust list");
    head = (struct robust_list_head){.list = {&head.list}, .futex_offset = 0};
    CALL("set_robust_list.self", set_robust_list, 0, &head, sizeof(head));
    observe("arg0.head", &head, sizeof(head));
    report();
    CASE("set_robust_list.bad_len", set_robust_list, EINVAL, &head, 16);
    require(syscall(SYS_set_robust_list, saved_head, saved_len) == 0, "restore robust list");
}

/* Slice 2G: rows without an entry point in the pinned syscall_64.tbl. */
static void unavailable_cases(void)
{
    static const struct { long number; const char *name; } rows[] = {
        {134, "uselib"}, {156, "_sysctl"}, {174, "create_module"},
        {177, "get_kernel_syms"}, {178, "query_module"}, {180, "nfsservctl"},
        {181, "getpmsg"}, {182, "putpmsg"}, {183, "afs_syscall"}, {184, "tuxcall"},
        {185, "security"}, {205, "set_thread_area"}, {211, "get_thread_area"},
        {212, "lookup_dcookie"}, {214, "epoll_ctl_old"}, {215, "epoll_wait_old"},
        {236, "vserver"},
    };
    char label[64];

    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        uint64_t started = monotonic_ns();
        long result = syscall(rows[i].number, 0, 0, 0, 0, 0, 0);
        int error = errno;
        uint64_t finished = monotonic_ns();

        errno = error;
        snprintf(label, sizeof(label), "unavailable.%s", rows[i].name);
        observed_labeled(label, rows[i].name, rows[i].number, result, ENOSYS,
                         started, finished, NULL);
    }
}

static void memory_and_process_cases(void)
{
    struct utsname uts;
    struct sysinfo info;
    struct rusage usage;
    struct rlimit limit;
    struct tms ticks;
    struct timespec ts, zero = {0};
    struct timeval tv;
    cpu_set_t affinity;
    unsigned cpu = 0, node = 0;
    unsigned futex_word = 0;
    char random[32], residency;
    pid_t child;
    int status;
    long address = TEST(mmap, NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    require(address != -1, "private mapping");
    memset((void *)address, 0x41, 4096);
    TEST(mincore, address, 4096, &residency);
    TEST(mprotect, address, 4096, PROT_READ);
    TEST(madvise, address, 4096, MADV_NORMAL);
    TEST(munmap, address, 4096);
    TEST(getrandom, random, sizeof(random), 0);
    TEST(uname, &uts);
    TEST(sysinfo, &info);
    TEST(gettimeofday, &tv, NULL);
    TEST(clock_gettime, CLOCK_MONOTONIC, &ts);
    TEST(clock_getres, CLOCK_MONOTONIC, &ts);
    TEST(nanosleep, &zero, NULL);
    TEST(clock_nanosleep, CLOCK_MONOTONIC, 0, &zero, NULL);
    TEST(times, &ticks);
    TEST(getrusage, RUSAGE_SELF, &usage);
    TEST(getrlimit, RLIMIT_NOFILE, &limit);
    TEST(prlimit64, 0, RLIMIT_NOFILE, NULL, &limit);
    TEST(sched_getaffinity, 0, sizeof(affinity), &affinity);
    TEST(sched_getscheduler, 0);
    TEST(sched_yield, 0);
    TEST(getcpu, &cpu, &node, NULL);
    TEST(getpid, 0); TEST(getppid, 0); TEST(gettid, 0);
    TEST(getuid, 0); TEST(geteuid, 0); TEST(getgid, 0); TEST(getegid, 0);
    TEST(getpgid, 0); TEST(getsid, 0);
    gid_t groups[32];
    TEST(getgroups, 32, groups);
    uid_t uid[3]; gid_t gid[3];
    TEST(getresuid, &uid[0], &uid[1], &uid[2]);
    TEST(getresgid, &gid[0], &gid[1], &gid[2]);
    uint64_t signals = 0;
    TEST(rt_sigprocmask, SIG_SETMASK, NULL, &signals, sizeof(signals));
    TEST(rt_sigpending, &signals, sizeof(signals));
    TEST(kill, getpid(), 0);
    TEST(tgkill, getpid(), syscall(SYS_gettid), 0);
    TEST(futex, &futex_word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
    REJECT(futex, EAGAIN, &futex_word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
    uint64_t fork_start = monotonic_ns();
    child = syscall(SYS_fork);
    if (child == 0) _exit(17);
    int fork_errno = errno;
    uint64_t fork_end = monotonic_ns();
    errno = fork_errno;
    observed("fork", SYS_fork, child, 0, fork_start, fork_end);
    if (child > 0) {
        TEST(wait4, child, &status, 0, &usage);
        require(WIFEXITED(status) && WEXITSTATUS(status) == 17, "child status");
    }
}

static void aio_cases(void)
{
    aio_context_t context = 0;
    struct iocb request = {0}, *requests[] = {&request};
    struct io_event completion;
    struct timespec timeout = {2, 0};
    void *data = NULL;
    int fd;

    if (TEST(io_setup, 8, &context) < 0) return;
    require(posix_memalign(&data, 4096, 4096) == 0, "aligned AIO payload");
    memset(data, 'A', 4096); memcpy(data, marker, sizeof(marker));
    fd = TEST(openat, AT_FDCWD, "aio", O_CREAT | O_RDWR | O_DIRECT, 0600);
    if (fd >= 0) {
        request.aio_data = 0x616e7461;
        request.aio_lio_opcode = IOCB_CMD_PWRITE;
        request.aio_fildes = fd;
        request.aio_buf = (uintptr_t)data;
        request.aio_nbytes = 4096;
        if (TEST(io_submit, context, 1, requests) == 1) {
            require(TEST(io_getevents, context, 1, 1, &completion, &timeout) == 1,
                    "AIO write completion");
            require(completion.data == request.aio_data && completion.res == 4096,
                    "AIO write result");
            request.aio_lio_opcode = IOCB_CMD_PREAD;
            memset(data, 0, 4096);
            if (TEST(io_submit, context, 1, requests) == 1) {
                require(TEST(io_getevents, context, 1, 1, &completion, &timeout) == 1,
                        "AIO read completion");
                require(completion.res == 4096 && !memcmp(data, marker, sizeof(marker)),
                        "AIO output payload");
            }
        }
        TEST(close, fd);
        TEST(unlink, "aio");
    }
    TEST(io_destroy, context);
    free(data);
}

static void uring_cases(void)
{
    struct io_uring_params p = {0};
    struct io_uring_sqe *sqes;
    void *sq, *cq;
    size_t sq_size, cq_size;
    int fd = TEST(io_uring_setup, 2, &p);

    if (fd < 0) return;
    sq_size = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    cq_size = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        if (sq_size < cq_size) sq_size = cq_size;
        cq_size = sq_size;
    }
    sq = mmap(NULL, sq_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, IORING_OFF_SQ_RING);
    require(sq != MAP_FAILED, "uring SQ map");
    cq = p.features & IORING_FEAT_SINGLE_MMAP ? sq :
        mmap(NULL, cq_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, IORING_OFF_CQ_RING);
    require(cq != MAP_FAILED, "uring CQ map");
    sqes = mmap(NULL, p.sq_entries * sizeof(*sqes), PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, IORING_OFF_SQES);
    require(sqes != MAP_FAILED, "uring SQE map");
    memset(&sqes[0], 0, sizeof(sqes[0]));
    sqes[0].opcode = IORING_OP_NOP; sqes[0].user_data = 0x616e7475;
    unsigned *array = sq + p.sq_off.array;
    unsigned *tail = sq + p.sq_off.tail;
    array[0] = 0;
    __atomic_store_n(tail, 1, __ATOMIC_RELEASE);
    require(TEST(io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) == 1,
            "uring NOP submit");
    unsigned *cq_head = cq + p.cq_off.head;
    unsigned *cq_tail = cq + p.cq_off.tail;
    struct io_uring_cqe *cqe = cq + p.cq_off.cqes;
    require(__atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) != *cq_head &&
            cqe[0].user_data == 0x616e7475 && cqe[0].res == 0, "uring NOP completion");
    __atomic_store_n(cq_head, 1, __ATOMIC_RELEASE);
    void *data = NULL;
    require(posix_memalign(&data, 4096, 4096) == 0, "uring aligned buffer");
    memset(data, 'U', 4096); memcpy(data, marker, sizeof(marker));
    struct iovec registered = {data, 4096};
    int registration = TEST(io_uring_register, fd, IORING_REGISTER_BUFFERS, &registered, 1);
    if (registration == 0) {
        int file = TEST(openat, AT_FDCWD, "uring-fixed", O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        require(file >= 0, "uring private file");
        unsigned sq_mask = *(unsigned *)(sq + p.sq_off.ring_mask);
        unsigned cq_mask = *(unsigned *)(cq + p.cq_off.ring_mask);
        for (unsigned request = 0; request < 2; request++) {
            unsigned sequence = request + 1;
            unsigned slot = sequence & sq_mask;
            uint64_t correlation = 0x616e747600ULL + request;
            if (request) memset(data, 0, 4096);
            memset(&sqes[slot], 0, sizeof(sqes[slot]));
            sqes[slot].opcode = request ? IORING_OP_READ_FIXED : IORING_OP_WRITE_FIXED;
            sqes[slot].fd = file;
            sqes[slot].addr = (uintptr_t)data;
            sqes[slot].len = 4096;
            sqes[slot].user_data = correlation;
            array[slot] = slot;
            __atomic_store_n(tail, sequence + 1, __ATOMIC_RELEASE);
            require(TEST(io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) == 1,
                    "uring fixed submission");
            unsigned head = __atomic_load_n(cq_head, __ATOMIC_RELAXED);
            require(__atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) != head &&
                    cqe[head & cq_mask].user_data == correlation &&
                    cqe[head & cq_mask].res == 4096, "uring fixed completion");
            __atomic_store_n(cq_head, head + 1, __ATOMIC_RELEASE);
            if (request) require(!memcmp(data, marker, sizeof(marker)), "uring fixed output");
        }
        TEST(io_uring_register, fd, IORING_UNREGISTER_BUFFERS, NULL, 0);
        free(data);
        data = NULL;
        require(posix_memalign(&data, 4096, 8192) == 0, "uring retry buffer");
        memset(data, 'V', 8192);
        require(TEST(pwrite64, file, data + 4096, 4096, 4096) == 4096,
                "uring retry second page");
        TEST(fsync, file);
        TEST(fadvise64, file, 4096, 4096, POSIX_FADV_DONTNEED);
        memset(data, 0, 8192);
        registered = (struct iovec){data, 8192};
        require(TEST(io_uring_register, fd, IORING_REGISTER_BUFFERS, &registered, 1) == 0,
                "uring retry registration");
        unsigned slot = 3 & sq_mask;
        memset(&sqes[slot], 0, sizeof(sqes[slot]));
        sqes[slot].opcode = IORING_OP_READ_FIXED;
        sqes[slot].fd = file;
        sqes[slot].addr = (uintptr_t)data;
        sqes[slot].len = 8192;
        sqes[slot].user_data = 0x616e747602ULL;
        array[slot] = slot;
        __atomic_store_n(tail, 4, __ATOMIC_RELEASE);
        require(TEST(io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) == 1,
                "uring retry submission");
        unsigned head = __atomic_load_n(cq_head, __ATOMIC_RELAXED);
        require(__atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) != head &&
                cqe[head & cq_mask].user_data == 0x616e747602ULL &&
                cqe[head & cq_mask].res == 8192, "uring retry completion");
        __atomic_store_n(cq_head, head + 1, __ATOMIC_RELEASE);
        require(!memcmp(data, marker, sizeof(marker)), "uring retry first page");
        for (unsigned index = 4096; index < 8192; index++)
            require(((char *)data)[index] == 'V', "uring retry second-page output");
        TEST(io_uring_register, fd, IORING_UNREGISTER_BUFFERS, NULL, 0);
        TEST(close, file);
        TEST(unlink, "uring-fixed");
    }
    free(data);
    munmap(sqes, p.sq_entries * sizeof(*sqes));
    if (cq != sq) munmap(cq, cq_size);
    munmap(sq, sq_size);
    TEST(close, fd);
}

/* Slice 2F: async requests are matched by user_data in
 * tests/monitor/fixtures/native-schema-async, not by syscall case.
 */
struct ring {
    struct io_uring_params p;
    int fd;
    void *sq, *cq;
    size_t sq_size, cq_size;
    struct io_uring_sqe *sqes;
    unsigned *sq_tail, *sq_array, *sq_flags, *cq_head, *cq_tail, sq_mask, cq_mask;
    struct io_uring_cqe *cqes;
};

static int ring_open(struct ring *r, unsigned entries, unsigned flags)
{
    memset(r, 0, sizeof(*r));
    r->p.flags = flags;
    if (flags & IORING_SETUP_SQPOLL) r->p.sq_thread_idle = 2000;
    r->fd = TEST(io_uring_setup, entries, &r->p);
    if (r->fd < 0) return -1;
    r->sq_size = r->p.sq_off.array + r->p.sq_entries * sizeof(unsigned);
    r->cq_size = r->p.cq_off.cqes + r->p.cq_entries * sizeof(struct io_uring_cqe);
    if (r->sq_size < r->cq_size) r->sq_size = r->cq_size;
    r->sq = mmap(NULL, r->sq_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                 r->fd, IORING_OFF_SQ_RING);
    r->sqes = mmap(NULL, r->p.sq_entries * sizeof(*r->sqes), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQES);
    require(r->p.features & IORING_FEAT_SINGLE_MMAP, "2F single-mmap ring");
    require(r->sq != MAP_FAILED && r->sqes != MAP_FAILED, "2F ring maps");
    r->cq = r->sq;
    r->sq_tail = r->sq + r->p.sq_off.tail;
    r->sq_array = r->sq + r->p.sq_off.array;
    r->sq_flags = r->sq + r->p.sq_off.flags;
    r->sq_mask = *(unsigned *)(r->sq + r->p.sq_off.ring_mask);
    r->cq_head = r->cq + r->p.cq_off.head;
    r->cq_tail = r->cq + r->p.cq_off.tail;
    r->cq_mask = *(unsigned *)(r->cq + r->p.cq_off.ring_mask);
    r->cqes = r->cq + r->p.cq_off.cqes;
    return 0;
}

static struct io_uring_sqe *ring_sqe(struct ring *r, uint8_t opcode, uint64_t user_data)
{
    unsigned tail = *r->sq_tail, slot = tail & r->sq_mask;
    struct io_uring_sqe *sqe = &r->sqes[slot];

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = opcode;
    sqe->user_data = user_data;
    r->sq_array[slot] = slot;
    return sqe;
}

/* Publish every prepared SQE, then wait for `wait` completions. */
static void ring_submit(struct ring *r, unsigned count, unsigned wait)
{
    __atomic_store_n(r->sq_tail, *r->sq_tail + count, __ATOMIC_RELEASE);
    if (r->p.flags & IORING_SETUP_SQPOLL) {
        if (__atomic_load_n(r->sq_flags, __ATOMIC_ACQUIRE) & IORING_SQ_NEED_WAKEUP)
            TEST(io_uring_enter, r->fd, 0, 0, IORING_ENTER_SQ_WAKEUP, NULL, 0);
        if (wait)
            TEST(io_uring_enter, r->fd, 0, wait, IORING_ENTER_GETEVENTS, NULL, 0);
        return;
    }
    require(TEST(io_uring_enter, r->fd, count, wait, wait ? IORING_ENTER_GETEVENTS : 0,
                 NULL, 0) == (long)count, "2F submission");
}

/* Take the completion for user_data. Earlier completions for other requests
 * are kept until asked for.
 */
static struct { uint64_t user_data; int result; } stash[16];
static unsigned stashed;

static int ring_result(struct ring *r, uint64_t user_data, int *result)
{
    for (unsigned i = 0; i < stashed; i++) {
        if (stash[i].user_data == user_data) {
            *result = stash[i].result;
            stash[i] = stash[--stashed];
            return 0;
        }
    }
    for (int attempt = 0; attempt < 200; attempt++) {
        unsigned head = *r->cq_head;
        while (head != __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE)) {
            struct io_uring_cqe *cqe = &r->cqes[head & r->cq_mask];
            int found = cqe->user_data == user_data;
            if (found) {
                *result = cqe->res;
            } else {
                require(stashed < 16, "2F completion stash");
                stash[stashed].user_data = cqe->user_data;
                stash[stashed++].result = cqe->res;
            }
            __atomic_store_n(r->cq_head, ++head, __ATOMIC_RELEASE);
            if (found) return 0;
        }
        TEST(io_uring_enter, r->fd, 0, 1, IORING_ENTER_GETEVENTS, NULL, 0);
    }
    return -1;
}

static void ring_close(struct ring *r)
{
    munmap(r->sqes, r->p.sq_entries * sizeof(*r->sqes));
    munmap(r->sq, r->sq_size);
    TEST(close, r->fd);
}

static void async_begin(void)
{
    pending.used = 0;
    pending.observed[0] = 0;
}

static void async_report(const char *label, uint64_t user_data, long result)
{
    pthread_mutex_lock(&output_lock);
    printf("ANT_ASYNC {\"label\":\"%s\",\"user_data\":\"0x%016llx\",\"result\":%ld,"
           "\"observed\":{%s}}\n", label, (unsigned long long)user_data, result,
           pending.observed);
    pthread_mutex_unlock(&output_lock);    /* Each request queues several async records; pace like the syscall cases
     * so the kernel publishes them before the next request adds more.
     */
    struct timespec pause = {0, 20000000};
    nanosleep(&pause, NULL);
}

static int uring_case(struct ring *r, const char *label, uint64_t user_data,
                      int expected)
{
    int result = 0;

    ring_submit(r, 1, 1);
    require(ring_result(r, user_data, &result) == 0, label);
    if (result != expected) {
        printf("2F %s result %d expected %d\n", label, result, expected);
        require(0, label);
    }
    return result;
}

#define UD(n) (0x2f00000000000000ULL + (n))

static void slice_2f_cases(void)
{
    static const char iowq[] = "ANTINOMIE-IOWQ-READ-PAYLOAD-0001";
    static const char sqpoll[] = "ANTINOMIE-SQPOLL";
    struct io_uring_sqe *sqe;
    struct ring r, poll;
    char buffer[64];
    int pipes[2], result;

    if (ring_open(&r, 16, 0) < 0) return;
    require(pipe(pipes) == 0, "2F pipe");

    /* io-wq: IOSQE_ASYNC punts the read to a worker of this process. */
    require(write(pipes[1], iowq, 32) == 32, "2F pipe payload");
    async_begin();
    sqe = ring_sqe(&r, IORING_OP_READ, UD(1));
    sqe->fd = pipes[0]; sqe->addr = (uintptr_t)buffer; sqe->len = 32;
    sqe->flags = IOSQE_ASYNC;
    result = uring_case(&r, "2f.uring_read_iowq", UD(1), 32);
    require(!memcmp(buffer, iowq, 32), "2F io-wq payload");
    async_report("2f.uring_read_iowq", UD(1), result);

    /* AIO O_DIRECT read on the ext4 root: completion arrives in interrupt
     * context, so the output is read when io_getevents reaps it.
     */
    {
        aio_context_t context = 0;
        struct iocb request = {0}, *requests[] = {&request};
        struct io_event completion;
        struct timespec timeout = {5, 0};
        void *data = NULL;
        int fd;

        if (TEST(io_setup, 4, &context) == 0) {
            require(posix_memalign(&data, 4096, 4096) == 0, "2F aligned AIO buffer");
            for (int i = 0; i < 4096; i++) ((char *)data)[i] = "ANTINOMIE-AIO-2F"[i % 16];
            fd = TEST(openat, AT_FDCWD, "aio-2f", O_CREAT | O_RDWR | O_DIRECT, 0600);
            require(fd >= 0 && TEST(pwrite64, fd, data, 4096, 0) == 4096, "2F AIO file");
            memset(data, 0, 4096);
            request.aio_data = UD(2);
            request.aio_lio_opcode = IOCB_CMD_PREAD;
            request.aio_fildes = fd;
            request.aio_buf = (uintptr_t)data;
            request.aio_nbytes = 4096;
            async_begin();
            require(TEST(io_submit, context, 1, requests) == 1 &&
                    TEST(io_getevents, context, 1, 1, &completion, &timeout) == 1 &&
                    completion.data == UD(2) && completion.res == 4096, "2F AIO read");
            observe("async.payload.output", data, 4096);
            async_report("2f.aio_direct_read_reaped", UD(2), completion.res);
            TEST(close, fd);
            TEST(unlink, "aio-2f");
            TEST(io_destroy, context);
            free(data);
        }
    }

    /* SQPOLL: the kernel thread submits; the request belongs to this run. */
    if (ring_open(&poll, 4, IORING_SETUP_SQPOLL) == 0) {
        async_begin();
        sqe = ring_sqe(&poll, IORING_OP_WRITE, UD(3));
        sqe->fd = pipes[1]; sqe->addr = (uintptr_t)sqpoll; sqe->len = 16;
        result = uring_case(&poll, "2f.sqpoll_write", UD(3), 16);
        require(read(pipes[0], buffer, 16) == 16 && !memcmp(buffer, sqpoll, 16),
                "2F SQPOLL payload");
        async_report("2f.sqpoll_write", UD(3), result);
        ring_close(&poll);
    }

    {
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        socklen_t length = offsetof(struct sockaddr_un, sun_path) + 1 +
                           sizeof("antinomie-2f-bind") - 1;
        int sock = TEST(socket, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

        memcpy(address.sun_path + 1, "antinomie-2f-bind", sizeof("antinomie-2f-bind") - 1);
        async_begin();
        sqe = ring_sqe(&r, IORING_OP_BIND, UD(4));
        sqe->fd = sock; sqe->addr = (uintptr_t)&address; sqe->addr2 = length;
        result = uring_case(&r, "2f.bind", UD(4), 0);
        observe("async.operand.sockaddr", &address, length);
        async_report("2f.bind", UD(4), result);
        TEST(close, sock);
    }

    {
        int files[2] = {-1, -1}, update[2] = {pipes[0], pipes[1]};

        require(TEST(io_uring_register, r.fd, IORING_REGISTER_FILES, files, 2) == 0,
                "2F file table");
        async_begin();
        sqe = ring_sqe(&r, IORING_OP_FILES_UPDATE, UD(5));
        sqe->fd = -1; sqe->addr = (uintptr_t)update; sqe->len = 2; sqe->off = 0;
        result = uring_case(&r, "2f.files_update", UD(5), 2);
        observe("async.operand.fds", update, sizeof(update));
        async_report("2f.files_update", UD(5), result);
        TEST(io_uring_register, r.fd, IORING_UNREGISTER_FILES, NULL, 0);
    }

    {
        siginfo_t info;
        long child = fork();

        if (child == 0) _exit(0);
        memset(&info, 0, sizeof(info));
        async_begin();
        sqe = ring_sqe(&r, IORING_OP_WAITID, UD(6));
        sqe->len = P_PID; sqe->fd = child; sqe->file_index = WEXITED;
        sqe->addr2 = (uintptr_t)&info;
        result = uring_case(&r, "2f.waitid", UD(6), 0);
        require(info.si_pid == child && info.si_status == 0, "2F waitid siginfo");
        observe("async.operand.siginfo", &info, sizeof(info));
        async_report("2f.waitid", UD(6), result);
    }

    {
        static uint32_t word;
        struct futex_waitv waiter = {.val = 1, .uaddr = (uintptr_t)&word,
                                     .flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE};

        async_begin();
        sqe = ring_sqe(&r, IORING_OP_FUTEX_WAKE, UD(7));
        sqe->fd = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE; sqe->addr = (uintptr_t)&word;
        sqe->addr2 = 1; sqe->addr3 = FUTEX_BITSET_MATCH_ANY;
        result = uring_case(&r, "2f.futex_wake", UD(7), 0);
        async_report("2f.futex_wake", UD(7), result);

        async_begin();
        sqe = ring_sqe(&r, IORING_OP_FUTEX_WAITV, UD(8));
        sqe->addr = (uintptr_t)&waiter; sqe->len = 1;
        result = uring_case(&r, "2f.futex_waitv_mismatch", UD(8), -EAGAIN);
        observe("async.operand.futexv", &waiter, sizeof(waiter));
        async_report("2f.futex_waitv_mismatch", UD(8), result);
    }

    {
        static char buffers[4][128];

        async_begin();
        sqe = ring_sqe(&r, IORING_OP_PROVIDE_BUFFERS, UD(9));
        sqe->fd = 4; sqe->addr = (uintptr_t)buffers; sqe->len = 128;
        sqe->buf_group = 1; sqe->off = 0;
        result = uring_case(&r, "2f.provide_buffers", UD(9), 0);
        async_report("2f.provide_buffers", UD(9), result);
        sqe = ring_sqe(&r, IORING_OP_REMOVE_BUFFERS, UD(0x20));
        sqe->fd = 4; sqe->buf_group = 1;
        uring_case(&r, "2f.remove_buffers", UD(0x20), 4);
    }

    {
        int sock = TEST(socket, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        int value = 65536, out = 0;

        async_begin();
        sqe = ring_sqe(&r, IORING_OP_URING_CMD, UD(10));
        sqe->fd = sock; sqe->cmd_op = SOCKET_URING_OP_SETSOCKOPT;
        sqe->level = SOL_SOCKET; sqe->optname = SO_RCVBUF;
        sqe->optval = (uintptr_t)&value; sqe->optlen = sizeof(value);
        result = uring_case(&r, "2f.setsockopt_cmd", UD(10), 0);
        async_report("2f.setsockopt_cmd", UD(10), result);

        async_begin();
        sqe = ring_sqe(&r, IORING_OP_URING_CMD, UD(11));
        sqe->fd = sock; sqe->cmd_op = SOCKET_URING_OP_GETSOCKOPT;
        sqe->level = SOL_SOCKET; sqe->optname = SO_RCVBUF;
        sqe->optval = (uintptr_t)&out; sqe->optlen = sizeof(out);
        result = uring_case(&r, "2f.getsockopt_cmd", UD(11), 4);
        observe("async.operand.optval", &out, sizeof(out));
        async_report("2f.getsockopt_cmd", UD(11), result);
        TEST(close, sock);
    }

    {
        struct __kernel_timespec ten = {10, 0};
        int timeout = 0, cancel = 0;

        sqe = ring_sqe(&r, IORING_OP_TIMEOUT, UD(12));
        sqe->addr = (uintptr_t)&ten; sqe->len = 1;
        ring_submit(&r, 1, 0);
        sqe = ring_sqe(&r, IORING_OP_ASYNC_CANCEL, UD(13));
        sqe->addr = UD(12);
        ring_submit(&r, 1, 2);
        require(ring_result(&r, UD(12), &timeout) == 0, "2F timeout completion");
        require(ring_result(&r, UD(13), &cancel) == 0, "2F cancel completion");
        if (timeout != -ECANCELED || cancel != 0)
            printf("2F cancel: timeout %d cancel %d\n", timeout, cancel);
        require(timeout == -ECANCELED && cancel == 0, "2F canceled timeout");
        async_begin();
        async_report("2f.timeout_canceled", UD(12), timeout);
        async_report("2f.async_cancel", UD(13), cancel);
    }

    TEST(close, pipes[0]);
    TEST(close, pipes[1]);
    ring_close(&r);
}

/* Contract 14.6: more requests in flight than the recorder tracks. */
static int async_stress_mode(void)
{
    struct __kernel_timespec ten = {10, 0};
    struct io_uring_sqe *sqe;
    unsigned completed = 0;
    struct ring r;

    require(ring_open(&r, 512, 0) == 0, "stress ring");
    for (unsigned i = 0; i < 300; i++) {
        sqe = ring_sqe(&r, IORING_OP_TIMEOUT, 0x2f57000000000000ULL + i);
        sqe->addr = (uintptr_t)&ten; sqe->len = 1;
        __atomic_store_n(r.sq_tail, *r.sq_tail + 1, __ATOMIC_RELEASE);
    }
    require(syscall(SYS_io_uring_enter, r.fd, 300, 0, 0, NULL, 0) == 300, "stress submit");
    sqe = ring_sqe(&r, IORING_OP_ASYNC_CANCEL, 0x2f57ffffffffffffULL);
    sqe->cancel_flags = IORING_ASYNC_CANCEL_ANY;
    __atomic_store_n(r.sq_tail, *r.sq_tail + 1, __ATOMIC_RELEASE);
    require(syscall(SYS_io_uring_enter, r.fd, 1, 301, IORING_ENTER_GETEVENTS, NULL, 0) == 1,
            "stress cancel");
    while (*r.cq_head != __atomic_load_n(r.cq_tail, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(r.cq_head, *r.cq_head + 1, __ATOMIC_RELEASE);
        completed++;
    }
    ring_close(&r);
    printf("ASYNC STRESS completions=%u failures=%u\n", completed, failures);
    require(completed == 301, "stress completions");
    if (failures)
        return 1;
    puts("ASYNC STRESS PASS");
    return 0;
}

static void *thread_cases(void *arg)
{
    cpu_set_t target;
    int cpu = (int)(intptr_t)arg;

    if (cpu >= 0) {
        CPU_ZERO(&target); CPU_SET(cpu, &target);
        TEST(sched_setaffinity, 0, sizeof(target), &target);
    }
    for (int i = 0; i < 8; i++) {
        TEST(gettid, 0);
        TEST(sched_yield, 0);
    }
    return NULL;
}

static void *root_process_case(void *arg)
{
    if ((intptr_t)arg == 1) {
        usleep(50000);
        execl("/bin/sh", "sh", "-c", "echo NONLEADER-EXEC; sleep 1; exit 19", NULL);
        _exit(90);
    }
    puts("ROOT-GROUP-LIVE"); fflush(stdout);
    sleep(1);
    _exit(23);
}

int main(int argc, char **argv)
{
    char directory[] = "/tmp/antinomie-native-XXXXXX", input[16];
    pthread_t threads[4];
    cpu_set_t available;
    int selected[4] = {-1, -1, -1, -1}, count = 0;
    int original = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    alarm(30);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc == 2 && (!strcmp(argv[1], "--nonleader-exec") ||
                      !strcmp(argv[1], "--leader-exit"))) {
        pthread_t thread;
        int mode = !strcmp(argv[1], "--nonleader-exec");
        require(!pthread_create(&thread, NULL, root_process_case, (void *)(intptr_t)mode),
                "root-process case thread");
        if (!mode) pthread_exit(NULL);
        for (;;) pause();
    }
    if (argc == 2 && !strcmp(argv[1], "--root-bpf"))
        return root_bpf_mode();
    if (argc == 2 && !strcmp(argv[1], "--async-stress"))
        return async_stress_mode();
    require(argc == 1, "known probe mode");
    require(original >= 0 && mkdtemp(directory) && chdir(directory) == 0,
            "isolated working directory");
    file_cases(); descriptor_cases(); sockopt_cases(); unavailable_cases();
    prctl_cases(); ptrace_cases(); keyctl_cases(); sysfs_cases(); slice_2c_cases();
    bpf_unprivileged_cases(); rt_sigreturn_case(); slice_2d_cases();
    memory_and_process_cases(); aio_cases(); uring_cases(); slice_2f_cases();
    /* Async records are published later, in one burst, by a kernel worker.
     * Let it drain before the pinned threads, so the functional run stays
     * paced; overflow is exercised separately by --async-stress.
     */
    struct timespec drain = {0, 500000000};
    nanosleep(&drain, NULL);
    require(sched_getaffinity(0, sizeof(available), &available) == 0, "available CPUs");
    for (int cpu = 0; cpu < CPU_SETSIZE && count < 4; cpu++)
        if (CPU_ISSET(cpu, &available)) selected[count++] = cpu;
    printf("NATIVE CPUS available_for_test=%d\n", count);
    for (int i = 0; i < 4; i++)
        require(!pthread_create(&threads[i], NULL, thread_cases, (void *)(intptr_t)selected[i]),
                "create four threads");
    for (int i = 0; i < 4; i++)
        require(!pthread_join(threads[i], NULL), "join four threads");
    require(!fchdir(original) && !close(original) && !rmdir(directory), "private resource cleanup");
    printf("NATIVE READY failures=%u\n", failures);
    require(read(STDIN_FILENO, input, sizeof(input)) > 0, "host release barrier");
    if (failures) return 1;
    puts("NATIVE PASS");
    return 0;
}
