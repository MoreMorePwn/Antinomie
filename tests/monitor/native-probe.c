// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <linux/futex.h>
#include <linux/io_uring.h>
#include <linux/openat2.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static const char marker[] = "ANTINOMIE-NATIVE-PAYLOAD";
static unsigned failures;
static unsigned case_count;
static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t monotonic_ns(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time)) abort();
    return (uint64_t)time.tv_sec * 1000000000 + time.tv_nsec;
}

static long observed(const char *name, long nr, long value, int expected_errno,
                     uint64_t started_ns, uint64_t finished_ns)
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
           "\"started_ns\":%llu,\"finished_ns\":%llu}\n", name, nr, value,
           error, verdict, ++case_count, syscall(SYS_gettid),
           (unsigned long long)started_ns, (unsigned long long)finished_ns);
    pthread_mutex_unlock(&output_lock);
    /* Functional coverage is paced; overflow is a separate lossy stress test. */
    struct timespec pause = {0, 2000000};
    nanosleep(&pause, NULL);
    errno = error;
    return value;
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
    require(argc == 1, "known probe mode");
    require(original >= 0 && mkdtemp(directory) && chdir(directory) == 0,
            "isolated working directory");
    file_cases(); descriptor_cases(); memory_and_process_cases(); aio_cases(); uring_cases();
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
