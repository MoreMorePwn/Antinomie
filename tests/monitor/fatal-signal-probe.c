// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// fatal-signal-probe.c — benign children that end on a signal in every way the
// guest records a sender for (contract revision 21), for a recorded run whose
// task-exit records are then read with the event-dump example:
//
//   killed    SIGKILL from its parent (kill): sender = the parent, SI_USER
//   peer      SIGKILL from a sibling (tgkill): sender = the sibling, SI_TKILL
//   self      SIGTERM it sends itself: sender = itself
//   alarm     SIGALRM of alarm(): the kernel, SI_KERNEL
//   segv      SIGSEGV of a null store: delivered, SEGV_MAPERR (si_code 1)
//   oom       (root, with --oom) SIGKILL of the memory cgroup OOM killer in a
//             32 MiB cgroup: SI_KERNEL, the OOM mark and the kernel's line
//
// The ioctl decoders of revision 21 (FIONREAD, FIONBIO, FS_IOC_GETFLAGS and
// FS_IOC_SETFLAGS) and arch_prctl ARCH_CET_STATUS are exercised too, once each.
//
// Build: gcc -static -O2 -Wall -Wextra -o fatal-signal-probe fatal-signal-probe.c
// Run in a disposable guest only; it prints one line per child and
// "FATAL PROBE DONE" at the end.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CGROUP_ROOT "/sys/fs/cgroup"
#define CGROUP "/sys/fs/cgroup/fatal-probe"

static void report(const char *what, pid_t pid)
{
    int status = 0;

    if (waitpid(pid, &status, 0) != pid) {
        printf("PROBE %s pid %d: waitpid failed: %s\n", what, pid, strerror(errno));
        return;
    }
    if (WIFSIGNALED(status))
        printf("PROBE %s pid %d: signal %d\n", what, pid, WTERMSIG(status));
    else
        printf("PROBE %s pid %d: exit %d\n", what, pid, WEXITSTATUS(status));
    fflush(stdout);
}

static pid_t child(const char *name)
{
    fflush(stdout);
    pid_t pid = fork();

    if (pid == 0)
        prctl(PR_SET_NAME, name);
    return pid;
}

static int write_file(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    ssize_t len = (ssize_t)strlen(text);
    int ok;

    if (fd < 0)
        return -1;
    ok = write(fd, text, len) == len ? 0 : -1;
    close(fd);
    return ok;
}

static void decoders(void)
{
    int pair[2], queued = -1, on = 1;
    unsigned int flags = 0;
    unsigned long long cet[3] = {0, 0, 0};

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0) {
        if (write(pair[0], "probe", 5) != 5)
            perror("write");
        ioctl(pair[1], FIONREAD, &queued);
        ioctl(pair[1], FIONBIO, &on);
        close(pair[0]);
        close(pair[1]);
    }
    int fd = open("fatal-probe-file", O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd >= 0) {
        if (ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0)
            ioctl(fd, FS_IOC_SETFLAGS, &flags);
        close(fd);
        unlink("fatal-probe-file");
    }
#ifdef SYS_arch_prctl
    long cet_result = syscall(SYS_arch_prctl, 0x3001, cet);
    printf("PROBE decoders: FIONREAD %d, flags %#x, ARCH_CET_STATUS %ld\n", queued, flags,
           cet_result);
#else
    printf("PROBE decoders: FIONREAD %d, flags %#x\n", queued, flags);
#endif
    fflush(stdout);
}

static void oom_child(void)
{
    char pid[32];

    // cgroup2 where the guest has not mounted it (BusyBox); sys/mount.h and
    // linux/fs.h do not go together, hence the raw call.
    if (access(CGROUP_ROOT "/cgroup.subtree_control", F_OK) != 0)
        syscall(SYS_mount, "none", CGROUP_ROOT, "cgroup2", 0UL, NULL);
    // The memory controller for the child cgroup; harmless when it is on.
    write_file(CGROUP_ROOT "/cgroup.subtree_control", "+memory");
    if (mkdir(CGROUP, 0755) != 0 && errno != EEXIST) {
        printf("PROBE oom: no cgroup: %s\n", strerror(errno));
        _exit(2);
    }
    write_file(CGROUP "/memory.swap.max", "0");
    snprintf(pid, sizeof pid, "%d", getpid());
    if (write_file(CGROUP "/memory.max", "33554432") != 0 ||
        write_file(CGROUP "/cgroup.procs", pid) != 0) {
        printf("PROBE oom: cgroup not usable: %s\n", strerror(errno));
        _exit(2);
    }
    // Touch 256 MiB, page by page, until the cgroup's OOM killer ends it.
    size_t size = 256u << 20;
    char *memory = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED)
        _exit(3);
    for (size_t offset = 0; offset < size; offset += 4096)
        memory[offset] = 1;
    _exit(4);
}

int main(int argc, char **argv)
{
    int oom = argc > 1 && strcmp(argv[1], "--oom") == 0;
    struct rlimit no_core = {0, 0};
    pid_t pid;

    setrlimit(RLIMIT_CORE, &no_core);
    setvbuf(stdout, NULL, _IOLBF, 0);
    decoders();

    pid = child("probe-killed");
    if (pid == 0) {
        pause();
        _exit(0);
    }
    usleep(100000);
    kill(pid, SIGKILL);
    report("killed", pid);

    pid = child("probe-peer");
    if (pid == 0) {
        pause();
        _exit(0);
    }
    pid_t peer = child("probe-sender");
    if (peer == 0) {
        usleep(100000);
        syscall(SYS_tgkill, pid, pid, SIGKILL);
        _exit(0);
    }
    report("peer", pid);
    report("sender", peer);

    pid = child("probe-self");
    if (pid == 0) {
        kill(getpid(), SIGTERM);
        _exit(0);
    }
    report("self", pid);

    pid = child("probe-alarm");
    if (pid == 0) {
        alarm(1);
        pause();
        _exit(0);
    }
    report("alarm", pid);

    pid = child("probe-segv");
    if (pid == 0) {
        *(volatile int *)0 = 1;
        _exit(0);
    }
    report("segv", pid);

    if (oom) {
        pid = child("probe-oom");
        if (pid == 0)
            oom_child();
        report("oom", pid);
        rmdir(CGROUP);
    }
    printf("FATAL PROBE DONE\n");
    return 0;
}
