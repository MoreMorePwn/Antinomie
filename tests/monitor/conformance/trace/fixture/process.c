// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// process.c — creating, running, waiting for and signalling processes, the
// per-thread kernel registrations, namespaces and per-process controls.
//
// Slots: fork vfork clone clone3 execve execveat exit exit_group wait4 waitid
// kill tkill tgkill getpid getppid gettid set_tid_address set_robust_list
// get_robust_list rseq unshare setns prctl arch_prctl personality seccomp
// ptrace getcpu uname sysinfo getrusage times.
//
// Child process indexes 400-459. Every child is reaped before the area ends.
#include "areas.h"

#include <asm/prctl.h>
#include <elf.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/rseq.h>
#include <sys/sysinfo.h>
#include <sys/times.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif
#ifndef ARCH_GET_CPUID
#define ARCH_GET_CPUID 0x1011
#endif
#ifndef ARCH_SET_CPUID
#define ARCH_SET_CPUID 0x1012
#endif
#ifndef ARCH_GET_XCOMP_SUPP
#define ARCH_GET_XCOMP_SUPP 0x1021
#endif
#ifndef PR_GET_TID_ADDRESS
#define PR_GET_TID_ADDRESS 40
#endif
#ifndef SECCOMP_GET_ACTION_AVAIL
#define SECCOMP_GET_ACTION_AVAIL 2
#endif
#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif

// waitid idtype for a pidfd (glibc declares it only as an enumerator).
#define ANT_P_PIDFD 3
// A pid above PID_MAX_LIMIT: never allocated, so lookups fail with ESRCH and
// nothing can ever receive a signal sent to it.
#define NO_PID 0x3ffffff0L

// struct clone_args (linux-6.12 uapi), spelled out so the extents are fixed.
struct ant_clone_args {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
    uint64_t set_tid, set_tid_size, cgroup;
};
#define CLONE_ARGS_VER0 64
#define CLONE_ARGS_VER1 80
#define CLONE_ARGS_VER2 88

// What a child that cannot report its own last call leaves for the parent.
struct remote_slot {
    long pid, tid;
    uint64_t t0;
};

static struct remote_slot *slot;
// Children block reading hold[0] until they are signalled or the pipe closes.
static int hold[2] = {-1, -1};
static unsigned long ptrace_word = 0x414e54494e4f4d49UL;
static struct sock_filter allow_all[1] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
static struct sock_fprog allow_program;
static struct sock_fprog empty_program;
// The user namespace a holder child created, for setns.
static long ns_holder;
static char ns_path[64];
// Paths the exec cases pass: writable data, so a child's copy is resident.
static char empty_path[] = "";
static char x_path[] = "x";
static char dot_path[] = ".";
static char missing_image[] = "ant-missing-image";

static long self_tid(void)
{
    return syscall(SYS_gettid);
}

// A forked child's page tables do not map the file-backed pages its parent
// read; the recorder cannot fault them in, so children read what they pass.
static void touch(const void *data, size_t len)
{
    const volatile unsigned char *bytes = data;
    for (size_t i = 0; i < len; i++)
        (void)bytes[i];
}

static void touch_vector(char *const vector[])
{
    for (size_t i = 0; vector[i]; i++)
        touch(vector[i], strlen(vector[i]) + 1);
}

static void describe_vector(int arg, char *const vector[])
{
    char key[48];
    for (int i = 0; vector[i]; i++) {
        snprintf(key, sizeof key, "arg%d.string[%d]", arg, i);
        in_key(key, vector[i], strlen(vector[i]) + 1);
    }
}

// Wait for a child as setup (not a described case); its status or -1.
static int collect(long pid, int options, const char *what)
{
    int status = 0;
    long got;
    if (pid <= 0) {
        ora_fail(what);
        return -1;
    }
    do
        got = wait4((pid_t)pid, &status, options, NULL);
    while (got < 0 && errno == EINTR);
    if (got != pid) {
        ora_fail(what);
        return -1;
    }
    return status;
}

static void collect_exit(long pid, int code, int options, const char *what)
{
    int status = collect(pid, options, what);
    if (status != -1 && (!WIFEXITED(status) || WEXITSTATUS(status) != code))
        ora_fail(what);
}

// A clone-like CALL returned in the child: drop the parent's pending case.
#define FORKED(result, code)                                                                       \
    do {                                                                                           \
        if ((result) == 0) {                                                                       \
            ora_forget();                                                                          \
            _exit(code);                                                                           \
        }                                                                                          \
    } while (0)

static void hold_body(void)
{
    sigset_t all;
    char byte;
    signal(SIGTERM, SIG_DFL);
    sigfillset(&all);
    sigprocmask(SIG_UNBLOCK, &all, NULL);
    close(hold[1]);
    while (read(hold[0], &byte, 1) < 0 && errno == EINTR)
        ;
    _exit(0);
}

static pid_t hold_child(void)
{
    ora_flush();
    pid_t pid = fork();
    if (pid == 0)
        hold_body();
    if (pid < 0)
        ora_fail("hold child fork");
    return pid;
}

// vfork in assembly: the child shares the caller's stack, so it must not
// return through C code. It exits with `code`, or execs and exits 127.
static long vfork_then_exit(long code)
{
    long ret = SYS_vfork;
    __asm__ volatile("syscall\n\t"
                     "test %%rax, %%rax\n\t"
                     "jnz 1f\n\t"
                     "mov $60, %%eax\n\t"
                     "syscall\n\t"
                     "1:"
                     : "+a"(ret)
                     : "D"(code)
                     : "rcx", "r11", "memory");
    return ret;
}

static long vfork_then_exec(const char *path, char *const argv[], char *const envp[])
{
    long ret = SYS_vfork;
    __asm__ volatile("syscall\n\t"
                     "test %%rax, %%rax\n\t"
                     "jnz 1f\n\t"
                     "mov $59, %%eax\n\t"
                     "syscall\n\t"
                     "mov $127, %%edi\n\t"
                     "mov $60, %%eax\n\t"
                     "syscall\n\t"
                     "1:"
                     : "+a"(ret)
                     : "D"(path), "S"(argv), "d"(envp)
                     : "rcx", "r11", "memory");
    return ret;
}

// ---------------------------------------------------------------------------
// Identity of the task, kernel-held per-thread pointers, machine information.

static void tid_address_child(void *unused)
{
    static pid_t clear_slot = -1;
    (void)unused;
    long tid = CALL("set_tid_address.child", set_tid_address, WANT_OK, &clear_slot);
    want_status(0, "in", "ASYNC_UNOBSERVED");
    volatile_case();
    why("the kernel stores the pointer and writes it only when the thread exits");
    DONE();
    if (tid != self_tid())
        ora_fail("set_tid_address returns the caller's tid");
    CALL("set_tid_address.null", set_tid_address, WANT_OK, NULL);
    want_status(0, "in", "ASYNC_UNOBSERVED");
    volatile_case();
    DONE();
}

static void rseq_child(void *unused)
{
    char *area = (char *)__builtin_thread_pointer() + __rseq_offset;
    unsigned char before[32];
    (void)unused;
    // A forked child keeps glibc's registration of its parent's thread area.
    CALL("rseq.unregister", rseq, WANT_OK, area, 32, RSEQ_FLAG_UNREGISTER, RSEQ_SIG);
    in_any(0);
    out_key("arg0.rseq", area, 32);
    DONE();
    memcpy(before, area, sizeof before);
    CALL("rseq.register", rseq, WANT_OK, area, 32, 0, RSEQ_SIG);
    in_buf(0, before, sizeof before);
    want_key_status("arg0.rseq.updates", "ASYNC_UNOBSERVED");
    why("after registering, the kernel rewrites the cpu ids on every return to user space");
    DONE();
}

static void self_cases(void)
{
    struct robust_list_head head, *saved = NULL, *seen = NULL;
    size_t saved_len = 0, len = 0;
    char *area = (char *)__builtin_thread_pointer() + __rseq_offset;

    CALL0("getpid.self", getpid, WANT_OK);
    volatile_case();
    DONE();
    CALL0("getppid.self", getppid, WANT_OK);
    volatile_case();
    DONE();
    CALL0("gettid.self", gettid, WANT_OK);
    volatile_case();
    DONE();
    in_child(401, "set_tid_address child", tid_address_child, NULL);

    // glibc registered a robust list at startup: read it, replace it, restore it.
    CALL("get_robust_list.self", get_robust_list, WANT_OK, 0, &saved, &saved_len);
    out_buf(1, &saved, sizeof saved);
    out_buf(2, &saved_len, sizeof saved_len);
    volatile_case();
    DONE();
    memset(&head, 0, sizeof head);
    head.list.next = &head.list;
    CALL("set_robust_list.self", set_robust_list, WANT_OK, &head, sizeof head);
    in_key("arg0.head", &head, sizeof head);
    want_key_status("arg0.head.traversal", "ASYNC_UNOBSERVED");
    why("the kernel walks the list only when the thread exits");
    DONE();
    CALL("get_robust_list.after_set", get_robust_list, WANT_OK, 0, &seen, &len);
    out_buf(1, &seen, sizeof seen);
    out_buf(2, &len, sizeof len);
    volatile_case();
    DONE();
    if (seen != &head)
        ora_fail("get_robust_list returns the registered head");
    CALL("set_robust_list.bad_len", set_robust_list, EINVAL, &head, 16);
    want_key_status("arg0.head", "INVALID_EXTENT");
    DONE();
    CALL("set_robust_list.restore", set_robust_list, WANT_OK, saved, saved_len);
    if (saved && saved_len == sizeof head) {
        in_key("arg0.head", saved, sizeof head);
        want_key_status("arg0.head.traversal", "ASYNC_UNOBSERVED");
    }
    volatile_case();
    DONE();
    CASE("get_robust_list.no_such_pid", get_robust_list, ESRCH, NO_PID, &seen, &len);
    CASE("get_robust_list.fault", get_robust_list, EFAULT, 0, 1, &len);

    // rseq: glibc registered this thread's area (32 bytes) at startup.
    CALL("rseq.register_again", rseq, EBUSY, area, 32, 0, RSEQ_SIG);
    in_any(0);
    why("glibc already registered this thread's rseq area");
    DONE();
    CALL("rseq.unregister_bad_signature", rseq, EPERM, area, 32, RSEQ_FLAG_UNREGISTER, 0xdead);
    in_any(0);
    DONE();
    CALL("rseq.bad_flags", rseq, EINVAL, area, 32, 2, RSEQ_SIG);
    in_any(0);
    DONE();
    CALL("rseq.wrong_length", rseq, EINVAL, area, 16, 0, RSEQ_SIG);
    in_any(0);
    DONE();
    in_child(402, "rseq child", rseq_child, NULL);
}

static void info_cases(void)
{
    unsigned cpu = 0, node = 0;
    unsigned char cache[128];
    struct utsname name;
    struct sysinfo info;
    struct rusage usage;
    struct tms tms;
    long persona;

    CALL("getcpu.cpu_and_node", getcpu, WANT_OK, &cpu, &node, NULL);
    out_buf(0, &cpu, sizeof cpu);
    out_buf(1, &node, sizeof node);
    volatile_case();
    DONE();
    memset(cache, 0, sizeof cache);
    CALL("getcpu.ignored_cache", getcpu, WANT_OK, &cpu, NULL, cache);
    out_buf(0, &cpu, sizeof cpu);
    want_key_status("arg2.ignored_cache", "NOT_WRITTEN");
    why("the cache argument has been unused since Linux 2.6.24");
    volatile_case();
    DONE();
    CASE("getcpu.no_outputs", getcpu, WANT_OK, NULL, NULL, NULL);
    CASE("getcpu.fault", getcpu, EFAULT, 1, NULL, NULL);

    memset(&name, 0, sizeof name);
    CALL("uname.buffer", uname, WANT_OK, &name);
    out_buf(0, &name, sizeof name);
    volatile_case();
    DONE();
    CASE("uname.fault", uname, EFAULT, 1);
    memset(&info, 0, sizeof info);
    CALL("sysinfo.buffer", sysinfo, WANT_OK, &info);
    out_any(0);
    volatile_case();
    DONE();
    CASE("sysinfo.fault", sysinfo, EFAULT, 1);

    memset(&usage, 0, sizeof usage);
    CALL("getrusage.self", getrusage, WANT_OK, RUSAGE_SELF, &usage);
    out_any(1);
    volatile_case();
    DONE();
    CALL("getrusage.children", getrusage, WANT_OK, RUSAGE_CHILDREN, &usage);
    out_any(1);
    volatile_case();
    DONE();
    CALL("getrusage.thread", getrusage, WANT_OK, RUSAGE_THREAD, &usage);
    out_any(1);
    volatile_case();
    DONE();
    CASE("getrusage.bad_who", getrusage, EINVAL, 99, &usage);
    CASE("getrusage.fault", getrusage, EFAULT, RUSAGE_SELF, 1);

    memset(&tms, 0, sizeof tms);
    CALL("times.buffer", times, WANT_OK, &tms);
    out_any(0);
    volatile_case();
    DONE();
    CALL("times.null", times, WANT_OK, NULL);
    want_status(0, "out", "NULL_POINTER");
    volatile_case();
    DONE();
    CASE("times.fault", times, EFAULT, 1);

    persona = CALL("personality.query", personality, WANT_OK, 0xffffffffL);
    why("0xffffffff only reads the persona");
    DONE();
    CASE("personality.set_no_randomize", personality, WANT_OK,
         (persona & 0xffffffffL) | ADDR_NO_RANDOMIZE);
    CASE("personality.read_back", personality, WANT_OK, 0xffffffffL);
    CASE("personality.restore", personality, WANT_OK, persona & 0xffffffffL);
}

// ---------------------------------------------------------------------------
// Process creation.

static void fork_cases(void)
{
    struct ant_clone_args args;
    struct {
        struct ant_clone_args args;
        uint64_t tail;
    } wide;
    struct rusage usage;
    siginfo_t info;
    pid_t parent_tid, child_tid, wanted_tid = 300;
    int pidfd = -1, status;
    long pid, got;

    ora_flush();
    pid = CALL0("fork.plain", fork, WANT_OK);
    if (pid == 0) {
        ora_forget();
        ora_child(400);
        CALL0("getppid.forked_child", getppid, WANT_OK);
        volatile_case();
        DONE();
        CALL0("getpid.forked_child", getpid, WANT_OK);
        volatile_case();
        DONE();
        _exit(ora_failures() ? 3 : 0);
    }
    volatile_case();
    DONE();
    status = -1;
    memset(&usage, 0, sizeof usage);
    got = CALL("wait4.status_rusage", wait4, WANT_OK, pid, &status, 0, &usage);
    out_buf(1, &status, sizeof status);
    out_any(3);
    volatile_case();
    DONE();
    if (got != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        ora_fail("fork child exit");

    // vfork: the parent sleeps until the child exits.
    uint64_t t0 = ora_now();
    pid = vfork_then_exit(6);
    uint64_t t1 = ora_now();
    remote_begin("vfork.child_exits", "vfork", SYS_vfork, getpid(), self_tid(), t0, t1, 0,
                 (long[6]){0}, pid);
    volatile_case();
    why("made in assembly: a vfork child shares the caller's stack and cannot return through C");
    DONE();
    status = collect(pid, 0, "vfork child");
    remote_begin("exit.vfork_child", "exit", SYS_exit, pid, pid, t0, t1, 1, (long[6]){6}, 0);
    remote_noreturn(status);
    volatile_case();
    DONE();
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 6)
        ora_fail("vfork child exit code");

    // clone with the flag sets that change what the recorder reads.
    ora_flush();
    pid = CALL("clone.sigchld", clone, WANT_OK, SIGCHLD, 0, NULL, NULL, 0);
    FORKED(pid, 4);
    volatile_case();
    DONE();
    got = CALL("wait4.null_pointers", wait4, WANT_OK, pid, NULL, 0, NULL);
    want_status(1, "out", "NULL_POINTER");
    want_status(3, "out", "NULL_POINTER");
    volatile_case();
    DONE();
    if (got != pid)
        ora_fail("wait4 without outputs");

    parent_tid = child_tid = 0;
    ora_flush();
    pid = CALL("clone.parent_and_child_tid", clone, WANT_OK,
               CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | SIGCHLD, 0, &parent_tid, &child_tid, 0);
    if (pid == 0) {
        ora_forget();
        _exit(child_tid == (pid_t)self_tid() ? 0 : 1);
    }
    out_buf(2, &parent_tid, sizeof parent_tid);
    want_key_status("arg3.child_tid", "ASYNC_UNOBSERVED");
    why("the child writes its own tid in its own copy of memory");
    volatile_case();
    DONE();
    if (parent_tid != pid)
        ora_fail("clone parent_tid");
    status = -1;
    got = CALL("wait4.any_child", wait4, WANT_OK, -1, &status, 0, NULL);
    out_buf(1, &status, sizeof status);
    want_status(3, "out", "NULL_POINTER");
    volatile_case();
    DONE();
    if (got != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        ora_fail("clone settid child");

    ora_flush();
    pid = CALL("clone.clear_child_tid", clone, WANT_OK, CLONE_CHILD_CLEARTID | SIGCHLD, 0, NULL,
               &child_tid, 0);
    FORKED(pid, 0);
    want_key_status("arg3.clear_child_tid", "ASYNC_UNOBSERVED");
    why("the kernel clears the child's word when the child exits");
    volatile_case();
    DONE();
    collect_exit(pid, 0, 0, "clone cleartid child");

    ora_flush();
    pid = CALL("clone.vfork_flag", clone, WANT_OK, CLONE_VFORK | SIGCHLD, 0, NULL, NULL, 0);
    FORKED(pid, 0);
    why("CLONE_VFORK without CLONE_VM: the child has its own memory, the parent waits");
    volatile_case();
    DONE();
    collect_exit(pid, 0, 0, "clone vfork child");

    ora_flush();
    pid = CALL("clone.no_exit_signal", clone, WANT_OK, 0, 0, NULL, NULL, 0);
    FORKED(pid, 5);
    volatile_case();
    DONE();
    status = -1;
    got = CALL("wait4.all_children", wait4, WANT_OK, pid, &status, __WALL, NULL);
    out_buf(1, &status, sizeof status);
    want_status(3, "out", "NULL_POINTER");
    why("a child without an exit signal is visible only to __WALL or __WCLONE");
    volatile_case();
    DONE();
    if (got != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 5)
        ora_fail("clone child without exit signal");

    ora_flush();
    pid = CALL("clone.new_user_namespace", clone, WANT_OK, CLONE_NEWUSER | SIGCHLD, 0, NULL, NULL,
               0);
    FORKED(pid, 0);
    volatile_case();
    DONE();
    collect_exit(pid, 0, 0, "clone user namespace child");

    ora_flush();
    pid = CALL("clone.sighand_without_vm", clone, EINVAL, CLONE_SIGHAND | SIGCHLD, 0, NULL, NULL,
               0);
    FORKED(pid, 0);
    DONE();
    ora_flush();
    pid = CALL("clone.pidfd_with_parent_settid", clone, EINVAL,
               CLONE_PIDFD | CLONE_PARENT_SETTID | SIGCHLD, 0, &pidfd, NULL, 0);
    FORKED(pid, 0);
    why("clone() returns the pidfd and the parent tid through the same pointer");
    DONE();

    // clone3: the three struct sizes, the pointer outputs, set_tid, sizes.
    memset(&args, 0, sizeof args);
    args.exit_signal = SIGCHLD;
    ora_flush();
    pid = CALL("clone3.ver0", clone3, WANT_OK, &args, CLONE_ARGS_VER0);
    FORKED(pid, 0);
    in_key("arg0.clone_args", &args, CLONE_ARGS_VER0);
    volatile_case();
    DONE();
    collect_exit(pid, 0, 0, "clone3 ver0 child");

    memset(&args, 0, sizeof args);
    parent_tid = 0;
    args.flags = CLONE_PARENT_SETTID;
    args.parent_tid = (uintptr_t)&parent_tid;
    args.exit_signal = SIGCHLD;
    ora_flush();
    pid = CALL("clone3.ver1_parent_tid", clone3, WANT_OK, &args, CLONE_ARGS_VER1);
    FORKED(pid, 0);
    in_key("arg0.clone_args", &args, CLONE_ARGS_VER1);
    out_key("arg0.clone_args.parent_tid", &parent_tid, sizeof parent_tid);
    volatile_case();
    DONE();
    collect_exit(pid, 0, 0, "clone3 ver1 child");

    memset(&args, 0, sizeof args);
    parent_tid = child_tid = 0;
    pidfd = -1;
    args.flags = CLONE_PIDFD | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
    args.pidfd = (uintptr_t)&pidfd;
    args.parent_tid = (uintptr_t)&parent_tid;
    args.child_tid = (uintptr_t)&child_tid;
    args.exit_signal = SIGCHLD;
    ora_flush();
    pid = CALL("clone3.ver2_tids_and_pidfd", clone3, WANT_OK, &args, CLONE_ARGS_VER2);
    if (pid == 0) {
        ora_forget();
        _exit(child_tid == (pid_t)self_tid() ? 0 : 1);
    }
    in_key("arg0.clone_args", &args, CLONE_ARGS_VER2);
    out_key("arg0.clone_args.pidfd", &pidfd, sizeof pidfd);
    out_key("arg0.clone_args.parent_tid", &parent_tid, sizeof parent_tid);
    want_key_status("arg0.clone_args.child_tid", "ASYNC_UNOBSERVED");
    want_key_status("arg0.clone_args.clear_child_tid", "ASYNC_UNOBSERVED");
    volatile_case();
    DONE();
    memset(&info, 0, sizeof info);
    CALL("waitid.p_pidfd", waitid, WANT_OK, ANT_P_PIDFD, pidfd, &info, WEXITED, NULL);
    out_buf(2, &info, sizeof info);
    want_status(4, "out", "NULL_POINTER");
    volatile_case();
    DONE();
    if (info.si_pid != pid || info.si_code != CLD_EXITED || info.si_status != 0)
        ora_fail("clone3 child exit through its pidfd");
    if (pidfd >= 0)
        close(pidfd);

    memset(&args, 0, sizeof args);
    args.set_tid = (uintptr_t)&wanted_tid;
    args.set_tid_size = 1;
    args.exit_signal = SIGCHLD;
    ora_flush();
    pid = CALL("clone3.set_tid_unprivileged", clone3, EPERM, &args, CLONE_ARGS_VER1);
    FORKED(pid, 0);
    in_key("arg0.clone_args", &args, CLONE_ARGS_VER1);
    in_key("arg0.clone_args.set_tid", &wanted_tid, sizeof wanted_tid);
    why("choosing the child's pid needs CAP_CHECKPOINT_RESTORE");
    DONE();
    args.set_tid_size = 40;
    ora_flush();
    pid = CALL("clone3.set_tid_size_too_big", clone3, EINVAL, &args, CLONE_ARGS_VER1);
    FORKED(pid, 0);
    in_key("arg0.clone_args", &args, CLONE_ARGS_VER1);
    want_key_status("arg0.clone_args.set_tid", "INVALID_EXTENT");
    why("set_tid_size above MAX_PID_NS_LEVEL (32)");
    DONE();

    memset(&args, 0, sizeof args);
    args.exit_signal = SIGCHLD;
    ora_flush();
    pid = CALL("clone3.size_too_small", clone3, EINVAL, &args, 32);
    FORKED(pid, 0);
    want_key_status("arg0.clone_args", "INVALID_EXTENT");
    DONE();
    ora_flush();
    pid = CALL("clone3.size_too_large", clone3, E2BIG, &args, 8192);
    FORKED(pid, 0);
    want_key_status("arg0.clone_args", "INVALID_EXTENT");
    why("sizes above PAGE_SIZE are refused before anything is copied");
    DONE();
    args.exit_signal = 0x100;
    ora_flush();
    pid = CALL("clone3.bad_exit_signal", clone3, EINVAL, &args, CLONE_ARGS_VER0);
    FORKED(pid, 0);
    in_key("arg0.clone_args", &args, CLONE_ARGS_VER0);
    DONE();
    args.exit_signal = SIGCHLD;
    args.flags = 1ULL << 40;
    ora_flush();
    pid = CALL("clone3.unknown_flag", clone3, EINVAL, &args, CLONE_ARGS_VER0);
    FORKED(pid, 0);
    in_key("arg0.clone_args", &args, CLONE_ARGS_VER0);
    DONE();

    memset(&wide, 0, sizeof wide);
    wide.args.exit_signal = SIGCHLD;
    ora_flush();
    pid = CALL("clone3.zero_tail", clone3, WANT_OK, &wide, sizeof wide);
    FORKED(pid, 0);
    in_key("arg0.clone_args", &wide.args, CLONE_ARGS_VER2);
    in_key("arg0.clone_args.extension", &wide.tail, sizeof wide.tail);
    why("a larger struct is accepted when the bytes the kernel does not know are zero");
    volatile_case();
    DONE();
    collect_exit(pid, 0, 0, "clone3 zero tail child");
    wide.tail = 1;
    ora_flush();
    pid = CALL("clone3.nonzero_tail", clone3, E2BIG, &wide, sizeof wide);
    FORKED(pid, 0);
    in_key("arg0.clone_args", &wide.args, CLONE_ARGS_VER2);
    in_key("arg0.clone_args.extension", &wide.tail, sizeof wide.tail);
    DONE();
}

// ---------------------------------------------------------------------------
// Signals to tasks, waiting for them.

static void signal_wait_cases(void)
{
    struct robust_list_head *head = NULL;
    struct rusage usage;
    siginfo_t info;
    size_t len = 0;
    long tid = self_tid(), seized, got;
    pid_t first, second, third, fourth;
    int status, pidfd = -1, clean = 1;

    CASE("kill.self_probe", kill, WANT_OK, getpid(), 0);
    CASE("kill.no_such_process", kill, ESRCH, NO_PID, 0);
    CASE("kill.bad_signal", kill, EINVAL, getpid(), 99);
    CASE("tkill.self_probe", tkill, WANT_OK, tid, 0);
    CASE("tkill.no_such_thread", tkill, ESRCH, NO_PID, 0);
    CASE("tkill.bad_tid", tkill, EINVAL, 0, 0);
    CASE("tkill.bad_signal", tkill, EINVAL, tid, 99);
    CASE("tgkill.self_probe", tgkill, WANT_OK, getpid(), tid, 0);
    CASE("tgkill.wrong_group", tgkill, ESRCH, NO_PID, tid, 0);
    CASE("tgkill.bad_tgid", tgkill, EINVAL, 0, tid, 0);
    CASE("tgkill.bad_signal", tgkill, EINVAL, getpid(), tid, 99);

    // First child: seized, interrupted, released, then terminated.
    first = hold_child();
    status = 0;
    got = CALL("wait4.wnohang_running", wait4, WANT_OK, first, &status, WNOHANG, NULL);
    why("the child is still blocked: nothing to reap, nothing written");
    DONE();
    if (got != 0)
        ora_fail("wait4 WNOHANG on a running child");
    seized = CALL("ptrace.seize", ptrace, WANT_ANY, PTRACE_SEIZE, first, 0, PTRACE_O_EXITKILL);
    why("Yama ptrace_scope 1 lets a parent attach to its own child; scope 2 or 3 refuses");
    DONE();
    if (seized == 0) {
        clean = 0;
        CASE("ptrace.interrupt", ptrace, WANT_OK, PTRACE_INTERRUPT, first, 0, 0);
        status = collect(first, 0, "seized child stop");
        if (status != -1 && WIFSTOPPED(status)) {
            if (CASE("ptrace.detach", ptrace, WANT_OK, PTRACE_DETACH, first, 0, 0) == 0)
                clean = 1;
        }
    }
    CASE("kill.child_sigterm", kill, WANT_OK, first, SIGTERM);
    if (!clean)
        kill(first, SIGKILL);
    status = -1;
    memset(&usage, 0, sizeof usage);
    got = CALL("wait4.signaled", wait4, WANT_OK, first, &status, 0, &usage);
    out_buf(1, &status, sizeof status);
    out_any(3);
    volatile_case();
    DONE();
    if (got != first || !WIFSIGNALED(status) || (clean && WTERMSIG(status) != SIGTERM))
        ora_fail("child ended by SIGTERM");

    // Second child: inspected, killed with tkill, reaped by waitid.
    second = hold_child();
    CALL("get_robust_list.child", get_robust_list, WANT_OK, second, &head, &len);
    out_buf(1, &head, sizeof head);
    out_buf(2, &len, sizeof len);
    why("reading a child's robust list needs only same-user ptrace read access");
    volatile_case();
    DONE();
    memset(&info, 0, sizeof info);
    memset(&usage, 0x5a, sizeof usage);
    CALL("waitid.wnohang_running", waitid, WANT_OK, P_PID, second, &info, WEXITED | WNOHANG,
         &usage);
    out_buf(2, &info, sizeof info);
    out_buf(4, &usage, sizeof usage);
    why("nothing to reap: the kernel zeroes the reported siginfo fields and leaves rusage alone");
    DONE();
    CASE("tkill.child_sigkill", tkill, WANT_OK, second, SIGKILL);
    memset(&info, 0, sizeof info);
    CALL("waitid.wnowait", waitid, WANT_OK, P_PID, second, &info, WEXITED | WNOWAIT, NULL);
    out_buf(2, &info, sizeof info);
    want_status(4, "out", "NULL_POINTER");
    volatile_case();
    DONE();
    memset(&info, 0, sizeof info);
    memset(&usage, 0, sizeof usage);
    CALL("waitid.p_pid", waitid, WANT_OK, P_PID, second, &info, WEXITED, &usage);
    out_buf(2, &info, sizeof info);
    out_any(4);
    volatile_case();
    DONE();
    if (info.si_pid != second || info.si_code != CLD_KILLED || info.si_status != SIGKILL)
        ora_fail("tkill child reaped by waitid");

    // Third child: created with a pidfd, killed with tgkill, reaped through the pidfd.
    ora_flush();
    third = (pid_t)CALL("clone.pidfd", clone, WANT_OK, CLONE_PIDFD | SIGCHLD, 0, &pidfd, NULL, 0);
    if (third == 0) {
        ora_forget();
        hold_body();
    }
    out_buf(2, &pidfd, sizeof pidfd);
    volatile_case();
    DONE();
    CASE("tgkill.child_sigkill", tgkill, WANT_OK, third, third, SIGKILL);
    memset(&info, 0, sizeof info);
    CALL("waitid.p_pidfd_killed", waitid, WANT_OK, ANT_P_PIDFD, pidfd, &info, WEXITED, NULL);
    out_buf(2, &info, sizeof info);
    want_status(4, "out", "NULL_POINTER");
    volatile_case();
    DONE();
    if (info.si_pid != third || info.si_code != CLD_KILLED)
        ora_fail("tgkill child reaped by pidfd");
    if (pidfd >= 0)
        close(pidfd);

    // Fourth child: reaped by a wait4 whose status pointer faults.
    fourth = hold_child();
    kill(fourth, SIGKILL);
    memset(&info, 0, sizeof info);
    waitid(P_PID, fourth, &info, WEXITED | WNOWAIT);
    got = CALL("wait4.fault_status", wait4, EFAULT, fourth, 1, 0, NULL);
    why("the kernel reaps the child, then fails to store its status");
    DONE();
    if (wait4(fourth, &status, WNOHANG, NULL) != -1 || errno != ECHILD)
        ora_fail("wait4 with a bad status pointer reaps the child");

    CASE("wait4.bad_options", wait4, EINVAL, -1, &status, 0x00100000, NULL);
    CASE("waitid.bad_idtype", waitid, EINVAL, 99, 0, &info, WEXITED, NULL);
    CASE("waitid.no_options", waitid, EINVAL, P_ALL, 0, &info, 0, NULL);
}

// ---------------------------------------------------------------------------
// exec, exit and exit_group: the parent reports what the child cannot.

static void exec_failure_child(void *unused)
{
    char *const argv[] = {self_path, (char *)"--exec-target", (char *)"3", NULL};
    char *const envp[] = {(char *)"ANT_EXEC=failure", NULL};
    const char *missing = missing_image;
    int fd = open(self_path, O_PATH | O_CLOEXEC);
    (void)unused;
    touch_vector(argv);
    touch_vector(envp);

    CALL("execve.missing", execve, ENOENT, missing, argv, envp);
    in_str(0, missing);
    describe_vector(1, argv);
    describe_vector(2, envp);
    DONE();
    CALL("execve.directory", execve, EACCES, dot_path, argv, envp);
    in_str(0, dot_path);
    describe_vector(1, argv);
    describe_vector(2, envp);
    DONE();
    CALL("execve.bad_argv", execve, EFAULT, self_path, 1, envp);
    in_str(0, self_path);
    want_key_status("arg1.ptr[0]", "COPY_FAULT");
    describe_vector(2, envp);
    why("the argument vector is read before the point of no return");
    DONE();
    CALL("execve.null_path", execve, EFAULT, NULL, argv, envp);
    want_status(0, "in", "NULL_POINTER");
    describe_vector(1, argv);
    describe_vector(2, envp);
    DONE();
    CALL("execveat.bad_dirfd", execveat, EBADF, 999, x_path, argv, envp, 0);
    in_str(1, x_path);
    describe_vector(2, argv);
    describe_vector(3, envp);
    DONE();
    CALL("execveat.bad_flags", execveat, EINVAL, AT_FDCWD, self_path, argv, envp, 0x1);
    in_str(1, self_path);
    describe_vector(2, argv);
    describe_vector(3, envp);
    DONE();
    CALL("execveat.empty_path_without_flag", execveat, ENOENT, fd, empty_path, argv, envp, 0);
    in_str(1, empty_path);
    describe_vector(2, argv);
    describe_vector(3, envp);
    DONE();
    if (fd >= 0)
        close(fd);
}

static void exit_case(const char *label, const char *name, long nr, int code)
{
    memset(slot, 0, sizeof *slot);
    ora_flush();
    pid_t pid = fork();
    if (pid == 0) {
        slot->pid = getpid();
        slot->tid = self_tid();
        slot->t0 = ora_now();
        syscall(nr, code);
        _exit(98);
    }
    int status = collect(pid, 0, label);
    remote_begin(label, name, nr, slot->pid, slot->tid, slot->t0, ora_now(), 1,
                 (long[6]){code}, 0);
    remote_noreturn(status);
    volatile_case();
    DONE();
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != code)
        ora_fail(label);
}

static void exec_cases(void)
{
    char *const argv[] = {self_path, (char *)"--exec-target", (char *)"7", NULL};
    char *const envp[] = {(char *)"ANT_EXEC=execve", (char *)"LC_ALL=C", NULL};
    char *const at_argv[] = {self_path, (char *)"--exec-target", (char *)"8", NULL};
    char *const at_envp[] = {(char *)"ANT_EXEC=execveat", NULL};
    char *const v_argv[] = {self_path, (char *)"--exec-target", (char *)"9", NULL};
    char *const v_envp[] = {(char *)"ANT_EXEC=vfork", NULL};
    int status, fd;
    pid_t pid;

    // execve of this program in a forked child.
    memset(slot, 0, sizeof *slot);
    ora_flush();
    pid = fork();
    if (pid == 0) {
        touch_vector(argv);
        touch_vector(envp);
        slot->pid = getpid();
        slot->tid = self_tid();
        slot->t0 = ora_now();
        syscall(SYS_execve, self_path, argv, envp);
        _exit(99);
    }
    status = collect(pid, 0, "execve child");
    remote_begin("execve.self_target", "execve", SYS_execve, slot->pid, slot->tid, slot->t0,
                 ora_now(), 3, (long[6]){(long)self_path, (long)argv, (long)envp}, 0);
    in_str(0, self_path);
    describe_vector(1, argv);
    describe_vector(2, envp);
    why("the new image prints ANT_EXEC_TARGET and exits with the code its argument names");
    volatile_case();
    DONE();
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 7)
        ora_fail("execve target exit code");

    // execveat of an O_PATH descriptor with AT_EMPTY_PATH.
    fd = open(self_path, O_PATH);
    if (fd < 0)
        ora_fail("O_PATH descriptor of the fixture");
    memset(slot, 0, sizeof *slot);
    ora_flush();
    pid = fork();
    if (pid == 0) {
        touch_vector(at_argv);
        touch_vector(at_envp);
        slot->pid = getpid();
        slot->tid = self_tid();
        slot->t0 = ora_now();
        syscall(SYS_execveat, fd, empty_path, at_argv, at_envp, AT_EMPTY_PATH);
        _exit(99);
    }
    status = collect(pid, 0, "execveat child");
    remote_begin("execveat.empty_path", "execveat", SYS_execveat, slot->pid, slot->tid, slot->t0,
                 ora_now(), 5, (long[6]){fd, (long)empty_path, (long)at_argv, (long)at_envp, AT_EMPTY_PATH},
                 0);
    in_str(1, empty_path);
    describe_vector(2, at_argv);
    describe_vector(3, at_envp);
    volatile_case();
    DONE();
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 8)
        ora_fail("execveat target exit code");
    if (fd >= 0)
        close(fd);

    // execve from a vfork child: the parent resumes when the exec succeeds.
    uint64_t t0 = ora_now();
    pid = (pid_t)vfork_then_exec(self_path, v_argv, v_envp);
    uint64_t t1 = ora_now();
    remote_begin("vfork.child_execs", "vfork", SYS_vfork, getpid(), self_tid(), t0, t1, 0,
                 (long[6]){0}, pid);
    volatile_case();
    DONE();
    status = collect(pid, 0, "vfork exec child");
    // The parent resumes when the new image is committed, before the
    // child's execve returns into it: its window ends after the wait.
    remote_begin("execve.vfork_child", "execve", SYS_execve, pid, pid, t0, ora_now(), 3,
                 (long[6]){(long)self_path, (long)v_argv, (long)v_envp}, 0);
    in_str(0, self_path);
    describe_vector(1, v_argv);
    describe_vector(2, v_envp);
    why("the vfork child shares the parent's memory, so the vectors are the parent's");
    volatile_case();
    DONE();
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 9)
        ora_fail("vfork execve target exit code");

    in_child(411, "exec failures", exec_failure_child, NULL);
    exit_case("exit.child", "exit", SYS_exit, 5);
    exit_case("exit_group.child", "exit_group", SYS_exit_group, 9);
}

// ---------------------------------------------------------------------------
// Namespaces.

static void userns_child(void *unused)
{
    (void)unused;
    CASE("unshare.new_user_namespace", unshare, WANT_OK, CLONE_NEWUSER);
    CALL("unshare.mount_namespace_as_owner", unshare, WANT_OK, CLONE_NEWNS);
    why("the creator of a user namespace holds CAP_SYS_ADMIN inside it");
    DONE();
}

static void unshare_denied_child(void *unused)
{
    (void)unused;
    CASE("unshare.mount_namespace_denied", unshare, EPERM, CLONE_NEWNS);
    CASE("unshare.net_namespace_denied", unshare, EPERM, CLONE_NEWNET);
}

static void setns_path_child(void *unused)
{
    (void)unused;
    touch(ns_path, sizeof ns_path);
    int fd = open(ns_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        ora_fail("open the holder's user namespace");
        return;
    }
    CASE("setns.wrong_namespace_type", setns, EINVAL, fd, CLONE_NEWNET);
    CASE("setns.user_namespace", setns, WANT_OK, fd, CLONE_NEWUSER);
    CASE("setns.already_member", setns, EINVAL, fd, 0);
    close(fd);
}

static void setns_pidfd_child(void *unused)
{
    (void)unused;
    long fd = syscall(SYS_pidfd_open, ns_holder, 0);
    CALL("setns.pidfd_user", setns, WANT_ANY, fd, CLONE_NEWUSER);
    why("joining through a pidfd also checks ptrace read access; same user, so it should succeed");
    DONE();
    CASE("setns.bad_fd", setns, EBADF, 999, 0);
    if (fd >= 0)
        close((int)fd);
}

static void namespace_cases(void)
{
    int ready[2], release[2];
    char byte = 0;

    CASE("unshare.files", unshare, WANT_OK, CLONE_FILES);
    CASE("unshare.fs", unshare, WANT_OK, CLONE_FS);
    CASE("unshare.nothing", unshare, WANT_OK, 0);
    CASE("unshare.bad_flag", unshare, EINVAL, CLONE_PTRACE);
    in_child(406, "user namespace child", userns_child, NULL);
    in_child(407, "namespace denied child", unshare_denied_child, NULL);

    // A holder child creates a user namespace; siblings join it with setns.
    if (pipe2(ready, O_CLOEXEC) != 0 || pipe2(release, O_CLOEXEC) != 0) {
        ora_fail("namespace pipes");
        return;
    }
    ora_flush();
    ns_holder = fork();
    if (ns_holder == 0) {
        ora_child(408);
        close(ready[0]);
        close(release[1]);
        long done = CASE("unshare.user_namespace_holder", unshare, WANT_OK, CLONE_NEWUSER);
        byte = done == 0 ? 'y' : 'n';
        if (write(ready[1], &byte, 1) != 1)
            ora_fail("holder ready");
        while (read(release[0], &byte, 1) < 0 && errno == EINTR)
            ;
        _exit(ora_failures() ? 3 : 0);
    }
    close(ready[1]);
    close(release[0]);
    if (ns_holder < 0 || read(ready[0], &byte, 1) != 1 || byte != 'y') {
        ora_fail("user namespace holder");
    } else {
        snprintf(ns_path, sizeof ns_path, "/proc/%ld/ns/user", ns_holder);
        in_child(409, "setns by path", setns_path_child, NULL);
        in_child(410, "setns by pidfd", setns_pidfd_child, NULL);
    }
    close(release[1]);
    close(ready[0]);
    if (ns_holder > 0)
        ora_wait((pid_t)ns_holder, "user namespace holder");
}

// ---------------------------------------------------------------------------
// prctl, arch_prctl, seccomp.

static void privileges_child(void *unused)
{
    (void)unused;
    touch(&allow_program, sizeof allow_program);
    touch(allow_all, sizeof allow_all);
    touch(&empty_program, sizeof empty_program);

    CALL("seccomp.filter_without_no_new_privs", seccomp, EACCES, SECCOMP_SET_MODE_FILTER, 0,
         &allow_program);
    in_key("arg2.program", &allow_program, sizeof allow_program);
    in_key("arg2.program.filter", allow_all, sizeof allow_all);
    why("an unprivileged filter needs no_new_privs first");
    DONE();
    CASE("prctl.set_dumpable_off", prctl, WANT_OK, PR_SET_DUMPABLE, 0, 0, 0, 0);
    CASE("prctl.get_dumpable_off", prctl, WANT_OK, PR_GET_DUMPABLE, 0, 0, 0, 0);
    CASE("prctl.set_no_new_privs_bad_args", prctl, EINVAL, PR_SET_NO_NEW_PRIVS, 1, 1, 0, 0);
    CASE("prctl.set_no_new_privs", prctl, WANT_OK, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    CASE("prctl.get_no_new_privs_set", prctl, WANT_OK, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    CALL("seccomp.filter_bad_flags", seccomp, EINVAL, SECCOMP_SET_MODE_FILTER, 0x80000000L,
         &allow_program);
    in_key("arg2.program", &allow_program, sizeof allow_program);
    in_key("arg2.program.filter", allow_all, sizeof allow_all);
    DONE();
    CALL("seccomp.filter_empty", seccomp, EINVAL, SECCOMP_SET_MODE_FILTER, 0, &empty_program);
    in_key("arg2.program", &empty_program, sizeof empty_program);
    want_key_status("arg2.program.filter", "INVALID_EXTENT");
    DONE();
    CALL("seccomp.filter_allow_all", seccomp, WANT_OK, SECCOMP_SET_MODE_FILTER, 0,
         &allow_program);
    in_key("arg2.program", &allow_program, sizeof allow_program);
    in_key("arg2.program.filter", allow_all, sizeof allow_all);
    DONE();
    CALL("prctl.set_seccomp_filter", prctl, WANT_OK, PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
         &allow_program, 0, 0);
    in_key("arg2.program", &allow_program, sizeof allow_program);
    in_key("arg2.program.filter", allow_all, sizeof allow_all);
    DONE();
    CASE("prctl.get_seccomp_filtered", prctl, WANT_OK, PR_GET_SECCOMP, 0, 0, 0, 0);
}

static void arch_child(void *unused)
{
    (void)unused;
    CALL("arch_prctl.set_cpuid_off", arch_prctl, WANT_ANY, ARCH_SET_CPUID, 0);
    why("CPUID faulting needs CPU or hypervisor support; ENODEV without it");
    DONE();
    CASE("arch_prctl.get_cpuid_child", arch_prctl, WANT_OK, ARCH_GET_CPUID, 0);
    CASE("arch_prctl.set_gs_zero", arch_prctl, WANT_OK, ARCH_SET_GS, 0);
}

static void control_cases(void)
{
    char original[16], name[16];
    unsigned long value, tid_address = 0;
    uint32_t action;
    struct seccomp_notif_sizes sizes;
    int pdeath = -1;
    long dumpable, slack;

    memset(original, 0, sizeof original);
    if (syscall(SYS_prctl, PR_GET_NAME, original, 0, 0, 0) != 0)
        ora_fail("current thread name");
    CALL("prctl.set_name", prctl, WANT_OK, PR_SET_NAME, "ant-process", 0, 0, 0);
    in_str(1, "ant-process");
    DONE();
    memset(name, 0x55, sizeof name);
    CALL("prctl.get_name", prctl, WANT_OK, PR_GET_NAME, name, 0, 0, 0);
    out_buf(1, name, sizeof name);
    DONE();
    CALL("prctl.set_name_long", prctl, WANT_OK, PR_SET_NAME, "ant-process-name-too-long", 0, 0,
         0);
    want_status(1, "in", "INVALID_EXTENT");
    why("the kernel keeps 15 bytes; the recorder marks a string longer than TASK_COMM_LEN");
    DONE();
    CALL("prctl.restore_name", prctl, WANT_OK, PR_SET_NAME, original, 0, 0, 0);
    in_str(1, original);
    volatile_case();
    DONE();
    dumpable = CASE("prctl.get_dumpable", prctl, WANT_OK, PR_GET_DUMPABLE, 0, 0, 0, 0);
    CASE("prctl.set_dumpable_same", prctl, WANT_OK, PR_SET_DUMPABLE, dumpable, 0, 0, 0);
    CASE("prctl.set_dumpable_bad", prctl, EINVAL, PR_SET_DUMPABLE, 2, 0, 0, 0);
    CASE("prctl.get_seccomp", prctl, WANT_OK, PR_GET_SECCOMP, 0, 0, 0, 0);
    CASE("prctl.get_no_new_privs", prctl, WANT_OK, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    CASE("prctl.capbset_read", prctl, WANT_OK, PR_CAPBSET_READ, 0, 0, 0, 0);
    CASE("prctl.capbset_read_bad", prctl, EINVAL, PR_CAPBSET_READ, 999, 0, 0, 0);
    slack = CASE("prctl.get_timerslack", prctl, WANT_OK, PR_GET_TIMERSLACK, 0, 0, 0, 0);
    CASE("prctl.set_timerslack", prctl, WANT_OK, PR_SET_TIMERSLACK, 100000, 0, 0, 0);
    CASE("prctl.get_timerslack_changed", prctl, WANT_OK, PR_GET_TIMERSLACK, 0, 0, 0, 0);
    CASE("prctl.restore_timerslack", prctl, WANT_OK, PR_SET_TIMERSLACK, slack, 0, 0, 0);
    CALL("prctl.get_tid_address", prctl, WANT_OK, PR_GET_TID_ADDRESS, &tid_address, 0, 0, 0);
    out_buf(1, &tid_address, sizeof tid_address);
    volatile_case();
    DONE();
    CALL("prctl.get_pdeathsig", prctl, WANT_OK, PR_GET_PDEATHSIG, &pdeath, 0, 0, 0);
    out_buf(1, &pdeath, sizeof pdeath);
    DONE();
    CALL("prctl.unknown_option", prctl, EINVAL, 0x7fffffff, 0, 0, 0, 0);
    want_key_status("prctl.unknown_selector", "NO_DECODER");
    DONE();
    in_child(403, "privileges child", privileges_child, NULL);

    value = 0;
    CALL("arch_prctl.get_fs", arch_prctl, WANT_OK, ARCH_GET_FS, &value);
    out_buf(1, &value, sizeof value);
    volatile_case();
    DONE();
    if (value != (unsigned long)__builtin_thread_pointer())
        ora_fail("ARCH_GET_FS is the thread pointer");
    value = 1;
    CALL("arch_prctl.get_gs", arch_prctl, WANT_OK, ARCH_GET_GS, &value);
    out_buf(1, &value, sizeof value);
    DONE();
    CASE("arch_prctl.get_cpuid", arch_prctl, WANT_OK, ARCH_GET_CPUID, 0);
    value = 0;
    CALL("arch_prctl.get_xcomp_supp", arch_prctl, WANT_OK, ARCH_GET_XCOMP_SUPP, &value);
    out_buf(1, &value, sizeof value);
    volatile_case();
    DONE();
    CASE("arch_prctl.get_fs_fault", arch_prctl, EFAULT, ARCH_GET_FS, 1);
    CALL("arch_prctl.unknown_code", arch_prctl, EINVAL, 0x9999, 0);
    want_key_status("arch_prctl.unknown_selector", "NO_DECODER");
    DONE();
    in_child(404, "arch_prctl child", arch_child, NULL);

    action = SECCOMP_RET_ALLOW;
    CALL("seccomp.action_avail", seccomp, WANT_OK, SECCOMP_GET_ACTION_AVAIL, 0, &action);
    in_buf(2, &action, sizeof action);
    DONE();
    action = 0x12340000;
    CALL("seccomp.action_unavailable", seccomp, EOPNOTSUPP, SECCOMP_GET_ACTION_AVAIL, 0, &action);
    in_buf(2, &action, sizeof action);
    DONE();
    CALL("seccomp.action_avail_bad_flags", seccomp, EINVAL, SECCOMP_GET_ACTION_AVAIL, 1, &action);
    in_buf(2, &action, sizeof action);
    DONE();
    memset(&sizes, 0, sizeof sizes);
    CALL("seccomp.notif_sizes", seccomp, WANT_OK, SECCOMP_GET_NOTIF_SIZES, 0, &sizes);
    out_buf(2, &sizes, sizeof sizes);
    DONE();
    CALL("seccomp.unknown_op", seccomp, EINVAL, 99, 0, &action);
    want_key_status("seccomp.unknown_selector", "NO_DECODER");
    DONE();
    CASE("seccomp.strict_bad_flags", seccomp, EINVAL, SECCOMP_SET_MODE_STRICT, 1, NULL);
}

// ---------------------------------------------------------------------------
// ptrace of a child that asked for it.

static void ptrace_cases(void)
{
    struct user_regs_struct regs;
    struct user_fpregs_struct fpregs;
    unsigned char regset[512], info[128];
    struct iovec iov, iov_in;
    unsigned long word, message;
    uint64_t mask;
    siginfo_t siginfo;
    long result;
    int status;

    ora_flush();
    pid_t child = fork();
    if (child == 0) {
        ora_child(405);
        if (CASE("ptrace.traceme", ptrace, WANT_OK, PTRACE_TRACEME, 0, 0, 0) != 0)
            _exit(3);
        kill(getpid(), SIGSTOP);
        _exit(ptrace_word == 0x5345545345544553UL && !ora_failures() ? 0 : 3);
    }
    status = collect(child, 0, "tracee stop");
    if (status == -1)
        return;
    if (!WIFSTOPPED(status)) {
        ora_fail("tracee did not stop");
        return;
    }
    CASE("ptrace.setoptions", ptrace, WANT_OK, PTRACE_SETOPTIONS, child, 0,
         PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
    word = 0;
    CALL("ptrace.peekdata", ptrace, WANT_OK, PTRACE_PEEKDATA, child, &ptrace_word, &word);
    want_key_status("arg2.tracee_address", "ADDRESS_ONLY");
    out_key("arg3.word", &word, sizeof word);
    why("the address belongs to the tracee; the recorder never dereferences it");
    DONE();
    if (word != 0x414e54494e4f4d49UL)
        ora_fail("tracee word");
    CALL("ptrace.pokedata", ptrace, WANT_OK, PTRACE_POKEDATA, child, &ptrace_word,
         0x5345545345544553UL);
    want_key_status("arg2.tracee_address", "ADDRESS_ONLY");
    DONE();
    CALL("ptrace.peekdata_unmapped", ptrace, EIO, PTRACE_PEEKDATA, child, 8, &word);
    want_key_status("arg2.tracee_address", "ADDRESS_ONLY");
    DONE();
    word = 0;
    CALL("ptrace.peekuser", ptrace, WANT_OK, PTRACE_PEEKUSER, child,
         offsetof(struct user, regs.orig_rax), &word);
    out_key("arg3.word", &word, sizeof word);
    volatile_case();
    DONE();
    memset(&regs, 0, sizeof regs);
    CALL("ptrace.getregs", ptrace, WANT_OK, PTRACE_GETREGS, child, 0, &regs);
    out_key("arg3.regs", &regs, sizeof regs);
    volatile_case();
    DONE();
    CALL("ptrace.setregs", ptrace, WANT_OK, PTRACE_SETREGS, child, 0, &regs);
    in_key("arg3.regs", &regs, sizeof regs);
    volatile_case();
    DONE();
    memset(&fpregs, 0, sizeof fpregs);
    CALL("ptrace.getfpregs", ptrace, WANT_OK, PTRACE_GETFPREGS, child, 0, &fpregs);
    out_key("arg3.fpregs", &fpregs, sizeof fpregs);
    volatile_case();
    DONE();
    memset(regset, 0, sizeof regset);
    iov.iov_base = regset;
    iov.iov_len = sizeof regset;
    iov_in = iov;
    CALL("ptrace.getregset", ptrace, WANT_OK, PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
    in_key("arg3.iovec", &iov_in, sizeof iov_in);
    out_key("arg3.iov_len", &iov.iov_len, sizeof iov.iov_len);
    out_key("arg3.iovec.data", regset, iov.iov_len <= sizeof regset ? iov.iov_len : 0);
    volatile_case();
    DONE();
    iov.iov_len = sizeof regset;
    iov_in = iov;
    CALL("ptrace.getregset_bad_type", ptrace, EINVAL, PTRACE_GETREGSET, child, 0x9999, &iov);
    in_key("arg3.iovec", &iov_in, sizeof iov_in);
    DONE();
    memset(&siginfo, 0, sizeof siginfo);
    CALL("ptrace.getsiginfo", ptrace, WANT_OK, PTRACE_GETSIGINFO, child, 0, &siginfo);
    out_key("arg3.siginfo", &siginfo, sizeof siginfo);
    volatile_case();
    DONE();
    mask = ~0ULL;
    CALL("ptrace.getsigmask", ptrace, WANT_OK, PTRACE_GETSIGMASK, child, sizeof mask, &mask);
    out_key("arg3.sigmask", &mask, sizeof mask);
    DONE();
    CASE("ptrace.getsigmask_bad_size", ptrace, EINVAL, PTRACE_GETSIGMASK, child, 4, &mask);
    message = 1;
    CALL("ptrace.geteventmsg", ptrace, WANT_OK, PTRACE_GETEVENTMSG, child, 0, &message);
    out_key("arg3.message", &message, sizeof message);
    DONE();
    memset(info, 0, sizeof info);
    result = CALL("ptrace.get_syscall_info", ptrace, WANT_OK, PTRACE_GET_SYSCALL_INFO, child,
                  sizeof info, info);
    if (result >= 0)
        out_key("arg3.info", info, (size_t)result < sizeof info ? (size_t)result : sizeof info);
    volatile_case();
    DONE();
    word = 0;
    CALL("ptrace.arch_prctl_get_fs", ptrace, WANT_OK, PTRACE_ARCH_PRCTL, child, &word,
         ARCH_GET_FS);
    out_key("arg2.value", &word, sizeof word);
    volatile_case();
    DONE();
    CASE("ptrace.attach_already_traced", ptrace, EPERM, PTRACE_ATTACH, child, 0, 0);
    CALL("ptrace.peekdata_not_traced", ptrace, ESRCH, PTRACE_PEEKDATA, NO_PID, &ptrace_word,
         &word);
    want_key_status("arg2.tracee_address", "ADDRESS_ONLY");
    DONE();
    CALL("ptrace.unknown_request", ptrace, EIO, 0x7fff, child, 0, 0);
    want_key_status("ptrace.unknown_selector", "NO_DECODER");
    DONE();
    if (CASE("ptrace.cont", ptrace, WANT_OK, PTRACE_CONT, child, 0, 0) != 0)
        kill(child, SIGKILL);
    collect_exit(child, 0, 0, "tracee exit");
}

void area_process(void)
{
    slot = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (slot == MAP_FAILED) {
        ora_fail("remote slot page");
        return;
    }
    memset(slot, 0, 4096);
    if (pipe2(hold, O_CLOEXEC) != 0) {
        ora_fail("hold pipe");
        munmap(slot, 4096);
        return;
    }
    memset(&allow_program, 0, sizeof allow_program);
    allow_program.len = 1;
    allow_program.filter = allow_all;
    memset(&empty_program, 0, sizeof empty_program);
    empty_program.filter = allow_all;

    self_cases();
    info_cases();
    fork_cases();
    signal_wait_cases();
    exec_cases();
    namespace_cases();
    control_cases();
    ptrace_cases();

    close(hold[1]);
    close(hold[0]);
    int status;
    siginfo_t info;
    memset(&info, 0, sizeof info);
    CASE("wait4.no_children", wait4, ECHILD, -1, &status, WNOHANG, NULL);
    CASE("waitid.no_children", waitid, ECHILD, P_ALL, 0, &info, WEXITED | WNOHANG, NULL);
    munmap(slot, 4096);
    slot = NULL;
}
