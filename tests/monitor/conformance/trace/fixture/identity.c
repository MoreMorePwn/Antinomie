// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// identity.c — credentials, capabilities, sessions and process groups,
// scheduling, I/O priority, resource limits, Landlock and LSM attributes.
//
// Slots: getuid geteuid getgid getegid setuid setgid setreuid setregid
// setresuid setresgid getresuid getresgid setfsuid setfsgid getgroups
// setgroups capget capset setpgid getpgrp setsid getsid getpgid getpriority
// setpriority sched_setparam sched_getparam sched_setscheduler
// sched_getscheduler sched_get_priority_max sched_get_priority_min
// sched_rr_get_interval sched_setaffinity sched_getaffinity sched_setattr
// sched_getattr sched_yield ioprio_set ioprio_get getrlimit setrlimit
// prlimit64 landlock_create_ruleset landlock_add_rule landlock_restrict_self
// lsm_get_self_attr lsm_set_self_attr lsm_list_modules.
//
// Child process indexes 460-479. Every attribute of the main process this
// area changes is restored before it returns.
#include "areas.h"

#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef SYS_landlock_add_rule
#define SYS_landlock_add_rule 445
#endif
#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif
#ifndef SYS_lsm_get_self_attr
#define SYS_lsm_get_self_attr 459
#endif
#ifndef SYS_lsm_set_self_attr
#define SYS_lsm_set_self_attr 460
#endif
#ifndef SYS_lsm_list_modules
#define SYS_lsm_list_modules 461
#endif
#ifndef SCHED_BATCH
#define SCHED_BATCH 3
#endif
#ifndef SCHED_IDLE
#define SCHED_IDLE 5
#endif
#ifndef SCHED_RESET_ON_FORK
#define SCHED_RESET_ON_FORK 0x40000000
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

// A pid above PID_MAX_LIMIT: never allocated, lookups fail with ESRCH.
#define NO_PID 0x3ffffff0L

// I/O priority encoding (linux/ioprio.h).
#define IOPRIO_WHO_PROCESS 1
#define IOPRIO_WHO_PGRP 2
#define IOPRIO_WHO_USER 3
#define IOPRIO_CLASS_RT 1
#define IOPRIO_CLASS_BE 2
#define IOPRIO_VALUE(class, data) (((class) << 13) | (data))

// Landlock uapi (linux-6.12), spelled out so the extents are fixed.
#define LL_CREATE_RULESET_VERSION 1U
#define LL_RULE_PATH_BENEATH 1
#define LL_RULE_NET_PORT 2
#define LL_FS_EXECUTE (1ULL << 0)
#define LL_FS_WRITE_FILE (1ULL << 1)
#define LL_FS_READ_FILE (1ULL << 2)
#define LL_FS_READ_DIR (1ULL << 3)
#define LL_FS_REMOVE_DIR (1ULL << 4)
#define LL_NET_BIND_TCP (1ULL << 0)
struct ll_ruleset_attr {
    uint64_t handled_access_fs, handled_access_net, scoped;
};
struct ll_path_beneath {
    uint64_t allowed_access;
    int32_t parent_fd;
} __attribute__((packed));
struct ll_net_port {
    uint64_t allowed_access, port;
};

// LSM syscall uapi (linux/lsm.h).
#define ANT_LSM_ATTR_UNDEF 0
#define ANT_LSM_ATTR_CURRENT 100
#define ANT_LSM_FLAG_SINGLE 1
#define ANT_LSM_ID_SELINUX 101
struct ant_lsm_ctx {
    uint64_t id, flags, len, ctx_len;
};

// struct sched_attr (linux-6.12 uapi): VER0 is 48 bytes, VER1 56.
struct ant_sched_attr {
    uint32_t size, sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime, sched_deadline, sched_period;
    uint32_t sched_util_min, sched_util_max;
};
#define SCHED_ATTR_VER0 48
#define SCHED_ATTR_VER1 56

static int hold[2] = {-1, -1};
static int landlock_errno;
static long ruleset_fd = -1;

// A forked child does not map file-backed pages its parent read until it
// reads them itself; the recorder cannot fault them in.
static void touch(const void *data, size_t len)
{
    const volatile unsigned char *bytes = data;
    for (size_t i = 0; i < len; i++)
        (void)bytes[i];
}

// What a Landlock case must return: its own outcome when Landlock is built
// and enabled, else the error the version query reported (ENOSYS or EOPNOTSUPP).
static long ll(long want)
{
    return landlock_errno ? landlock_errno : want;
}

static pid_t hold_child(void)
{
    ora_flush();
    pid_t pid = fork();
    if (pid == 0) {
        char byte;
        close(hold[1]);
        while (read(hold[0], &byte, 1) < 0 && errno == EINTR)
            ;
        _exit(0);
    }
    if (pid < 0)
        ora_fail("hold child fork");
    return pid;
}

static void release_child(pid_t pid, const char *what)
{
    int status;
    long got;
    if (pid <= 0)
        return;
    kill(pid, SIGKILL);
    do
        got = waitpid(pid, &status, 0);
    while (got < 0 && errno == EINTR);
    if (got != pid)
        ora_fail(what);
}

// ---------------------------------------------------------------------------
// User and group ids: the main process sets only the ids it already has.

static void id_cases(void)
{
    uid_t ruid = 0, euid = 0, suid = 0;
    gid_t rgid = 0, egid = 0, sgid = 0;
    long same;

    CASE0("getuid.self", getuid, WANT_OK);
    CASE0("geteuid.self", geteuid, WANT_OK);
    CASE0("getgid.self", getgid, WANT_OK);
    CASE0("getegid.self", getegid, WANT_OK);
    CALL("getresuid.self", getresuid, WANT_OK, &ruid, &euid, &suid);
    out_buf(0, &ruid, sizeof ruid);
    out_buf(1, &euid, sizeof euid);
    out_buf(2, &suid, sizeof suid);
    DONE();
    CASE("getresuid.fault", getresuid, EFAULT, 1, &euid, &suid);
    CALL("getresgid.self", getresgid, WANT_OK, &rgid, &egid, &sgid);
    out_buf(0, &rgid, sizeof rgid);
    out_buf(1, &egid, sizeof egid);
    out_buf(2, &sgid, sizeof sgid);
    DONE();
    CASE("getresgid.fault", getresgid, EFAULT, &rgid, &egid, 1);
    if (ruid == 0 || euid == 0)
        ora_fail("the identity area runs as an unprivileged user");
    same = ruid == euid && euid == suid && rgid == egid && egid == sgid;
    if (!same)
        ora_fail("the identity area expects equal real, effective and saved ids");

    CASE("setuid.own", setuid, WANT_OK, ruid);
    CASE("setuid.root", setuid, EPERM, 0);
    CASE("setgid.own", setgid, WANT_OK, rgid);
    CASE("setgid.root", setgid, EPERM, 0);
    CASE("setreuid.unchanged", setreuid, WANT_OK, -1, -1);
    CASE("setreuid.own", setreuid, WANT_OK, ruid, euid);
    CASE("setreuid.root", setreuid, EPERM, 0, -1);
    CASE("setregid.unchanged", setregid, WANT_OK, -1, -1);
    CASE("setregid.own", setregid, WANT_OK, rgid, egid);
    CASE("setregid.root", setregid, EPERM, -1, 0);
    CASE("setresuid.unchanged", setresuid, WANT_OK, -1, -1, -1);
    CASE("setresuid.own", setresuid, WANT_OK, ruid, euid, suid);
    CASE("setresuid.root", setresuid, EPERM, 0, 0, 0);
    CASE("setresgid.unchanged", setresgid, WANT_OK, -1, -1, -1);
    CASE("setresgid.own", setresgid, WANT_OK, rgid, egid, sgid);
    CASE("setresgid.root", setresgid, EPERM, -1, -1, 0);
    // setfsuid/setfsgid never fail: they return the previous id either way.
    CASE("setfsuid.query", setfsuid, WANT_OK, -1);
    CASE("setfsuid.own", setfsuid, WANT_OK, euid);
    CALL("setfsuid.root_ignored", setfsuid, WANT_OK, 0);
    why("an unprivileged change is ignored; the call returns the unchanged fsuid");
    DONE();
    if (CASE("setfsuid.after_refusal", setfsuid, WANT_OK, -1) != (long)euid)
        ora_fail("fsuid unchanged");
    CASE("setfsgid.query", setfsgid, WANT_OK, -1);
    CASE("setfsgid.own", setfsgid, WANT_OK, egid);
    CALL("setfsgid.root_ignored", setfsgid, WANT_OK, 0);
    why("an unprivileged change is ignored; the call returns the unchanged fsgid");
    DONE();
    if (CASE("setfsgid.after_refusal", setfsgid, WANT_OK, -1) != (long)egid)
        ora_fail("fsgid unchanged");
}

static void group_cases(void)
{
    gid_t list[64];
    long count, got;

    count = CALL("getgroups.count", getgroups, WANT_OK, 0, NULL);
    want_status(1, "out", "NULL_POINTER");
    DONE();
    if (count < 0 || count > 64)
        count = 64;
    memset(list, 0, sizeof list);
    got = CALL("getgroups.full", getgroups, WANT_OK, count, list);
    out_buf(1, list, got > 0 ? (size_t)got * sizeof list[0] : 0);
    DONE();
    if (got < 0)
        got = 0;
    CASE("getgroups.negative", getgroups, EINVAL, -1, list);
    CALL("setgroups.current", setgroups, EPERM, got, list);
    in_buf(1, list, (size_t)got * sizeof list[0]);
    why("changing the supplementary groups needs CAP_SETGID");
    DONE();
    CALL("setgroups.empty_denied", setgroups, EPERM, 0, list);
    in_buf(1, list, 0);
    DONE();
    CALL("setgroups.null", setgroups, EPERM, 0, NULL);
    want_status(1, "in", "NULL_POINTER");
    DONE();
    CALL("setgroups.negative", setgroups, EPERM, -1, list);
    want_status(1, "in", "INVALID_EXTENT");
    why("the privilege check comes before the size check");
    DONE();
}

static void capability_cases(void)
{
    struct __user_cap_header_struct header, sent;
    struct __user_cap_data_struct data[2], raised[2];
    uint32_t version;
    int32_t pid;

    memset(data, 0, sizeof data);
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    CALL("capget.v3_self", capget, WANT_OK, &header, data);
    version = header.version;
    pid = header.pid;
    in_key("arg0.version", &version, sizeof version);
    in_key("arg0.pid", &pid, sizeof pid);
    out_key("arg1.capabilities", data, sizeof data);
    DONE();
    header.version = 0;
    CALL("capget.version_query", capget, WANT_OK, &header, NULL);
    version = 0;
    in_key("arg0.version", &version, sizeof version);
    out_key("arg0.required_version", &header.version, sizeof header.version);
    why("an unknown version with no data pointer reports the kernel's version and succeeds");
    DONE();
    header.version = 0x12345678;
    CALL("capget.bad_version", capget, EINVAL, &header, data);
    version = 0x12345678;
    in_key("arg0.version", &version, sizeof version);
    out_key("arg0.required_version", &header.version, sizeof header.version);
    DONE();
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    CALL("capget.v3_null_data", capget, WANT_OK, &header, NULL);
    version = _LINUX_CAPABILITY_VERSION_3;
    in_key("arg0.version", &version, sizeof version);
    DONE();
    struct __user_cap_data_struct legacy[1];
    memset(legacy, 0, sizeof legacy);
    header.version = _LINUX_CAPABILITY_VERSION_1;
    header.pid = 0;
    CALL("capget.v1_self", capget, WANT_OK, &header, legacy);
    version = _LINUX_CAPABILITY_VERSION_1;
    pid = 0;
    in_key("arg0.version", &version, sizeof version);
    in_key("arg0.pid", &pid, sizeof pid);
    out_key("arg1.capabilities", legacy, sizeof legacy);
    why("version 1 carries one 32-bit word set");
    DONE();
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = (int)NO_PID;
    CALL("capget.no_such_pid", capget, ESRCH, &header, data);
    version = _LINUX_CAPABILITY_VERSION_3;
    pid = (int32_t)NO_PID;
    in_key("arg0.version", &version, sizeof version);
    in_key("arg0.pid", &pid, sizeof pid);
    DONE();
    CALL("capget.bad_header", capget, EFAULT, 1, data);
    want_key_status("arg0.version", "COPY_FAULT");
    DONE();

    // capset with exactly the current sets drops nothing and succeeds.
    sent.version = _LINUX_CAPABILITY_VERSION_3;
    sent.pid = 0;
    CALL("capset.unchanged", capset, WANT_OK, &sent, data);
    version = _LINUX_CAPABILITY_VERSION_3;
    pid = 0;
    in_key("arg0.version", &version, sizeof version);
    in_key("arg0.pid", &pid, sizeof pid);
    in_key("arg1.capabilities", data, sizeof data);
    DONE();
    memcpy(raised, data, sizeof raised);
    raised[0].effective |= 1U << CAP_SYS_ADMIN;
    raised[0].permitted |= 1U << CAP_SYS_ADMIN;
    CALL("capset.raise", capset, EPERM, &sent, raised);
    in_key("arg0.version", &version, sizeof version);
    in_key("arg0.pid", &pid, sizeof pid);
    in_key("arg1.capabilities", raised, sizeof raised);
    why("a permitted set larger than the current one is refused");
    DONE();
    sent.pid = (int)NO_PID;
    CALL("capset.other_pid", capset, EPERM, &sent, data);
    pid = (int32_t)NO_PID;
    in_key("arg0.version", &version, sizeof version);
    in_key("arg0.pid", &pid, sizeof pid);
    in_key("arg1.capabilities", data, sizeof data);
    why("capset may only change the calling thread");
    DONE();
}

// ---------------------------------------------------------------------------
// Sessions and process groups: changes happen only in children.

static void session_child(void *unused)
{
    (void)unused;
    CALL0("setsid.child", setsid, WANT_OK);
    volatile_case();
    DONE();
    CALL("getsid.new_session", getsid, WANT_OK, 0);
    volatile_case();
    DONE();
    CASE0("setsid.already_leader", setsid, EPERM);
    CASE("setpgid.session_leader", setpgid, EPERM, 0, 0);
}

static void group_child(void *unused)
{
    (void)unused;
    CASE("setpgid.own_group", setpgid, WANT_OK, 0, 0);
    CALL("getpgid.own_group", getpgid, WANT_OK, 0);
    volatile_case();
    DONE();
    CALL0("getpgrp.own_group", getpgrp, WANT_OK);
    volatile_case();
    DONE();
    CASE("setpgid.missing_group", setpgid, EPERM, 0, NO_PID);
    CASE("setpgid.negative_group", setpgid, EINVAL, 0, -1);
    CASE("setpgid.no_such_process", setpgid, ESRCH, NO_PID, 0);
}

static void session_cases(void)
{
    CALL0("getpgrp.self", getpgrp, WANT_OK);
    volatile_case();
    DONE();
    CALL("getpgid.self", getpgid, WANT_OK, 0);
    volatile_case();
    DONE();
    CALL("getpgid.parent", getpgid, WANT_OK, getppid());
    volatile_case();
    DONE();
    CASE("getpgid.no_such_process", getpgid, ESRCH, NO_PID);
    CALL("getsid.self", getsid, WANT_OK, 0);
    volatile_case();
    DONE();
    CASE("getsid.no_such_process", getsid, ESRCH, NO_PID);
    in_child(460, "setsid child", session_child, NULL);
    in_child(461, "process group child", group_child, NULL);

    // A parent may move its own child (that has not exec'd) to a new group.
    pid_t child = hold_child();
    CALL("setpgid.own_child", setpgid, WANT_OK, child, child);
    volatile_case();
    DONE();
    CALL("getpgid.own_child", getpgid, WANT_OK, child);
    volatile_case();
    DONE();
    struct rlimit64 limit;
    memset(&limit, 0, sizeof limit);
    CALL("prlimit64.read_child", prlimit64, WANT_OK, child, RLIMIT_NOFILE, NULL, &limit);
    want_status(2, "in", "NULL_POINTER");
    out_buf(3, &limit, sizeof limit);
    why("reading a same-user child's limits needs no privilege");
    DONE();
    release_child(child, "process group hold child");
}

// ---------------------------------------------------------------------------
// Nice values and scheduling: the main process sets only what it has.

static void nice_child(void *unused)
{
    long current = *(long *)unused, raised = current + 5 > 19 ? 19 : current + 5;
    CASE("setpriority.raise_nice", setpriority, WANT_OK, PRIO_PROCESS, 0, raised);
    CASE("getpriority.after_raise", getpriority, WANT_OK, PRIO_PROCESS, 0);
    CASE("setpriority.lower_nice", setpriority, EACCES, PRIO_PROCESS, 0, -20);
    CASE("setpriority.no_such_process", setpriority, ESRCH, PRIO_PROCESS, NO_PID, 0);
    CASE("setpriority.bad_which_child", setpriority, EINVAL, 99, 0, 0);
}

static void policy_child(void *unused)
{
    struct sched_param param;
    struct ant_sched_attr attr;
    cpu_set_t set, one;
    long len;
    (void)unused;
    memset(&param, 0, sizeof param);
    CALL("sched_setscheduler.batch", sched_setscheduler, WANT_OK, 0, SCHED_BATCH, &param);
    in_buf(2, &param, sizeof param);
    DONE();
    CASE("sched_getscheduler.batch", sched_getscheduler, WANT_OK, 0);
    memset(&attr, 0, sizeof attr);
    attr.size = SCHED_ATTR_VER0;
    attr.sched_policy = SCHED_BATCH;
    attr.sched_nice = 19;
    CALL("sched_setattr.batch_nice", sched_setattr, WANT_OK, 0, &attr, 0);
    in_buf(1, &attr, SCHED_ATTR_VER0);
    why("a user may raise its own nice value");
    DONE();
    memset(&attr, 0, sizeof attr);
    CALL("sched_getattr.batch", sched_getattr, WANT_OK, 0, &attr, SCHED_ATTR_VER1, 0);
    out_buf(1, &attr, SCHED_ATTR_VER1);
    DONE();
    CALL("sched_setscheduler.idle_reset_on_fork", sched_setscheduler, WANT_OK, 0,
         SCHED_IDLE | SCHED_RESET_ON_FORK, &param);
    in_buf(2, &param, sizeof param);
    DONE();
    CASE("sched_getscheduler.idle", sched_getscheduler, WANT_OK, 0);
    CALL("sched_setscheduler.leave_idle", sched_setscheduler, EPERM, 0, SCHED_OTHER, &param);
    in_buf(2, &param, sizeof param);
    why("an unprivileged task can neither leave SCHED_IDLE at nice 19 nor clear reset-on-fork");
    DONE();
    // Pin to the first allowed CPU.
    memset(&set, 0, sizeof set);
    len = syscall(SYS_sched_getaffinity, 0, sizeof set, &set);
    CPU_ZERO(&one);
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++)
        if (CPU_ISSET(cpu, &set)) {
            CPU_SET(cpu, &one);
            break;
        }
    if (len <= 0 || len > (long)sizeof one)
        len = 8;
    CALL("sched_setaffinity.one_cpu", sched_setaffinity, WANT_OK, 0, len, &one);
    in_buf(2, &one, (size_t)len);
    DONE();
}

static void scheduling_cases(void)
{
    struct sched_param param, high;
    struct ant_sched_attr attr;
    struct {
        struct ant_sched_attr attr;
        uint64_t tail;
    } wide;
    struct timespec slice;
    cpu_set_t set, empty;
    long prio, nice, len;

    prio = CASE("getpriority.self", getpriority, WANT_OK, PRIO_PROCESS, 0);
    nice = prio > 0 ? 20 - prio : 0;
    CALL("getpriority.group", getpriority, WANT_OK, PRIO_PGRP, 0);
    volatile_case();
    DONE();
    CALL("getpriority.user", getpriority, WANT_OK, PRIO_USER, getuid());
    volatile_case();
    DONE();
    CASE("getpriority.bad_which", getpriority, EINVAL, 99, 0);
    CASE("getpriority.no_such_process", getpriority, ESRCH, PRIO_PROCESS, NO_PID);
    CASE("setpriority.same", setpriority, WANT_OK, PRIO_PROCESS, 0, nice);
    in_child(462, "nice child", nice_child, &nice);

    memset(&param, 0, sizeof param);
    CASE("sched_getscheduler.self", sched_getscheduler, WANT_OK, 0);
    CASE("sched_getscheduler.no_such_process", sched_getscheduler, ESRCH, NO_PID);
    CASE("sched_getscheduler.negative_pid", sched_getscheduler, EINVAL, -1);
    param.sched_priority = -1;
    CALL("sched_getparam.self", sched_getparam, WANT_OK, 0, &param);
    out_buf(1, &param, sizeof param);
    DONE();
    CASE("sched_getparam.no_such_process", sched_getparam, ESRCH, NO_PID, &param);
    CASE("sched_getparam.null", sched_getparam, EINVAL, 0, NULL);
    memset(&param, 0, sizeof param);
    CALL("sched_setparam.same", sched_setparam, WANT_OK, 0, &param);
    in_buf(1, &param, sizeof param);
    DONE();
    high.sched_priority = 50;
    CALL("sched_setparam.priority_for_normal", sched_setparam, EINVAL, 0, &high);
    in_buf(1, &high, sizeof high);
    why("SCHED_OTHER takes only priority 0");
    DONE();
    CALL("sched_setparam.null", sched_setparam, EINVAL, 0, NULL);
    want_status(1, "in", "NULL_POINTER");
    DONE();
    CALL("sched_setscheduler.same", sched_setscheduler, WANT_OK, 0, SCHED_OTHER, &param);
    in_buf(2, &param, sizeof param);
    DONE();
    high.sched_priority = 10;
    CALL("sched_setscheduler.fifo_denied", sched_setscheduler, EPERM, 0, SCHED_FIFO, &high);
    in_buf(2, &high, sizeof high);
    why("real-time policies need CAP_SYS_NICE or an RLIMIT_RTPRIO allowance");
    DONE();
    CALL("sched_setscheduler.bad_policy", sched_setscheduler, EINVAL, 0, 99, &param);
    in_buf(2, &param, sizeof param);
    DONE();
    CASE("sched_get_priority_max.fifo", sched_get_priority_max, WANT_OK, SCHED_FIFO);
    CASE("sched_get_priority_max.other", sched_get_priority_max, WANT_OK, SCHED_OTHER);
    CASE("sched_get_priority_max.bad_policy", sched_get_priority_max, EINVAL, 99);
    CASE("sched_get_priority_min.rr", sched_get_priority_min, WANT_OK, SCHED_RR);
    CASE("sched_get_priority_min.batch", sched_get_priority_min, WANT_OK, SCHED_BATCH);
    CASE("sched_get_priority_min.bad_policy", sched_get_priority_min, EINVAL, -1);
    memset(&slice, 0, sizeof slice);
    CALL("sched_rr_get_interval.self", sched_rr_get_interval, WANT_OK, 0, &slice);
    out_any(1);
    volatile_case();
    DONE();
    CASE("sched_rr_get_interval.no_such_process", sched_rr_get_interval, ESRCH, NO_PID, &slice);
    CASE("sched_rr_get_interval.fault", sched_rr_get_interval, EFAULT, 0, 1);

    // Affinity: read the mask, set the same mask back, refuse an empty one.
    memset(&set, 0, sizeof set);
    len = CALL("sched_getaffinity.self", sched_getaffinity, WANT_OK, 0, sizeof set, &set);
    out_buf(2, &set, len > 0 ? (size_t)len : 0);
    why("returns the kernel's cpumask size; only that many bytes are written");
    DONE();
    if (len <= 0 || len > (long)sizeof set)
        len = 8;
    CASE("sched_getaffinity.unaligned", sched_getaffinity, EINVAL, 0, 4, &set);
    CASE("sched_getaffinity.no_such_process", sched_getaffinity, ESRCH, NO_PID, sizeof set, &set);
    CALL("sched_setaffinity.same", sched_setaffinity, WANT_OK, 0, len, &set);
    in_buf(2, &set, (size_t)len);
    DONE();
    CPU_ZERO(&empty);
    CALL("sched_setaffinity.empty", sched_setaffinity, EINVAL, 0, len, &empty);
    in_buf(2, &empty, (size_t)len);
    DONE();
    CALL("sched_setaffinity.no_such_process", sched_setaffinity, ESRCH, NO_PID, len, &set);
    in_buf(2, &set, (size_t)len);
    DONE();

    // sched_setattr / sched_getattr: struct sizes and the size handshake.
    memset(&attr, 0, sizeof attr);
    attr.size = SCHED_ATTR_VER0;
    attr.sched_policy = SCHED_OTHER;
    attr.sched_nice = (int32_t)nice;
    CALL("sched_setattr.ver0_same", sched_setattr, WANT_OK, 0, &attr, 0);
    in_buf(1, &attr, SCHED_ATTR_VER0);
    DONE();
    attr.size = 0;
    CALL("sched_setattr.size_zero", sched_setattr, WANT_OK, 0, &attr, 0);
    in_buf(1, &attr, SCHED_ATTR_VER0);
    why("size 0 means SCHED_ATTR_SIZE_VER0");
    DONE();
    attr.size = SCHED_ATTR_VER1;
    CALL("sched_setattr.ver1_same", sched_setattr, WANT_OK, 0, &attr, 0);
    in_buf(1, &attr, SCHED_ATTR_VER1);
    DONE();
    attr.size = 40;
    CALL("sched_setattr.too_small", sched_setattr, E2BIG, 0, &attr, 0);
    want_key_status("arg1.sched_attr", "INVALID_EXTENT");
    out_key("arg1.sched_attr.required_size", &attr.size, sizeof attr.size);
    why("the kernel answers a short struct with E2BIG and writes the size it knows");
    DONE();
    attr.size = SCHED_ATTR_VER0;
    CALL("sched_setattr.bad_flags", sched_setattr, EINVAL, 0, &attr, 1);
    in_buf(1, &attr, SCHED_ATTR_VER0);
    why("flags are checked first; the struct is still recorded at entry");
    DONE();
    memset(&wide, 0, sizeof wide);
    wide.attr.size = sizeof wide;
    wide.attr.sched_policy = SCHED_OTHER;
    wide.attr.sched_nice = (int32_t)nice;
    CALL("sched_setattr.zero_tail", sched_setattr, WANT_OK, 0, &wide, 0);
    in_key("arg1.sched_attr", &wide.attr, SCHED_ATTR_VER1);
    in_key("arg1.sched_attr.extension", &wide.tail, sizeof wide.tail);
    DONE();
    attr.size = SCHED_ATTR_VER0;
    attr.sched_policy = SCHED_FIFO;
    attr.sched_priority = 10;
    CALL("sched_setattr.fifo", sched_setattr, EPERM, 0, &attr, 0);
    in_buf(1, &attr, SCHED_ATTR_VER0);
    DONE();
    memset(&attr, 0, sizeof attr);
    CALL("sched_getattr.ver0", sched_getattr, WANT_OK, 0, &attr, SCHED_ATTR_VER0, 0);
    out_buf(1, &attr, SCHED_ATTR_VER0);
    DONE();
    memset(&attr, 0, sizeof attr);
    CALL("sched_getattr.ver1", sched_getattr, WANT_OK, 0, &attr, SCHED_ATTR_VER1, 0);
    out_buf(1, &attr, SCHED_ATTR_VER1);
    DONE();
    CASE("sched_getattr.too_small", sched_getattr, EINVAL, 0, &attr, 40, 0);
    CASE("sched_getattr.bad_flags", sched_getattr, EINVAL, 0, &attr, SCHED_ATTR_VER0, 1);
    CASE("sched_getattr.no_such_process", sched_getattr, ESRCH, NO_PID, &attr, SCHED_ATTR_VER0,
         0);
    CASE0("sched_yield.self", sched_yield, WANT_OK);
    in_child(463, "scheduling policy child", policy_child, NULL);
}

static void ioprio_cases(void)
{
    long original = CASE("ioprio_get.self", ioprio_get, WANT_OK, IOPRIO_WHO_PROCESS, 0);
    long prio = syscall(SYS_getpriority, PRIO_PROCESS, 0);
    long nice = prio > 0 ? 20 - prio : 0;
    // A task that never set an I/O priority reports the best-effort level its
    // nice value implies; restoring "none" keeps it following the nice value.
    long restore = original == IOPRIO_VALUE(IOPRIO_CLASS_BE, (nice + 20) / 5) ? 0 : original;
    CASE("ioprio_set.best_effort_low", ioprio_set, WANT_OK, IOPRIO_WHO_PROCESS, 0,
         IOPRIO_VALUE(IOPRIO_CLASS_BE, 7));
    CASE("ioprio_get.changed", ioprio_get, WANT_OK, IOPRIO_WHO_PROCESS, 0);
    CASE("ioprio_set.restore", ioprio_set, WANT_OK, IOPRIO_WHO_PROCESS, 0,
         restore >= 0 ? restore : 0);
    CASE("ioprio_set.realtime", ioprio_set, EPERM, IOPRIO_WHO_PROCESS, 0,
         IOPRIO_VALUE(IOPRIO_CLASS_RT, 0));
    CASE("ioprio_set.bad_class", ioprio_set, EINVAL, IOPRIO_WHO_PROCESS, 0, IOPRIO_VALUE(7, 0));
    CALL("ioprio_get.user", ioprio_get, WANT_OK, IOPRIO_WHO_USER, getuid());
    volatile_case();
    DONE();
    CASE("ioprio_get.bad_which", ioprio_get, EINVAL, 99, 0);
    CASE("ioprio_get.no_such_process", ioprio_get, ESRCH, IOPRIO_WHO_PROCESS, NO_PID);
}

// ---------------------------------------------------------------------------
// Resource limits: lower RLIMIT_NOFILE's soft limit and restore it.

static void limit_cases(void)
{
    struct rlimit original, lowered, check, bad;
    struct rlimit64 old64, new64, orig64;

    memset(&original, 0, sizeof original);
    CALL("getrlimit.nofile", getrlimit, WANT_OK, RLIMIT_NOFILE, &original);
    out_buf(1, &original, sizeof original);
    volatile_case();
    DONE();
    CASE("getrlimit.bad_resource", getrlimit, EINVAL, 99, &check);
    CASE("getrlimit.fault", getrlimit, EFAULT, RLIMIT_NOFILE, 1);
    lowered = original;
    if (lowered.rlim_cur > 256)
        lowered.rlim_cur = 256;
    CALL("setrlimit.lower_soft", setrlimit, WANT_OK, RLIMIT_NOFILE, &lowered);
    in_buf(1, &lowered, sizeof lowered);
    volatile_case();
    DONE();
    memset(&check, 0, sizeof check);
    CALL("getrlimit.lowered", getrlimit, WANT_OK, RLIMIT_NOFILE, &check);
    out_buf(1, &check, sizeof check);
    volatile_case();
    DONE();
    CALL("setrlimit.restore", setrlimit, WANT_OK, RLIMIT_NOFILE, &original);
    in_buf(1, &original, sizeof original);
    volatile_case();
    DONE();
    bad.rlim_cur = original.rlim_cur;
    bad.rlim_max = original.rlim_max + 1;
    CALL("setrlimit.raise_hard", setrlimit, EPERM, RLIMIT_NOFILE, &bad);
    in_buf(1, &bad, sizeof bad);
    why("raising a hard limit needs CAP_SYS_RESOURCE (and NOFILE is capped by nr_open)");
    volatile_case();
    DONE();
    bad.rlim_cur = original.rlim_max;
    bad.rlim_max = original.rlim_max > 0 ? original.rlim_max - 1 : 0;
    CALL("setrlimit.soft_above_hard", setrlimit, EINVAL, RLIMIT_NOFILE, &bad);
    in_buf(1, &bad, sizeof bad);
    volatile_case();
    DONE();
    CALL("setrlimit.null", setrlimit, EFAULT, RLIMIT_NOFILE, NULL);
    want_status(1, "in", "NULL_POINTER");
    DONE();

    memset(&orig64, 0, sizeof orig64);
    CALL("prlimit64.read", prlimit64, WANT_OK, 0, RLIMIT_NOFILE, NULL, &orig64);
    want_status(2, "in", "NULL_POINTER");
    out_buf(3, &orig64, sizeof orig64);
    volatile_case();
    DONE();
    new64 = orig64;
    if (new64.rlim_cur > 200)
        new64.rlim_cur = 200;
    memset(&old64, 0, sizeof old64);
    CALL("prlimit64.lower_soft", prlimit64, WANT_OK, 0, RLIMIT_NOFILE, &new64, &old64);
    in_buf(2, &new64, sizeof new64);
    out_buf(3, &old64, sizeof old64);
    volatile_case();
    DONE();
    CALL("prlimit64.restore", prlimit64, WANT_OK, 0, RLIMIT_NOFILE, &orig64, NULL);
    in_buf(2, &orig64, sizeof orig64);
    want_status(3, "out", "NULL_POINTER");
    volatile_case();
    DONE();
    CALL("prlimit64.no_such_process", prlimit64, ESRCH, NO_PID, RLIMIT_NOFILE, NULL, &old64);
    want_status(2, "in", "NULL_POINTER");
    DONE();
    CALL("prlimit64.bad_resource", prlimit64, EINVAL, 0, 99, NULL, &old64);
    want_status(2, "in", "NULL_POINTER");
    DONE();
    if (getrlimit(RLIMIT_NOFILE, &check) != 0 || check.rlim_cur != original.rlim_cur ||
        check.rlim_max != original.rlim_max)
        ora_fail("RLIMIT_NOFILE restored");
}

// ---------------------------------------------------------------------------
// Landlock: rulesets are built in the main process, enforced in a child.

static void landlock_child(void *unused)
{
    (void)unused;
    CASE("landlock_restrict_self.without_no_new_privs", landlock_restrict_self, ll(EPERM),
         ruleset_fd, 0);
    if (syscall(SYS_prctl, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0) != 0)
        ora_fail("no_new_privs for landlock");
    CASE("landlock_restrict_self.bad_flags", landlock_restrict_self, ll(EINVAL), ruleset_fd, 1);
    CASE("landlock_restrict_self.bad_fd", landlock_restrict_self, ll(EBADF), 999, 0);
    CASE("landlock_restrict_self.enforce", landlock_restrict_self, ll(WANT_OK), ruleset_fd, 0);
}

static void landlock_cases(void)
{
    struct ll_ruleset_attr attr, net_attr;
    struct ll_path_beneath beneath;
    struct ll_net_port port;
    long abi, net_fd;
    int dir;

    abi = CALL("landlock_create_ruleset.version", landlock_create_ruleset, WANT_ANY, NULL, 0,
               LL_CREATE_RULESET_VERSION);
    why("the ABI version when Landlock is built and enabled; ENOSYS or EOPNOTSUPP otherwise");
    DONE();
    landlock_errno = abi < 0 ? errno : 0;

    memset(&attr, 0, sizeof attr);
    attr.handled_access_fs = LL_FS_EXECUTE | LL_FS_WRITE_FILE | LL_FS_READ_FILE | LL_FS_READ_DIR;
    ruleset_fd = CALL("landlock_create_ruleset.fs_v1", landlock_create_ruleset, ll(WANT_OK), &attr,
                      8, 0);
    in_buf(0, &attr, 8);
    DONE();
    CALL("landlock_create_ruleset.too_small", landlock_create_ruleset, ll(EINVAL), &attr, 4, 0);
    want_status(0, "in", "INVALID_EXTENT");
    DONE();
    CASE("landlock_create_ruleset.bad_flags", landlock_create_ruleset, ll(EINVAL), &attr, 8, 0x80);
    memset(&net_attr, 0, sizeof net_attr);
    CALL("landlock_create_ruleset.nothing_handled", landlock_create_ruleset, ll(ENOMSG), &net_attr,
         16, 0);
    in_buf(0, &net_attr, 16);
    DONE();
    net_attr.handled_access_fs = LL_FS_READ_FILE;
    net_attr.handled_access_net = LL_NET_BIND_TCP;
    net_fd = CALL("landlock_create_ruleset.fs_and_net", landlock_create_ruleset, WANT_ANY,
                  &net_attr, 16, 0);
    in_buf(0, &net_attr, 16);
    why("network rules need Landlock ABI 4 (Linux 6.7) and CONFIG_INET");
    DONE();

    dir = open(work_dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0)
        ora_fail("landlock rule directory");
    memset(&beneath, 0, sizeof beneath);
    beneath.allowed_access = LL_FS_READ_FILE | LL_FS_READ_DIR;
    beneath.parent_fd = dir;
    CALL("landlock_add_rule.path_beneath", landlock_add_rule, ll(WANT_OK), ruleset_fd,
         LL_RULE_PATH_BENEATH, &beneath, 0);
    in_buf(2, &beneath, sizeof beneath);
    DONE();
    beneath.allowed_access = LL_FS_REMOVE_DIR;
    CALL("landlock_add_rule.not_handled", landlock_add_rule, ll(EINVAL), ruleset_fd,
         LL_RULE_PATH_BENEATH, &beneath, 0);
    in_buf(2, &beneath, sizeof beneath);
    why("a rule may only allow accesses its ruleset handles");
    DONE();
    beneath.allowed_access = LL_FS_READ_FILE;
    CALL("landlock_add_rule.bad_ruleset", landlock_add_rule, ll(EBADF), 999, LL_RULE_PATH_BENEATH,
         &beneath, 0);
    in_buf(2, &beneath, sizeof beneath);
    DONE();
    CALL("landlock_add_rule.bad_flags", landlock_add_rule, ll(EINVAL), ruleset_fd,
         LL_RULE_PATH_BENEATH, &beneath, 1);
    in_buf(2, &beneath, sizeof beneath);
    DONE();
    CALL("landlock_add_rule.unknown_type", landlock_add_rule, ll(EINVAL), ruleset_fd, 99, &beneath,
         0);
    want_key_status("landlock.unknown_rule", "NO_DECODER");
    DONE();
    memset(&port, 0, sizeof port);
    port.allowed_access = LL_NET_BIND_TCP;
    port.port = 8080;
    CALL("landlock_add_rule.net_port", landlock_add_rule, WANT_ANY, net_fd, LL_RULE_NET_PORT,
         &port, 0);
    in_buf(2, &port, sizeof port);
    why("succeeds only where the network ruleset above could be created");
    DONE();
    in_child(464, "landlock child", landlock_child, NULL);
    if (net_fd >= 0)
        close((int)net_fd);
    if (ruleset_fd >= 0)
        close((int)ruleset_fd);
    if (dir >= 0)
        close(dir);
}

// ---------------------------------------------------------------------------
// LSM attribute syscalls (Linux 6.8).

static void lsm_cases(void)
{
    uint64_t ids[32];
    uint32_t size, capacity;
    unsigned char buffer[512];
    struct ant_lsm_ctx selector, unknown;
    long count, got;
    int err;

    memset(ids, 0, sizeof ids);
    size = capacity = sizeof ids;
    count = CALL("lsm_list_modules.all", lsm_list_modules, WANT_OK, ids, &size, 0);
    in_key("lsm.capacity", &capacity, sizeof capacity);
    out_key("lsm.returned_size", &size, sizeof size);
    out_key("lsm.output", ids, size <= sizeof ids ? size : 0);
    why("the capability module is always listed, so at least one id");
    DONE();
    if (count < 1)
        ora_fail("lsm_list_modules count");
    size = capacity = 0;
    CALL("lsm_list_modules.too_small", lsm_list_modules, E2BIG, ids, &size, 0);
    in_key("lsm.capacity", &capacity, sizeof capacity);
    out_key("lsm.returned_size", &size, sizeof size);
    why("the kernel writes the size it needs, then refuses");
    DONE();
    size = capacity = sizeof ids;
    CALL("lsm_list_modules.bad_flags", lsm_list_modules, EINVAL, ids, &size, 1);
    in_key("lsm.capacity", &capacity, sizeof capacity);
    DONE();
    CALL("lsm_list_modules.bad_size_pointer", lsm_list_modules, EFAULT, ids, 1, 0);
    want_key_status("lsm.capacity", "COPY_FAULT");
    DONE();

    memset(buffer, 0, sizeof buffer);
    size = capacity = sizeof buffer;
    got = CALL("lsm_get_self_attr.current", lsm_get_self_attr, WANT_ANY, ANT_LSM_ATTR_CURRENT,
               buffer, &size, 0);
    err = errno;
    in_key("lsm.capacity", &capacity, sizeof capacity);
    if (got >= 0 || err == E2BIG)
        out_key("lsm.returned_size", &size, sizeof size);
    if (got >= 0)
        out_key("lsm.output", buffer, size <= sizeof buffer ? size : 0);
    why("the count of modules that report a current context: SELinux does, others may not "
        "(EOPNOTSUPP when none)");
    volatile_case();
    DONE();
    memset(&selector, 0, sizeof selector);
    memset(buffer, 0, sizeof buffer);
    selector.id = ANT_LSM_ID_SELINUX;
    memcpy(buffer, &selector, sizeof selector);
    size = capacity = sizeof buffer;
    got = CALL("lsm_get_self_attr.single_selinux", lsm_get_self_attr, WANT_ANY,
               ANT_LSM_ATTR_CURRENT, buffer, &size, ANT_LSM_FLAG_SINGLE);
    err = errno;
    in_key("lsm.capacity", &capacity, sizeof capacity);
    in_key("arg1.lsm_selector", &selector, sizeof selector);
    if (got >= 0 || err == E2BIG)
        out_key("lsm.returned_size", &size, sizeof size);
    if (got >= 0)
        out_key("lsm.output", buffer, size <= sizeof buffer ? size : 0);
    why("depends on SELinux being active in the guest");
    volatile_case();
    DONE();
    size = capacity = sizeof buffer;
    CALL("lsm_get_self_attr.undefined_attr", lsm_get_self_attr, EINVAL, ANT_LSM_ATTR_UNDEF, buffer,
         &size, 0);
    in_key("lsm.capacity", &capacity, sizeof capacity);
    DONE();
    CALL("lsm_get_self_attr.bad_flags", lsm_get_self_attr, EINVAL, ANT_LSM_ATTR_CURRENT, buffer,
         &size, 2);
    in_key("lsm.capacity", &capacity, sizeof capacity);
    DONE();

    memset(&unknown, 0, sizeof unknown);
    unknown.id = 0xdead;
    unknown.len = sizeof unknown;
    CALL("lsm_set_self_attr.unknown_module", lsm_set_self_attr, EOPNOTSUPP, ANT_LSM_ATTR_CURRENT,
         &unknown, sizeof unknown, 0);
    in_buf(1, &unknown, sizeof unknown);
    why("no module has this id, so no module changes anything");
    DONE();
    CALL("lsm_set_self_attr.too_small", lsm_set_self_attr, EINVAL, ANT_LSM_ATTR_CURRENT, &unknown,
         8, 0);
    want_status(1, "in", "INVALID_EXTENT");
    DONE();
    CALL("lsm_set_self_attr.bad_flags", lsm_set_self_attr, EINVAL, ANT_LSM_ATTR_CURRENT, &unknown,
         sizeof unknown, 1);
    in_buf(1, &unknown, sizeof unknown);
    DONE();
}

void area_identity(void)
{
    if (pipe2(hold, O_CLOEXEC) != 0) {
        ora_fail("identity hold pipe");
        return;
    }
    touch(work_dir, sizeof work_dir);
    id_cases();
    group_cases();
    capability_cases();
    session_cases();
    scheduling_cases();
    ioprio_cases();
    limit_cases();
    landlock_cases();
    lsm_cases();
    close(hold[0]);
    close(hold[1]);
}
