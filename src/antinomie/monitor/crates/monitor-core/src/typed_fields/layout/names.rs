// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Names for the members the layout decoder reads: which members hold flags,
//! an enumeration, a signal, an error, a descriptor, a time, a file mode, and
//! how the call that passed the structure changes what a time means.
//!
//! A rule is keyed by the layout's type and the member's path
//! (`it_value.tv_sec`); a few rules are by member name in any layout (`fd`,
//! `*_fd`, `exit_signal`). A member with no rule reads as a number, a pointer
//! as hex. Flag groups that the syscall table has (`open`, `clone_flags`,
//! `message`) are read with the ABI's constants; the others are the pinned
//! UAPI's values, which the shipped ABIs share.
use super::kernel;
use super::time::{self, TimeKind};
use super::{Cx, Raw};
use crate::syscalls::scalars::STATX_MASK;
use crate::typed_fields::{Call, Node, flags, named, pointer, signals};

type Table = &'static [(&'static str, u64)];

const EPOLL_EVENTS: Table = &[
    ("EPOLLIN", 0x1),
    ("EPOLLPRI", 0x2),
    ("EPOLLOUT", 0x4),
    ("EPOLLERR", 0x8),
    ("EPOLLHUP", 0x10),
    ("EPOLLNVAL", 0x20),
    ("EPOLLRDNORM", 0x40),
    ("EPOLLRDBAND", 0x80),
    ("EPOLLWRNORM", 0x100),
    ("EPOLLWRBAND", 0x200),
    ("EPOLLMSG", 0x400),
    ("EPOLLRDHUP", 0x2000),
    ("EPOLLEXCLUSIVE", 1 << 28),
    ("EPOLLWAKEUP", 1 << 29),
    ("EPOLLONESHOT", 1 << 30),
    ("EPOLLET", 1 << 31),
];

const SA_FLAGS: Table = &[
    ("SA_NOCLDSTOP", 0x1),
    ("SA_NOCLDWAIT", 0x2),
    ("SA_SIGINFO", 0x4),
    ("SA_UNSUPPORTED", 0x400),
    ("SA_EXPOSE_TAGBITS", 0x800),
    ("SA_RESTORER", 0x0400_0000),
    ("SA_ONSTACK", 0x0800_0000),
    ("SA_RESTART", 0x1000_0000),
    ("SA_NODEFER", 0x4000_0000),
    ("SA_RESETHAND", 0x8000_0000),
];

const RESOLVE: Table = &[
    ("RESOLVE_NO_XDEV", 0x01),
    ("RESOLVE_NO_MAGICLINKS", 0x02),
    ("RESOLVE_NO_SYMLINKS", 0x04),
    ("RESOLVE_BENEATH", 0x08),
    ("RESOLVE_IN_ROOT", 0x10),
    ("RESOLVE_CACHED", 0x20),
];

pub(in crate::typed_fields) const EFLAGS: Table = &[
    ("CF", 0x1),
    ("PF", 0x4),
    ("AF", 0x10),
    ("ZF", 0x40),
    ("SF", 0x80),
    ("TF", 0x100),
    ("IF", 0x200),
    ("DF", 0x400),
    ("OF", 0x800),
    ("NT", 0x4000),
    ("RF", 0x1_0000),
    ("VM", 0x2_0000),
    ("AC", 0x4_0000),
    ("ID", 0x20_0000),
];

const SCHED_POLICY: Table = &[
    ("SCHED_NORMAL", 0),
    ("SCHED_FIFO", 1),
    ("SCHED_RR", 2),
    ("SCHED_BATCH", 3),
    ("SCHED_IDLE", 5),
    ("SCHED_DEADLINE", 6),
    ("SCHED_EXT", 7),
];

const SCHED_FLAGS: Table = &[
    ("SCHED_FLAG_RESET_ON_FORK", 0x01),
    ("SCHED_FLAG_RECLAIM", 0x02),
    ("SCHED_FLAG_DL_OVERRUN", 0x04),
    ("SCHED_FLAG_KEEP_POLICY", 0x08),
    ("SCHED_FLAG_KEEP_PARAMS", 0x10),
    ("SCHED_FLAG_UTIL_CLAMP_MIN", 0x20),
    ("SCHED_FLAG_UTIL_CLAMP_MAX", 0x40),
];

const PERF_TYPE: Table = &[
    ("PERF_TYPE_HARDWARE", 0),
    ("PERF_TYPE_SOFTWARE", 1),
    ("PERF_TYPE_TRACEPOINT", 2),
    ("PERF_TYPE_HW_CACHE", 3),
    ("PERF_TYPE_RAW", 4),
    ("PERF_TYPE_BREAKPOINT", 5),
];

const MOUNT_ATTR: Table = &[
    ("MOUNT_ATTR_RDONLY", 0x1),
    ("MOUNT_ATTR_NOSUID", 0x2),
    ("MOUNT_ATTR_NODEV", 0x4),
    ("MOUNT_ATTR_NOEXEC", 0x8),
    ("MOUNT_ATTR_NOATIME", 0x10),
    ("MOUNT_ATTR_STRICTATIME", 0x20),
    ("MOUNT_ATTR_NODIRATIME", 0x80),
    ("MOUNT_ATTR_IDMAP", 0x10_0000),
    ("MOUNT_ATTR_NOSYMFOLLOW", 0x20_0000),
];

const PROPAGATION: Table = &[
    ("MS_UNBINDABLE", 1 << 17),
    ("MS_PRIVATE", 1 << 18),
    ("MS_SLAVE", 1 << 19),
    ("MS_SHARED", 1 << 20),
];

const LANDLOCK_FS: Table = &[
    ("LANDLOCK_ACCESS_FS_EXECUTE", 0x1),
    ("LANDLOCK_ACCESS_FS_WRITE_FILE", 0x2),
    ("LANDLOCK_ACCESS_FS_READ_FILE", 0x4),
    ("LANDLOCK_ACCESS_FS_READ_DIR", 0x8),
    ("LANDLOCK_ACCESS_FS_REMOVE_DIR", 0x10),
    ("LANDLOCK_ACCESS_FS_REMOVE_FILE", 0x20),
    ("LANDLOCK_ACCESS_FS_MAKE_CHAR", 0x40),
    ("LANDLOCK_ACCESS_FS_MAKE_DIR", 0x80),
    ("LANDLOCK_ACCESS_FS_MAKE_REG", 0x100),
    ("LANDLOCK_ACCESS_FS_MAKE_SOCK", 0x200),
    ("LANDLOCK_ACCESS_FS_MAKE_FIFO", 0x400),
    ("LANDLOCK_ACCESS_FS_MAKE_BLOCK", 0x800),
    ("LANDLOCK_ACCESS_FS_MAKE_SYM", 0x1000),
    ("LANDLOCK_ACCESS_FS_REFER", 0x2000),
    ("LANDLOCK_ACCESS_FS_TRUNCATE", 0x4000),
    ("LANDLOCK_ACCESS_FS_IOCTL_DEV", 0x8000),
];

const LANDLOCK_NET: Table = &[
    ("LANDLOCK_ACCESS_NET_BIND_TCP", 0x1),
    ("LANDLOCK_ACCESS_NET_CONNECT_TCP", 0x2),
];

const LANDLOCK_SCOPE: Table = &[
    ("LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET", 0x1),
    ("LANDLOCK_SCOPE_SIGNAL", 0x2),
];

const ADJ_MODES: Table = &[
    ("ADJ_OFFSET", 0x1),
    ("ADJ_FREQUENCY", 0x2),
    ("ADJ_MAXERROR", 0x4),
    ("ADJ_ESTERROR", 0x8),
    ("ADJ_STATUS", 0x10),
    ("ADJ_TIMECONST", 0x20),
    ("ADJ_TAI", 0x80),
    ("ADJ_SETOFFSET", 0x100),
    ("ADJ_MICRO", 0x1000),
    ("ADJ_NANO", 0x2000),
    ("ADJ_TICK", 0x4000),
];

const TIMEX_STATUS: Table = &[
    ("STA_PLL", 0x1),
    ("STA_PPSFREQ", 0x2),
    ("STA_PPSTIME", 0x4),
    ("STA_FLL", 0x8),
    ("STA_INS", 0x10),
    ("STA_DEL", 0x20),
    ("STA_UNSYNC", 0x40),
    ("STA_FREQHOLD", 0x80),
    ("STA_PPSSIGNAL", 0x100),
    ("STA_PPSJITTER", 0x200),
    ("STA_PPSWANDER", 0x400),
    ("STA_PPSERROR", 0x800),
    ("STA_CLOCKERR", 0x1000),
    ("STA_NANO", 0x2000),
    ("STA_MODE", 0x4000),
    ("STA_CLK", 0x8000),
];

const LOCK_TYPE: Table = &[("F_RDLCK", 0), ("F_WRLCK", 1), ("F_UNLCK", 2)];
const WHENCE: Table = &[
    ("SEEK_SET", 0),
    ("SEEK_CUR", 1),
    ("SEEK_END", 2),
    ("SEEK_DATA", 3),
    ("SEEK_HOLE", 4),
];
const OWNER_TYPE: Table = &[("F_OWNER_TID", 0), ("F_OWNER_PID", 1), ("F_OWNER_PGRP", 2)];
const SYSCALL_INFO_OP: Table = &[
    ("PTRACE_SYSCALL_INFO_NONE", 0),
    ("PTRACE_SYSCALL_INFO_ENTRY", 1),
    ("PTRACE_SYSCALL_INFO_EXIT", 2),
    ("PTRACE_SYSCALL_INFO_SECCOMP", 3),
];

/// `f_type` of statfs: the filesystem's magic number.
const FS_MAGIC: Table = &[
    ("EXT4_SUPER_MAGIC", 0xef53),
    ("TMPFS_MAGIC", 0x0102_1994),
    ("PROC_SUPER_MAGIC", 0x9fa0),
    ("SYSFS_MAGIC", 0x6265_6572),
    ("DEVPTS_SUPER_MAGIC", 0x1cd1),
    ("OVERLAYFS_SUPER_MAGIC", 0x794c_7630),
    ("BTRFS_SUPER_MAGIC", 0x9123_683e),
    ("XFS_SUPER_MAGIC", 0x5846_5342),
    ("NFS_SUPER_MAGIC", 0x6969),
    ("CGROUP_SUPER_MAGIC", 0x0027_e0eb),
    ("CGROUP2_SUPER_MAGIC", 0x6367_7270),
    ("SQUASHFS_MAGIC", 0x7371_7368),
    ("FUSE_SUPER_MAGIC", 0x6573_5546),
    ("RAMFS_MAGIC", 0x8584_58f6),
    ("HUGETLBFS_MAGIC", 0x9584_58f6),
    ("DEBUGFS_MAGIC", 0x6462_6720),
    ("TRACEFS_MAGIC", 0x7472_6163),
    ("SECURITYFS_MAGIC", 0x7363_6673),
    ("SELINUX_MAGIC", 0xf97c_ff8c),
    ("BPF_FS_MAGIC", 0xcafe_4a11),
    ("ISOFS_SUPER_MAGIC", 0x9660),
    ("MSDOS_SUPER_MAGIC", 0x4d44),
    ("NTFS_SB_MAGIC", 0x5346_544e),
    ("V9FS_MAGIC", 0x0102_1997),
    ("DEVMEM_MAGIC", 0x454d_444d),
];

/// How a member's value is written.
#[derive(Clone, Copy)]
enum Fmt {
    Hex,
    /// An address: `NULL` or hex.
    Ptr,
    /// x86 flags without the always-set bit 1.
    Eflags,
    Flags(Table),
    /// A host flag group, read with the ABI's constants.
    Group(&'static str),
    Enum(Table),
    Signal,
    SigSet,
    Handler,
    /// Permission bits in octal (`0644`).
    Perm,
    /// A stat `st_mode`: file type and permission bits.
    StatMode,
    Fd,
    Errno,
    Rlimit,
    FsMagic,
    /// Seconds since the epoch, as a UTC date; 0 stays 0.
    Date,
}

/// The rule of member `path` of layout `layout`.
fn rule(layout: &str, path: &str) -> Option<Fmt> {
    use Fmt::*;
    let base = layout.split('[').next().unwrap_or(layout);
    let rule = match (base, path) {
        ("sigaction", "sa_handler") => Handler,
        ("sigaction", "sa_flags") => Flags(SA_FLAGS),
        ("sigaction", "sa_restorer") => Ptr,
        ("sigaction", "sa_mask" | "sa_mask.sig[0]") => SigSet,
        ("epoll_event", "events") => Flags(EPOLL_EVENTS),
        ("epoll_event", "data") => Hex,
        ("flock", "l_type") => Enum(LOCK_TYPE),
        ("flock", "l_whence") => Enum(WHENCE),
        ("f_owner_ex", "type") => Enum(OWNER_TYPE),
        ("open_how", "flags") => Group("open"),
        ("open_how", "mode") => Perm,
        ("open_how", "resolve") => Flags(RESOLVE),
        (
            "clone_args",
            "pidfd" | "child_tid" | "parent_tid" | "stack" | "tls" | "set_tid" | "cgroup",
        ) => Ptr,
        ("clone_args", "flags") => Group("clone_flags"),
        ("clone_args", "exit_signal") => Signal,
        ("user_regs_struct", "flags") => Eflags,
        ("user_regs_struct", "orig_ax") => return None,
        ("user_regs_struct", _) => Hex,
        ("ptrace_syscall_info", "op") => Enum(SYSCALL_INFO_OP),
        ("ptrace_syscall_info", "arch") => Hex,
        ("rlimit" | "rlimit64", "rlim_cur" | "rlim_max") => Rlimit,
        ("stat", "st_mode") | ("statx", "stx_mode") => StatMode,
        ("statx", "stx_mask") => Flags(STATX_MASK),
        ("statfs", "f_type") => FsMagic,
        ("sched_attr", "sched_policy") => Enum(SCHED_POLICY),
        ("sched_attr", "sched_flags") => Flags(SCHED_FLAGS),
        ("msghdr" | "mmsghdr", "msg_flags" | "msg_hdr.msg_flags") => Group("message"),
        ("timex", "modes") => Flags(ADJ_MODES),
        ("timex", "status") => Flags(TIMEX_STATUS),
        ("perf_event_attr", "type") => Enum(PERF_TYPE),
        ("perf_event_attr", "sample_type") => Flags(kernel::SAMPLE_TYPE),
        ("perf_event_attr", "read_format") => Flags(kernel::READ_FORMAT),
        ("perf_event_attr", "precise_ip") => Enum(kernel::PRECISE_IP),
        ("perf_event_attr", "bp_type") => Enum(kernel::BREAKPOINT_TYPE),
        ("perf_event_attr", "config" | "config1" | "config2" | "config3" | "sig_data") => Hex,
        ("perf_event_attr", "sample_regs_user" | "sample_regs_intr") => Hex,
        ("perf_event_attr", "branch_sample_type") => Hex,
        ("msqid64_ds" | "semid64_ds" | "shmid64_ds", path) if path.ends_with("time") => Date,
        ("if_dqblk" | "if_nextdqblk", "dqb_btime" | "dqb_itime") => Date,
        ("if_dqblk" | "if_nextdqblk", "dqb_valid") => Flags(kernel::QIF),
        ("if_dqinfo", "dqi_flags") => Flags(kernel::DQF),
        ("if_dqinfo", "dqi_valid") => Flags(kernel::IIF),
        ("fs_quota_stat" | "fs_quota_statv", "qs_flags") => Flags(kernel::FS_QUOTA_STATE),
        ("fs_disk_quota", "d_flags") => Flags(kernel::FS_QUOTA_TYPE),
        ("fs_disk_quota", "d_fieldmask") => Flags(kernel::FS_DQ_FIELDS),
        ("fs_disk_quota", "d_btimer" | "d_itimer" | "d_rtbtimer") => Date,
        ("lsm_ctx", "id") => Enum(kernel::LSM_ID),
        ("lsm_ctx", "flags") => Flags(kernel::LSM_FLAGS),
        ("mount_attr", "attr_set" | "attr_clr") => Flags(MOUNT_ATTR),
        ("mount_attr", "propagation") => Enum(PROPAGATION),
        ("landlock_ruleset_attr", "handled_access_fs") => Flags(LANDLOCK_FS),
        ("landlock_ruleset_attr", "handled_access_net") => Flags(LANDLOCK_NET),
        ("landlock_ruleset_attr", "scoped") => Flags(LANDLOCK_SCOPE),
        ("landlock_path_beneath_attr", "allowed_access") => Flags(LANDLOCK_FS),
        ("landlock_net_port_attr", "allowed_access") => Flags(LANDLOCK_NET),
        ("msqid64_ds" | "semid64_ds" | "shmid64_ds", path) if path.ends_with("perm.mode") => Perm,
        ("msqid64_ds" | "semid64_ds" | "shmid64_ds", path) if path.ends_with("perm.key") => Hex,
        _ => return by_name(path),
    };
    Some(rule)
}

/// Rules by a member's own name, whatever the layout.
fn by_name(path: &str) -> Option<Fmt> {
    let name = path.rsplit('.').next().unwrap_or(path);
    if name == "fd" || name.ends_with("_fd") {
        return Some(Fmt::Fd);
    }
    if name == "exit_signal" || name.ends_with("_signo") {
        return Some(Fmt::Signal);
    }
    if name.ends_with("_errno") {
        return Some(Fmt::Errno);
    }
    None
}

/// `value` by name, else decimal.
fn enumerated(value: u64, table: Table) -> String {
    named(value, table)
}

/// A file mode: its type name when it has one, then the permission bits.
pub(super) fn stat_mode(mode: u64) -> String {
    let kind = match mode & 0o170_000 {
        0o140_000 => "S_IFSOCK",
        0o120_000 => "S_IFLNK",
        0o100_000 => "S_IFREG",
        0o060_000 => "S_IFBLK",
        0o040_000 => "S_IFDIR",
        0o020_000 => "S_IFCHR",
        0o010_000 => "S_IFIFO",
        _ => "",
    };
    let permissions = format!("{:04o}", mode & 0o7777);
    if kind.is_empty() {
        permissions
    } else {
        format!("{kind}|{permissions}")
    }
}

fn group_flags(abi: crate::syscalls::Abi, group: &str, value: u64) -> String {
    let found = crate::syscalls::table(abi).flag_group(group, value);
    let mut parts = found.names;
    if found.unknown_bits != 0 {
        parts.push(format!("{:#x}", found.unknown_bits));
    }
    if parts.is_empty() {
        "0".into()
    } else {
        parts.join("|")
    }
}

/// A member's text: its rule's, else a number (hex for a pointer).
pub(super) fn leaf(cx: &Cx<'_>, path: &str, raw: &Raw) -> String {
    let value = raw.value;
    match rule(cx.layout, path) {
        Some(Fmt::Hex) => format!("{value:#x}"),
        Some(Fmt::Ptr) => pointer(value),
        Some(Fmt::Eflags) => flags(value & !0x2, EFLAGS),
        Some(Fmt::Flags(table)) => flags(value, table),
        Some(Fmt::Group(group)) => group_flags(cx.abi, group, value),
        Some(Fmt::Enum(table)) => enumerated(value, table),
        Some(Fmt::Signal) => {
            if value == 0 {
                "0".into()
            } else {
                signals::signal_name(value)
            }
        }
        Some(Fmt::SigSet) => signals::sigset(&value.to_le_bytes())
            .map_or_else(|| value.to_string(), |set| set.full_line()),
        Some(Fmt::Handler) => match value {
            0 => "SIG_DFL".into(),
            1 => "SIG_IGN".into(),
            u64::MAX => "SIG_ERR".into(),
            _ => pointer(value),
        },
        Some(Fmt::Date) => match time::time(raw.signed, 0, 1, TimeKind::Wall) {
            Some(date) if value != 0 => date,
            _ => plain(raw),
        },
        Some(Fmt::Perm) => format!("{value:04o}"),
        Some(Fmt::StatMode) => stat_mode(value),
        Some(Fmt::Fd) => match raw.signed {
            -100 => "AT_FDCWD".into(),
            fd => fd.to_string(),
        },
        Some(Fmt::Errno) => match crate::errno::errno_name(raw.signed.unsigned_abs()) {
            Some(name) if raw.signed != 0 => name.to_owned(),
            _ => raw.signed.to_string(),
        },
        Some(Fmt::Rlimit) => {
            if value == u64::MAX || value == u64::MAX >> 1 {
                "RLIM_INFINITY".into()
            } else {
                value.to_string()
            }
        }
        Some(Fmt::FsMagic) => match FS_MAGIC.iter().find(|(_, magic)| *magic == value) {
            Some((name, _)) => (*name).to_owned(),
            None => format!("{value:#x}"),
        },
        None => plain(raw),
    }
}

/// A member with no rule: a number, an address as hex.
pub(super) fn plain(raw: &Raw) -> String {
    if raw.leaf.pointer {
        pointer(raw.value)
    } else if raw.leaf.signed {
        raw.signed.to_string()
    } else {
        raw.value.to_string()
    }
}

// Times -------------------------------------------------------------------

/// Layouts whose one-line form is the time they hold.
pub(super) fn summary_layout(layout: &str) -> bool {
    matches!(layout, "timespec" | "timeval")
}

fn number(nodes: &[Node], name: &str) -> Option<i64> {
    nodes
        .iter()
        .find(|node| node.name == name)
        .and_then(|node| node.text.parse().ok())
}

/// The time a `{tv_sec, tv_nsec}` or `{tv_sec, tv_usec}` holds, when the
/// members are those.
fn time_of(nodes: &[Node], kind: TimeKind) -> Option<String> {
    let seconds = number(nodes, "tv_sec")?;
    if nodes.len() != 2 {
        return None;
    }
    let (fraction, unit) = match number(nodes, "tv_nsec") {
        Some(nanoseconds) => (nanoseconds, 1),
        None => (number(nodes, "tv_usec")?, 1_000),
    };
    time::time(seconds, fraction, unit, kind)
}

/// A structure of two time members (`it_value`) as its time: the interval of
/// a timer is a duration even when its value is an absolute time.
pub(super) fn group(cx: &Cx<'_>, path: &str, nodes: &[Node]) -> Option<String> {
    let kind = if path.ends_with("it_interval") {
        TimeKind::Duration
    } else {
        cx.time
    };
    time_of(nodes, kind)
}

/// The one-line form of a whole layout that is a time (an array's element
/// too: `timespec[2]`).
pub(super) fn summary(cx: &Cx<'_>, nodes: &[Node]) -> Option<String> {
    let base = cx.layout.split('[').next().unwrap_or(cx.layout);
    summary_layout(base)
        .then(|| time_of(nodes, cx.time))
        .flatten()
}

/// What the times in the call's field mean: a duration, a date on the wall
/// clock, or a reading of another clock.
pub(super) fn time_kind(call: Option<&Call<'_>>, arg: Option<usize>) -> TimeKind {
    let Some(call) = call else {
        return TimeKind::Duration;
    };
    let args = call.args.unwrap_or([0; 6]);
    let known = call.args.is_some();
    let on_clock = |clock: u64| {
        // CLOCK_REALTIME, CLOCK_REALTIME_ALARM and CLOCK_TAI are wall clocks.
        if matches!(clock as u32, 0 | 8 | 11) {
            TimeKind::Wall
        } else {
            TimeKind::Clock
        }
    };
    match (call.name, arg) {
        ("utimensat" | "futimesat" | "utimes" | "utime" | "settimeofday" | "gettimeofday", _) => {
            TimeKind::Wall
        }
        ("mq_timedsend" | "mq_timedreceive", _) => TimeKind::Wall,
        ("clock_settime" | "clock_gettime", _) if known => on_clock(args[0]),
        ("clock_nanosleep", Some(2)) if known && args[1] & 1 == 1 => on_clock(args[0]),
        ("timer_settime" | "timerfd_settime", Some(2)) if known && args[1] & 1 == 1 => {
            TimeKind::Clock
        }
        ("futex", Some(3)) if known => {
            // FUTEX_WAIT_BITSET, FUTEX_LOCK_PI, FUTEX_WAIT_REQUEUE_PI read an
            // absolute time, on CLOCK_MONOTONIC unless FUTEX_CLOCK_REALTIME.
            match args[1] & 127 {
                9 | 6 | 11 if args[1] & 256 != 0 => TimeKind::Wall,
                9 | 6 | 11 => TimeKind::Clock,
                _ => TimeKind::Duration,
            }
        }
        ("futex_wait", Some(4)) if known => on_clock(args[5]),
        ("futex_waitv", Some(3)) if known => on_clock(args[4]),
        _ => TimeKind::Duration,
    }
}
