// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Names of enumerated arguments the schema types as plain integers: commands,
//! operations, clocks, resources and the like (Linux 6.12 UAPI values). The
//! trace shows the name and keeps the number available; a value the table
//! does not know reads `Unknown <what> <hex>`.

use super::Constants;

type Table = &'static [(&'static str, u64)];

const FCNTL: Table = &[
    ("F_DUPFD", 0),
    ("F_GETFD", 1),
    ("F_SETFD", 2),
    ("F_GETFL", 3),
    ("F_SETFL", 4),
    ("F_GETLK", 5),
    ("F_SETLK", 6),
    ("F_SETLKW", 7),
    ("F_SETOWN", 8),
    ("F_GETOWN", 9),
    ("F_SETSIG", 10),
    ("F_GETSIG", 11),
    ("F_SETOWN_EX", 15),
    ("F_GETOWN_EX", 16),
    ("F_GETOWNER_UIDS", 17),
    ("F_OFD_GETLK", 36),
    ("F_OFD_SETLK", 37),
    ("F_OFD_SETLKW", 38),
    ("F_SETLEASE", 1024),
    ("F_GETLEASE", 1025),
    ("F_NOTIFY", 1026),
    ("F_DUPFD_QUERY", 1027),
    ("F_CREATED_QUERY", 1028),
    ("F_CANCELLK", 1029),
    ("F_DUPFD_CLOEXEC", 1030),
    ("F_SETPIPE_SZ", 1031),
    ("F_GETPIPE_SZ", 1032),
    ("F_ADD_SEALS", 1033),
    ("F_GET_SEALS", 1034),
    ("F_GET_RW_HINT", 1035),
    ("F_SET_RW_HINT", 1036),
    ("F_GET_FILE_RW_HINT", 1037),
    ("F_SET_FILE_RW_HINT", 1038),
];

const ARCH_PRCTL: Table = &[
    ("ARCH_SET_GS", 0x1001),
    ("ARCH_SET_FS", 0x1002),
    ("ARCH_GET_FS", 0x1003),
    ("ARCH_GET_GS", 0x1004),
    ("ARCH_GET_CPUID", 0x1011),
    ("ARCH_SET_CPUID", 0x1012),
    ("ARCH_GET_XCOMP_SUPP", 0x1021),
    ("ARCH_GET_XCOMP_PERM", 0x1022),
    ("ARCH_REQ_XCOMP_PERM", 0x1023),
    ("ARCH_GET_XCOMP_GUEST_PERM", 0x1024),
    ("ARCH_REQ_XCOMP_GUEST_PERM", 0x1025),
    ("ARCH_MAP_VDSO_X32", 0x2001),
    ("ARCH_MAP_VDSO_32", 0x2002),
    ("ARCH_MAP_VDSO_64", 0x2003),
    ("ARCH_GET_UNTAG_MASK", 0x4001),
    ("ARCH_ENABLE_TAGGED_ADDR", 0x4002),
    ("ARCH_GET_MAX_TAG_BITS", 0x4003),
    ("ARCH_FORCE_TAGGED_SVA", 0x4004),
    ("ARCH_SHSTK_ENABLE", 0x5001),
    ("ARCH_SHSTK_DISABLE", 0x5002),
    ("ARCH_SHSTK_LOCK", 0x5003),
    ("ARCH_SHSTK_UNLOCK", 0x5004),
    ("ARCH_SHSTK_STATUS", 0x5005),
];

const WHENCE: Table = &[
    ("SEEK_SET", 0),
    ("SEEK_CUR", 1),
    ("SEEK_END", 2),
    ("SEEK_DATA", 3),
    ("SEEK_HOLE", 4),
];

const SIGMASK_HOW: Table = &[("SIG_BLOCK", 0), ("SIG_UNBLOCK", 1), ("SIG_SETMASK", 2)];

const MADVISE: Table = &[
    ("MADV_NORMAL", 0),
    ("MADV_RANDOM", 1),
    ("MADV_SEQUENTIAL", 2),
    ("MADV_WILLNEED", 3),
    ("MADV_DONTNEED", 4),
    ("MADV_FREE", 8),
    ("MADV_REMOVE", 9),
    ("MADV_DONTFORK", 10),
    ("MADV_DOFORK", 11),
    ("MADV_MERGEABLE", 12),
    ("MADV_UNMERGEABLE", 13),
    ("MADV_HUGEPAGE", 14),
    ("MADV_NOHUGEPAGE", 15),
    ("MADV_DONTDUMP", 16),
    ("MADV_DODUMP", 17),
    ("MADV_WIPEONFORK", 18),
    ("MADV_KEEPONFORK", 19),
    ("MADV_COLD", 20),
    ("MADV_PAGEOUT", 21),
    ("MADV_POPULATE_READ", 22),
    ("MADV_POPULATE_WRITE", 23),
    ("MADV_DONTNEED_LOCKED", 24),
    ("MADV_COLLAPSE", 25),
    ("MADV_HWPOISON", 100),
    ("MADV_SOFT_OFFLINE", 101),
];

const FADVISE: Table = &[
    ("POSIX_FADV_NORMAL", 0),
    ("POSIX_FADV_RANDOM", 1),
    ("POSIX_FADV_SEQUENTIAL", 2),
    ("POSIX_FADV_WILLNEED", 3),
    ("POSIX_FADV_DONTNEED", 4),
    ("POSIX_FADV_NOREUSE", 5),
];

const FAMILY: Table = &[
    ("AF_UNSPEC", 0),
    ("AF_UNIX", 1),
    ("AF_INET", 2),
    ("AF_AX25", 3),
    ("AF_IPX", 4),
    ("AF_APPLETALK", 5),
    ("AF_NETROM", 6),
    ("AF_BRIDGE", 7),
    ("AF_ATMPVC", 8),
    ("AF_X25", 9),
    ("AF_INET6", 10),
    ("AF_ROSE", 11),
    ("AF_DECnet", 12),
    ("AF_NETBEUI", 13),
    ("AF_SECURITY", 14),
    ("AF_KEY", 15),
    ("AF_NETLINK", 16),
    ("AF_PACKET", 17),
    ("AF_ASH", 18),
    ("AF_ECONET", 19),
    ("AF_ATMSVC", 20),
    ("AF_RDS", 21),
    ("AF_SNA", 22),
    ("AF_IRDA", 23),
    ("AF_PPPOX", 24),
    ("AF_WANPIPE", 25),
    ("AF_LLC", 26),
    ("AF_IB", 27),
    ("AF_MPLS", 28),
    ("AF_CAN", 29),
    ("AF_TIPC", 30),
    ("AF_BLUETOOTH", 31),
    ("AF_IUCV", 32),
    ("AF_RXRPC", 33),
    ("AF_ISDN", 34),
    ("AF_PHONET", 35),
    ("AF_IEEE802154", 36),
    ("AF_CAIF", 37),
    ("AF_ALG", 38),
    ("AF_NFC", 39),
    ("AF_VSOCK", 40),
    ("AF_KCM", 41),
    ("AF_QIPCRTR", 42),
    ("AF_SMC", 43),
    ("AF_XDP", 44),
    ("AF_MCTP", 45),
];

const SHUTDOWN: Table = &[("SHUT_RD", 0), ("SHUT_WR", 1), ("SHUT_RDWR", 2)];

const EPOLL_OP: Table = &[
    ("EPOLL_CTL_ADD", 1),
    ("EPOLL_CTL_DEL", 2),
    ("EPOLL_CTL_MOD", 3),
];

const CLOCKS: Table = &[
    ("CLOCK_REALTIME", 0),
    ("CLOCK_MONOTONIC", 1),
    ("CLOCK_PROCESS_CPUTIME_ID", 2),
    ("CLOCK_THREAD_CPUTIME_ID", 3),
    ("CLOCK_MONOTONIC_RAW", 4),
    ("CLOCK_REALTIME_COARSE", 5),
    ("CLOCK_MONOTONIC_COARSE", 6),
    ("CLOCK_BOOTTIME", 7),
    ("CLOCK_REALTIME_ALARM", 8),
    ("CLOCK_BOOTTIME_ALARM", 9),
    ("CLOCK_TAI", 11),
];

const RLIMIT: Table = &[
    ("RLIMIT_CPU", 0),
    ("RLIMIT_FSIZE", 1),
    ("RLIMIT_DATA", 2),
    ("RLIMIT_STACK", 3),
    ("RLIMIT_CORE", 4),
    ("RLIMIT_RSS", 5),
    ("RLIMIT_NPROC", 6),
    ("RLIMIT_NOFILE", 7),
    ("RLIMIT_MEMLOCK", 8),
    ("RLIMIT_AS", 9),
    ("RLIMIT_LOCKS", 10),
    ("RLIMIT_SIGPENDING", 11),
    ("RLIMIT_MSGQUEUE", 12),
    ("RLIMIT_NICE", 13),
    ("RLIMIT_RTPRIO", 14),
    ("RLIMIT_RTTIME", 15),
];

const RUSAGE: Table = &[
    ("RUSAGE_SELF", 0),
    ("RUSAGE_CHILDREN", 0xffff_ffff),
    ("RUSAGE_THREAD", 1),
];

const PRIORITY_WHICH: Table = &[("PRIO_PROCESS", 0), ("PRIO_PGRP", 1), ("PRIO_USER", 2)];

const IOPRIO_WHO: Table = &[
    ("IOPRIO_WHO_PROCESS", 1),
    ("IOPRIO_WHO_PGRP", 2),
    ("IOPRIO_WHO_USER", 3),
];

const IDTYPE: Table = &[("P_ALL", 0), ("P_PID", 1), ("P_PGID", 2), ("P_PIDFD", 3)];

const POLICY: Table = &[
    ("SCHED_OTHER", 0),
    ("SCHED_FIFO", 1),
    ("SCHED_RR", 2),
    ("SCHED_BATCH", 3),
    ("SCHED_IDLE", 5),
    ("SCHED_DEADLINE", 6),
    ("SCHED_EXT", 7),
];

const SEMCTL: Table = &[
    ("IPC_RMID", 0),
    ("IPC_SET", 1),
    ("IPC_STAT", 2),
    ("IPC_INFO", 3),
    ("GETPID", 11),
    ("GETVAL", 12),
    ("GETALL", 13),
    ("GETNCNT", 14),
    ("GETZCNT", 15),
    ("SETVAL", 16),
    ("SETALL", 17),
    ("SEM_STAT", 18),
    ("SEM_INFO", 19),
    ("SEM_STAT_ANY", 20),
];

const MSGCTL: Table = &[
    ("IPC_RMID", 0),
    ("IPC_SET", 1),
    ("IPC_STAT", 2),
    ("IPC_INFO", 3),
    ("MSG_STAT", 11),
    ("MSG_INFO", 12),
    ("MSG_STAT_ANY", 13),
];

const SHMCTL: Table = &[
    ("IPC_RMID", 0),
    ("IPC_SET", 1),
    ("IPC_STAT", 2),
    ("IPC_INFO", 3),
    ("SHM_LOCK", 11),
    ("SHM_UNLOCK", 12),
    ("SHM_STAT", 13),
    ("SHM_INFO", 14),
    ("SHM_STAT_ANY", 15),
];

const FSCONFIG: Table = &[
    ("FSCONFIG_SET_FLAG", 0),
    ("FSCONFIG_SET_STRING", 1),
    ("FSCONFIG_SET_BINARY", 2),
    ("FSCONFIG_SET_PATH", 3),
    ("FSCONFIG_SET_PATH_EMPTY", 4),
    ("FSCONFIG_SET_FD", 5),
    ("FSCONFIG_CMD_CREATE", 6),
    ("FSCONFIG_CMD_RECONFIGURE", 7),
    ("FSCONFIG_CMD_CREATE_EXCL", 8),
];

const MEMBARRIER: Table = &[
    ("MEMBARRIER_CMD_QUERY", 0),
    ("MEMBARRIER_CMD_GLOBAL", 1),
    ("MEMBARRIER_CMD_GLOBAL_EXPEDITED", 2),
    ("MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED", 4),
    ("MEMBARRIER_CMD_PRIVATE_EXPEDITED", 8),
    ("MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED", 16),
    ("MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE", 32),
    ("MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE", 64),
    ("MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ", 128),
    ("MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ", 256),
    ("MEMBARRIER_CMD_GET_REGISTRATIONS", 512),
];

const SECCOMP_OP: Table = &[
    ("SECCOMP_SET_MODE_STRICT", 0),
    ("SECCOMP_SET_MODE_FILTER", 1),
    ("SECCOMP_GET_ACTION_AVAIL", 2),
    ("SECCOMP_GET_NOTIF_SIZES", 3),
];

const URING_REGISTER: Table = &[
    ("IORING_REGISTER_BUFFERS", 0),
    ("IORING_UNREGISTER_BUFFERS", 1),
    ("IORING_REGISTER_FILES", 2),
    ("IORING_UNREGISTER_FILES", 3),
    ("IORING_REGISTER_EVENTFD", 4),
    ("IORING_UNREGISTER_EVENTFD", 5),
    ("IORING_REGISTER_FILES_UPDATE", 6),
    ("IORING_REGISTER_EVENTFD_ASYNC", 7),
    ("IORING_REGISTER_PROBE", 8),
    ("IORING_REGISTER_PERSONALITY", 9),
    ("IORING_UNREGISTER_PERSONALITY", 10),
    ("IORING_REGISTER_RESTRICTIONS", 11),
    ("IORING_REGISTER_ENABLE_RINGS", 12),
    ("IORING_REGISTER_FILES2", 13),
    ("IORING_REGISTER_FILES_UPDATE2", 14),
    ("IORING_REGISTER_BUFFERS2", 15),
    ("IORING_REGISTER_BUFFERS_UPDATE", 16),
    ("IORING_REGISTER_IOWQ_AFF", 17),
    ("IORING_UNREGISTER_IOWQ_AFF", 18),
    ("IORING_REGISTER_IOWQ_MAX_WORKERS", 19),
    ("IORING_REGISTER_RING_FDS", 20),
    ("IORING_UNREGISTER_RING_FDS", 21),
    ("IORING_REGISTER_PBUF_RING", 22),
    ("IORING_UNREGISTER_PBUF_RING", 23),
    ("IORING_REGISTER_SYNC_CANCEL", 24),
    ("IORING_REGISTER_FILE_ALLOC_RANGE", 25),
    ("IORING_REGISTER_PBUF_STATUS", 26),
    ("IORING_REGISTER_NAPI", 27),
    ("IORING_UNREGISTER_NAPI", 28),
    ("IORING_REGISTER_CLOCK", 29),
    ("IORING_REGISTER_CLONE_BUFFERS", 30),
];

const SYSLOG: Table = &[
    ("SYSLOG_ACTION_CLOSE", 0),
    ("SYSLOG_ACTION_OPEN", 1),
    ("SYSLOG_ACTION_READ", 2),
    ("SYSLOG_ACTION_READ_ALL", 3),
    ("SYSLOG_ACTION_READ_CLEAR", 4),
    ("SYSLOG_ACTION_CLEAR", 5),
    ("SYSLOG_ACTION_CONSOLE_OFF", 6),
    ("SYSLOG_ACTION_CONSOLE_ON", 7),
    ("SYSLOG_ACTION_CONSOLE_LEVEL", 8),
    ("SYSLOG_ACTION_SIZE_UNREAD", 9),
    ("SYSLOG_ACTION_SIZE_BUFFER", 10),
];

const REBOOT_MAGIC1: Table = &[("LINUX_REBOOT_MAGIC1", 0xfee1_dead)];

const REBOOT_MAGIC2: Table = &[
    ("LINUX_REBOOT_MAGIC2", 672_274_793),
    ("LINUX_REBOOT_MAGIC2A", 85_072_278),
    ("LINUX_REBOOT_MAGIC2B", 369_367_448),
    ("LINUX_REBOOT_MAGIC2C", 537_993_216),
];

const REBOOT_CMD: Table = &[
    ("LINUX_REBOOT_CMD_RESTART", 0x0123_4567),
    ("LINUX_REBOOT_CMD_HALT", 0xcdef_0123),
    ("LINUX_REBOOT_CMD_CAD_ON", 0x89ab_cdef),
    ("LINUX_REBOOT_CMD_CAD_OFF", 0),
    ("LINUX_REBOOT_CMD_POWER_OFF", 0x4321_fedc),
    ("LINUX_REBOOT_CMD_RESTART2", 0xa1b2_c3d4),
    ("LINUX_REBOOT_CMD_SW_SUSPEND", 0xd000_fce2),
    ("LINUX_REBOOT_CMD_KEXEC", 0x4558_4543),
];

const KCMP: Table = &[
    ("KCMP_FILE", 0),
    ("KCMP_VM", 1),
    ("KCMP_FILES", 2),
    ("KCMP_FS", 3),
    ("KCMP_SIGHAND", 4),
    ("KCMP_IO", 5),
    ("KCMP_SYSVSEM", 6),
    ("KCMP_EPOLL_TFD", 7),
];

const LANDLOCK_RULE: Table = &[
    ("LANDLOCK_RULE_PATH_BENEATH", 1),
    ("LANDLOCK_RULE_NET_PORT", 2),
];

/// Requests other code commonly issues; any other request is shown by its
/// encoding (`_IOR('Z', 0x7e, 4)`), which is all its number says.
const IOCTL: Table = &[
    ("FIBMAP", 0x1),
    ("FIGETBSZ", 0x2),
    ("BLKSSZGET", 0x1268),
    ("PERF_EVENT_IOC_ENABLE", 0x2400),
    ("PERF_EVENT_IOC_DISABLE", 0x2401),
    ("PERF_EVENT_IOC_RESET", 0x2403),
    ("TCGETS", 0x5401),
    ("TCSETS", 0x5402),
    ("TCSETSW", 0x5403),
    ("TCSETSF", 0x5404),
    ("TCGETA", 0x5405),
    ("TCSETA", 0x5406),
    ("TCSBRK", 0x5409),
    ("TCXONC", 0x540a),
    ("TCFLSH", 0x540b),
    ("TIOCEXCL", 0x540c),
    ("TIOCNXCL", 0x540d),
    ("TIOCSCTTY", 0x540e),
    ("TIOCGPGRP", 0x540f),
    ("TIOCSPGRP", 0x5410),
    ("TIOCOUTQ", 0x5411),
    ("TIOCSTI", 0x5412),
    ("TIOCGWINSZ", 0x5413),
    ("TIOCSWINSZ", 0x5414),
    ("TIOCMGET", 0x5415),
    ("TIOCMSET", 0x5418),
    ("FIONREAD", 0x541b),
    ("TIOCLINUX", 0x541c),
    ("TIOCCONS", 0x541d),
    ("FIONBIO", 0x5421),
    ("TIOCNOTTY", 0x5422),
    ("TIOCSETD", 0x5423),
    ("TIOCGETD", 0x5424),
    ("TIOCSBRK", 0x5427),
    ("TIOCCBRK", 0x5428),
    ("TIOCGSID", 0x5429),
    ("TIOCGPTPEER", 0x5441),
    ("FIONCLEX", 0x5450),
    ("FIOCLEX", 0x5451),
    ("FIOASYNC", 0x5452),
    ("FIOQSIZE", 0x5460),
    ("SIOCGIFNAME", 0x8910),
    ("SIOCGIFCONF", 0x8912),
    ("SIOCGIFFLAGS", 0x8913),
    ("SIOCSIFFLAGS", 0x8914),
    ("SIOCGIFADDR", 0x8915),
    ("SIOCGIFMTU", 0x8921),
    ("SIOCGIFHWADDR", 0x8927),
    ("SIOCGIFINDEX", 0x8933),
    ("TIOCSPTLCK", 0x4004_5431),
    ("FICLONE", 0x4004_9409),
    ("FS_IOC_SETFLAGS", 0x4008_6602),
    ("TCSETS2", 0x402c_542b),
    ("TCSETSW2", 0x402c_542c),
    ("TCSETSF2", 0x402c_542d),
    ("RNDGETENTCNT", 0x8004_5200),
    ("TIOCGPTN", 0x8004_5430),
    ("TIOCGDEV", 0x8004_5432),
    ("FS_IOC_GETFLAGS", 0x8008_6601),
    ("BLKGETSIZE64", 0x8008_1272),
    ("TCGETS2", 0x802c_542a),
    ("FIFREEZE", 0xc004_5877),
    ("FITHAW", 0xc004_5878),
];

/// A value's name in a table of x86-64 values, read with the architecture's
/// constants (a name the arch lacks never matches).
fn lookup(c: &Constants, table: Table, value: u64) -> Option<&'static str> {
    table
        .iter()
        .find(|&&(name, number)| c.value(name, number) == Some(value))
        .map(|&(name, _)| name)
}

fn named(c: &Constants, table: Table, value: u64, what: &str) -> String {
    lookup(c, table, value).map_or_else(|| format!("Unknown {what} {value:#x}"), Into::into)
}

/// An ioctl request by name, else by its `_IOC` encoding.
fn ioctl(c: &Constants, request: u64) -> String {
    let request = request as u32;
    if let Some(name) = lookup(c, IOCTL, u64::from(request)) {
        return name.into();
    }
    let nr = request & 0xff;
    let kind = (request >> 8) & 0xff;
    let size = (request >> 16) & 0x3fff;
    let kind = match char::from_u32(kind) {
        Some(c) if c.is_ascii_graphic() => format!("'{c}'"),
        _ => format!("{kind:#x}"),
    };
    match request >> 30 {
        0 if size == 0 => format!("_IO({kind}, {nr:#x})"),
        1 => format!("_IOW({kind}, {nr:#x}, {size})"),
        2 => format!("_IOR({kind}, {nr:#x}, {size})"),
        3 => format!("_IOWR({kind}, {nr:#x}, {size})"),
        _ => format!("_IOC(0, {kind}, {nr:#x}, {size})"),
    }
}

/// A clock id: a named clock, or the CPU clock of a process or thread
/// (`MAKE_PROCESS_CPUCLOCK`: the inverted PID shifted left by 3).
fn clock(c: &Constants, value: u64) -> String {
    let id = value as i32;
    if id >= 0 {
        return named(c, CLOCKS, u64::from(id as u32), "clock");
    }
    let pid = !(id >> 3);
    let which = match id & 3 {
        0 => "profiling",
        1 => "virtual",
        2 => "scheduler",
        _ => "invalid",
    };
    let owner = if id & 4 != 0 { "thread" } else { "process" };
    format!("CPU clock ({which}) of {owner} {pid}")
}

/// A scheduling policy with its SCHED_RESET_ON_FORK flag.
fn policy(c: &Constants, value: u64) -> String {
    const RESET_ON_FORK: u64 = 0x4000_0000;
    let value = value & 0xffff_ffff;
    let base = named(c, POLICY, value & !RESET_ON_FORK, "policy");
    if value & RESET_ON_FORK != 0 {
        format!("{base}|SCHED_RESET_ON_FORK")
    } else {
        base
    }
}

/// A SysV IPC control command, with the IPC_64 flag glibc adds.
fn ipc(c: &Constants, table: Table, value: u64) -> String {
    const IPC_64: u64 = 0x100;
    let value = value & 0xffff_ffff;
    let base = named(c, table, value & !IPC_64, "command");
    if value & IPC_64 != 0 {
        format!("{base}|IPC_64")
    } else {
        base
    }
}

/// io_uring_register's opcode, with the registered-ring flag.
fn uring_register(c: &Constants, value: u64) -> String {
    const USE_REGISTERED_RING: u64 = 1 << 31;
    let value = value & 0xffff_ffff;
    let base = named(c, URING_REGISTER, value & !USE_REGISTERED_RING, "opcode");
    if value & USE_REGISTERED_RING != 0 {
        format!("{base}|IORING_REGISTER_USE_REGISTERED_RING")
    } else {
        base
    }
}

/// The name of argument `index` of syscall `number` when the schema types it
/// as a plain integer but its values are named constants.
/// The name of argument `index` of `call` when the call's argument is an
/// enumerated selector, with the architecture's values.
pub(super) fn named_argument(
    c: &Constants,
    call: &str,
    index: usize,
    args: &[u64; 6],
) -> Option<String> {
    let value = args[index];
    let int = value & 0xffff_ffff;
    Some(match (call, index) {
        ("fcntl", 1) => named(c, FCNTL, int, "command"),
        ("arch_prctl", 0) => named(c, ARCH_PRCTL, int, "code"),
        ("ioctl", 1) => ioctl(c, value),
        ("lseek", 2) => named(c, WHENCE, int, "whence"),
        ("rt_sigprocmask", 0) => named(c, SIGMASK_HOW, int, "how"),
        ("madvise", 2) | ("process_madvise", 3) => named(c, MADVISE, int, "advice"),
        ("fadvise64", 3) => named(c, FADVISE, int, "advice"),
        ("socket" | "socketpair", 0) => named(c, FAMILY, int, "family"),
        ("shutdown", 1) => named(c, SHUTDOWN, int, "how"),
        ("epoll_ctl", 1) => named(c, EPOLL_OP, int, "operation"),
        (
            "timer_create" | "clock_settime" | "clock_gettime" | "clock_getres" | "clock_nanosleep"
            | "timerfd_create" | "clock_adjtime",
            0,
        ) => clock(c, value),
        ("getrlimit" | "setrlimit", 0) | ("prlimit64", 1) => named(c, RLIMIT, int, "resource"),
        ("getrusage", 0) => named(c, RUSAGE, int, "who"),
        ("getpriority" | "setpriority", 0) => named(c, PRIORITY_WHICH, int, "which"),
        ("ioprio_set" | "ioprio_get", 0) => named(c, IOPRIO_WHO, int, "which"),
        ("waitid", 0) => named(c, IDTYPE, int, "id type"),
        ("sched_setscheduler", 1) | ("sched_get_priority_max" | "sched_get_priority_min", 0) => {
            policy(c, value)
        }
        ("semctl", 2) => ipc(c, SEMCTL, value),
        ("msgctl", 1) => ipc(c, MSGCTL, value),
        ("shmctl", 1) => ipc(c, SHMCTL, value),
        ("fsconfig", 1) => named(c, FSCONFIG, int, "command"),
        ("membarrier", 0) => named(c, MEMBARRIER, int, "command"),
        ("seccomp", 0) => named(c, SECCOMP_OP, int, "operation"),
        ("io_uring_register", 1) => uring_register(c, value),
        ("syslog", 0) => named(c, SYSLOG, int, "action"),
        ("reboot", 0) => named(c, REBOOT_MAGIC1, int, "magic"),
        ("reboot", 1) => named(c, REBOOT_MAGIC2, int, "magic"),
        ("reboot", 2) => named(c, REBOOT_CMD, int, "command"),
        ("kcmp", 2) => named(c, KCMP, int, "type"),
        ("landlock_add_rule", 1) => named(c, LANDLOCK_RULE, int, "rule type"),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::named_argument;

    fn name(number: u64, index: usize, value: u64) -> String {
        let mut args = [0; 6];
        args[index] = value;
        let table = super::super::native();
        named_argument(
            table.constants(),
            table.name_of(number).unwrap(),
            index,
            &args,
        )
        .unwrap()
    }

    #[test]
    fn commands_and_operations_read_by_name() {
        assert_eq!(name(72, 1, 1030), "F_DUPFD_CLOEXEC");
        assert_eq!(name(158, 0, 0x1003), "ARCH_GET_FS");
        assert_eq!(name(8, 2, 2), "SEEK_END");
        assert_eq!(name(233, 1, 3), "EPOLL_CTL_MOD");
        assert_eq!(name(41, 0, 10), "AF_INET6");
        assert_eq!(name(98, 0, u64::MAX), "RUSAGE_CHILDREN");
        assert_eq!(name(66, 2, 0x100 | 13), "GETALL|IPC_64");
        assert_eq!(name(144, 1, 0x4000_0003), "SCHED_BATCH|SCHED_RESET_ON_FORK");
        assert_eq!(name(169, 2, 0), "LINUX_REBOOT_CMD_CAD_OFF");
        assert_eq!(name(72, 1, 0x7fff), "Unknown command 0x7fff");
        assert!(named_argument(super::super::native().constants(), "read", 0, &[0; 6]).is_none());
    }

    #[test]
    fn clocks_include_cpu_clocks_of_processes_and_threads() {
        assert_eq!(name(228, 0, 1), "CLOCK_MONOTONIC");
        // MAKE_PROCESS_CPUCLOCK(42, CPUCLOCK_SCHED) = (~42 << 3) | 2
        let process = ((!42i32) << 3 | 2) as u32 as u64;
        assert_eq!(name(228, 0, process), "CPU clock (scheduler) of process 42");
        let thread = ((!42i32) << 3 | 4 | 2) as u32 as u64;
        assert_eq!(name(228, 0, thread), "CPU clock (scheduler) of thread 42");
        assert_eq!(name(228, 0, 99), "Unknown clock 0x63");
    }

    #[test]
    fn ioctl_requests_read_by_name_or_encoding() {
        assert_eq!(name(16, 1, 0x5401), "TCGETS");
        assert_eq!(name(16, 1, 0x802c_542a), "TCGETS2");
        assert_eq!(name(16, 1, 0x8004_5a7e), "_IOR('Z', 0x7e, 4)");
        assert_eq!(name(16, 1, 0xc010_6f01), "_IOWR('o', 0x1, 16)");
        assert_eq!(name(16, 1, 0x4c03), "_IO('L', 0x3)");
    }
}
