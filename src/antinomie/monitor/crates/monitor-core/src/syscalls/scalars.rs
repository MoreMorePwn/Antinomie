// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Names for plain-integer arguments whose values are flags or enumerations the
//! schema does not type: inotify and fanotify masks, access modes, the socket
//! protocol by family, memory-policy modes, interval timers, personalities,
//! the argument of `fcntl` by command and the sub-arguments of `prctl` by
//! option. Values are the pinned UAPI's; flags that differ per architecture
//! (`O_*`) are read with the table's constants.
use super::{Constants, Table, named};

type Names = &'static [(&'static str, u64)];

pub const STATX_MASK: Names = &[
    ("STATX_TYPE", 0x1),
    ("STATX_MODE", 0x2),
    ("STATX_NLINK", 0x4),
    ("STATX_UID", 0x8),
    ("STATX_GID", 0x10),
    ("STATX_ATIME", 0x20),
    ("STATX_MTIME", 0x40),
    ("STATX_CTIME", 0x80),
    ("STATX_INO", 0x100),
    ("STATX_SIZE", 0x200),
    ("STATX_BLOCKS", 0x400),
    ("STATX_BTIME", 0x800),
    ("STATX_MNT_ID", 0x1000),
    ("STATX_DIOALIGN", 0x2000),
    ("STATX_MNT_ID_UNIQUE", 0x4000),
    ("STATX_SUBVOL", 0x8000),
];

const INOTIFY: Names = &[
    ("IN_ACCESS", 0x1),
    ("IN_MODIFY", 0x2),
    ("IN_ATTRIB", 0x4),
    ("IN_CLOSE_WRITE", 0x8),
    ("IN_CLOSE_NOWRITE", 0x10),
    ("IN_OPEN", 0x20),
    ("IN_MOVED_FROM", 0x40),
    ("IN_MOVED_TO", 0x80),
    ("IN_CREATE", 0x100),
    ("IN_DELETE", 0x200),
    ("IN_DELETE_SELF", 0x400),
    ("IN_MOVE_SELF", 0x800),
    ("IN_UNMOUNT", 0x2000),
    ("IN_Q_OVERFLOW", 0x4000),
    ("IN_IGNORED", 0x8000),
    ("IN_ONLYDIR", 0x0100_0000),
    ("IN_DONT_FOLLOW", 0x0200_0000),
    ("IN_EXCL_UNLINK", 0x0400_0000),
    ("IN_MASK_CREATE", 0x1000_0000),
    ("IN_MASK_ADD", 0x2000_0000),
    ("IN_ISDIR", 0x4000_0000),
    ("IN_ONESHOT", 0x8000_0000),
];

const FANOTIFY: Names = &[
    ("FAN_ACCESS", 0x1),
    ("FAN_MODIFY", 0x2),
    ("FAN_ATTRIB", 0x4),
    ("FAN_CLOSE_WRITE", 0x8),
    ("FAN_CLOSE_NOWRITE", 0x10),
    ("FAN_OPEN", 0x20),
    ("FAN_MOVED_FROM", 0x40),
    ("FAN_MOVED_TO", 0x80),
    ("FAN_CREATE", 0x100),
    ("FAN_DELETE", 0x200),
    ("FAN_DELETE_SELF", 0x400),
    ("FAN_MOVE_SELF", 0x800),
    ("FAN_OPEN_EXEC", 0x1000),
    ("FAN_Q_OVERFLOW", 0x4000),
    ("FAN_FS_ERROR", 0x8000),
    ("FAN_OPEN_PERM", 0x1_0000),
    ("FAN_ACCESS_PERM", 0x2_0000),
    ("FAN_OPEN_EXEC_PERM", 0x4_0000),
    ("FAN_EVENT_ON_CHILD", 0x0800_0000),
    ("FAN_RENAME", 0x1000_0000),
    ("FAN_ONDIR", 0x4000_0000),
];

const ACCESS: Names = &[("R_OK", 4), ("W_OK", 2), ("X_OK", 1)];

const MEMPOLICY: Names = &[
    ("MPOL_DEFAULT", 0),
    ("MPOL_PREFERRED", 1),
    ("MPOL_BIND", 2),
    ("MPOL_INTERLEAVE", 3),
    ("MPOL_LOCAL", 4),
    ("MPOL_PREFERRED_MANY", 5),
    ("MPOL_WEIGHTED_INTERLEAVE", 6),
];
const MEMPOLICY_FLAGS: Names = &[
    ("MPOL_F_NUMA_BALANCING", 1 << 13),
    ("MPOL_F_RELATIVE_NODES", 1 << 14),
    ("MPOL_F_STATIC_NODES", 1 << 15),
];

const ITIMER: Names = &[
    ("ITIMER_REAL", 0),
    ("ITIMER_VIRTUAL", 1),
    ("ITIMER_PROF", 2),
];

const PERSONALITY: Names = &[
    ("PER_LINUX", 0),
    ("PER_SVR4", 1),
    ("PER_SVR3", 2),
    ("PER_BSD", 6),
    ("PER_LINUX32", 8),
    ("PER_HPUX", 0x10),
];
const PERSONALITY_FLAGS: Names = &[
    ("UNAME26", 0x0002_0000),
    ("ADDR_NO_RANDOMIZE", 0x0004_0000),
    ("FDPIC_FUNCPTRS", 0x0008_0000),
    ("MMAP_PAGE_ZERO", 0x0010_0000),
    ("ADDR_COMPAT_LAYOUT", 0x0020_0000),
    ("READ_IMPLIES_EXEC", 0x0040_0000),
    ("ADDR_LIMIT_32BIT", 0x0080_0000),
    ("SHORT_INODE", 0x0100_0000),
    ("WHOLE_SECONDS", 0x0200_0000),
    ("STICKY_TIMEOUTS", 0x0400_0000),
    ("ADDR_LIMIT_3GB", 0x0800_0000),
];

const SEALS: Names = &[
    ("F_SEAL_SEAL", 1),
    ("F_SEAL_SHRINK", 2),
    ("F_SEAL_GROW", 4),
    ("F_SEAL_WRITE", 8),
    ("F_SEAL_FUTURE_WRITE", 0x10),
    ("F_SEAL_EXEC", 0x20),
];
const DNOTIFY: Names = &[
    ("DN_ACCESS", 1),
    ("DN_MODIFY", 2),
    ("DN_CREATE", 4),
    ("DN_DELETE", 8),
    ("DN_RENAME", 0x10),
    ("DN_ATTRIB", 0x20),
    ("DN_MULTISHOT", 0x8000_0000),
];
const LEASE: Names = &[("F_RDLCK", 0), ("F_WRLCK", 1), ("F_UNLCK", 2)];

const NETLINK: Names = &[
    ("NETLINK_ROUTE", 0),
    ("NETLINK_UNUSED", 1),
    ("NETLINK_USERSOCK", 2),
    ("NETLINK_FIREWALL", 3),
    ("NETLINK_SOCK_DIAG", 4),
    ("NETLINK_NFLOG", 5),
    ("NETLINK_XFRM", 6),
    ("NETLINK_SELINUX", 7),
    ("NETLINK_ISCSI", 8),
    ("NETLINK_AUDIT", 9),
    ("NETLINK_FIB_LOOKUP", 10),
    ("NETLINK_CONNECTOR", 11),
    ("NETLINK_NETFILTER", 12),
    ("NETLINK_IP6_FW", 13),
    ("NETLINK_DNRTMSG", 14),
    ("NETLINK_KOBJECT_UEVENT", 15),
    ("NETLINK_GENERIC", 16),
    ("NETLINK_SCSITRANSPORT", 18),
    ("NETLINK_ECRYPTFS", 19),
    ("NETLINK_RDMA", 20),
    ("NETLINK_CRYPTO", 21),
];

/// `ETH_P_*` as the program passes it: in network byte order.
const ETHERNET: Names = &[
    ("ETH_P_ALL", 0x0003),
    ("ETH_P_IP", 0x0800),
    ("ETH_P_ARP", 0x0806),
    ("ETH_P_IPV6", 0x86dd),
    ("ETH_P_LOOP", 0x0060),
    ("ETH_P_8021Q", 0x8100),
];

const SPECULATION: Names = &[
    ("PR_SPEC_STORE_BYPASS", 0),
    ("PR_SPEC_INDIRECT_BRANCH", 1),
    ("PR_SPEC_L1D_FLUSH", 2),
];
const SPECULATION_STATE: Names = &[
    ("PR_SPEC_PRCTL", 1),
    ("PR_SPEC_ENABLE", 2),
    ("PR_SPEC_DISABLE", 4),
    ("PR_SPEC_FORCE_DISABLE", 8),
    ("PR_SPEC_DISABLE_NOEXEC", 16),
];
const AMBIENT: Names = &[
    ("PR_CAP_AMBIENT_IS_SET", 1),
    ("PR_CAP_AMBIENT_RAISE", 2),
    ("PR_CAP_AMBIENT_LOWER", 3),
    ("PR_CAP_AMBIENT_CLEAR_ALL", 4),
];
const DUMPABLE: Names = &[
    ("SUID_DUMP_DISABLE", 0),
    ("SUID_DUMP_USER", 1),
    ("SUID_DUMP_ROOT", 2),
];
const SECCOMP_MODE: Names = &[
    ("SECCOMP_MODE_DISABLED", 0),
    ("SECCOMP_MODE_STRICT", 1),
    ("SECCOMP_MODE_FILTER", 2),
];

/// One value by name, else decimal.
fn one(value: u64, names: Names) -> String {
    names
        .iter()
        .find(|(_, candidate)| *candidate == value)
        .map_or_else(|| value.to_string(), |(name, _)| (*name).to_owned())
}

/// Flag names joined with `|`, unnamed bits in hex; `0` for none.
fn bits(value: u64, names: Names) -> String {
    if value == 0 {
        return "0".into();
    }
    let mut parts = Vec::new();
    let mut rest = value;
    for (name, bit) in names {
        if value & bit == *bit {
            parts.push((*name).to_owned());
            rest &= !bit;
        }
    }
    if rest != 0 {
        parts.push(format!("{rest:#x}"));
    }
    parts.join("|")
}

/// `O_*` flags of the table's ABI, without the access mode.
fn open_flags(table: &'static Table, value: u64) -> String {
    let found = table.flag_group("open", value);
    let mut parts: Vec<String> = found
        .names
        .into_iter()
        .filter(|name| name != "O_RDONLY")
        .collect();
    if found.unknown_bits != 0 {
        parts.push(format!("{:#x}", found.unknown_bits));
    }
    if parts.is_empty() {
        "0".into()
    } else {
        parts.join("|")
    }
}

fn signal(value: u64) -> String {
    if value == 0 {
        "0".into()
    } else {
        crate::typed_fields::signal_name(value)
    }
}

fn capability(value: u64) -> String {
    crate::typed_fields::capability_name(value).map_or_else(|| value.to_string(), str::to_owned)
}

fn mempolicy(value: u64) -> String {
    let mode = value & 0xffff & !(0xe000);
    let rest = value & 0xe000;
    let name = one(mode, MEMPOLICY);
    if rest == 0 {
        name
    } else {
        format!("{name}|{}", bits(rest, MEMPOLICY_FLAGS))
    }
}

fn socket_protocol(family: u64, value: u64) -> Option<String> {
    let value = value as u32 as u64;
    match family as u32 {
        2 | 10 => Some(one(value, super::super::typed_fields::PROTOCOLS)),
        16 => Some(one(value, NETLINK)),
        // AF_PACKET takes htons(ETH_P_*).
        17 => Some(one(u64::from((value as u16).swap_bytes()), ETHERNET)),
        _ => None,
    }
}

fn personality(value: u64) -> String {
    let value = value & 0xffff_ffff;
    let flags = value & !0xff;
    let base = one(value & 0xff, PERSONALITY);
    if flags == 0 {
        base
    } else {
        format!("{base}|{}", bits(flags, PERSONALITY_FLAGS))
    }
}

fn fcntl(table: &'static Table, args: &[u64; 6]) -> Option<String> {
    let value = args[2];
    Some(match args[1] as u32 {
        2 => bits(value, &[("FD_CLOEXEC", 1)]),
        4 => open_flags(table, value),
        10 => signal(value),
        1024 => one(value, LEASE),
        1026 => bits(value, DNOTIFY),
        1033 => bits(value, SEALS),
        _ => return None,
    })
}

/// `prctl`'s `arg2`.. (`index` 1..=4) by its option.
fn prctl(index: usize, args: &[u64; 6]) -> Option<String> {
    let option = args[0] as u32;
    let value = args[index];
    Some(match (option, index) {
        (1, 1) => signal(value),
        (4, 1) => one(value, DUMPABLE),
        (22, 1) => one(value, SECCOMP_MODE),
        (23 | 24, 1) => capability(value),
        (26, 1) => one(value, &[("PR_TSC_ENABLE", 1), ("PR_TSC_SIGSEGV", 2)]),
        (14, 1) => one(
            value,
            &[("PR_TIMING_STATISTICAL", 0), ("PR_TIMING_TIMESTAMP", 1)],
        ),
        (47, 1) => one(value, AMBIENT),
        (47, 2) if matches!(args[1], 1..=3) => capability(value),
        (52 | 53, 1) => one(value, SPECULATION),
        (53, 2) => bits(value, SPECULATION_STATE),
        (0x5961_6d61, 1) if value == u64::MAX => "PR_SET_PTRACER_ANY".into(),
        _ => return None,
    })
}

/// The name of argument `index` of `call` when it is one of the plain
/// integers named here.
pub(super) fn name(
    table: &'static Table,
    call: &str,
    index: usize,
    args: &[u64; 6],
) -> Option<String> {
    let value = args[index];
    Some(match (call, index) {
        ("inotify_add_watch", 2) => bits(value & 0xffff_ffff, INOTIFY),
        ("fanotify_mark", 2) => bits(value, FANOTIFY),
        ("access", 1) | ("faccessat" | "faccessat2", 2) => {
            if value & 7 == 0 {
                "F_OK".into()
            } else {
                bits(value & 0xffff_ffff, ACCESS)
            }
        }
        ("mq_open", 1) => open_flags(table, value),
        ("socket", 2) => socket_protocol(args[0], value)?,
        ("set_mempolicy", 0) | ("mbind", 2) => mempolicy(value),
        ("getitimer" | "setitimer", 0) => one(value, ITIMER),
        ("personality", 0) if value != 0xffff_ffff => personality(value),
        ("statx", 3) => bits(value & 0xffff_ffff, STATX_MASK),
        ("fcntl", 2) => fcntl(table, args)?,
        ("prctl", 1..=4) => prctl(index, args)?,
        _ => return None,
    })
}

/// `QCMD(subcommand, type)` as used by quotactl and quotactl_fd.
pub(super) fn quota_command(constants: &Constants, cmd: u64) -> String {
    const SUBCOMMANDS: &[(&str, u64)] = &[
        ("Q_SYNC", 0x80_0001),
        ("Q_QUOTAON", 0x80_0002),
        ("Q_QUOTAOFF", 0x80_0003),
        ("Q_GETFMT", 0x80_0004),
        ("Q_GETINFO", 0x80_0005),
        ("Q_SETINFO", 0x80_0006),
        ("Q_GETQUOTA", 0x80_0007),
        ("Q_SETQUOTA", 0x80_0008),
        ("Q_GETNEXTQUOTA", 0x80_0009),
        ("Q_XQUOTAON", 0x5801),
        ("Q_XQUOTAOFF", 0x5802),
        ("Q_XGETQUOTA", 0x5803),
        ("Q_XSETQLIM", 0x5804),
        ("Q_XGETQSTAT", 0x5805),
        ("Q_XQUOTARM", 0x5806),
        ("Q_XQUOTASYNC", 0x5807),
        ("Q_XGETQSTATV", 0x5808),
        ("Q_XGETNEXTQUOTA", 0x5809),
    ];
    let cmd = cmd as u32;
    let subcommand = named(constants, SUBCOMMANDS, u64::from(cmd >> 8), "subcommand");
    let kind = match cmd & 0xff {
        0 => "USRQUOTA".into(),
        1 => "GRPQUOTA".into(),
        2 => "PRJQUOTA".into(),
        other => format!("Unknown type {other}"),
    };
    format!("{subcommand} / {kind}")
}

#[cfg(test)]
mod tests {
    use super::super::native;

    fn shown(call: &str, index: usize, args: [u64; 6]) -> Option<String> {
        let table = native();
        table.selector_name(table.number(call)?, index, &args)
    }

    #[test]
    fn plain_integers_read_by_name() {
        let mut args = [0; 6];
        args[2] = 0x100 | 0x200;
        assert_eq!(
            shown("inotify_add_watch", 2, args).unwrap(),
            "IN_CREATE|IN_DELETE"
        );
        args[2] = 0x2000_0004;
        assert_eq!(
            shown("inotify_add_watch", 2, args).unwrap(),
            "IN_ATTRIB|IN_MASK_ADD"
        );
        args[1] = 6;
        assert_eq!(shown("access", 1, args).unwrap(), "R_OK|W_OK");
        assert_eq!(shown("access", 1, [0; 6]).unwrap(), "F_OK");
        assert_eq!(
            shown("setitimer", 0, [2, 0, 0, 0, 0, 0]).unwrap(),
            "ITIMER_PROF"
        );
        assert_eq!(
            shown("socket", 2, [2, 1, 6, 0, 0, 0]).unwrap(),
            "IPPROTO_TCP"
        );
        assert_eq!(
            shown("socket", 2, [17, 3, 0x0300, 0, 0, 0]).unwrap(),
            "ETH_P_ALL"
        );
        assert_eq!(
            shown("mbind", 2, [0, 0, 2 | 0x8000, 0, 0, 0]).unwrap(),
            "MPOL_BIND|MPOL_F_STATIC_NODES"
        );
        assert_eq!(
            shown("personality", 0, [0x4_0000, 0, 0, 0, 0, 0]).unwrap(),
            "PER_LINUX|ADDR_NO_RANDOMIZE"
        );
        assert_eq!(
            shown("fcntl", 2, [3, 1033, 0x2 | 0x8, 0, 0, 0]).unwrap(),
            "F_SEAL_SHRINK|F_SEAL_WRITE"
        );
        assert_eq!(
            shown("fcntl", 2, [3, 4, 0o4000 | 0o2000, 0, 0, 0]).unwrap(),
            "O_APPEND|O_NONBLOCK"
        );
        assert_eq!(
            shown("prctl", 1, [22, 2, 0, 0, 0, 0]).unwrap(),
            "SECCOMP_MODE_FILTER"
        );
        assert_eq!(
            shown("prctl", 1, [23, 12, 0, 0, 0, 0]).unwrap(),
            "CAP_NET_ADMIN"
        );
        assert_eq!(shown("prctl", 1, [1, 9, 0, 0, 0, 0]).unwrap(), "SIGKILL");
        assert!(shown("fcntl", 2, [3, 5, 0, 0, 0, 0]).is_none());
    }
}
