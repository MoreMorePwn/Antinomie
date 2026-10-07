// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Pinned native declaration metadata and argument-specific flag interpretation.
use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Debug, Deserialize)]
pub struct ArgumentInfo {
    pub name: String,
    pub c_type: String,
    pub pointer: bool,
    pub flags: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyscallInfo {
    pub number: u64,
    pub name: String,
    pub abi: String,
    pub entry_point: Option<String>,
    pub arg_count: Option<u8>,
    pub arguments: Vec<ArgumentInfo>,
}

#[derive(Deserialize)]
struct Inventory {
    syscalls: Vec<SyscallInfo>,
}

/// Names of active flags and the bits whose meaning the pinned schema cannot decode.
#[derive(Debug, PartialEq, Eq)]
pub struct FlagValue {
    pub names: Vec<String>,
    pub unknown_bits: u64,
}

fn inventory() -> &'static [SyscallInfo] {
    static INVENTORY: OnceLock<Inventory> = OnceLock::new();
    &INVENTORY
        .get_or_init(|| {
            // This is a generated, compiled-in constant verified by the inventory tests.
            serde_json::from_str(include_str!("../../../protocol/native-syscalls.json"))
                .expect("invalid compiled native syscall inventory")
        })
        .syscalls
}

pub fn syscall(number: u64) -> Option<&'static SyscallInfo> {
    let table = inventory();
    table
        .binary_search_by_key(&number, |entry| entry.number)
        .ok()
        .map(|index| &table[index])
}

pub fn name(number: u64) -> String {
    syscall(number).map_or_else(|| format!("syscall_{number}"), |entry| entry.name.clone())
}

type FlagRule = (&'static str, u64, u64);

fn bits(flags: &'static [(&'static str, u64)]) -> Vec<FlagRule> {
    flags
        .iter()
        .map(|&(name, mask)| (name, mask, mask))
        .collect()
}

fn rules(group: &str) -> Vec<FlagRule> {
    match group {
        "open" => {
            let mut values = bits(&[
                ("O_CREAT", 0o100),
                ("O_EXCL", 0o200),
                ("O_NOCTTY", 0o400),
                ("O_TRUNC", 0o1000),
                ("O_APPEND", 0o2000),
                ("O_NONBLOCK", 0o4000),
                ("O_DSYNC", 0o10000),
                ("O_ASYNC", 0o20000),
                ("O_DIRECT", 0o40000),
                ("O_LARGEFILE", 0o100000),
                ("O_DIRECTORY", 0o200000),
                ("O_NOFOLLOW", 0o400000),
                ("O_NOATIME", 0o1000000),
                ("O_CLOEXEC", 0o2000000),
                ("O_SYNC", 0o4010000),
                ("O_PATH", 0o10000000),
                ("O_TMPFILE", 0o20200000),
            ]);
            values.extend([("O_RDONLY", 3, 0), ("O_WRONLY", 3, 1), ("O_RDWR", 3, 2)]);
            values
        }
        "protection" => {
            let mut values = bits(&[
                ("PROT_READ", 1),
                ("PROT_WRITE", 2),
                ("PROT_EXEC", 4),
                ("PROT_SEM", 8),
                ("PROT_GROWSDOWN", 0x0100_0000),
                ("PROT_GROWSUP", 0x0200_0000),
            ]);
            values.push(("PROT_NONE", u64::MAX, 0));
            values
        }
        "mmap" => {
            let mut values = bits(&[
                ("MAP_FIXED", 0x10),
                ("MAP_ANONYMOUS", 0x20),
                ("MAP_32BIT", 0x40),
                ("MAP_GROWSDOWN", 0x100),
                ("MAP_DENYWRITE", 0x800),
                ("MAP_EXECUTABLE", 0x1000),
                ("MAP_LOCKED", 0x2000),
                ("MAP_NORESERVE", 0x4000),
                ("MAP_POPULATE", 0x8000),
                ("MAP_NONBLOCK", 0x10000),
                ("MAP_STACK", 0x20000),
                ("MAP_HUGETLB", 0x40000),
                ("MAP_SYNC", 0x80000),
                ("MAP_FIXED_NOREPLACE", 0x100000),
            ]);
            values.extend([
                ("MAP_SHARED", 0xf, 1),
                ("MAP_PRIVATE", 0xf, 2),
                ("MAP_SHARED_VALIDATE", 0xf, 3),
            ]);
            values
        }
        "clone" | "clone_flags" => bits(&[
            ("CLONE_VM", 0x100),
            ("CLONE_FS", 0x200),
            ("CLONE_FILES", 0x400),
            ("CLONE_SIGHAND", 0x800),
            ("CLONE_PIDFD", 0x1000),
            ("CLONE_PTRACE", 0x2000),
            ("CLONE_VFORK", 0x4000),
            ("CLONE_PARENT", 0x8000),
            ("CLONE_THREAD", 0x10000),
            ("CLONE_NEWNS", 0x20000),
            ("CLONE_SYSVSEM", 0x40000),
            ("CLONE_SETTLS", 0x80000),
            ("CLONE_PARENT_SETTID", 0x100000),
            ("CLONE_CHILD_CLEARTID", 0x200000),
            ("CLONE_DETACHED", 0x400000),
            ("CLONE_UNTRACED", 0x800000),
            ("CLONE_CHILD_SETTID", 0x01000000),
            ("CLONE_NEWCGROUP", 0x02000000),
            ("CLONE_NEWUTS", 0x04000000),
            ("CLONE_NEWIPC", 0x08000000),
            ("CLONE_NEWUSER", 0x10000000),
            ("CLONE_NEWPID", 0x20000000),
            ("CLONE_NEWNET", 0x40000000),
            ("CLONE_IO", 0x80000000),
            ("CLONE_CLEAR_SIGHAND", 0x1_0000_0000),
            ("CLONE_INTO_CGROUP", 0x2_0000_0000),
        ]),
        "socket_type" => {
            let mut values = bits(&[("SOCK_NONBLOCK", 0o4000), ("SOCK_CLOEXEC", 0o2000000)]);
            values.extend([
                ("SOCK_STREAM", 0xf, 1),
                ("SOCK_DGRAM", 0xf, 2),
                ("SOCK_RAW", 0xf, 3),
                ("SOCK_RDM", 0xf, 4),
                ("SOCK_SEQPACKET", 0xf, 5),
                ("SOCK_DCCP", 0xf, 6),
                ("SOCK_PACKET", 0xf, 10),
            ]);
            values
        }
        "accept" => bits(&[("SOCK_NONBLOCK", 0o4000), ("SOCK_CLOEXEC", 0o2000000)]),
        "message" => bits(&[
            ("MSG_OOB", 1),
            ("MSG_PEEK", 2),
            ("MSG_DONTROUTE", 4),
            ("MSG_CTRUNC", 8),
            ("MSG_PROBE", 0x10),
            ("MSG_TRUNC", 0x20),
            ("MSG_DONTWAIT", 0x40),
            ("MSG_EOR", 0x80),
            ("MSG_WAITALL", 0x100),
            ("MSG_FIN", 0x200),
            ("MSG_SYN", 0x400),
            ("MSG_CONFIRM", 0x800),
            ("MSG_RST", 0x1000),
            ("MSG_ERRQUEUE", 0x2000),
            ("MSG_NOSIGNAL", 0x4000),
            ("MSG_MORE", 0x8000),
            ("MSG_WAITFORONE", 0x10000),
            ("MSG_BATCH", 0x40000),
            ("MSG_SOCK_DEVMEM", 0x02000000),
            ("MSG_ZEROCOPY", 0x04000000),
            ("MSG_FASTOPEN", 0x20000000),
            ("MSG_CMSG_CLOEXEC", 0x40000000),
        ]),
        "cloexec" => bits(&[("O_CLOEXEC", 0o2000000)]),
        "descriptor" => bits(&[("CLOEXEC", 0o2000000), ("NONBLOCK", 0o4000)]),
        "eventfd" => bits(&[
            ("EFD_SEMAPHORE", 1),
            ("EFD_NONBLOCK", 0o4000),
            ("EFD_CLOEXEC", 0o2000000),
        ]),
        "pipe" => bits(&[
            ("O_NONBLOCK", 0o4000),
            ("O_DIRECT", 0o40000),
            ("O_CLOEXEC", 0o2000000),
            ("O_NOTIFICATION_PIPE", 0o200),
        ]),
        "execveat" => bits(&[("AT_SYMLINK_NOFOLLOW", 0x100), ("AT_EMPTY_PATH", 0x1000)]),
        "unlinkat" => bits(&[("AT_REMOVEDIR", 0x200)]),
        "rename" => bits(&[
            ("RENAME_NOREPLACE", 1),
            ("RENAME_EXCHANGE", 2),
            ("RENAME_WHITEOUT", 4),
        ]),
        "accessat" => bits(&[
            ("AT_SYMLINK_NOFOLLOW", 0x100),
            ("AT_EACCESS", 0x200),
            ("AT_EMPTY_PATH", 0x1000),
        ]),
        "statat" | "statx" => {
            let mut values = bits(&[
                ("AT_SYMLINK_NOFOLLOW", 0x100),
                ("AT_NO_AUTOMOUNT", 0x800),
                ("AT_EMPTY_PATH", 0x1000),
            ]);
            if group == "statx" {
                values.extend([
                    ("AT_STATX_SYNC_AS_STAT", 0x6000, 0),
                    ("AT_STATX_FORCE_SYNC", 0x6000, 0x2000),
                    ("AT_STATX_DONT_SYNC", 0x6000, 0x4000),
                ]);
            }
            values
        }
        "linkat" => bits(&[("AT_SYMLINK_FOLLOW", 0x400), ("AT_EMPTY_PATH", 0x1000)]),
        "nofollow_empty" => bits(&[("AT_SYMLINK_NOFOLLOW", 0x100), ("AT_EMPTY_PATH", 0x1000)]),
        "random" => bits(&[
            ("GRND_NONBLOCK", 1),
            ("GRND_RANDOM", 2),
            ("GRND_INSECURE", 4),
        ]),
        "memfd" => bits(&[
            ("MFD_CLOEXEC", 1),
            ("MFD_ALLOW_SEALING", 2),
            ("MFD_HUGETLB", 4),
            ("MFD_NOEXEC_SEAL", 8),
            ("MFD_EXEC", 16),
        ]),
        "uring_enter" => bits(&[
            ("IORING_ENTER_GETEVENTS", 1),
            ("IORING_ENTER_SQ_WAKEUP", 2),
            ("IORING_ENTER_SQ_WAIT", 4),
            ("IORING_ENTER_EXT_ARG", 8),
            ("IORING_ENTER_REGISTERED_RING", 16),
            ("IORING_ENTER_ABS_TIMER", 32),
        ]),
        "splice" => bits(&[
            ("SPLICE_F_MOVE", 1),
            ("SPLICE_F_NONBLOCK", 2),
            ("SPLICE_F_MORE", 4),
            ("SPLICE_F_GIFT", 8),
        ]),
        "mremap" => bits(&[
            ("MREMAP_MAYMOVE", 1),
            ("MREMAP_FIXED", 2),
            ("MREMAP_DONTUNMAP", 4),
        ]),
        "flock" => bits(&[
            ("LOCK_SH", 1),
            ("LOCK_EX", 2),
            ("LOCK_NB", 4),
            ("LOCK_UN", 8),
        ]),
        "unmount" => bits(&[
            ("MNT_FORCE", 1),
            ("MNT_DETACH", 2),
            ("MNT_EXPIRE", 4),
            ("UMOUNT_NOFOLLOW", 8),
        ]),
        "mount" => bits(&[
            ("MS_RDONLY", 1),
            ("MS_NOSUID", 2),
            ("MS_NODEV", 4),
            ("MS_NOEXEC", 8),
            ("MS_SYNCHRONOUS", 16),
            ("MS_REMOUNT", 32),
            ("MS_MANDLOCK", 64),
            ("MS_DIRSYNC", 128),
            ("MS_NOSYMFOLLOW", 256),
            ("MS_NOATIME", 1024),
            ("MS_NODIRATIME", 2048),
            ("MS_BIND", 4096),
            ("MS_MOVE", 8192),
            ("MS_REC", 16384),
            ("MS_SILENT", 32768),
            ("MS_POSIXACL", 1 << 16),
            ("MS_UNBINDABLE", 1 << 17),
            ("MS_PRIVATE", 1 << 18),
            ("MS_SLAVE", 1 << 19),
            ("MS_SHARED", 1 << 20),
            ("MS_RELATIME", 1 << 21),
            ("MS_KERNMOUNT", 1 << 22),
            ("MS_I_VERSION", 1 << 23),
            ("MS_STRICTATIME", 1 << 24),
            ("MS_LAZYTIME", 1 << 25),
        ]),
        "futex" => {
            let mut values = bits(&[("FUTEX_PRIVATE_FLAG", 128), ("FUTEX_CLOCK_REALTIME", 256)]);
            for (opcode, name) in [
                "FUTEX_WAIT",
                "FUTEX_WAKE",
                "FUTEX_FD",
                "FUTEX_REQUEUE",
                "FUTEX_CMP_REQUEUE",
                "FUTEX_WAKE_OP",
                "FUTEX_LOCK_PI",
                "FUTEX_UNLOCK_PI",
                "FUTEX_TRYLOCK_PI",
                "FUTEX_WAIT_BITSET",
                "FUTEX_WAKE_BITSET",
                "FUTEX_WAIT_REQUEUE_PI",
                "FUTEX_CMP_REQUEUE_PI",
                "FUTEX_LOCK_PI2",
            ]
            .into_iter()
            .enumerate()
            {
                values.push((name, 0xffff_ffff & !(128 | 256), opcode as u64));
            }
            values
        }
        "futex2" => {
            let mut values = bits(&[("FUTEX2_NUMA", 4), ("FUTEX2_PRIVATE", 128)]);
            values.extend([
                ("FUTEX2_SIZE_U8", 3, 0),
                ("FUTEX2_SIZE_U16", 3, 1),
                ("FUTEX2_SIZE_U32", 3, 2),
                ("FUTEX2_SIZE_U64", 3, 3),
            ]);
            values
        }
        "mlockall" => bits(&[("MCL_CURRENT", 1), ("MCL_FUTURE", 2), ("MCL_ONFAULT", 4)]),
        "mlock" => bits(&[("MLOCK_ONFAULT", 1)]),
        "open_tree" => bits(&[("OPEN_TREE_CLONE", 1), ("OPEN_TREE_CLOEXEC", 0o2000000)]),
        "move_mount" => bits(&[
            ("MOVE_MOUNT_F_SYMLINKS", 1),
            ("MOVE_MOUNT_F_AUTOMOUNTS", 2),
            ("MOVE_MOUNT_F_EMPTY_PATH", 4),
            ("MOVE_MOUNT_T_SYMLINKS", 0x10),
            ("MOVE_MOUNT_T_AUTOMOUNTS", 0x20),
            ("MOVE_MOUNT_T_EMPTY_PATH", 0x40),
            ("MOVE_MOUNT_SET_GROUP", 0x100),
            ("MOVE_MOUNT_BENEATH", 0x200),
        ]),
        "fsopen" => bits(&[("CLOEXEC", 1)]),
        "fspick" => bits(&[
            ("FSPICK_CLOEXEC", 1),
            ("FSPICK_SYMLINK_NOFOLLOW", 2),
            ("FSPICK_NO_AUTOMOUNT", 4),
            ("FSPICK_EMPTY_PATH", 8),
        ]),
        "close_range" => bits(&[("CLOSE_RANGE_UNSHARE", 2), ("CLOSE_RANGE_CLOEXEC", 4)]),
        "pidfd_open" => bits(&[("PIDFD_NONBLOCK", 0o4000), ("PIDFD_THREAD", 0o200)]),
        "pidfd_signal" => bits(&[
            ("PIDFD_SIGNAL_THREAD", 1),
            ("PIDFD_SIGNAL_THREAD_GROUP", 2),
            ("PIDFD_SIGNAL_PROCESS_GROUP", 4),
        ]),
        "waitid" | "wait4" => {
            let mut values = bits(&[
                ("WNOHANG", 1),
                ("WUNTRACED/WSTOPPED", 2),
                ("WEXITED", 4),
                ("WCONTINUED", 8),
                ("WNOWAIT", 0x1000000),
                ("__WNOTHREAD", 0x20000000),
                ("__WALL", 0x40000000),
                ("__WCLONE", 0x80000000),
            ]);
            if group == "wait4" {
                values.retain(|&(name, _, _)| name != "WEXITED" && name != "WNOWAIT");
            }
            values
        }
        "xattr" => bits(&[("XATTR_CREATE", 1), ("XATTR_REPLACE", 2)]),
        "fallocate" => bits(&[
            ("FALLOC_FL_KEEP_SIZE", 1),
            ("FALLOC_FL_PUNCH_HOLE", 2),
            ("FALLOC_FL_NO_HIDE_STALE", 4),
            ("FALLOC_FL_COLLAPSE_RANGE", 8),
            ("FALLOC_FL_ZERO_RANGE", 16),
            ("FALLOC_FL_INSERT_RANGE", 32),
            ("FALLOC_FL_UNSHARE_RANGE", 64),
        ]),
        "sync_range" => bits(&[
            ("SYNC_FILE_RANGE_WAIT_BEFORE", 1),
            ("SYNC_FILE_RANGE_WRITE", 2),
            ("SYNC_FILE_RANGE_WAIT_AFTER", 4),
        ]),
        "rwf" => bits(&[
            ("RWF_HIPRI", 1),
            ("RWF_DSYNC", 2),
            ("RWF_SYNC", 4),
            ("RWF_NOWAIT", 8),
            ("RWF_APPEND", 16),
            ("RWF_NOAPPEND", 32),
            ("RWF_ATOMIC", 64),
        ]),
        "rseq" => bits(&[("RSEQ_FLAG_UNREGISTER", 1)]),
        "membarrier_flags" => bits(&[("MEMBARRIER_CMD_FLAG_CPU", 1)]),
        "msync" => bits(&[("MS_ASYNC", 1), ("MS_INVALIDATE", 2), ("MS_SYNC", 4)]),
        "timer" => bits(&[("TIMER_ABSTIME", 1)]),
        "timerfd_settime" => bits(&[("TFD_TIMER_ABSTIME", 1), ("TFD_TIMER_CANCEL_ON_SET", 2)]),
        "module_init" => bits(&[
            ("MODULE_INIT_IGNORE_MODVERSIONS", 1),
            ("MODULE_INIT_IGNORE_VERMAGIC", 2),
            ("MODULE_INIT_COMPRESSED_FILE", 4),
        ]),
        "module_delete" => bits(&[("O_NONBLOCK", 0o4000), ("O_TRUNC", 0o1000)]),
        "mbind" => bits(&[
            ("MPOL_MF_STRICT", 1),
            ("MPOL_MF_MOVE", 2),
            ("MPOL_MF_MOVE_ALL", 4),
        ]),
        "mempolicy_get" => bits(&[
            ("MPOL_F_NODE", 1),
            ("MPOL_F_ADDR", 2),
            ("MPOL_F_MEMS_ALLOWED", 4),
        ]),
        "perf" => bits(&[
            ("PERF_FLAG_FD_NO_GROUP", 1),
            ("PERF_FLAG_FD_OUTPUT", 2),
            ("PERF_FLAG_PID_CGROUP", 4),
            ("PERF_FLAG_FD_CLOEXEC", 8),
        ]),
        "seccomp" => bits(&[
            ("SECCOMP_FILTER_FLAG_TSYNC", 1),
            ("SECCOMP_FILTER_FLAG_LOG", 2),
            ("SECCOMP_FILTER_FLAG_SPEC_ALLOW", 4),
            ("SECCOMP_FILTER_FLAG_NEW_LISTENER", 8),
            ("SECCOMP_FILTER_FLAG_TSYNC_ESRCH", 16),
            ("SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV", 32),
        ]),
        "userfaultfd" => bits(&[
            ("O_CLOEXEC", 0o2000000),
            ("O_NONBLOCK", 0o4000),
            ("UFFD_USER_MODE_ONLY", 1),
        ]),
        "handle_at" => bits(&[
            ("AT_SYMLINK_FOLLOW", 0x400),
            ("AT_EMPTY_PATH", 0x1000),
            ("AT_HANDLE_FID", 0x200),
            ("AT_HANDLE_MNT_ID_UNIQUE", 1),
        ]),
        "mount_setattr" => bits(&[
            ("AT_SYMLINK_NOFOLLOW", 0x100),
            ("AT_EMPTY_PATH", 0x1000),
            ("AT_RECURSIVE", 0x8000),
        ]),
        "landlock_create" => bits(&[
            ("LANDLOCK_CREATE_RULESET_VERSION", 1),
            ("LANDLOCK_CREATE_RULESET_ERRATA", 2),
        ]),
        "shadow_stack" => bits(&[("SHADOW_STACK_SET_TOKEN", 1)]),
        "listmount" => bits(&[("LISTMOUNT_REVERSE", 1)]),
        "lsm_get" => bits(&[("LSM_FLAG_SINGLE", 1)]),
        "ipc_create" | "shmget" => {
            let mut values = bits(&[("IPC_CREAT", 0o1000), ("IPC_EXCL", 0o2000)]);
            // Keep permission bits distinct from IPC creation flags.
            for (name, mask) in [
                ("S_IRUSR", 0o400),
                ("S_IWUSR", 0o200),
                ("S_IXUSR", 0o100),
                ("S_IRGRP", 0o40),
                ("S_IWGRP", 0o20),
                ("S_IXGRP", 0o10),
                ("S_IROTH", 0o4),
                ("S_IWOTH", 0o2),
                ("S_IXOTH", 0o1),
            ] {
                values.push((name, mask, mask));
            }
            if group == "shmget" {
                values.extend(bits(&[("SHM_HUGETLB", 0o4000), ("SHM_NORESERVE", 0o10000)]));
            }
            values
        }
        "shmat" => bits(&[
            ("SHM_RDONLY", 0o10000),
            ("SHM_RND", 0o20000),
            ("SHM_REMAP", 0o40000),
            ("SHM_EXEC", 0o100000),
        ]),
        "msgsnd" => bits(&[("IPC_NOWAIT", 0o4000)]),
        "msgrcv" => bits(&[
            ("IPC_NOWAIT", 0o4000),
            ("MSG_NOERROR", 0o10000),
            ("MSG_EXCEPT", 0o20000),
            ("MSG_COPY", 0o40000),
        ]),
        "fanotify_init" => {
            let mut values = bits(&[
                ("FAN_CLOEXEC", 1),
                ("FAN_NONBLOCK", 2),
                ("FAN_UNLIMITED_QUEUE", 0x10),
                ("FAN_UNLIMITED_MARKS", 0x20),
                ("FAN_ENABLE_AUDIT", 0x40),
                ("FAN_REPORT_PIDFD", 0x80),
                ("FAN_REPORT_TID", 0x100),
                ("FAN_REPORT_FID", 0x200),
                ("FAN_REPORT_DIR_FID", 0x400),
                ("FAN_REPORT_NAME", 0x800),
                ("FAN_REPORT_TARGET_FID", 0x1000),
                ("FAN_REPORT_FD_ERROR", 0x2000),
            ]);
            values.extend([
                ("FAN_CLASS_NOTIF", 12, 0),
                ("FAN_CLASS_CONTENT", 12, 4),
                ("FAN_CLASS_PRE_CONTENT", 12, 8),
            ]);
            values
        }
        "fanotify_mark" => {
            let mut values = bits(&[
                ("FAN_MARK_ADD", 1),
                ("FAN_MARK_REMOVE", 2),
                ("FAN_MARK_DONT_FOLLOW", 4),
                ("FAN_MARK_ONLYDIR", 8),
                ("FAN_MARK_IGNORED_MASK", 0x20),
                ("FAN_MARK_IGNORED_SURV_MODIFY", 0x40),
                ("FAN_MARK_FLUSH", 0x80),
                ("FAN_MARK_EVICTABLE", 0x200),
                ("FAN_MARK_IGNORE", 0x400),
            ]);
            values.extend([
                ("FAN_MARK_INODE", 0x110, 0),
                ("FAN_MARK_MOUNT", 0x110, 0x10),
                ("FAN_MARK_FILESYSTEM", 0x110, 0x100),
            ]);
            values
        }
        _ => Vec::new(),
    }
}

// Socket levels and options named by the pinned UAPI headers. The kernel capture
// table in kernel/antinomie/native_capture.c lists the same options; values were
// taken from `make headers_install` output for Linux 6.12.94.
const SOCKET_LEVELS: &[(&str, i32)] = &[
    ("IPPROTO_IP", 0),
    ("SOL_SOCKET", 1),
    ("IPPROTO_TCP", 6),
    ("IPPROTO_UDP", 17),
    ("IPPROTO_IPV6", 41),
    ("IPPROTO_RAW", 255),
    ("SOL_PACKET", 263),
    ("SOL_NETLINK", 270),
    ("SOL_ALG", 279),
];

const SOL_SOCKET_OPTIONS: &[(&str, i32)] = &[
    ("SO_DEBUG", 1),
    ("SO_REUSEADDR", 2),
    ("SO_TYPE", 3),
    ("SO_ERROR", 4),
    ("SO_DONTROUTE", 5),
    ("SO_BROADCAST", 6),
    ("SO_SNDBUF", 7),
    ("SO_RCVBUF", 8),
    ("SO_KEEPALIVE", 9),
    ("SO_OOBINLINE", 10),
    ("SO_NO_CHECK", 11),
    ("SO_PRIORITY", 12),
    ("SO_LINGER", 13),
    ("SO_BSDCOMPAT", 14),
    ("SO_REUSEPORT", 15),
    ("SO_PASSCRED", 16),
    ("SO_PEERCRED", 17),
    ("SO_RCVLOWAT", 18),
    ("SO_SNDLOWAT", 19),
    ("SO_RCVTIMEO_OLD", 20),
    ("SO_SNDTIMEO_OLD", 21),
    ("SO_BINDTODEVICE", 25),
    ("SO_ATTACH_FILTER", 26),
    ("SO_GET_FILTER", 26),
    ("SO_GET_FILTER", 26),
    ("SO_DETACH_FILTER", 27),
    ("SO_PEERNAME", 28),
    ("SO_TIMESTAMP_OLD", 29),
    ("SO_ACCEPTCONN", 30),
    ("SO_PEERSEC", 31),
    ("SO_SNDBUFFORCE", 32),
    ("SO_RCVBUFFORCE", 33),
    ("SO_PASSSEC", 34),
    ("SO_TIMESTAMPNS_OLD", 35),
    ("SO_MARK", 36),
    ("SO_TIMESTAMPING_OLD", 37),
    ("SO_PROTOCOL", 38),
    ("SO_DOMAIN", 39),
    ("SO_RXQ_OVFL", 40),
    ("SO_WIFI_STATUS", 41),
    ("SO_PEEK_OFF", 42),
    ("SO_NOFCS", 43),
    ("SO_LOCK_FILTER", 44),
    ("SO_SELECT_ERR_QUEUE", 45),
    ("SO_BUSY_POLL", 46),
    ("SO_MAX_PACING_RATE", 47),
    ("SO_BPF_EXTENSIONS", 48),
    ("SO_INCOMING_CPU", 49),
    ("SO_ATTACH_BPF", 50),
    ("SO_ATTACH_REUSEPORT_CBPF", 51),
    ("SO_ATTACH_REUSEPORT_EBPF", 52),
    ("SO_CNX_ADVICE", 53),
    ("SO_MEMINFO", 55),
    ("SO_INCOMING_NAPI_ID", 56),
    ("SO_COOKIE", 57),
    ("SO_PEERGROUPS", 59),
    ("SO_ZEROCOPY", 60),
    ("SO_TXTIME", 61),
    ("SO_BINDTOIFINDEX", 62),
    ("SO_TIMESTAMP_NEW", 63),
    ("SO_TIMESTAMPNS_NEW", 64),
    ("SO_TIMESTAMPING_NEW", 65),
    ("SO_RCVTIMEO_NEW", 66),
    ("SO_SNDTIMEO_NEW", 67),
    ("SO_DETACH_REUSEPORT_BPF", 68),
    ("SO_PREFER_BUSY_POLL", 69),
    ("SO_BUSY_POLL_BUDGET", 70),
    ("SO_NETNS_COOKIE", 71),
    ("SO_BUF_LOCK", 72),
    ("SO_RESERVE_MEM", 73),
    ("SO_TXREHASH", 74),
    ("SO_RCVMARK", 75),
    ("SO_PASSPIDFD", 76),
    ("SO_PEERPIDFD", 77),
    ("SO_DEVMEM_DONTNEED", 80),
];

const IP_OPTIONS: &[(&str, i32)] = &[
    ("IP_TOS", 1),
    ("IP_TTL", 2),
    ("IP_HDRINCL", 3),
    ("IP_OPTIONS", 4),
    ("IP_ROUTER_ALERT", 5),
    ("IP_RECVOPTS", 6),
    ("IP_RETOPTS", 7),
    ("IP_PKTINFO", 8),
    ("IP_PKTOPTIONS", 9),
    ("IP_MTU_DISCOVER", 10),
    ("IP_RECVERR", 11),
    ("IP_RECVTTL", 12),
    ("IP_RECVTOS", 13),
    ("IP_MTU", 14),
    ("IP_FREEBIND", 15),
    ("IP_IPSEC_POLICY", 16),
    ("IP_XFRM_POLICY", 17),
    ("IP_PASSSEC", 18),
    ("IP_TRANSPARENT", 19),
    ("IP_RECVORIGDSTADDR", 20),
    ("IP_MINTTL", 21),
    ("IP_NODEFRAG", 22),
    ("IP_CHECKSUM", 23),
    ("IP_BIND_ADDRESS_NO_PORT", 24),
    ("IP_RECVFRAGSIZE", 25),
    ("IP_RECVERR_RFC4884", 26),
    ("IP_MULTICAST_IF", 32),
    ("IP_MULTICAST_TTL", 33),
    ("IP_MULTICAST_LOOP", 34),
    ("IP_ADD_MEMBERSHIP", 35),
    ("IP_DROP_MEMBERSHIP", 36),
    ("IP_UNBLOCK_SOURCE", 37),
    ("IP_BLOCK_SOURCE", 38),
    ("IP_ADD_SOURCE_MEMBERSHIP", 39),
    ("IP_DROP_SOURCE_MEMBERSHIP", 40),
    ("IP_MSFILTER", 41),
    ("MCAST_JOIN_GROUP", 42),
    ("MCAST_BLOCK_SOURCE", 43),
    ("MCAST_UNBLOCK_SOURCE", 44),
    ("MCAST_LEAVE_GROUP", 45),
    ("MCAST_JOIN_SOURCE_GROUP", 46),
    ("MCAST_LEAVE_SOURCE_GROUP", 47),
    ("MCAST_MSFILTER", 48),
    ("IP_MULTICAST_ALL", 49),
    ("IP_UNICAST_IF", 50),
    ("IP_LOCAL_PORT_RANGE", 51),
    ("IP_PROTOCOL", 52),
];

const IPV6_OPTIONS: &[(&str, i32)] = &[
    ("IPV6_ADDRFORM", 1),
    ("IPV6_2292PKTINFO", 2),
    ("IPV6_2292HOPOPTS", 3),
    ("IPV6_2292DSTOPTS", 4),
    ("IPV6_2292RTHDR", 5),
    ("IPV6_2292PKTOPTIONS", 6),
    ("IPV6_2292HOPLIMIT", 8),
    ("IPV6_FLOWINFO", 11),
    ("IPV6_UNICAST_HOPS", 16),
    ("IPV6_MULTICAST_IF", 17),
    ("IPV6_MULTICAST_HOPS", 18),
    ("IPV6_MULTICAST_LOOP", 19),
    ("IPV6_ADD_MEMBERSHIP", 20),
    ("IPV6_DROP_MEMBERSHIP", 21),
    ("IPV6_ROUTER_ALERT", 22),
    ("IPV6_MTU_DISCOVER", 23),
    ("IPV6_MTU", 24),
    ("IPV6_RECVERR", 25),
    ("IPV6_V6ONLY", 26),
    ("IPV6_JOIN_ANYCAST", 27),
    ("IPV6_LEAVE_ANYCAST", 28),
    ("IPV6_MULTICAST_ALL", 29),
    ("IPV6_ROUTER_ALERT_ISOLATE", 30),
    ("IPV6_RECVERR_RFC4884", 31),
    ("IPV6_FLOWLABEL_MGR", 32),
    ("IPV6_FLOWINFO_SEND", 33),
    ("IPV6_IPSEC_POLICY", 34),
    ("IPV6_XFRM_POLICY", 35),
    ("MCAST_JOIN_GROUP", 42),
    ("MCAST_BLOCK_SOURCE", 43),
    ("MCAST_UNBLOCK_SOURCE", 44),
    ("MCAST_LEAVE_GROUP", 45),
    ("MCAST_JOIN_SOURCE_GROUP", 46),
    ("MCAST_LEAVE_SOURCE_GROUP", 47),
    ("MCAST_MSFILTER", 48),
    ("IPV6_RECVPKTINFO", 49),
    ("IPV6_PKTINFO", 50),
    ("IPV6_RECVHOPLIMIT", 51),
    ("IPV6_RECVHOPOPTS", 53),
    ("IPV6_HOPOPTS", 54),
    ("IPV6_RTHDRDSTOPTS", 55),
    ("IPV6_RECVRTHDR", 56),
    ("IPV6_RTHDR", 57),
    ("IPV6_RECVDSTOPTS", 58),
    ("IPV6_DSTOPTS", 59),
    ("IPV6_RECVPATHMTU", 60),
    ("IPV6_DONTFRAG", 62),
    ("IPV6_RECVTCLASS", 66),
    ("IPV6_TCLASS", 67),
    ("IPV6_AUTOFLOWLABEL", 70),
    ("IPV6_ADDR_PREFERENCES", 72),
    ("IPV6_MINHOPCOUNT", 73),
    ("IPV6_RECVORIGDSTADDR", 74),
    ("IPV6_TRANSPARENT", 75),
    ("IPV6_UNICAST_IF", 76),
    ("IPV6_RECVFRAGSIZE", 77),
    ("IPV6_FREEBIND", 78),
];

const TCP_OPTIONS: &[(&str, i32)] = &[
    ("TCP_NODELAY", 1),
    ("TCP_MAXSEG", 2),
    ("TCP_CORK", 3),
    ("TCP_KEEPIDLE", 4),
    ("TCP_KEEPINTVL", 5),
    ("TCP_KEEPCNT", 6),
    ("TCP_SYNCNT", 7),
    ("TCP_LINGER2", 8),
    ("TCP_DEFER_ACCEPT", 9),
    ("TCP_WINDOW_CLAMP", 10),
    ("TCP_INFO", 11),
    ("TCP_QUICKACK", 12),
    ("TCP_CONGESTION", 13),
    ("TCP_MD5SIG", 14),
    ("TCP_THIN_LINEAR_TIMEOUTS", 16),
    ("TCP_THIN_DUPACK", 17),
    ("TCP_USER_TIMEOUT", 18),
    ("TCP_REPAIR", 19),
    ("TCP_REPAIR_QUEUE", 20),
    ("TCP_QUEUE_SEQ", 21),
    ("TCP_REPAIR_OPTIONS", 22),
    ("TCP_FASTOPEN", 23),
    ("TCP_TIMESTAMP", 24),
    ("TCP_NOTSENT_LOWAT", 25),
    ("TCP_CC_INFO", 26),
    ("TCP_SAVE_SYN", 27),
    ("TCP_SAVED_SYN", 28),
    ("TCP_REPAIR_WINDOW", 29),
    ("TCP_FASTOPEN_CONNECT", 30),
    ("TCP_ULP", 31),
    ("TCP_MD5SIG_EXT", 32),
    ("TCP_FASTOPEN_KEY", 33),
    ("TCP_FASTOPEN_NO_COOKIE", 34),
    ("TCP_ZEROCOPY_RECEIVE", 35),
    ("TCP_INQ", 36),
    ("TCP_TX_DELAY", 37),
    ("TCP_AO_ADD_KEY", 38),
    ("TCP_AO_DEL_KEY", 39),
    ("TCP_AO_INFO", 40),
    ("TCP_AO_GET_KEYS", 41),
    ("TCP_AO_REPAIR", 42),
];

fn lookup(table: &[(&'static str, i32)], value: i32) -> Option<&'static str> {
    table
        .iter()
        .find(|&&(_, number)| number == value)
        .map(|&(name, _)| name)
}

fn socket_option_name(get: bool, level: i32, option: i32) -> String {
    const SOL_SOCKET: i32 = 1;
    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IPPROTO_TCP: i32 = 6;
    // SO_GET_FILTER shares SO_ATTACH_FILTER's number; the direction selects it.
    if get && level == SOL_SOCKET && option == 26 {
        return "SO_GET_FILTER".into();
    }
    let table: &[(&str, i32)] = match level {
        SOL_SOCKET => SOL_SOCKET_OPTIONS,
        IPPROTO_IP => IP_OPTIONS,
        IPPROTO_IPV6 => IPV6_OPTIONS,
        IPPROTO_TCP => TCP_OPTIONS,
        _ => &[],
    };
    if let Some(name) = lookup(table, option) {
        return name.into();
    }
    // The IP handlers pass options they do not know to netfilter.
    if level == IPPROTO_IP || level == IPPROTO_IPV6 {
        let prefix = if level == IPPROTO_IP { "IPT" } else { "IP6T" };
        let name = match (get, option) {
            (false, 64) => Some("SO_SET_REPLACE"),
            (false, 65) => Some("SO_SET_ADD_COUNTERS"),
            (true, 64) => Some("SO_GET_INFO"),
            (true, 65) => Some("SO_GET_ENTRIES"),
            (true, 66) => Some("SO_GET_REVISION_MATCH"),
            (true, 67) => Some("SO_GET_REVISION_TARGET"),
            _ => None,
        };
        if let Some(name) = name {
            return format!("{prefix}_{name}");
        }
    }
    format!("Unknown option {option:#x}")
}

/// Name a selector argument whose meaning may depend on another argument, such
/// as a socket option name given its level. None means the argument is not a
/// selector in the pinned schema.
pub fn selector_name(number: u64, index: usize, args: &[u64; 6]) -> Option<String> {
    match (number, index) {
        (54 | 55, 1) => Some(
            lookup(SOCKET_LEVELS, args[1] as i32)
                .map_or_else(|| format!("Unknown level {}", args[1] as i32), Into::into),
        ),
        (54 | 55, 2) => Some(socket_option_name(
            number == 55,
            args[1] as i32,
            args[2] as i32,
        )),
        _ => None,
    }
}

/// Return None when the argument is not classified as flags by the pinned schema.
pub fn argument_flags(number: u64, index: usize, value: u64) -> Option<FlagValue> {
    let group = syscall(number)?.arguments.get(index)?.flags.as_deref()?;
    let mut masks = rules(group);
    masks.sort_by_key(|&(_, mask, _)| std::cmp::Reverse(mask.count_ones()));
    let mut known = 0;
    let mut names = Vec::new();
    for (name, mask, expected) in masks {
        if value & mask == expected && mask & known == 0 {
            names.push(name.to_owned());
            known |= mask;
        }
    }
    if group == "clone" && value & 0xff != 0 {
        names.push(format!("exit_signal={}", value & 0xff));
        known |= 0xff;
    }
    Some(FlagValue {
        names,
        unknown_bits: value & !known,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_covers_pinned_native_slots_and_excludes_gaps() {
        assert_eq!(inventory().len(), 375);
        for pair in inventory().windows(2) {
            assert!(pair[0].number < pair[1].number);
        }
        assert_eq!(syscall(462).unwrap().name, "mseal");
        assert!(syscall(400).is_none());
        assert!(syscall(512).is_none());
        assert_eq!(syscall(56).unwrap().arg_count, Some(5));
        assert_eq!(syscall(9).unwrap().arg_count, Some(6));
        for number in [125, 126] {
            assert!(
                syscall(number)
                    .unwrap()
                    .arguments
                    .iter()
                    .all(|argument| argument.pointer)
            );
        }
    }

    #[test]
    fn modes_composites_and_unknown_bits_are_distinct() {
        let read = argument_flags(2, 1, 0).unwrap();
        assert_eq!(read.names, ["O_RDONLY"]);
        let tmpfile = argument_flags(2, 1, 0o20200002).unwrap();
        assert!(tmpfile.names.contains(&"O_TMPFILE".into()));
        assert!(!tmpfile.names.contains(&"O_DIRECTORY".into()));
        assert!(tmpfile.names.contains(&"O_RDWR".into()));
        assert_eq!(tmpfile.unknown_bits, 0);
        let future = argument_flags(2, 1, 1 << 63).unwrap();
        assert_eq!(future.unknown_bits, 1 << 63);
        assert!(argument_flags(0, 0, 0).is_none());
    }

    #[test]
    fn socket_option_names_follow_level_and_direction() {
        let args = |level: u64, option: u64| [3, level, option, 0, 4, 0];
        assert_eq!(
            selector_name(54, 1, &args(1, 8)).as_deref(),
            Some("SOL_SOCKET")
        );
        assert_eq!(
            selector_name(54, 2, &args(1, 8)).as_deref(),
            Some("SO_RCVBUF")
        );
        assert_eq!(
            selector_name(54, 2, &args(1, 26)).as_deref(),
            Some("SO_ATTACH_FILTER")
        );
        assert_eq!(
            selector_name(55, 2, &args(1, 26)).as_deref(),
            Some("SO_GET_FILTER")
        );
        assert_eq!(
            selector_name(54, 2, &args(41, 67)).as_deref(),
            Some("IPV6_TCLASS")
        );
        assert_eq!(
            selector_name(54, 2, &args(0, 64)).as_deref(),
            Some("IPT_SO_SET_REPLACE")
        );
        assert_eq!(
            selector_name(55, 2, &args(41, 65)).as_deref(),
            Some("IP6T_SO_GET_ENTRIES")
        );
        assert_eq!(
            selector_name(54, 2, &args(6, 11)).as_deref(),
            Some("TCP_INFO")
        );
        assert_eq!(
            selector_name(54, 2, &args(1, 0x7fff)).as_deref(),
            Some("Unknown option 0x7fff")
        );
        assert_eq!(
            selector_name(54, 1, &args(999, 1)).as_deref(),
            Some("Unknown level 999")
        );
        assert_eq!(selector_name(54, 3, &args(1, 8)), None);
        assert_eq!(selector_name(0, 1, &args(1, 8)), None);
    }

    #[test]
    fn socket_option_tables_have_unique_values() {
        for table in [SOL_SOCKET_OPTIONS, IP_OPTIONS, IPV6_OPTIONS, TCP_OPTIONS] {
            let mut values: Vec<_> = table
                .iter()
                .filter(|&&(name, _)| name != "SO_GET_FILTER")
                .map(|&(_, value)| value)
                .collect();
            let count = values.len();
            values.sort_unstable();
            values.dedup();
            assert_eq!(values.len(), count);
        }
    }

    #[test]
    fn flags_follow_the_syscall_not_an_unrelated_enum() {
        let accept = argument_flags(288, 3, 1).unwrap();
        assert!(accept.names.is_empty());
        assert_eq!(accept.unknown_bits, 1);
        let unshare = argument_flags(272, 0, 17).unwrap();
        assert!(unshare.names.is_empty());
        assert_eq!(unshare.unknown_bits, 17);
        let fstatat = argument_flags(262, 3, 0x2000).unwrap();
        assert_eq!(fstatat.unknown_bits, 0x2000);
        let futex = argument_flags(202, 1, 128).unwrap();
        assert_eq!(futex.unknown_bits, 0);
        assert!(futex.names.contains(&"FUTEX_WAIT".into()));
        assert!(futex.names.contains(&"FUTEX_PRIVATE_FLAG".into()));
    }
}
