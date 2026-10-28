// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Pinned native declaration metadata and argument-specific flag interpretation.
//!
//! The table is x86-64's (`protocol/native-syscalls.json`, generated per
//! architecture). A session decodes records only from a guest whose INFO
//! reports x86-64 (`GuestArch`); it launches and traces nothing on another.
use serde::Deserialize;
use std::collections::HashMap;
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

/// A system call ABI this host ships a table for. Records name their calls
/// through the table of the run's ABI; today only x86-64 has one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Abi {
    X86_64,
}

impl Abi {
    /// The ABI a guest architecture's native calls use, if its table is shipped.
    pub fn of(arch: crate::api::GuestArch) -> Option<Self> {
        match arch {
            crate::api::GuestArch::X86_64 => Some(Self::X86_64),
            crate::api::GuestArch::Unsupported(_) => None,
        }
    }
}

/// One ABI's calls, by number and by name. Rules and decoders key on the name
/// (`"execve"`) and read argument roles by argument name; the number is only
/// what the wire carries.
pub struct Table {
    pub abi: Abi,
    entries: &'static [SyscallInfo],
    by_name: HashMap<&'static str, usize>,
}

impl Table {
    fn load(abi: Abi) -> Self {
        let json = match abi {
            // This is a generated, compiled-in constant verified by the inventory tests.
            Abi::X86_64 => include_str!("../../../protocol/native-syscalls.json"),
        };
        let inventory: Inventory =
            serde_json::from_str(json).expect("invalid compiled native syscall inventory");
        // The table lives for the whole process, so its names can be 'static.
        let entries: &'static [SyscallInfo] = Vec::leak(inventory.syscalls);
        let mut by_name = HashMap::new();
        for (index, entry) in entries.iter().enumerate() {
            by_name.entry(entry.name.as_str()).or_insert(index);
        }
        Self {
            abi,
            entries,
            by_name,
        }
    }

    pub fn all(&self) -> &'static [SyscallInfo] {
        self.entries
    }

    pub fn by_number(&self, number: u64) -> Option<&'static SyscallInfo> {
        self.entries
            .binary_search_by_key(&number, |entry| entry.number)
            .ok()
            .map(|index| &self.entries[index])
    }

    pub fn by_name(&self, name: &str) -> Option<&'static SyscallInfo> {
        self.by_name.get(name).map(|&index| &self.entries[index])
    }

    /// The number of a call on this ABI, if the ABI has it (legacy names are
    /// absent on asm-generic architectures).
    pub fn number(&self, name: &str) -> Option<u64> {
        self.by_name(name).map(|entry| entry.number)
    }

    /// The table's name for a number.
    pub fn name_of(&self, number: u64) -> Option<&'static str> {
        self.by_number(number).map(|entry| entry.name.as_str())
    }

    /// The index of a call's argument by its name in the table (`flags` of
    /// `clone`, `argv` of `execve`), so a role does not depend on the
    /// architecture's argument order.
    pub fn argument(&self, call: &str, argument: &str) -> Option<usize> {
        self.by_name(call)?
            .arguments
            .iter()
            .position(|info| info.name == argument)
    }
}

/// The table of an ABI.
pub fn table(abi: Abi) -> &'static Table {
    static X86_64: OnceLock<Table> = OnceLock::new();
    match abi {
        Abi::X86_64 => X86_64.get_or_init(|| Table::load(Abi::X86_64)),
    }
}

/// The table of the ABI every run uses until a second one is shipped: the one
/// place that names it, so adding an ABI means threading the run's ABI to here.
pub fn native() -> &'static Table {
    table(Abi::X86_64)
}

pub fn all() -> &'static [SyscallInfo] {
    native().all()
}

pub fn syscall(number: u64) -> Option<&'static SyscallInfo> {
    native().by_number(number)
}

/// The number a name has on the run's ABI.
pub fn number(name: &str) -> Option<u64> {
    native().number(name)
}

/// The table's name for a number, without a copy.
pub fn known_name(number: u64) -> Option<&'static str> {
    native().name_of(number)
}

pub fn name(number: u64) -> String {
    known_name(number).map_or_else(|| format!("syscall_{number}"), str::to_owned)
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
                ("MAP_DROPPABLE", 0x08),
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
        "kexec" => {
            let mut values = bits(&[
                ("KEXEC_ON_CRASH", 0x1),
                ("KEXEC_PRESERVE_CONTEXT", 0x2),
                ("KEXEC_UPDATE_ELFCOREHDR", 0x4),
                ("KEXEC_CRASH_HOTPLUG_SUPPORT", 0x8),
            ]);
            // The architecture occupies the high 16 bits as one enum value.
            values.extend([
                ("KEXEC_ARCH_DEFAULT", 0xffff_0000, 0),
                ("KEXEC_ARCH_386", 0xffff_0000, 3 << 16),
                ("KEXEC_ARCH_X86_64", 0xffff_0000, 62 << 16),
            ]);
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

mod selectors;
mod socket_options;
use socket_options::{SOCKET_LEVELS, lookup, socket_option_name};

// prctl options, PR_SET_MM sub-options, ptrace requests and keyctl commands
// named by the pinned UAPI headers; the kernel capture in native_capture.c
// handles the same selectors.
const PRCTL_OPTIONS: &[(&str, u64)] = &[
    ("PR_SET_PDEATHSIG", 1),
    ("PR_GET_PDEATHSIG", 2),
    ("PR_GET_DUMPABLE", 3),
    ("PR_SET_DUMPABLE", 4),
    ("PR_GET_UNALIGN", 5),
    ("PR_SET_UNALIGN", 6),
    ("PR_GET_KEEPCAPS", 7),
    ("PR_SET_KEEPCAPS", 8),
    ("PR_GET_FPEMU", 9),
    ("PR_SET_FPEMU", 10),
    ("PR_GET_FPEXC", 11),
    ("PR_SET_FPEXC", 12),
    ("PR_GET_TIMING", 13),
    ("PR_SET_TIMING", 14),
    ("PR_SET_NAME", 15),
    ("PR_GET_NAME", 16),
    ("PR_GET_ENDIAN", 19),
    ("PR_SET_ENDIAN", 20),
    ("PR_GET_SECCOMP", 21),
    ("PR_SET_SECCOMP", 22),
    ("PR_CAPBSET_READ", 23),
    ("PR_CAPBSET_DROP", 24),
    ("PR_GET_TSC", 25),
    ("PR_SET_TSC", 26),
    ("PR_GET_SECUREBITS", 27),
    ("PR_SET_SECUREBITS", 28),
    ("PR_SET_TIMERSLACK", 29),
    ("PR_GET_TIMERSLACK", 30),
    ("PR_TASK_PERF_EVENTS_DISABLE", 31),
    ("PR_TASK_PERF_EVENTS_ENABLE", 32),
    ("PR_MCE_KILL", 33),
    ("PR_MCE_KILL_GET", 34),
    ("PR_SET_MM", 35),
    ("PR_SET_CHILD_SUBREAPER", 36),
    ("PR_GET_CHILD_SUBREAPER", 37),
    ("PR_SET_NO_NEW_PRIVS", 38),
    ("PR_GET_NO_NEW_PRIVS", 39),
    ("PR_GET_TID_ADDRESS", 40),
    ("PR_SET_THP_DISABLE", 41),
    ("PR_GET_THP_DISABLE", 42),
    ("PR_MPX_ENABLE_MANAGEMENT", 43),
    ("PR_MPX_DISABLE_MANAGEMENT", 44),
    ("PR_SET_FP_MODE", 45),
    ("PR_GET_FP_MODE", 46),
    ("PR_CAP_AMBIENT", 47),
    ("PR_SVE_SET_VL", 50),
    ("PR_SVE_GET_VL", 51),
    ("PR_GET_SPECULATION_CTRL", 52),
    ("PR_SET_SPECULATION_CTRL", 53),
    ("PR_PAC_RESET_KEYS", 54),
    ("PR_SET_TAGGED_ADDR_CTRL", 55),
    ("PR_GET_TAGGED_ADDR_CTRL", 56),
    ("PR_SET_IO_FLUSHER", 57),
    ("PR_GET_IO_FLUSHER", 58),
    ("PR_SET_SYSCALL_USER_DISPATCH", 59),
    ("PR_PAC_SET_ENABLED_KEYS", 60),
    ("PR_PAC_GET_ENABLED_KEYS", 61),
    ("PR_SCHED_CORE", 62),
    ("PR_SME_SET_VL", 63),
    ("PR_SME_GET_VL", 64),
    ("PR_SET_MDWE", 65),
    ("PR_GET_MDWE", 66),
    ("PR_SET_MEMORY_MERGE", 67),
    ("PR_GET_MEMORY_MERGE", 68),
    ("PR_RISCV_V_SET_CONTROL", 69),
    ("PR_RISCV_V_GET_CONTROL", 70),
    ("PR_RISCV_SET_ICACHE_FLUSH_CTX", 71),
    ("PR_PPC_GET_DEXCR", 72),
    ("PR_PPC_SET_DEXCR", 73),
    ("PR_GET_AUXV", 0x41555856),
    ("PR_SET_VMA", 0x53564d41),
    ("PR_SET_PTRACER", 0x59616d61),
];

const PRCTL_MM_OPTIONS: &[(&str, u64)] = &[
    ("PR_SET_MM_START_CODE", 1),
    ("PR_SET_MM_END_CODE", 2),
    ("PR_SET_MM_START_DATA", 3),
    ("PR_SET_MM_END_DATA", 4),
    ("PR_SET_MM_START_STACK", 5),
    ("PR_SET_MM_START_BRK", 6),
    ("PR_SET_MM_BRK", 7),
    ("PR_SET_MM_ARG_START", 8),
    ("PR_SET_MM_ARG_END", 9),
    ("PR_SET_MM_ENV_START", 10),
    ("PR_SET_MM_ENV_END", 11),
    ("PR_SET_MM_AUXV", 12),
    ("PR_SET_MM_EXE_FILE", 13),
    ("PR_SET_MM_MAP", 14),
    ("PR_SET_MM_MAP_SIZE", 15),
];

const PTRACE_REQUESTS: &[(&str, u64)] = &[
    ("PTRACE_TRACEME", 0),
    ("PTRACE_PEEKTEXT", 1),
    ("PTRACE_PEEKDATA", 2),
    ("PTRACE_PEEKUSR", 3),
    ("PTRACE_POKETEXT", 4),
    ("PTRACE_POKEDATA", 5),
    ("PTRACE_POKEUSR", 6),
    ("PTRACE_CONT", 7),
    ("PTRACE_KILL", 8),
    ("PTRACE_SINGLESTEP", 9),
    ("PTRACE_GETREGS", 12),
    ("PTRACE_SETREGS", 13),
    ("PTRACE_GETFPREGS", 14),
    ("PTRACE_SETFPREGS", 15),
    ("PTRACE_ATTACH", 16),
    ("PTRACE_DETACH", 17),
    ("PTRACE_GETFPXREGS", 18),
    ("PTRACE_SETFPXREGS", 19),
    ("PTRACE_OLDSETOPTIONS", 21),
    ("PTRACE_SYSCALL", 24),
    ("PTRACE_GET_THREAD_AREA", 25),
    ("PTRACE_SET_THREAD_AREA", 26),
    ("PTRACE_ARCH_PRCTL", 30),
    ("PTRACE_SYSEMU", 31),
    ("PTRACE_SYSEMU_SINGLESTEP", 32),
    ("PTRACE_SINGLEBLOCK", 33),
    ("PTRACE_SETOPTIONS", 0x4200),
    ("PTRACE_GETEVENTMSG", 0x4201),
    ("PTRACE_GETSIGINFO", 0x4202),
    ("PTRACE_SETSIGINFO", 0x4203),
    ("PTRACE_GETREGSET", 0x4204),
    ("PTRACE_SETREGSET", 0x4205),
    ("PTRACE_SEIZE", 0x4206),
    ("PTRACE_INTERRUPT", 0x4207),
    ("PTRACE_LISTEN", 0x4208),
    ("PTRACE_PEEKSIGINFO", 0x4209),
    ("PTRACE_GETSIGMASK", 0x420a),
    ("PTRACE_SETSIGMASK", 0x420b),
    ("PTRACE_SECCOMP_GET_FILTER", 0x420c),
    ("PTRACE_SECCOMP_GET_METADATA", 0x420d),
    ("PTRACE_GET_SYSCALL_INFO", 0x420e),
    ("PTRACE_GET_RSEQ_CONFIGURATION", 0x420f),
    ("PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG", 0x4210),
    ("PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG", 0x4211),
];

const KEYCTL_COMMANDS: &[(&str, u64)] = &[
    ("KEYCTL_GET_KEYRING_ID", 0),
    ("KEYCTL_JOIN_SESSION_KEYRING", 1),
    ("KEYCTL_UPDATE", 2),
    ("KEYCTL_REVOKE", 3),
    ("KEYCTL_CHOWN", 4),
    ("KEYCTL_SETPERM", 5),
    ("KEYCTL_DESCRIBE", 6),
    ("KEYCTL_CLEAR", 7),
    ("KEYCTL_LINK", 8),
    ("KEYCTL_UNLINK", 9),
    ("KEYCTL_SEARCH", 10),
    ("KEYCTL_READ", 11),
    ("KEYCTL_INSTANTIATE", 12),
    ("KEYCTL_NEGATE", 13),
    ("KEYCTL_SET_REQKEY_KEYRING", 14),
    ("KEYCTL_SET_TIMEOUT", 15),
    ("KEYCTL_ASSUME_AUTHORITY", 16),
    ("KEYCTL_GET_SECURITY", 17),
    ("KEYCTL_SESSION_TO_PARENT", 18),
    ("KEYCTL_REJECT", 19),
    ("KEYCTL_INSTANTIATE_IOV", 20),
    ("KEYCTL_INVALIDATE", 21),
    ("KEYCTL_GET_PERSISTENT", 22),
    ("KEYCTL_DH_COMPUTE", 23),
    ("KEYCTL_PKEY_QUERY", 24),
    ("KEYCTL_PKEY_ENCRYPT", 25),
    ("KEYCTL_PKEY_DECRYPT", 26),
    ("KEYCTL_PKEY_SIGN", 27),
    ("KEYCTL_PKEY_VERIFY", 28),
    ("KEYCTL_RESTRICT_KEYRING", 29),
    ("KEYCTL_MOVE", 30),
    ("KEYCTL_CAPABILITIES", 31),
    ("KEYCTL_WATCH_KEY", 32),
];

// bpf commands named by the pinned UAPI `enum bpf_cmd` (aliases keep the first name).
const BPF_COMMANDS: &[(&str, u64)] = &[
    ("BPF_MAP_CREATE", 0),
    ("BPF_MAP_LOOKUP_ELEM", 1),
    ("BPF_MAP_UPDATE_ELEM", 2),
    ("BPF_MAP_DELETE_ELEM", 3),
    ("BPF_MAP_GET_NEXT_KEY", 4),
    ("BPF_PROG_LOAD", 5),
    ("BPF_OBJ_PIN", 6),
    ("BPF_OBJ_GET", 7),
    ("BPF_PROG_ATTACH", 8),
    ("BPF_PROG_DETACH", 9),
    ("BPF_PROG_TEST_RUN", 10),
    ("BPF_PROG_GET_NEXT_ID", 11),
    ("BPF_MAP_GET_NEXT_ID", 12),
    ("BPF_PROG_GET_FD_BY_ID", 13),
    ("BPF_MAP_GET_FD_BY_ID", 14),
    ("BPF_OBJ_GET_INFO_BY_FD", 15),
    ("BPF_PROG_QUERY", 16),
    ("BPF_RAW_TRACEPOINT_OPEN", 17),
    ("BPF_BTF_LOAD", 18),
    ("BPF_BTF_GET_FD_BY_ID", 19),
    ("BPF_TASK_FD_QUERY", 20),
    ("BPF_MAP_LOOKUP_AND_DELETE_ELEM", 21),
    ("BPF_MAP_FREEZE", 22),
    ("BPF_BTF_GET_NEXT_ID", 23),
    ("BPF_MAP_LOOKUP_BATCH", 24),
    ("BPF_MAP_LOOKUP_AND_DELETE_BATCH", 25),
    ("BPF_MAP_UPDATE_BATCH", 26),
    ("BPF_MAP_DELETE_BATCH", 27),
    ("BPF_LINK_CREATE", 28),
    ("BPF_LINK_UPDATE", 29),
    ("BPF_LINK_GET_FD_BY_ID", 30),
    ("BPF_LINK_GET_NEXT_ID", 31),
    ("BPF_ENABLE_STATS", 32),
    ("BPF_ITER_CREATE", 33),
    ("BPF_LINK_DETACH", 34),
    ("BPF_PROG_BIND_MAP", 35),
    ("BPF_TOKEN_CREATE", 36),
];

const PTRACE_OPTIONS: &[(&str, u64)] = &[
    ("PTRACE_O_TRACESYSGOOD", 0x1),
    ("PTRACE_O_TRACEFORK", 0x2),
    ("PTRACE_O_TRACEVFORK", 0x4),
    ("PTRACE_O_TRACECLONE", 0x8),
    ("PTRACE_O_TRACEEXEC", 0x10),
    ("PTRACE_O_TRACEVFORKDONE", 0x20),
    ("PTRACE_O_TRACEEXIT", 0x40),
    ("PTRACE_O_TRACESECCOMP", 0x80),
    ("PTRACE_O_EXITKILL", 0x10_0000),
    ("PTRACE_O_SUSPEND_SECCOMP", 0x20_0000),
];

fn named(table: &[(&'static str, u64)], value: u64, kind: &str) -> String {
    table
        .iter()
        .find(|&&(_, number)| number == value)
        .map_or_else(
            || format!("Unknown {kind} {value:#x}"),
            |&(name, _)| name.into(),
        )
}

fn ptrace_options(value: u64) -> String {
    let mut known = 0;
    let mut names: Vec<String> = PTRACE_OPTIONS
        .iter()
        .filter(|&&(_, bit)| value & bit != 0)
        .map(|&(name, bit)| {
            known |= bit;
            name.to_owned()
        })
        .collect();
    if value & !known != 0 {
        names.push(format!("unknown bits {:#x}", value & !known));
    }
    if names.is_empty() {
        "0".into()
    } else {
        names.join(" | ")
    }
}

/// `QCMD(subcommand, type)` as used by quotactl and quotactl_fd.
fn quota_command(cmd: u64) -> String {
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
    let subcommand = named(SUBCOMMANDS, u64::from(cmd >> 8), "subcommand");
    let kind = match cmd & 0xff {
        0 => "USRQUOTA".into(),
        1 => "GRPQUOTA".into(),
        2 => "PRJQUOTA".into(),
        other => format!("Unknown type {other}"),
    };
    format!("{subcommand} / {kind}")
}

fn prctl_suboption(option: u64, value: u64) -> Option<String> {
    const PR_SET_MM: u64 = 35;
    const PR_SCHED_CORE: u64 = 62;
    const PR_SET_SYSCALL_USER_DISPATCH: u64 = 59;
    const PR_SET_VMA: u64 = 0x5356_4d41;
    let table: &[(&str, u64)] = match option {
        PR_SET_MM => PRCTL_MM_OPTIONS,
        PR_SCHED_CORE => &[
            ("PR_SCHED_CORE_GET", 0),
            ("PR_SCHED_CORE_CREATE", 1),
            ("PR_SCHED_CORE_SHARE_TO", 2),
            ("PR_SCHED_CORE_SHARE_FROM", 3),
        ],
        PR_SET_SYSCALL_USER_DISPATCH => &[("PR_SYS_DISPATCH_OFF", 0), ("PR_SYS_DISPATCH_ON", 1)],
        PR_SET_VMA => &[("PR_SET_VMA_ANON_NAME", 0)],
        _ => return None,
    };
    Some(named(table, value, "sub-option"))
}

/// Name a selector argument whose meaning may depend on another argument, such
/// as a socket option name given its level. None means the argument is not a
/// selector in the pinned schema.
pub fn selector_name(number: u64, index: usize, args: &[u64; 6]) -> Option<String> {
    const PTRACE_SETOPTIONS: u64 = 0x4200;
    const PTRACE_SEIZE: u64 = 0x4206;
    const PTRACE_OLDSETOPTIONS: u64 = 21;
    match (number, index) {
        (101, 0) => Some(named(PTRACE_REQUESTS, args[0], "request")),
        (101, 3)
            if matches!(
                args[0],
                PTRACE_SETOPTIONS | PTRACE_SEIZE | PTRACE_OLDSETOPTIONS
            ) =>
        {
            Some(ptrace_options(args[3]))
        }
        (139, 0) => Some(
            match args[0] {
                1 => "filesystem name to index",
                2 => "filesystem index to name",
                3 => "filesystem count",
                _ => return Some(format!("Unknown option {:#x}", args[0])),
            }
            .into(),
        ),
        (157, 0) => Some(named(PRCTL_OPTIONS, args[0] as u32 as u64, "option")),
        (157, 1) => prctl_suboption(args[0] as u32 as u64, args[1]),
        (250, 0) => Some(named(KEYCTL_COMMANDS, args[0] as u32 as u64, "command")),
        (321, 0) => Some(named(BPF_COMMANDS, args[0] as u32 as u64, "command")),
        (179, 0) => Some(quota_command(args[0])),
        (443, 1) => Some(quota_command(args[1])),
        (54 | 55, 1) => Some(
            lookup(SOCKET_LEVELS, args[1] as i32)
                .map_or_else(|| format!("Unknown level {}", args[1] as i32), Into::into),
        ),
        (54 | 55, 2) => Some(socket_option_name(
            number == 55,
            args[1] as i32,
            args[2] as i32,
        )),
        _ => selectors::named_argument(number, index, args),
    }
}

/// Return None when the argument is not classified as flags by the pinned schema.
pub fn argument_flags(number: u64, index: usize, value: u64) -> Option<FlagValue> {
    let group = syscall(number)?.arguments.get(index)?.flags.as_deref()?;
    // The inventory leaves some flag groups unnamed; these have one meaning.
    let group = match (number, index, group) {
        // memfd_secret(flags): only O_CLOEXEC is defined.
        (447, 0, "unknown") => "cloexec",
        _ => group,
    };
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
    use super::socket_options::{IP_OPTIONS, IPV6_OPTIONS, SOL_SOCKET_OPTIONS, TCP_OPTIONS};
    use super::*;

    #[test]
    fn inventory_covers_pinned_native_slots_and_excludes_gaps() {
        assert_eq!(all().len(), 375);
        for pair in all().windows(2) {
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
    fn selector_families_name_options_suboptions_and_ptrace_flags() {
        let args = |a: u64, b: u64, d: u64| [a, b, 0, d, 0, 0];
        assert_eq!(
            selector_name(157, 0, &args(15, 0, 0)).as_deref(),
            Some("PR_SET_NAME")
        );
        assert_eq!(
            selector_name(157, 0, &args(0x4155_5856, 0, 0)).as_deref(),
            Some("PR_GET_AUXV")
        );
        assert_eq!(
            selector_name(157, 1, &args(35, 12, 0)).as_deref(),
            Some("PR_SET_MM_AUXV")
        );
        assert_eq!(selector_name(157, 1, &args(15, 12, 0)), None);
        assert_eq!(
            selector_name(157, 0, &args(0x7fff_ffff, 0, 0)).as_deref(),
            Some("Unknown option 0x7fffffff")
        );
        assert_eq!(
            selector_name(101, 0, &args(2, 0, 0)).as_deref(),
            Some("PTRACE_PEEKDATA")
        );
        assert_eq!(
            selector_name(101, 0, &args(0x4204, 0, 0)).as_deref(),
            Some("PTRACE_GETREGSET")
        );
        assert_eq!(
            selector_name(101, 3, &args(0x4200, 0, 0x81)).as_deref(),
            Some("PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP")
        );
        assert_eq!(selector_name(101, 3, &args(2, 0, 0x81)), None);
        assert_eq!(
            selector_name(250, 0, &args(11, 0, 0)).as_deref(),
            Some("KEYCTL_READ")
        );
        assert_eq!(
            selector_name(139, 0, &args(2, 0, 0)).as_deref(),
            Some("filesystem index to name")
        );
        assert_eq!(
            selector_name(179, 0, &args(0x80_0004 << 8, 0, 0)).as_deref(),
            Some("Q_GETFMT / USRQUOTA")
        );
        assert_eq!(
            selector_name(443, 1, &args(3, (0x5808 << 8) | 2, 0)).as_deref(),
            Some("Q_XGETQSTATV / PRJQUOTA")
        );
        assert_eq!(
            selector_name(321, 0, &args(5, 0, 0)).as_deref(),
            Some("BPF_PROG_LOAD")
        );
        assert_eq!(
            selector_name(321, 0, &args(0x7fff, 0, 0)).as_deref(),
            Some("Unknown command 0x7fff")
        );
        let kexec = argument_flags(246, 3, (62 << 16) | 1).unwrap();
        assert_eq!(kexec.names, ["KEXEC_ARCH_X86_64", "KEXEC_ON_CRASH"]);
        assert_eq!(kexec.unknown_bits, 0);
    }

    #[test]
    fn socket_option_tables_have_unique_values() {
        for table in [
            PRCTL_OPTIONS,
            PRCTL_MM_OPTIONS,
            PTRACE_REQUESTS,
            KEYCTL_COMMANDS,
            BPF_COMMANDS,
        ] {
            let mut values: Vec<_> = table.iter().map(|&(_, value)| value).collect();
            let count = values.len();
            values.sort_unstable();
            values.dedup();
            assert_eq!(values.len(), count);
        }
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
