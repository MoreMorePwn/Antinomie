// SPDX-License-Identifier: GPL-3.0-only
//! The system calls the suspicious-activity rules read.
//!
//! When the recording quota is nearly full the recorder keeps only these calls
//! (and the process lifecycle) and counts the rest as dropped. The list lives
//! here, next to the rules, and is handed to the backend at start; the recorder
//! has no list of its own. A rule that begins to read another call must name it
//! here, beside the other calls of its group.
use super::super::file_category;

/// Calls the process tree, the task state and the lifecycle rules need to stay
/// whole: a program that is not seen to start or end cannot be followed.
pub const LIFECYCLE: &[&str] = &[
    "clone",
    "clone3",
    "fork",
    "vfork",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "wait4",
    "waitid",
    "setsid",
];

/// `file_category::classify` (read through `Ctx::touches` by the path rules):
/// every call that opens, creates, changes, removes, runs or maps a file.
pub const FILES: &[&str] = &[
    "open",
    "openat",
    "openat2",
    "creat",
    "memfd_create",
    "mkdir",
    "mkdirat",
    "mknod",
    "mknodat",
    "truncate",
    "ftruncate",
    "fallocate",
    "unlink",
    "unlinkat",
    "rmdir",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "chmod",
    "fchmod",
    "fchmodat",
    "fchmodat2",
    "chown",
    "fchown",
    "lchown",
    "fchownat",
    "utime",
    "utimes",
    "utimensat",
    "futimesat",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "setxattrat",
    "removexattrat",
    "sendfile",
    "copy_file_range",
    "splice",
    "mmap",
    "mmap2",
    "mprotect",
    "msync",
    "inotify_add_watch",
    "fanotify_mark",
    "flock",
    "mount",
    "umount2",
    "chroot",
    "ioctl",
];

/// `rules::process`, `rules::evasion` and `rules::probes`.
pub const PROCESS: &[&str] = &[
    "pkey_mprotect",
    "ptrace",
    "process_vm_writev",
    "process_vm_readv",
    "init_module",
    "finit_module",
    "delete_module",
    "seccomp",
    "prctl",
    "unshare",
    "setns",
    "reboot",
    "kexec_load",
    "kexec_file_load",
    "syslog",
    "kill",
    "tkill",
    "tgkill",
    "pidfd_send_signal",
    "personality",
    "io_uring_setup",
    "io_uring_enter",
    "bpf",
    // Credential records ride on these calls.
    "setuid",
    "setgid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
    "setfsuid",
    "setfsgid",
    "capset",
    // Sandbox and debugger checks, and sleeps of a minute or more.
    "rt_sigaction",
    "sysinfo",
    "nanosleep",
    "clock_nanosleep",
    "alarm",
    "timerfd_settime",
];

/// `rules::network` and `rules::ioc`: sockets, endpoints and traffic.
pub const NETWORK: &[&str] = &[
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "setsockopt",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
];

/// Calls the rules also read, but only to refine what the calls above already
/// showed: file contents (`read`, `write`), existence checks (`stat`,
/// `access`), directory listings, clock reads and readiness waits. They are
/// what a busy program issues millions of times, and the open, create, exec,
/// connect and send that give them a meaning are kept. Dropped and counted.
pub fn bulk() -> Vec<&'static str> {
    let mut bulk = vec![
        "getdents",
        "getdents64",
        "readdir",
        "fcntl",
        "clock_gettime",
        "gettimeofday",
        "time",
        "times",
        "poll",
        "select",
    ];
    bulk.extend(file_category::READS);
    bulk.extend(file_category::WRITES);
    bulk.extend(file_category::PROBES);
    bulk
}

/// The calls the recorder keeps once the quota is nearly full.
pub fn watched() -> Vec<String> {
    let bulk = bulk();
    let mut calls: Vec<String> = [LIFECYCLE, FILES, PROCESS, NETWORK]
        .concat()
        .into_iter()
        .filter(|call| !bulk.contains(call))
        .map(str::to_owned)
        .collect();
    calls.sort();
    calls.dedup();
    calls
}
