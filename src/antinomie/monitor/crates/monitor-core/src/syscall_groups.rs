//! Syscall groups for coloring the trace, in the manner of
//! Wireshark's coloring rules. Every native x86-64 syscall belongs to exactly
//! one group; a test checks that against `protocol/native-syscalls.json`.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SyscallGroup {
    Process,
    File,
    Network,
    Memory,
    Ipc,
    Signal,
    Polling,
    Security,
    System,
    Time,
    Info,
}

impl SyscallGroup {
    pub const ALL: [Self; 11] = [
        Self::Process,
        Self::File,
        Self::Network,
        Self::Memory,
        Self::Ipc,
        Self::Signal,
        Self::Polling,
        Self::Security,
        Self::System,
        Self::Time,
        Self::Info,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Process => "Process & threads",
            Self::File => "File & filesystem",
            Self::Network => "Network",
            Self::Memory => "Memory",
            Self::Ipc => "IPC & sync",
            Self::Signal => "Signals",
            Self::Polling => "Polling & async I/O",
            Self::Security => "Credentials & security",
            Self::System => "System & kernel",
            Self::Time => "Time & scheduling",
            Self::Info => "Info queries",
        }
    }

    /// The group of a native syscall by name, or `None` for a name outside
    /// the native table (compat ABIs, unknown numbers).
    pub fn of(name: &str) -> Option<Self> {
        Some(match name {
            "clone" | "fork" | "vfork" | "clone3" | "execve" | "execveat" | "exit"
            | "exit_group" | "wait4" | "waitid" | "ptrace" | "prctl" | "arch_prctl"
            | "personality" | "unshare" | "setns" | "set_tid_address" | "set_robust_list"
            | "get_robust_list" | "rseq" | "pidfd_open" | "pidfd_getfd" | "kcmp"
            | "process_mrelease" | "set_thread_area" | "get_thread_area" | "modify_ldt"
            | "setpgid" | "setsid" | "setrlimit" | "prlimit64" => Self::Process,
            "read" | "write" | "open" | "close" | "stat" | "fstat" | "lstat" | "lseek"
            | "ioctl" | "pread64" | "pwrite64" | "readv" | "writev" | "access" | "sendfile"
            | "dup" | "dup2" | "dup3" | "fcntl" | "flock" | "fsync" | "fdatasync" | "truncate"
            | "ftruncate" | "getdents" | "getdents64" | "getcwd" | "chdir" | "fchdir"
            | "rename" | "renameat" | "renameat2" | "mkdir" | "mkdirat" | "rmdir" | "creat"
            | "link" | "linkat" | "unlink" | "unlinkat" | "symlink" | "symlinkat" | "readlink"
            | "readlinkat" | "chmod" | "fchmod" | "fchmodat" | "fchmodat2" | "chown" | "fchown"
            | "lchown" | "fchownat" | "umask" | "utime" | "utimes" | "utimensat" | "futimesat"
            | "mknod" | "mknodat" | "statfs" | "fstatfs" | "ustat" | "sysfs" | "readahead"
            | "setxattr" | "lsetxattr" | "fsetxattr" | "getxattr" | "lgetxattr" | "fgetxattr"
            | "listxattr" | "llistxattr" | "flistxattr" | "removexattr" | "lremovexattr"
            | "fremovexattr" | "openat" | "openat2" | "newfstatat" | "faccessat" | "faccessat2"
            | "fadvise64" | "splice" | "tee" | "sync_file_range" | "vmsplice" | "fallocate"
            | "preadv" | "pwritev" | "preadv2" | "pwritev2" | "copy_file_range"
            | "name_to_handle_at" | "open_by_handle_at" | "syncfs" | "sync" | "statx"
            | "inotify_init" | "inotify_init1" | "inotify_add_watch" | "inotify_rm_watch"
            | "fanotify_init" | "fanotify_mark" | "close_range" | "cachestat"
            | "lookup_dcookie" | "mount" | "umount2" | "pivot_root" | "chroot" | "open_tree"
            | "move_mount" | "fsopen" | "fsconfig" | "fsmount" | "fspick" | "mount_setattr"
            | "statmount" | "listmount" | "quotactl" | "quotactl_fd" => Self::File,
            "socket" | "connect" | "accept" | "accept4" | "sendto" | "recvfrom" | "sendmsg"
            | "recvmsg" | "sendmmsg" | "recvmmsg" | "shutdown" | "bind" | "listen"
            | "getsockname" | "getpeername" | "socketpair" | "setsockopt" | "getsockopt" => {
                Self::Network
            }
            "mmap"
            | "mprotect"
            | "munmap"
            | "brk"
            | "mremap"
            | "msync"
            | "mincore"
            | "madvise"
            | "mlock"
            | "munlock"
            | "mlockall"
            | "munlockall"
            | "mlock2"
            | "remap_file_pages"
            | "mbind"
            | "set_mempolicy"
            | "get_mempolicy"
            | "set_mempolicy_home_node"
            | "migrate_pages"
            | "move_pages"
            | "process_vm_readv"
            | "process_vm_writev"
            | "process_madvise"
            | "pkey_mprotect"
            | "pkey_alloc"
            | "pkey_free"
            | "userfaultfd"
            | "memfd_secret"
            | "map_shadow_stack"
            | "mseal"
            | "membarrier" => Self::Memory,
            "pipe" | "pipe2" | "shmget" | "shmat" | "shmctl" | "shmdt" | "semget" | "semop"
            | "semctl" | "semtimedop" | "msgget" | "msgsnd" | "msgrcv" | "msgctl" | "mq_open"
            | "mq_unlink" | "mq_timedsend" | "mq_timedreceive" | "mq_notify" | "mq_getsetattr"
            | "futex" | "futex_waitv" | "futex_wake" | "futex_wait" | "futex_requeue"
            | "eventfd" | "eventfd2" | "memfd_create" => Self::Ipc,
            "rt_sigaction" | "rt_sigprocmask" | "rt_sigreturn" | "rt_sigpending"
            | "rt_sigtimedwait" | "rt_sigqueueinfo" | "rt_sigsuspend" | "rt_tgsigqueueinfo"
            | "sigaltstack" | "kill" | "tkill" | "tgkill" | "pause" | "signalfd" | "signalfd4"
            | "pidfd_send_signal" | "restart_syscall" => Self::Signal,
            "poll" | "select" | "pselect6" | "ppoll" | "epoll_create" | "epoll_create1"
            | "epoll_ctl" | "epoll_wait" | "epoll_pwait" | "epoll_pwait2" | "epoll_ctl_old"
            | "epoll_wait_old" | "io_setup" | "io_destroy" | "io_getevents" | "io_submit"
            | "io_cancel" | "io_pgetevents" | "io_uring_setup" | "io_uring_enter"
            | "io_uring_register" => Self::Polling,
            "setuid"
            | "setgid"
            | "setreuid"
            | "setregid"
            | "setresuid"
            | "setresgid"
            | "setfsuid"
            | "setfsgid"
            | "setgroups"
            | "capset"
            | "capget"
            | "seccomp"
            | "bpf"
            | "add_key"
            | "request_key"
            | "keyctl"
            | "landlock_create_ruleset"
            | "landlock_add_rule"
            | "landlock_restrict_self"
            | "lsm_get_self_attr"
            | "lsm_set_self_attr"
            | "lsm_list_modules" => Self::Security,
            "init_module" | "finit_module" | "delete_module" | "create_module"
            | "get_kernel_syms" | "query_module" | "kexec_load" | "kexec_file_load" | "reboot"
            | "syslog" | "perf_event_open" | "sethostname" | "setdomainname" | "iopl"
            | "ioperm" | "acct" | "_sysctl" | "nfsservctl" | "vhangup" | "swapon" | "swapoff"
            | "uselib" | "uretprobe" | "getpmsg" | "putpmsg" | "afs_syscall" | "tuxcall"
            | "security" | "vserver" => Self::System,
            "nanosleep"
            | "clock_nanosleep"
            | "getitimer"
            | "setitimer"
            | "alarm"
            | "gettimeofday"
            | "settimeofday"
            | "time"
            | "adjtimex"
            | "clock_adjtime"
            | "clock_settime"
            | "clock_gettime"
            | "clock_getres"
            | "timer_create"
            | "timer_settime"
            | "timer_gettime"
            | "timer_getoverrun"
            | "timer_delete"
            | "timerfd_create"
            | "timerfd_settime"
            | "timerfd_gettime"
            | "sched_yield"
            | "sched_setparam"
            | "sched_getparam"
            | "sched_setscheduler"
            | "sched_getscheduler"
            | "sched_get_priority_max"
            | "sched_get_priority_min"
            | "sched_rr_get_interval"
            | "sched_setaffinity"
            | "sched_getaffinity"
            | "sched_setattr"
            | "sched_getattr"
            | "getpriority"
            | "setpriority"
            | "ioprio_set"
            | "ioprio_get"
            | "getrandom" => Self::Time,
            "getpid" | "getppid" | "gettid" | "getpgrp" | "getpgid" | "getsid" | "getuid"
            | "getgid" | "geteuid" | "getegid" | "getgroups" | "getresuid" | "getresgid"
            | "uname" | "sysinfo" | "getrlimit" | "getrusage" | "times" | "getcpu" => Self::Info,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_native_syscall_has_one_group() {
        let table: serde_json::Value =
            serde_json::from_str(include_str!("../../../protocol/native-syscalls.json")).unwrap();
        let syscalls = table["syscalls"].as_array().unwrap();
        assert_eq!(syscalls.len(), 375);
        for syscall in syscalls {
            let name = syscall["name"].as_str().unwrap();
            assert!(SyscallGroup::of(name).is_some(), "{name} has no group");
        }
        assert_eq!(SyscallGroup::of("execve"), Some(SyscallGroup::Process));
        assert_eq!(SyscallGroup::of("openat"), Some(SyscallGroup::File));
        assert_eq!(SyscallGroup::of("connect"), Some(SyscallGroup::Network));
        assert_eq!(SyscallGroup::of("mprotect"), Some(SyscallGroup::Memory));
        assert_eq!(
            SyscallGroup::of("io_uring_enter"),
            Some(SyscallGroup::Polling)
        );
        assert_eq!(SyscallGroup::of("not_a_syscall"), None);
        let labels: std::collections::HashSet<_> = SyscallGroup::ALL
            .iter()
            .map(|group| group.label())
            .collect();
        assert_eq!(labels.len(), SyscallGroup::ALL.len());
    }
}
