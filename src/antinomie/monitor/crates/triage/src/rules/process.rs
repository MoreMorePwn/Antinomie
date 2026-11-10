// SPDX-License-Identifier: GPL-3.0-only
//! Rules for process, memory, credential and kernel-facing system calls.
use super::super::bpf_attach as attach;
use super::super::*;
use super::ctx::{base, Ctx};
use super::state::State;
use super::{Hit, Tier};
use antinomie_monitor_core::kernel_notes::{self, CredentialChange, Credentials};

pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const NS: u64 = 1_000_000_000;
pub const KILL_TARGETS: usize = 5;
pub const KILL_SPAN: u64 = 30 * NS;
/// Different processes SIGKILLed after their `/proc` files were read.
pub const KILLER_VICTIMS: usize = 3;
/// Programs that reap and stop their own services: not a killer.
const INIT_SYSTEMS: &[&str] = &["init", "systemd", "tini", "dumb-init", "runit", "s6-svscan"];
pub const FORKS_PER_SECOND: usize = 200;
pub const FORK_FAILURES: u32 = 20;
pub const EAGAIN: i64 = -11;
/// `CAP_SYS_MODULE` and `CAP_SYS_ADMIN`.
pub const DANGEROUS_CAPS: u64 = (1 << 16) | (1 << 21);

pub fn rules(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    match cx.name {
        "mmap" | "mprotect" | "pkey_mprotect" => memory(cx, st, out),
        "ptrace" => ptrace(cx, out),
        "process_vm_writev" | "process_vm_readv" => vm(cx, out),
        "memfd_create" => {
            let name = cx.text(0).unwrap_or_default();
            out.push(Hit::new(
                "process.memfd",
                &name,
                format!("memfd_create \"{name}\""),
            ));
        }
        "init_module" | "finit_module" => {
            let image = if cx.name == "finit_module" {
                cx.fd_path(cx.args[0]).unwrap_or("a descriptor").to_owned()
            } else {
                "an image in memory".into()
            };
            out.push(Hit::new(
                "persistence.module",
                &image,
                format!("{} loads a kernel module from {image}", cx.name),
            ));
        }
        "seccomp" if cx.args[0] == 1 => seccomp(cx, out),
        "prctl" => prctl(cx, out),
        "unshare" if cx.args[0] & CLONE_NEWUSER != 0 => user_namespace(cx, st, out),
        "setns" => {
            if cx
                .fd_path(cx.args[0])
                .is_some_and(|path| path.starts_with("/proc/1/ns/"))
            {
                out.push(Hit::new(
                    "privilege.container_escape",
                    "/proc/1/ns",
                    "setns into the namespaces of process 1".into(),
                ));
            }
        }
        "reboot" => reboot(cx, out),
        "kexec_load" | "kexec_file_load" => {
            out.push(Hit::new(
                "impact.reboot",
                "kexec",
                format!("{} stages a replacement kernel", cx.name),
            ));
        }
        "syslog" if matches!(cx.args[0], 4 | 5) => {
            out.push(Hit::new(
                "evasion.log_clear",
                "kernel ring buffer",
                "syslog clears the kernel ring buffer".into(),
            ));
        }
        "kill" | "tkill" | "tgkill" | "pidfd_send_signal" => kill(cx, st, out),
        "personality" if cx.args[0] & 0x0004_0000 != 0 => {
            out.push(Hit::new(
                "evasion.sysctl_security",
                "ADDR_NO_RANDOMIZE",
                "personality(ADDR_NO_RANDOMIZE) turns off address randomisation".into(),
            ));
        }
        "io_uring_setup" | "io_uring_enter" => {
            out.push(Hit::new(
                "evasion.io_uring_usage",
                "io_uring",
                format!("{}: work through a ring makes few system calls", cx.name),
            ));
        }
        "bpf" | "ioctl" => {
            bpf_program(cx, st, out);
            network_ioctl(cx, out);
        }
        "sendto" => netlink_query(cx, out),
        "uname"
            if cx.ok
                && !matches!(cx.image_name(), "uname")
                && !cx.image_name().starts_with("ld-") =>
        {
            out.push(
                Hit::new(
                    "discovery.system_info",
                    "OS and kernel",
                    "uname asks for the kernel name, release and machine".into(),
                )
                .detail("uname"),
            );
        }
        "clone" | "fork" | "vfork" | "clone3" => forks(cx, st, out),
        "write" => {
            dirty_pipe(cx, st, out);
            comm_write(cx, out);
        }
        "pwrite64" => comm_write(cx, out),
        "splice" => splice(cx, st),
        _ => {}
    }
    credentials(cx, st, out);
}

/// A program loaded or attached through `bpf`, a link, a raw tracepoint or a perf event.
pub fn bpf_program(cx: &Ctx, st: &State, out: &mut Vec<Hit>) {
    if let Some(command) = attach::command_of(cx.event, cx.args) {
        let attach = attach::attach(cx.call, command, cx.args, &st.bpf);
        // A failed attach changed nothing: it is Info, and apart from a success.
        let (tier, object) = if cx.failed {
            (Tier::Info, format!("{command} {} (failed)", attach.kind))
        } else {
            (attach.tier, format!("{command} {}", attach.kind))
        };
        out.push(
            Hit::new("bpf.program", object, attach.lifecycle(cx.ret))
                .tier(tier)
                .detail(format!("{command}: {}", attach.program()))
                .detail(format!("Target: {}", attach.target)),
        );
        return;
    }
    if let Some(command) = bpf::command_name(cx.event) {
        if matches!(
            command,
            "BPF_PROG_LOAD" | "BPF_PROG_ATTACH" | "BPF_PROG_DETACH"
        ) {
            out.push(Hit::new("bpf.program", command, command.to_owned()));
        }
    }
}

/// `PROT_WRITE | PROT_EXEC`, and writable memory flipped to executable.
pub fn memory(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    let prot = cx.args[2];
    let rule = if cx.ok {
        "memory.rwx"
    } else {
        "memory.rwx_attempt"
    };
    if prot & (PROT_WRITE | PROT_EXEC) == (PROT_WRITE | PROT_EXEC) {
        out.push(Hit::new(
            rule,
            cx.name,
            format!("{} with prot {prot:#x}", cx.name),
        ));
        return;
    }
    if !cx.ok {
        return;
    }
    let anonymous = cx.name != "mmap" || cx.args[3] & 0x20 != 0;
    let range = if cx.name == "mmap" {
        (cx.ret.unwrap_or(0) as u64, cx.args[1])
    } else {
        (cx.args[0], cx.args[1])
    };
    let task = st.task(cx);
    if prot & PROT_WRITE != 0 && anonymous {
        if task.writable.len() < 4096 {
            task.writable.push(range);
        }
    } else if cx.name == "mprotect" && prot & PROT_EXEC != 0 {
        let (start, length) = range;
        let end = start.saturating_add(length);
        if task
            .writable
            .iter()
            .any(|(from, size)| *from < end && start < from.saturating_add(*size))
        {
            out.push(Hit::new(
                "memory.wx_transition",
                "mprotect",
                format!("mprotect makes memory executable that this task mapped writable (at {start:#x})"),
            ));
        }
    }
}

pub fn ptrace(cx: &Ctx, out: &mut Vec<Hit>) {
    let request = cx.args[0];
    let pid = cx.args[1];
    let others = pid != u64::from(cx.event.pid) && pid != u64::from(cx.event.tid);
    let (rule, class) = match request {
        0 => return,
        16 | 0x4206 if others => ("injection.ptrace_attach", "attach"),
        4 | 5 | 6 | 13 | 15 | 0x4205 => ("injection.ptrace_poke", "poke"),
        _ => ("process.ptrace", "other"),
    };
    let object = format!("pid {pid} {class}");
    out.push(Hit::new(
        rule,
        &object,
        format!("ptrace request {request} on pid {pid}"),
    ));
    if matches!(request, 16 | 0x4206) && others && parent_pid(cx) == Some(pid as u32) {
        out.push(Hit::new(
            "evasion.traceme",
            "parent",
            "ptrace attaches to the task's own parent".into(),
        ));
    }
}

pub fn parent_pid(cx: &Ctx) -> Option<u32> {
    cx.files
        .process_images
        .get(&TaskKey {
            pid: cx.event.pid,
            cookie: cx.call.task_cookie,
        })
        .and_then(|node| node.parent)
        .map(|parent| parent.pid)
}

pub fn vm(cx: &Ctx, out: &mut Vec<Hit>) {
    let pid = cx.args[0];
    if pid == u64::from(cx.event.pid) || pid == u64::from(cx.event.tid) {
        return;
    }
    let rule = if cx.name == "process_vm_writev" {
        "injection.vm_write"
    } else {
        "credential.proc_mem_read"
    };
    out.push(Hit::new(
        rule,
        format!("pid {pid}"),
        format!("{} on pid {pid}", cx.name),
    ));
}

pub fn seccomp(_cx: &Ctx, out: &mut Vec<Hit>) {
    out.push(Hit::new(
        "bpf.seccomp_filter",
        "seccomp",
        "classic seccomp filter installation".into(),
    ));
}

pub fn prctl(cx: &Ctx, out: &mut Vec<Hit>) {
    match cx.args[0] {
        22 if cx.args[1] == 2 => seccomp(cx, out),
        4 if cx.args[1] == 0 => {
            out.push(Hit::new(
                "evasion.dumpable_off",
                "dumpable",
                "prctl(PR_SET_DUMPABLE, 0): the process cannot be attached to or dumped".into(),
            ));
        }
        15 => {
            let name = cx.text(1).unwrap_or_default();
            let before = out.len();
            masquerade(&name, cx.image_name(), "prctl(PR_SET_NAME)", out);
            if cx.ok {
                renamed(cx, &name, "prctl(PR_SET_NAME)", out.len() > before, out);
            }
        }
        _ => {}
    }
}

/// BusyBox's shell runs NOFORK and NOEXEC applets inside itself and sets `comm`
/// to the applet's name. That is the new name being an applet that the process,
/// a BusyBox binary or a shell, was asked to run in its own command line. A
/// rename to another name, or in a process that never asked for the applet,
/// is still a rename.
fn busybox_applet(cx: &Ctx, name: &str) -> bool {
    if !crate::process_cells::is_applet(name) {
        return false;
    }
    let image = crate::process_cells::family(cx.image_name());
    let busybox = image == "busybox"
        || cx
            .files
            .process_images
            .get(&TaskKey {
                pid: cx.event.pid,
                cookie: cx.call.task_cookie,
            })
            .is_some_and(|node| {
                node.exec_history
                    .iter()
                    .any(|path| crate::process_cells::file_name(path) == "busybox")
            });
    if busybox {
        return true;
    }
    image == "sh"
        && cx
            .files
            .process_images
            .get(&TaskKey {
                pid: cx.event.pid,
                cookie: cx.call.task_cookie,
            })
            .is_some_and(|node| {
                node.argv.iter().skip(1).any(|word| {
                    word.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
                        .any(|part| part == name)
                })
            })
}

/// The process gave itself a new name: `prctl(PR_SET_NAME)` or a write to its
/// `comm` file. LOW; MEDIUM when the name imitates a kernel thread or a daemon.
/// An empty `name` is a name the recording did not capture.
pub fn renamed(cx: &Ctx, name: &str, how: &str, imitates: bool, out: &mut Vec<Hit>) {
    let shown = if name.is_empty() {
        "new name not recorded".to_owned()
    } else {
        format!("{name:?}")
    };
    if !imitates && busybox_applet(cx, name) {
        return;
    }
    let mut hit = Hit::new(
        "evasion.process_rename",
        if name.is_empty() {
            "(not recorded)"
        } else {
            name
        },
        format!("{how} renames {} to {shown}", cx.image_name()),
    )
    .detail(format!("Program: {}", cx.image_name()));
    if imitates {
        hit = hit
            .tier(Tier::Medium)
            .detail("The new name imitates a kernel thread or a system daemon: MEDIUM. The same call is also listed under its own rule.");
    }
    out.push(hit);
}

/// A write to the task's own `comm` file renames it; one to `attr/` changes
/// its security label.
pub fn comm_write(cx: &Ctx, out: &mut Vec<Hit>) {
    if !cx.ok {
        return;
    }
    let Some(path) = cx.fd_path(cx.args[0]) else {
        return;
    };
    let path = super::ctx::proc_self(path, cx.event.pid);
    if path == "/proc/self/comm"
        || (path.starts_with("/proc/self/task/") && path.ends_with("/comm"))
    {
        let data = cx.payload(false);
        let name = String::from_utf8_lossy(&data);
        let name = name.trim_end_matches(['\n', '\0']).to_owned();
        let before = out.len();
        masquerade(&name, cx.image_name(), "write to comm", out);
        renamed(
            cx,
            &name,
            "a write to /proc/self/comm",
            out.len() > before,
            out,
        );
    } else if path.starts_with("/proc/self/attr/") {
        out.push(
            Hit::new(
                "evasion.process_rename",
                path.clone(),
                format!("a write to {path} changes the process's security attributes"),
            )
            .detail(format!("Program: {}", cx.image_name())),
        );
    }
}

/// `ioctl` calls that list the machine's interfaces, addresses and hardware address.
pub fn network_ioctl(cx: &Ctx, out: &mut Vec<Hit>) {
    let what = match cx.args[1] {
        0x8912 => "SIOCGIFCONF: the list of interfaces",
        0x8913 => "SIOCGIFFLAGS: an interface's flags",
        0x8915 => "SIOCGIFADDR: an interface's address",
        0x8919 => "SIOCGIFBRDADDR: an interface's broadcast address",
        0x891b => "SIOCGIFNETMASK: an interface's netmask",
        0x8927 => "SIOCGIFHWADDR: an interface's hardware address",
        0x8933 => "SIOCGIFINDEX: an interface's index",
        _ => return,
    };
    if cx.ok {
        out.push(
            Hit::new(
                "discovery.network_config",
                "network configuration",
                format!("ioctl {what}"),
            )
            .detail(format!("ioctl {what}")),
        );
    }
}

/// A route-socket request for the machine's links, addresses or routes
/// (`RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`), as `ip` and `getifaddrs` ask.
pub fn netlink_query(cx: &Ctx, out: &mut Vec<Hit>) {
    const AF_NETLINK: u64 = 16;
    if !cx.ok
        || cx
            .socket(cx.args[0])
            .is_none_or(|socket| socket.domain != AF_NETLINK)
    {
        return;
    }
    let Some(kind) = cx
        .bytes(1, "")
        .and_then(|bytes| bytes.get(4..6))
        .map(|kind| u16::from_le_bytes([kind[0], kind[1]]))
    else {
        return;
    };
    let what = match kind {
        18 => "RTM_GETLINK: the interfaces",
        22 => "RTM_GETADDR: the addresses",
        26 => "RTM_GETROUTE: the routes",
        _ => return,
    };
    out.push(
        Hit::new(
            "discovery.network_config",
            "network configuration",
            format!("netlink {what}"),
        )
        .detail(format!("netlink {what}")),
    );
}

/// A process named after a kernel thread or a system daemon.
pub fn masquerade(name: &str, image: &str, how: &str, out: &mut Vec<Hit>) {
    if name.is_empty() {
        return;
    }
    const THREADS: &[&str] = &[
        "kworker",
        "ksoftirqd",
        "kthreadd",
        "migration",
        "bioset",
        "watchdog",
        "rcu_",
        "kswapd",
        "jbd2",
        "kdevtmpfs",
        "khugepaged",
        "irq/",
        "kblockd",
        "ata_sff",
        "scsi_eh",
        "md/",
        "crypto",
        "kcompactd",
    ];
    const DAEMONS: &[&str] = &[
        "sshd",
        "systemd-journald",
        "dbus-daemon",
        "crond",
        "cron",
        "udevd",
        "systemd-udevd",
        "agetty",
        "rsyslogd",
        "auditd",
        "NetworkManager",
        "dhclient",
        "ntpd",
        "chronyd",
        "snapd",
        "containerd",
        "dockerd",
        "systemd",
        "init",
    ];
    let bare = name.trim_matches(|c| c == '[' || c == ']');
    let kthread = name.starts_with('[') || THREADS.iter().any(|prefix| bare.starts_with(prefix));
    if kthread {
        out.push(Hit::new(
            "evasion.masquerade_kthread",
            name,
            format!("{how} names a user process {name:?}, like a kernel thread"),
        ));
    } else if DAEMONS.contains(&base(name)) && base(name) != image {
        out.push(Hit::new(
            "evasion.masquerade_daemon",
            name,
            format!("{how} names the process {name:?} but it runs {image:?}"),
        ));
    }
}

pub fn user_namespace(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    st.userns.insert(cx.call.task_cookie);
    out.push(Hit::new(
        "privilege.userns",
        cx.name,
        format!("{} with CLONE_NEWUSER", cx.name),
    ));
}

pub fn reboot(cx: &Ctx, out: &mut Vec<Hit>) {
    let command = cx.args[2] as u32;
    let what = match command {
        0x0123_4567 => "RESTART",
        0xCDEF_0123 => "HALT",
        0x4321_FEDC => "POWER_OFF",
        0xA1B2_C3D4 => "RESTART2",
        0x4558_4543 => "KEXEC",
        _ => return,
    };
    out.push(Hit::new("impact.reboot", what, format!("reboot({what})")));
}

/// Many signals to processes that are not the run's own.
pub fn kill(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    // The process, thread group or descriptor the signal goes to, by role.
    let target = match cx.name {
        "tgkill" => cx.arg("tgid"),
        "pidfd_send_signal" => cx.arg("pidfd"),
        _ => cx.arg("pid"),
    };
    let signal = cx.arg("sig");
    if !matches!(signal, 9 | 15) || target == 0 || (target as i64) < 0 {
        return;
    }
    let pid = target as u32;
    let ours = cx.files.process_images.keys().any(|task| task.pid == pid);
    if ours {
        return;
    }
    let time = cx.time();
    let image = cx.image_name();
    let task = st.task(cx);
    // Mirai-style killer: scan /proc, then SIGKILL what was found.
    if signal == 9
        && task.proc_pids.contains(&pid)
        && !INIT_SYSTEMS.contains(&image)
        && task.killed_read.insert(pid)
        && task.killed_read.len() >= KILLER_VICTIMS
        && !task.killer_done
    {
        task.killer_done = true;
        let victims: Vec<String> = task.killed_read.iter().map(u32::to_string).collect();
        out.push(
            Hit::new(
                "evasion.process_killer",
                "kill",
                format!(
                    "SIGKILL sent to {} processes whose /proc entries it had read (pids {})",
                    victims.len(),
                    victims.join(", ")
                ),
            )
            .detail("The task listed processes under /proc and then killed them, the way a bot removes rival malware and security tools."),
        );
    }
    task.kills.push(time, KILL_SPAN, pid);
    if task.kills.distinct() >= KILL_TARGETS && !task.kill_done {
        task.kill_done = true;
        out.push(Hit::new(
            "evasion.kill_list",
            "kill",
            format!(
                "signal {signal} sent to {} processes the run did not start",
                task.kills.distinct()
            ),
        ));
    }
}

/// Process creation rate, and fork failures.
pub fn forks(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    if cx.name == "clone" && cx.arg("clone_flags") & 0x0001_0000 != 0 {
        return;
    }
    let time = cx.time();
    let failed = cx.ret == Some(EAGAIN);
    let task = st.task(cx);
    if failed {
        task.fork_failures += 1;
    }
    task.forks.push(time, NS, time);
    if !task.fork_done
        && (task.forks.len() > FORKS_PER_SECOND || task.fork_failures >= FORK_FAILURES)
    {
        task.fork_done = true;
        out.push(Hit::new(
            "impact.fork_bomb",
            "forks",
            format!(
                "{} process creations within a second, {} refused (EAGAIN)",
                task.forks.len(),
                task.fork_failures
            ),
        ));
    }
}

/// `splice` of a file into a pipe, remembered for a following write to the pipe.
pub fn splice(cx: &Ctx, st: &mut State) {
    let Some(path) = cx.fd_path(cx.args[0]).map(str::to_owned) else {
        return;
    };
    let classes = file_location::classify(&path, &[]);
    let guarded = classes.iter().any(|class| {
        matches!(
            class,
            file_location::Location::System
                | file_location::Location::Credentials
                | file_location::Location::Persistence
        )
    });
    if guarded && cx.ok {
        let pipe = cx.args[2];
        let task = st.task(cx);
        if task.spliced.len() < 64 {
            task.spliced.insert(pipe, path);
        }
    }
}

pub fn dirty_pipe(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    let fd = cx.args[0];
    let task = st.task(cx);
    if let Some(path) = task.spliced.remove(&fd) {
        out.push(
            Hit::new(
                "privilege.dirty_pipe",
                &path,
                format!("write into a pipe that was just fed with {path}"),
            )
            .detail(
                "The CVE-2022-0847 pattern: a splice of a file, then a write into the same pipe.",
            ),
        );
    }
}

/// Credential records: gains, drops, setuid programs and root without a legitimate path.
pub fn credentials(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    for creds in cx
        .call
        .kernel_notes
        .iter()
        .filter_map(kernel_notes::credentials)
    {
        let cookie = cx.call.task_cookie;
        let previous = st.creds.insert(cookie, creds);
        let Some(previous) = previous else { continue };
        let namespaced = st.userns.contains(&cookie);
        let root = creds.euid == 0 && previous.euid != 0;
        let added = creds.cap_effective & !previous.cap_effective;
        let gained = root || (!namespaced && added != 0);
        let lost = (previous.euid == 0 && creds.euid != 0)
            || (previous.cap_effective & !creds.cap_effective != 0 && added == 0);
        let detail = describe(&previous, &creds);
        match creds.change {
            CredentialChange::ExecSetId | CredentialChange::ExecCaps => {
                let image = cx.exec_path().unwrap_or_default();
                let classes = file_location::classify(&image, &[]);
                let risky = classes.contains(&file_location::Location::Temp)
                    || classes.contains(&file_location::Location::Hidden)
                    || st.written.contains(&image);
                let mut hit = Hit::new(
                    "privilege.setuid_exec",
                    &image,
                    format!("{image} runs with raised rights"),
                )
                .detail(detail.clone());
                if risky {
                    hit = hit.tier(Tier::Medium).detail("The program is in a staging or hidden directory, or the run wrote it: MEDIUM.");
                }
                out.push(hit);
                if gained {
                    out.push(
                        Hit::new(
                            "privilege.gain",
                            "exec",
                            format!("rights gained by running {image}"),
                        )
                        .detail(detail),
                    );
                }
            }
            CredentialChange::SetUid
            | CredentialChange::SetRes
            | CredentialChange::CapSet
            | CredentialChange::Prctl => {
                if gained {
                    out.push(
                        Hit::new(
                            "privilege.gain",
                            cx.name,
                            format!("{} raises the task's rights", cx.name),
                        )
                        .detail(detail),
                    );
                } else if lost {
                    out.push(
                        Hit::new(
                            "privilege.drop",
                            cx.name,
                            format!("{} gives up rights", cx.name),
                        )
                        .detail(detail),
                    );
                }
            }
            CredentialChange::Other => {
                let dangerous = root || (!namespaced && added & DANGEROUS_CAPS != 0);
                if dangerous {
                    out.push(
                        Hit::new(
                            "privilege.kernel_exploit",
                            cx.name,
                            format!("the kernel gave this task root during {}, which is not a credential call", cx.name),
                        )
                        .detail(detail)
                        .detail("A credentials record with the reason Other: commit_creds ran inside a call that does not change credentials."),
                    );
                }
            }
            _ => {}
        }
    }
}

pub fn describe(before: &Credentials, after: &Credentials) -> String {
    format!(
        "euid {} → {}; effective capabilities {:#x} → {:#x}",
        before.euid, after.euid, before.cap_effective, after.cap_effective
    )
}
