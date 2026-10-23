// SPDX-License-Identifier: GPL-3.0-only
//! Rules for process, memory, credential and kernel-facing system calls.
use super::super::*;
use super::ctx::{base, nr, Ctx};
use super::state::State;
use super::{Hit, Tier};
use antinomie_monitor_core::kernel_notes::{self, CredentialChange, Credentials};

const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const NS: u64 = 1_000_000_000;
const KILL_TARGETS: usize = 5;
const KILL_SPAN: u64 = 30 * NS;
const FORKS_PER_SECOND: usize = 200;
const FORK_FAILURES: u32 = 20;
const EAGAIN: i64 = -11;
/// `CAP_SYS_MODULE` and `CAP_SYS_ADMIN`.
const DANGEROUS_CAPS: u64 = (1 << 16) | (1 << 21);

pub(super) fn rules(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    match cx.nr {
        nr::MMAP | nr::MPROTECT | nr::PKEY_MPROTECT => memory(cx, st, out),
        nr::PTRACE => ptrace(cx, out),
        nr::PROCESS_VM_WRITEV | nr::PROCESS_VM_READV => vm(cx, out),
        nr::MEMFD_CREATE => {
            let name = cx.text(0).unwrap_or_default();
            out.push(Hit::new(
                "process.memfd",
                &name,
                format!("memfd_create \"{name}\""),
            ));
        }
        nr::INIT_MODULE | nr::FINIT_MODULE => {
            let image = if cx.nr == nr::FINIT_MODULE {
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
        nr::SECCOMP if cx.args[0] == 1 => seccomp(cx, out),
        nr::PRCTL => prctl(cx, out),
        nr::UNSHARE if cx.args[0] & CLONE_NEWUSER != 0 => user_namespace(cx, st, out),
        nr::SETNS => {
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
        nr::REBOOT => reboot(cx, out),
        nr::KEXEC_LOAD | nr::KEXEC_FILE_LOAD => {
            out.push(Hit::new(
                "impact.reboot",
                "kexec",
                format!("{} stages a replacement kernel", cx.name),
            ));
        }
        nr::SYSLOG if matches!(cx.args[0], 4 | 5) => {
            out.push(Hit::new(
                "evasion.log_clear",
                "kernel ring buffer",
                "syslog clears the kernel ring buffer".into(),
            ));
        }
        nr::KILL | nr::TKILL | nr::TGKILL | nr::PIDFD_SEND_SIGNAL => kill(cx, st, out),
        nr::PERSONALITY if cx.args[0] & 0x0004_0000 != 0 => {
            out.push(Hit::new(
                "evasion.sysctl_security",
                "ADDR_NO_RANDOMIZE",
                "personality(ADDR_NO_RANDOMIZE) turns off address randomisation".into(),
            ));
        }
        nr::IO_URING_SETUP | nr::IO_URING_ENTER => {
            out.push(Hit::new(
                "evasion.io_uring_usage",
                "io_uring",
                format!("{}: work through a ring makes few system calls", cx.name),
            ));
        }
        321 => {
            if let Some(command) = bpf::command_name(cx.event) {
                if matches!(
                    command,
                    "BPF_PROG_LOAD" | "BPF_PROG_ATTACH" | "BPF_PROG_DETACH"
                ) {
                    out.push(Hit::new("bpf.program", command, command.to_owned()));
                }
            }
        }
        nr::CLONE | 57 | 58 | nr::CLONE3 => forks(cx, st, out),
        nr::WRITE => dirty_pipe(cx, st, out),
        275 => splice(cx, st),
        _ => {}
    }
    credentials(cx, st, out);
}

/// `PROT_WRITE | PROT_EXEC`, and writable memory flipped to executable.
fn memory(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
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
    let anonymous = cx.nr != nr::MMAP || cx.args[3] & 0x20 != 0;
    let range = if cx.nr == nr::MMAP {
        (cx.ret.unwrap_or(0) as u64, cx.args[1])
    } else {
        (cx.args[0], cx.args[1])
    };
    let task = st.task(cx);
    if prot & PROT_WRITE != 0 && anonymous {
        if task.writable.len() < 4096 {
            task.writable.push(range);
        }
    } else if cx.nr == nr::MPROTECT && prot & PROT_EXEC != 0 {
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

fn ptrace(cx: &Ctx, out: &mut Vec<Hit>) {
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

fn parent_pid(cx: &Ctx) -> Option<u32> {
    cx.files
        .process_images
        .get(&TaskKey {
            pid: cx.event.pid,
            cookie: cx.call.task_cookie,
        })
        .and_then(|node| node.parent)
        .map(|parent| parent.pid)
}

fn vm(cx: &Ctx, out: &mut Vec<Hit>) {
    let pid = cx.args[0];
    if pid == u64::from(cx.event.pid) || pid == u64::from(cx.event.tid) {
        return;
    }
    let rule = if cx.nr == nr::PROCESS_VM_WRITEV {
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

fn seccomp(_cx: &Ctx, out: &mut Vec<Hit>) {
    out.push(Hit::new(
        "bpf.seccomp_filter",
        "seccomp",
        "classic seccomp filter installation".into(),
    ));
}

fn prctl(cx: &Ctx, out: &mut Vec<Hit>) {
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
            masquerade(&name, cx.image_name(), "prctl(PR_SET_NAME)", out);
        }
        _ => {}
    }
}

/// A process named after a kernel thread or a system daemon.
pub(super) fn masquerade(name: &str, image: &str, how: &str, out: &mut Vec<Hit>) {
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

fn user_namespace(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    st.userns.insert(cx.call.task_cookie);
    out.push(Hit::new(
        "privilege.userns",
        cx.name,
        format!("{} with CLONE_NEWUSER", cx.name),
    ));
}

fn reboot(cx: &Ctx, out: &mut Vec<Hit>) {
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
fn kill(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    let (target, signal) = match cx.nr {
        nr::KILL | nr::TKILL => (cx.args[0], cx.args[1]),
        nr::TGKILL => (cx.args[0], cx.args[2]),
        _ => (cx.args[0], cx.args[1]),
    };
    if !matches!(signal, 9 | 15) || target == 0 || (target as i64) < 0 {
        return;
    }
    let pid = target as u32;
    let ours = cx.files.process_images.keys().any(|task| task.pid == pid);
    if ours {
        return;
    }
    let time = cx.time();
    let task = st.task(cx);
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
fn forks(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    if cx.nr == nr::CLONE && cx.args[0] & 0x0001_0000 != 0 {
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
fn splice(cx: &Ctx, st: &mut State) {
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

fn dirty_pipe(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
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
fn credentials(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
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

fn describe(before: &Credentials, after: &Credentials) -> String {
    format!(
        "euid {} → {}; effective capabilities {:#x} → {:#x}",
        before.euid, after.euid, before.cap_effective, after.cap_effective
    )
}
