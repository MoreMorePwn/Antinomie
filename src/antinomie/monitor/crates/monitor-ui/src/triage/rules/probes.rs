// SPDX-License-Identifier: GPL-3.0-only
//! Anti-analysis checks and what the guest answered.
//!
//! Every check a task makes to learn whether it runs in a VM, a container or
//! under a debugger is kept with the answer the guest gave, and the task's next
//! thirty seconds are summarised. Only checks that are system calls are seen:
//! `CPUID` and `RDTSC` run in the program itself and leave no trace here.
use super::super::file_category::Category as Op;
use super::super::*;
use super::ctx::{base, nr, proc_self, Ctx, Touch};
use super::noise::{Agg, Gaps};
use super::state::{State, Window};
use super::{Hit, Tier};
use std::collections::BTreeMap;

const NS: u64 = 1_000_000_000;
/// How long after the last check the task is watched.
const WATCH: u64 = 30 * NS;
/// An exit or a sleep this soon after a revealing answer looks like a reaction.
const REACTION: u64 = 5 * NS;
/// Anything longer than this is "a sleep" for the follow-up summary.
const SLEEP_NOTE: u64 = 5 * NS;
const PROBE_LIMIT: usize = 256;
const EVENT_LIMIT: usize = 512;
/// Time reads per second that make a timing loop.
const TIMING_READS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Class {
    Dmi,
    Cpu,
    Storage,
    Hypervisor,
    Mac,
    Uptime,
    Timing,
    Container,
    Debugger,
}

impl Class {
    fn label(self) -> &'static str {
        match self {
            Self::Dmi => "machine identity (DMI/SMBIOS)",
            Self::Cpu => "CPU",
            Self::Storage => "disk",
            Self::Hypervisor => "hypervisor devices",
            Self::Mac => "MAC address",
            Self::Uptime => "uptime",
            Self::Timing => "timing",
            Self::Container => "container",
            Self::Debugger => "debugger",
        }
    }

    /// What decides the answer, in the words of the Stealth profile window.
    fn decided_by(self) -> &'static str {
        match self {
            Self::Dmi => "Stealth profile › Machine identity (BIOS, system, board and chassis strings, serials, UUID).",
            Self::Cpu => "Stealth profile › CPU (hypervisor flag, KVM signature, model and brand).",
            Self::Storage => "Stealth profile › Devices (disk bus, model and serial).",
            Self::Hypervisor => "Stealth profile › Devices and CPU (VMware port, KVM signature, PCI devices). The root disk, SeaBIOS and the q35 layout stay visible (Still visible).",
            Self::Mac => "Stealth profile › Network card (model and MAC address).",
            Self::Uptime => "Not set by the profile: a freshly started guest shows minutes of uptime (Still visible).",
            Self::Timing => "Not set by the profile: VM-exit timing and the cost of traced calls are in Still visible.",
            Self::Container => "The guest is not a container, so a container check finds nothing.",
            Self::Debugger => "Antinomie's debugger uses no ptrace: TracerPid stays 0 and PTRACE_TRACEME succeeds unless something else traces the program.",
        }
    }

    /// Checks of these classes are listed under the debugger or container rows.
    fn row(self) -> &'static str {
        match self {
            Self::Debugger => "evasion.debugger_check",
            Self::Container => "evasion.container_check",
            _ => "evasion.sandbox_probe",
        }
    }
}

/// One check: what was looked at, and what came back.
pub(super) struct Probe {
    class: Class,
    what: String,
    via: &'static str,
    key: (u64, u64, u64),
    time: u64,
    answer: Option<String>,
    /// The answer would show a VM, a container or a debugger.
    shows: Option<bool>,
    count: u64,
    gaps: Gaps,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Event {
    Network,
    Write,
    Spawn,
    Sleep(u64),
    Exit,
}

#[derive(Default)]
pub(super) struct TaskProbes {
    pid: u32,
    tid: u32,
    items: Vec<Probe>,
    /// Descriptor → the check that waits for its first read.
    pending: BTreeMap<u64, usize>,
    network_before: u32,
    writes_before: u32,
    events: Vec<(u64, Event)>,
    last: u64,
    reads: Window<u64>,
    timing_done: bool,
}

#[derive(Default)]
pub(super) struct Probes {
    tasks: BTreeMap<u64, TaskProbes>,
    /// Tasks that called `PTRACE_TRACEME` and have not exec'd since.
    pub traceme: std::collections::BTreeSet<u64>,
    /// Tasks whose `PTRACE_TRACEME` was followed by an exec: a debugger's child.
    pub traced_exec: std::collections::BTreeSet<u64>,
}

/// What a path says to a check, if it is one.
fn classify(path: &str) -> Option<Class> {
    let p = path;
    if p.starts_with("/sys/class/dmi/id/")
        || p.starts_with("/sys/devices/virtual/dmi/id/")
        || p.starts_with("/sys/firmware/dmi/")
    {
        Some(Class::Dmi)
    } else if p == "/proc/cpuinfo" {
        Some(Class::Cpu)
    } else if p == "/proc/scsi/scsi"
        || (p.starts_with("/sys/block/") && (p.ends_with("/model") || p.ends_with("/vendor")))
        || p.starts_with("/sys/class/nvme/")
    {
        Some(Class::Storage)
    } else if p.starts_with("/sys/hypervisor")
        || p.starts_with("/proc/xen")
        || matches!(
            p,
            "/dev/vboxguest"
                | "/dev/vboxuser"
                | "/dev/vmci"
                | "/sys/firmware/qemu_fw_cfg"
                | "/proc/ioports"
                | "/proc/iomem"
                | "/proc/modules"
        )
        || p.starts_with("/sys/bus/virtio")
        || (p.starts_with("/sys/bus/pci/devices/")
            && matches!(base(p), "vendor" | "device" | "subsystem_vendor"))
        || p.starts_with("/sys/module/vbox")
        || p.starts_with("/sys/module/vmw")
        || p.starts_with("/sys/module/hv_")
        || p.starts_with("/sys/module/virtio")
        || p.starts_with("/sys/module/kvm")
        || p.ends_with("/current_clocksource")
        || p == "/proc/bus/input/devices"
        || p == "/sys/class/misc/vboxguest"
    {
        Some(Class::Hypervisor)
    } else if p.starts_with("/sys/class/net/") && p.ends_with("/address") {
        Some(Class::Mac)
    } else if p == "/proc/uptime" {
        Some(Class::Uptime)
    } else if matches!(
        p,
        "/.dockerenv"
            | "/run/.containerenv"
            | "/proc/1/cgroup"
            | "/proc/self/cgroup"
            | "/proc/1/sched"
    ) {
        Some(Class::Container)
    } else if p == "/proc/self/status" || p == "/proc/self/maps" {
        Some(Class::Debugger)
    } else {
        None
    }
}

const VM_WORDS: &[&str] = &[
    "qemu",
    "kvm",
    "virtualbox",
    "vbox",
    "vmware",
    "bochs",
    "xen",
    "hyper-v",
    "microsoft corporation",
    "parallels",
    "innotek",
    "seabios",
    "ovmf",
    "edk ii",
    "red hat",
    "bhyve",
    "virtual machine",
    "virtio",
    "standard pc",
    "vmw",
];

fn mentions_vm(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    VM_WORDS.iter().any(|word| lower.contains(word))
}

fn first_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let line = text.lines().next().unwrap_or("").trim().to_owned();
    shorten(&line, 90)
}

fn shorten(text: &str, limit: usize) -> String {
    let mut shown: String = text.chars().take(limit).collect();
    if text.chars().count() > limit {
        shown.push('…');
    }
    shown
}

/// What the bytes a check read say, and whether they would give a VM, container or debugger away.
fn judge(class: Class, path: &str, bytes: &[u8]) -> (String, Option<bool>) {
    let text = String::from_utf8_lossy(bytes);
    match class {
        Class::Dmi => {
            let value = first_line(bytes);
            let chassis = base(path) == "chassis_type" && matches!(value.as_str(), "1" | "2");
            (format!("\"{value}\""), Some(mentions_vm(&value) || chassis))
        }
        Class::Cpu => {
            let flags = text.lines().find(|line| line.starts_with("flags"));
            let model = text.lines().find(|line| line.starts_with("model name"));
            let hypervisor =
                flags.is_some_and(|line| line.split_whitespace().any(|flag| flag == "hypervisor"));
            let named = model.is_some_and(mentions_vm);
            let shown = model
                .map(|line| {
                    shorten(
                        line.split_once(':').map_or(line, |(_, rest)| rest).trim(),
                        60,
                    )
                })
                .unwrap_or_default();
            let model = if shown.is_empty() {
                String::new()
            } else {
                format!("model name \"{shown}\"; ")
            };
            let answer = if hypervisor {
                format!("{model}flags include hypervisor")
            } else {
                format!("{model}no hypervisor flag")
            };
            (answer, Some(hypervisor || named))
        }
        Class::Storage | Class::Hypervisor => {
            if base(path) == "vendor" || base(path) == "subsystem_vendor" {
                let id = text.trim().to_ascii_lowercase();
                let known = [
                    "0x1af4", "0x15ad", "0x80ee", "0x1234", "0x1b36", "0x5853", "0x1414",
                ]
                .contains(&id.as_str());
                return (format!("vendor {id}"), Some(known));
            }
            if base(path) == "current_clocksource" {
                let value = first_line(bytes);
                return (
                    format!("\"{value}\""),
                    Some(
                        value.contains("kvm") || value.contains("hyperv") || value.contains("xen"),
                    ),
                );
            }
            let value = first_line(bytes);
            (format!("\"{value}\""), Some(mentions_vm(&text)))
        }
        Class::Mac => {
            let value = first_line(bytes).to_ascii_lowercase();
            let vm = [
                "52:54:00", "08:00:27", "0a:00:27", "00:0c:29", "00:50:56", "00:05:69", "00:1c:14",
                "00:16:3e", "00:15:5d", "00:1c:42", "00:03:ff",
            ]
            .iter()
            .any(|prefix| value.starts_with(prefix));
            (value, Some(vm))
        }
        Class::Uptime => {
            let seconds: f64 = text
                .split_whitespace()
                .next()
                .and_then(|word| word.parse().ok())
                .unwrap_or(0.0);
            (format!("up {seconds:.0} s"), Some(seconds < 1800.0))
        }
        Class::Container => {
            let hit = ["docker", "kubepods", "containerd", "lxc", "podman", "crio"]
                .iter()
                .any(|word| text.contains(word));
            (first_line(bytes), Some(hit))
        }
        Class::Debugger => {
            if let Some(line) = text.lines().find(|line| line.starts_with("TracerPid:")) {
                let pid: u64 = line["TracerPid:".len()..].trim().parse().unwrap_or(0);
                (format!("TracerPid {pid}"), Some(pid != 0))
            } else {
                let tool = [
                    "frida",
                    "gum-js",
                    "libfaketime",
                    "strace",
                    "ltrace",
                    "gdb",
                    "valgrind",
                    "libasan",
                    "libgcov",
                ]
                .iter()
                .find(|word| text.contains(**word));
                (
                    tool.map_or("no instrumentation libraries".into(), |word| {
                        format!("maps name {word}")
                    }),
                    Some(tool.is_some()),
                )
            }
        }
        Class::Timing => (shorten(&text, 60), None),
    }
}

/// How an existence check came out.
fn existence(cx: &Ctx, class: Class) -> (String, Option<bool>) {
    let Some(ret) = cx.ret else {
        return ("no result recorded".into(), None);
    };
    if ret >= 0 {
        let shows = matches!(class, Class::Hypervisor | Class::Container);
        ("exists".into(), shows.then_some(true))
    } else {
        let name = crate::values::errno_name(ret.unsigned_abs()).unwrap_or("error");
        let shows = matches!(class, Class::Hypervisor | Class::Container).then_some(false);
        (format!("not available ({name})"), shows)
    }
}

impl TaskProbes {
    fn record(&mut self, probe: Probe) -> usize {
        if let Some(index) = self.items.iter().position(|old| {
            old.class == probe.class && old.what == probe.what && old.via == probe.via
        }) {
            let old = &mut self.items[index];
            old.count += 1;
            old.gaps.add(probe.time);
            if old.answer.is_none() {
                old.answer = probe.answer;
                old.shows = probe.shows;
            }
            return index;
        }
        self.last = self.last.max(probe.time);
        if self.items.len() >= PROBE_LIMIT {
            return self.items.len() - 1;
        }
        self.items.push(probe);
        self.items.len() - 1
    }
}

fn new_probe(cx: &Ctx, class: Class, what: &str, answer: Option<(String, Option<bool>)>) -> Probe {
    let (answer, shows) = answer.map_or((None, None), |(text, shows)| (Some(text), shows));
    let mut gaps = Gaps::default();
    gaps.add(cx.time());
    Probe {
        class,
        what: what.to_owned(),
        via: probe_via(cx.name),
        key: (cx.call.stream_id, cx.call.task_cookie, cx.call.call_id),
        time: cx.time(),
        answer,
        shows,
        count: 1,
        gaps,
    }
}

fn probe_via(name: &str) -> &'static str {
    match name {
        "open" | "openat" | "openat2" => "open",
        "stat" | "lstat" | "newfstatat" | "statx" | "fstat" => "stat",
        "access" | "faccessat" | "faccessat2" => "access",
        "read" | "pread64" | "readv" => "read",
        "readlink" | "readlinkat" => "readlink",
        "getdents64" => "list",
        "ptrace" => "ptrace",
        "prctl" => "prctl",
        "rt_sigaction" => "signal",
        "sysinfo" => "sysinfo",
        "ioctl" => "ioctl",
        _ => "call",
    }
}

fn task<'a>(st: &'a mut State, cx: &Ctx) -> &'a mut TaskProbes {
    let entry = st.probes.tasks.entry(cx.call.task_cookie).or_default();
    entry.pid = cx.event.pid;
    entry.tid = cx.event.tid;
    entry
}

/// A file the call opened, read or looked up may be a check.
pub(super) fn path(cx: &Ctx, st: &mut State, touch: &Touch, _out: &mut Vec<Hit>) {
    let own = proc_self(&touch.path, cx.event.pid);
    let Some(class) = classify(&own) else { return };
    let disk = |class: Class| {
        matches!(
            class,
            Class::Dmi | Class::Cpu | Class::Storage | Class::Mac | Class::Uptime | Class::Debugger
        )
    };
    match touch.op {
        Op::Probed => {
            let answer = existence(cx, class);
            task(st, cx).record(new_probe(cx, class, &own, Some(answer)));
        }
        Op::Opened if disk(class) || own.starts_with("/proc/") || own.starts_with("/sys/") => {
            if !cx.ok {
                let answer = existence(cx, class);
                task(st, cx).record(new_probe(cx, class, &own, Some(answer)));
                return;
            }
            let fd = cx.ret.unwrap_or(-1) as u64;
            let existence_only = matches!(class, Class::Container) || own.starts_with("/dev/");
            let answer = existence_only.then(|| existence(cx, class));
            let tp = task(st, cx);
            let index = tp.record(new_probe(cx, class, &own, answer));
            if !existence_only {
                tp.pending.insert(fd, index);
            }
        }
        Op::Opened => {
            let answer = existence(cx, class);
            task(st, cx).record(new_probe(cx, class, &own, Some(answer)));
        }
        Op::Read if cx.ok => {
            let fd = cx.args[0];
            let bytes = cx.payload(true);
            let tp = task(st, cx);
            let index = tp.pending.get(&fd).copied();
            let (text, shows) = judge(class, &own, &bytes);
            // Runtimes read their own memory map for stack bounds: only a map naming a tool is a check.
            if own == "/proc/self/maps" && shows != Some(true) {
                return;
            }
            match index {
                Some(index) => {
                    if let Some(probe) = tp.items.get_mut(index) {
                        if probe.answer.as_deref().is_none_or(|old| old == "exists") {
                            probe.answer = Some(text);
                            probe.shows = shows;
                        }
                    }
                }
                None => {
                    let mut probe = new_probe(cx, class, &own, Some((text, shows)));
                    probe.via = "read";
                    tp.record(probe);
                }
            }
        }
        _ => {}
    }
}

/// Calls that are checks without naming a file.
pub(super) fn call(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    match cx.nr {
        nr::PTRACE if cx.args[0] == 0 => {
            // PTRACE_TRACEME: -EPERM means something already traces this task.
            let traced = cx.ret == Some(-1);
            let answer = if cx.ok {
                "accepted: nothing else traces this task".to_owned()
            } else if traced {
                "refused (EPERM): the task is already traced".to_owned()
            } else {
                "no result recorded".into()
            };
            task(st, cx).record(new_probe(
                cx,
                Class::Debugger,
                "ptrace(PTRACE_TRACEME)",
                Some((answer, Some(traced))),
            ));
            st.probes.traceme.insert(cx.call.task_cookie);
            out.push(
                Hit::new(
                    "evasion.traceme",
                    "PTRACE_TRACEME",
                    "ptrace(PTRACE_TRACEME) on itself".into(),
                )
                .detail(if cx.ok {
                    "The call succeeded: no debugger was attached."
                } else {
                    "The call failed: a tracer was already attached."
                }),
            );
        }
        nr::PRCTL if cx.args[0] == 3 => {
            let answer = cx
                .ret
                .map(|ret| format!("dumpable {ret}"))
                .unwrap_or_else(|| "no result recorded".into());
            task(st, cx).record(new_probe(
                cx,
                Class::Debugger,
                "prctl(PR_GET_DUMPABLE)",
                Some((answer, None)),
            ));
        }
        13 if cx.args[0] == 5 && cx.args[1] != 0 => {
            // A SIGTRAP handler: a breakpoint would be caught by the program.
            let handler = cx.word(1, "", 0).unwrap_or(2);
            if handler > 1 {
                task(st, cx).record(new_probe(
                    cx,
                    Class::Debugger,
                    "SIGTRAP handler installed",
                    Some(("handler set".into(), None)),
                ));
            }
        }
        nr::SYSINFO if cx.ok => {
            let seconds = cx.word(0, "", 0).unwrap_or(u64::MAX);
            if seconds != u64::MAX {
                let answer = (format!("up {seconds} s"), Some(seconds < 1800));
                task(st, cx).record(new_probe(cx, Class::Uptime, "sysinfo", Some(answer)));
            }
        }
        // SIOCGIFHWADDR
        nr::IOCTL if cx.args[1] == 0x8927 => {
            let mac = cx
                .bytes(2, "")
                .and_then(|bytes| bytes.get(18..24))
                .map(|mac| {
                    mac.iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(":")
                });
            let answer = mac.map(|text| {
                let vm = judge(Class::Mac, "", text.as_bytes()).1;
                (text, vm)
            });
            task(st, cx).record(new_probe(cx, Class::Mac, "ioctl SIOCGIFHWADDR", answer));
        }
        // clock_gettime, gettimeofday, time, times
        228 | 96 | 201 | 100 => {
            let time = cx.time();
            let tp = task(st, cx);
            tp.reads.push(time, NS, time);
            if !tp.timing_done && tp.reads.len() >= TIMING_READS {
                tp.timing_done = true;
                let answer = format!("{} clock reads within one second", tp.reads.len());
                tp.record(new_probe(
                    cx,
                    Class::Timing,
                    "clock reads in a loop",
                    Some((answer, None)),
                ));
            }
        }
        _ => {}
    }
}

/// A program that runs a check for the task, such as `dmidecode` or `systemd-detect-virt`.
pub(super) fn tool(cx: &Ctx, st: &mut State, name: &str, text: &str) {
    let class = match name {
        "dmidecode" => Class::Dmi,
        "lscpu" => Class::Cpu,
        "systemd-detect-virt" | "virt-what" => Class::Hypervisor,
        _ => return,
    };
    let answer = (
        "run as a program; its output is not captured".to_owned(),
        None,
    );
    task(st, cx).record(new_probe(cx, class, text, Some(answer)));
}

/// The task wrote a file.
pub(super) fn note_write(cx: &Ctx, st: &mut State) {
    let tp = st.probes.tasks.entry(cx.call.task_cookie).or_default();
    if tp.items.is_empty() {
        tp.writes_before += 1;
    } else if tp.events.len() < EVENT_LIMIT {
        tp.events.push((cx.time(), Event::Write));
    }
}

/// Behaviour around the checks: network use, writes, new processes, sleeps and exit.
pub(super) fn behaviour(cx: &Ctx, st: &mut State) {
    let time = cx.time();
    let event = match cx.nr {
        nr::SOCKET
        | nr::CONNECT
        | nr::SENDTO
        | nr::SENDMSG
        | nr::BIND
        | nr::LISTEN
        | nr::ACCEPT => Some(Event::Network),
        nr::CLONE | 57 | 58 | nr::CLONE3 | nr::EXECVE | nr::EXECVEAT if cx.ok => Some(Event::Spawn),
        nr::NANOSLEEP | nr::CLOCK_NANOSLEEP => sleep_ns(cx).map(Event::Sleep),
        60 | 231 => Some(Event::Exit),
        _ if cx.call.task_exit.is_some() => Some(Event::Exit),
        _ => None,
    };
    if matches!(event, Some(Event::Network)) {
        let tp = st.probes.tasks.get_mut(&cx.call.task_cookie);
        match tp {
            Some(tp) if tp.items.is_empty() => tp.network_before += 1,
            Some(tp) => tp.events.push((time, Event::Network)),
            None => {
                let tp = task(st, cx);
                tp.network_before += 1;
            }
        }
        return;
    }
    if let Some(event) = event {
        if let Some(tp) = st.probes.tasks.get_mut(&cx.call.task_cookie) {
            if !tp.items.is_empty() && tp.events.len() < EVENT_LIMIT {
                tp.events.push((time, event));
            }
        }
    }
}

/// The requested sleep, in nanoseconds, of `nanosleep` and `clock_nanosleep`.
pub(super) fn sleep_ns(cx: &Ctx) -> Option<u64> {
    let argument = if cx.nr == nr::NANOSLEEP { 0 } else { 2 };
    let seconds = cx.word(argument, "", 0)?;
    let nanos = cx.word(argument, "", 8).unwrap_or(0);
    // An absolute sleep (TIMER_ABSTIME) is a time of day, not a length.
    if cx.nr == nr::CLOCK_NANOSLEEP && cx.args[1] & 1 != 0 {
        return None;
    }
    seconds.checked_mul(NS)?.checked_add(nanos)
}

/// One row per task and kind of check, with the follow-up and the verdict.
pub(super) fn rows(st: &State, files: &FdState) -> Vec<Agg> {
    let mut rows = Vec::new();
    for (cookie, tp) in &st.probes.tasks {
        if tp.items.is_empty() {
            continue;
        }
        let follow = follow_up(tp);
        // A debugger's child calls PTRACE_TRACEME right before its exec: not a check.
        let debugged = st.probes.traced_exec.contains(cookie);
        let mut kinds: BTreeMap<&'static str, Vec<&Probe>> = BTreeMap::new();
        for probe in tp
            .items
            .iter()
            .filter(|probe| !(debugged && probe.what == "ptrace(PTRACE_TRACEME)"))
        {
            kinds.entry(probe.class.row()).or_default().push(probe);
        }
        let node = files.process_images.get(&TaskKey {
            pid: tp.pid,
            cookie: *cookie,
        });
        let image = node
            .map(|node| node.comm.clone())
            .filter(|image| image != "?");
        let revealing = tp
            .items
            .iter()
            .any(|probe| probe.shows == Some(true) && probe.class.row() == "evasion.sandbox_probe");
        for (rule, probes) in kinds {
            rows.push(row(rule, *cookie, tp, &probes, &follow, image.as_deref()));
        }
        if let Some(reaction) = follow.reaction(revealing) {
            let first = tp
                .items
                .iter()
                .find(|probe| probe.shows == Some(true))
                .unwrap_or(&tp.items[0]);
            let mut agg = base_row(
                "evasion.probe_then_exit",
                *cookie,
                tp,
                first,
                image.as_deref(),
            );
            agg.summary = format!("{reaction} after a check that would show a VM");
            agg.detail = vec![
                format!("The answer that would show a VM: {} → {}", first.what, first.answer.as_deref().unwrap_or("?")),
                follow.describe(),
                "Heuristic: this reads only the calls recorded after the checks. It cannot know why the program stopped; a different Stealth profile may make it go on.".into(),
            ];
            rows.push(agg);
        }
    }
    rows
}

/// What the task did in the thirty seconds after its last check.
struct Follow {
    exited: Option<u64>,
    network: u32,
    writes: u32,
    spawned: u32,
    longest_sleep: u64,
    sleep_at: Option<u64>,
    network_before: u32,
    writes_before: u32,
    seconds_seen: bool,
}

impl Follow {
    fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(delta) = self.exited {
            parts.push(format!(
                "exited {:.1} s after the last check",
                delta as f64 / 1e9
            ));
        }
        if self.longest_sleep >= SLEEP_NOTE {
            parts.push(format!("slept {:.0} s", self.longest_sleep as f64 / 1e9));
        }
        if self.exited.is_none() {
            if self.network + self.writes + self.spawned == 0 {
                if self.network_before > 0 {
                    parts.push(format!(
                        "stopped making network calls ({} before the checks, none after)",
                        self.network_before
                    ));
                } else if self.writes_before > 0 {
                    parts.push(format!(
                        "stopped writing files ({} writes before the checks, none after)",
                        self.writes_before
                    ));
                } else {
                    parts.push("did no network, file or process work in the next 30 s".into());
                }
            } else {
                parts.push(format!(
                    "went on: {} network calls, {} file writes, {} new processes in the next 30 s",
                    self.network, self.writes, self.spawned
                ));
            }
        } else if self.network + self.writes > 0 {
            parts.push(format!(
                "{} network calls and {} file writes before exiting",
                self.network, self.writes
            ));
        }
        format!(
            "After the last check: {}. Heuristic, from the recorded calls only.",
            parts.join("; ")
        )
    }

    /// An exit or a long sleep right after a check that would show a VM, with no work done.
    fn reaction(&self, revealing: bool) -> Option<&'static str> {
        if !revealing || self.network + self.writes + self.spawned > 0 {
            return None;
        }
        if self.exited.is_some_and(|delta| delta <= REACTION) {
            return Some("The task exited within 5 s");
        }
        self.sleep_at
            .filter(|delta| *delta <= REACTION)
            .map(|_| "The task went to sleep within 5 s")
    }
}

fn follow_up(tp: &TaskProbes) -> Follow {
    let last = tp.last;
    let mut follow = Follow {
        exited: None,
        network: 0,
        writes: 0,
        spawned: 0,
        longest_sleep: 0,
        sleep_at: None,
        network_before: tp.network_before,
        writes_before: tp.writes_before,
        seconds_seen: false,
    };
    for (time, event) in &tp.events {
        if *time < last {
            continue;
        }
        let delta = time - last;
        match event {
            Event::Exit if follow.exited.is_none() => follow.exited = Some(delta),
            Event::Exit => {}
            _ if delta > WATCH => {}
            Event::Network => follow.network += 1,
            Event::Write => follow.writes += 1,
            Event::Spawn => follow.spawned += 1,
            Event::Sleep(length) => {
                if *length >= SLEEP_NOTE && *length > follow.longest_sleep {
                    follow.longest_sleep = *length;
                    follow.sleep_at.get_or_insert(delta);
                }
            }
        }
    }
    follow.seconds_seen = true;
    follow
}

fn base_row(
    rule: &'static str,
    cookie: u64,
    tp: &TaskProbes,
    first: &Probe,
    image: Option<&str>,
) -> Agg {
    let spec = super::spec(rule).expect("classified rule");
    Agg {
        rule,
        cookie,
        pid: tp.pid,
        tid: tp.tid,
        process: process_identity(tp.pid, tp.tid, image),
        image: image.map(str::to_owned),
        object: "checks".into(),
        summary: String::new(),
        attack: spec.attack,
        base: spec.tier,
        count: 1,
        failed: 0,
        allowed: 0,
        first_ns: first.time,
        last_ns: tp.last.max(first.time),
        stream: first.key.0,
        call_id: first.key.2,
        ret: None,
        high_confidence: true,
        outcome: "recorded".into(),
        evidence: format!("{} call {}", first.via, first.key.2),
        gaps: Gaps::default(),
        flags: 0,
        detail: Vec::new(),
        siblings: 0,
        samples: Vec::new(),
        packet: None,
        tier: spec.tier,
        why: Vec::new(),
    }
}

fn row(
    rule: &'static str,
    cookie: u64,
    tp: &TaskProbes,
    probes: &[&Probe],
    follow: &Follow,
    image: Option<&str>,
) -> Agg {
    let first = probes
        .iter()
        .min_by_key(|probe| probe.time)
        .copied()
        .unwrap_or(probes[0]);
    let mut agg = base_row(rule, cookie, tp, first, image);
    agg.count = probes.iter().map(|probe| probe.count).sum();
    agg.last_ns = probes
        .iter()
        .map(|probe| probe.time)
        .max()
        .unwrap_or(first.time);
    let mut classes: Vec<Class> = probes.iter().map(|probe| probe.class).collect();
    classes.sort();
    classes.dedup();
    let showing = probes
        .iter()
        .filter(|probe| probe.shows == Some(true))
        .count();
    let labels: Vec<_> = classes.iter().map(|class| class.label()).collect();
    agg.summary = format!(
        "{} check{} ({}); {} would show {}",
        probes.len(),
        if probes.len() == 1 { "" } else { "s" },
        labels.join(", "),
        showing,
        match rule {
            "evasion.debugger_check" => "a debugger",
            "evasion.container_check" => "a container",
            _ => "a VM",
        }
    );
    if rule == "evasion.sandbox_probe" {
        // One kind of check is INFO; reading several kinds of VM evidence is a check.
        agg.base = if classes.len() >= 2 {
            Tier::Medium
        } else {
            Tier::Info
        };
    }
    agg.detail
        .push("Checks and the answers the guest gave:".into());
    for probe in probes {
        let mut line = format!(
            "{}: {} [{}] → {}",
            probe.class.label(),
            probe.what,
            probe.via,
            probe.answer.as_deref().unwrap_or("no answer captured")
        );
        match probe.shows {
            Some(true) => line.push_str("  (would show it)"),
            Some(false) => line.push_str("  (does not show it)"),
            None => {}
        }
        if probe.count > 1 {
            line.push_str(&format!("  ×{}", probe.count));
            if let Some(period) = probe.gaps.period() {
                line.push_str(&format!(" every ~{}", super::noise::pace(period)));
            }
        }
        line.push_str(&format!("  (call {})", probe.key.2));
        agg.detail.push(line);
    }
    for class in &classes {
        agg.detail
            .push(format!("{}: {}", class.label(), class.decided_by()));
    }
    agg.detail.push(follow.describe());
    agg.detail.push(
        "Instruction-level checks (CPUID, RDTSC) run inside the program and are not visible here."
            .into(),
    );
    if rule == "evasion.sandbox_probe" {
        agg.detail
            .push("ATT&CK lists T1497 under both Stealth and Discovery.".into());
    }
    agg
}
