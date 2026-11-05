// SPDX-License-Identifier: GPL-3.0-only
//! Why a run's process tree ended, said in words.
//!
//! The recording keeps how each task ended (an exit code, or the fatal
//! signal). A revision-21 guest also records who sent the fatal signal: the
//! sending task (pid, uid, name), the kernel, or the kernel's out-of-memory
//! killer with the line it logged ([`FatalSignal`]); the text names it. For
//! a recording without that record (an older guest) what can be said is
//! limited to: the signals the recorded calls sent (`kill`, `tkill`, `tgkill`,
//! `pidfd_send_signal`), the parent-death signal a task asked for (`prctl`
//! `PR_SET_PDEATHSIG`), and whether the run was stopped from the app (the
//! run status carries STOP_REQUESTED and KILL_ESCALATED). A signal none of
//! these explains came from outside the recorded calls; the text says so and
//! marks what it infers.
use super::*;
use antinomie_monitor_core::fatal_signal::{self, FatalSignal};

/// Signal calls kept for the explanation; the rest are counted.
const SENT_LIMIT: usize = 512;
/// A tree that ended sooner than this was over before it could do much.
const SHORT_TREE_NS: u64 = 10_000_000_000;
/// `prctl` option that asks for a signal when the parent exits.
const PR_SET_PDEATHSIG: u64 = 1;
/// Run-status flags (`protocol/run-status.md`).
const STOP_REQUESTED: u64 = 4;
const KILL_ESCALATED: u64 = 32;
/// Tasks listed by name in a note.
const LISTED: usize = 4;

/// One recorded call that sent a signal.
struct SignalCall {
    time_ns: u64,
    sender: u32,
    call: &'static str,
    /// The pid (or tid) argument, and for `tgkill` the tid argument too.
    targets: [i64; 2],
    signal: u8,
}

/// What the scan saw of signals, for explaining how tasks ended.
#[derive(Default)]
pub(super) struct SignalNotes {
    sent: Vec<SignalCall>,
    omitted: u64,
    /// `(pid, signal)` of each `prctl(PR_SET_PDEATHSIG, signal)`.
    parent_death: Vec<(u32, u8)>,
    /// The run status flags from `run.json`; `None` for a run without them.
    pub(super) run_flags: Option<u64>,
}

impl SignalNotes {
    /// Remember `invocation` when it sends a signal or asks for a parent-death signal.
    pub(super) fn observe(&mut self, invocation: &InvocationSummary, event: &EventSummary) {
        let name = event.syscall_name.as_str();
        if !matches!(
            name,
            "kill" | "tkill" | "tgkill" | "pidfd_send_signal" | "prctl"
        ) {
            return;
        }
        let Some(args) = findings::call_args(invocation) else {
            return;
        };
        let pid = |value: u64| i64::from(value as u32 as i32);
        let (call, targets, signal) = match name {
            "kill" => ("kill", [pid(args[0]); 2], args[1]),
            "tkill" => ("tkill", [pid(args[0]); 2], args[1]),
            "tgkill" => ("tgkill", [pid(args[0]), pid(args[1])], args[2]),
            "pidfd_send_signal" => ("pidfd_send_signal", [-1; 2], args[1]),
            _ => {
                if args[0] == PR_SET_PDEATHSIG && (1..=64).contains(&args[1]) {
                    self.parent_death.push((event.pid, args[1] as u8));
                }
                return;
            }
        };
        if !(1..=64).contains(&signal) {
            return;
        }
        if invocation
            .exit
            .as_ref()
            .and_then(|exit| exit.result)
            .is_some_and(|result| result < 0)
        {
            return;
        }
        if self.sent.len() >= SENT_LIMIT {
            self.omitted += 1;
            return;
        }
        self.sent.push(SignalCall {
            time_ns: event.timestamp_ns,
            sender: event.pid,
            call,
            targets,
            signal: signal as u8,
        });
    }
}

/// The signal name as `kill -l` spells it; the number for the rare ones.
fn signal_name(signal: u8) -> String {
    match signal {
        1 => "SIGHUP".into(),
        2 => "SIGINT".into(),
        3 => "SIGQUIT".into(),
        4 => "SIGILL".into(),
        5 => "SIGTRAP".into(),
        6 => "SIGABRT".into(),
        7 => "SIGBUS".into(),
        8 => "SIGFPE".into(),
        9 => "SIGKILL".into(),
        10 => "SIGUSR1".into(),
        11 => "SIGSEGV".into(),
        12 => "SIGUSR2".into(),
        13 => "SIGPIPE".into(),
        14 => "SIGALRM".into(),
        15 => "SIGTERM".into(),
        24 => "SIGXCPU".into(),
        other => format!("signal {other}"),
    }
}

/// "pid 489 \"systemd\"": the name the task gave itself, else its program.
fn who(node: &ProcessNode) -> String {
    let name = node
        .renames
        .last()
        .cloned()
        .or_else(|| node.exec_history.last().cloned())
        .unwrap_or_else(|| node.comm.clone());
    let name = name.rsplit('/').next().unwrap_or_default();
    if name.is_empty() || name == "?" {
        format!("pid {}", node.pid)
    } else {
        format!("pid {} \"{name}\"", node.pid)
    }
}

fn millis(ns: u64) -> String {
    if ns < 1_000_000_000 {
        format!("{} ms", ns / 1_000_000)
    } else {
        format!("{:.1} s", ns as f64 / 1e9)
    }
}

/// What the end of the run says.
pub(super) struct RunEnd {
    pub(super) text: String,
    /// The whole tree ended within seconds (the report puts this note in its
    /// statement too).
    pub(super) short_tree: bool,
}

/// The note for a run whose tree ended at once, or whose tasks were killed by a signal.
pub(super) fn run_end(scan: &ArchiveScan) -> Option<RunEnd> {
    let tasks: Vec<_> = scan.process.iter().filter(|node| !node.thread).collect();
    if tasks.is_empty() || scan.root_crash.is_some() {
        return None;
    }
    let start = tasks.iter().filter_map(|node| node.first_ns).min()?;
    let short = short_tree(scan, &tasks, start);
    let killed = killed_text(scan, &tasks, start);
    match (short, killed) {
        (None, None) => None,
        (Some(text), None) => Some(RunEnd {
            text,
            short_tree: true,
        }),
        (Some(text), Some(killed)) => Some(RunEnd {
            text: format!("{text} {killed}"),
            short_tree: true,
        }),
        (None, Some(text)) => Some(RunEnd {
            text,
            short_tree: false,
        }),
    }
}

/// "The sample's process tree ended after 43 ms (2 processes). Last failing
/// step: ...": said when every process of the run exited within seconds, so a
/// reader knows the short report is the sample's own doing (a failed install
/// step, a check that told it to stop), not a lost recording.
fn short_tree(scan: &ArchiveScan, tasks: &[&ProcessNode], first: u64) -> Option<String> {
    if !tasks.iter().all(|node| node.state.starts_with("task exit")) {
        return None;
    }
    let last = tasks.iter().filter_map(|node| node.last_ns).max()?;
    let span = last.saturating_sub(first);
    if span >= SHORT_TREE_NS {
        return None;
    }
    let count = tasks.len();
    let mut note = format!(
        "The sample's process tree ended after {} ({count} process{}).",
        millis(span),
        if count == 1 { "" } else { "es" }
    );
    match &scan.last_failed_step {
        Some(step) => note.push_str(&format!(
            " Last failing step: {step}. If this is an install or setup step, the sample stopped because it failed."
        )),
        None => note.push_str(" No create, write or exec call was refused before it ended."),
    }
    Some(note)
}

/// Which tasks died of a signal and, as far as the recording knows, why.
fn killed_text(scan: &ArchiveScan, tasks: &[&ProcessNode], start: u64) -> Option<String> {
    // A process is killed when its first thread's exit says so, or when its other
    // threads' exits do (a group kill can leave the leader's own exit unrecorded).
    let ended: Vec<(&ProcessNode, u8, u64, Option<&FatalSignal>)> = tasks
        .iter()
        .copied()
        .filter_map(|node| {
            let group = || {
                scan.process
                    .iter()
                    .filter(|other| other.thread && other.pid == node.pid)
            };
            let signal = node
                .end_signal
                .or_else(|| group().find_map(|other| other.end_signal))?;
            let last = node
                .last_ns
                .into_iter()
                .chain(group().filter_map(|other| other.last_ns))
                .max()
                .unwrap_or(start);
            let record = node
                .end_sender
                .as_ref()
                .or_else(|| group().find_map(|other| other.end_sender.as_ref()))
                .filter(|record| record.signal == signal);
            Some((node, signal, last, record))
        })
        .collect();
    if ended.is_empty() {
        return None;
    }
    let killed: Vec<&ProcessNode> = ended.iter().map(|(node, ..)| *node).collect();
    let recorded_any = ended.iter().any(|(.., record)| record.is_some());
    let notes = &scan.signals;
    let stopped = notes
        .run_flags
        .is_some_and(|flags| flags & STOP_REQUESTED != 0);
    let escalated = notes
        .run_flags
        .is_some_and(|flags| flags & KILL_ESCALATED != 0);
    let mut names: Vec<String> = ended
        .iter()
        .map(|(_, signal, ..)| signal_name(*signal))
        .collect();
    names.sort();
    names.dedup();
    let count = tasks.len();
    let of = format!(
        "{} of {count} process{} ended on a signal ({})",
        killed.len(),
        if count == 1 { "" } else { "es" },
        names.join(", ")
    );
    if stopped
        && ended.iter().all(|(_, signal, _, record)| {
            matches!(signal, 9 | 15) && record.is_none_or(|record| record.from_kernel())
        })
    {
        return Some(format!(
            "{of}: a Stop was requested for this run, and the guest sends SIGTERM and, after the grace period, SIGKILL to every process still alive{}.",
            if escalated {
                " (it needed SIGKILL here)"
            } else {
                ""
            }
        ));
    }
    let mut listed = Vec::new();
    let mut unexplained = 0usize;
    for (node, signal, last, record) in &ended {
        let (node, signal) = (*node, *signal);
        let at = format!(" at +{}", millis(last.saturating_sub(start)));
        // The kernel sends a parent-death signal from the exiting parent's
        // context, so its record names the parent: the prctl says why.
        let parent_pid = node.parent.as_ref().map(|parent| parent.pid);
        let how = parent_exit(scan, notes, node, signal)
            .filter(|_| {
                record.is_none_or(|record| {
                    record
                        .sender
                        .as_ref()
                        .is_none_or(|sender| Some(sender.pid) == parent_pid)
                })
            })
            .or_else(|| {
                record.and_then(|record| recorded(&scan.process, notes, node, record, start))
            })
            .or_else(|| sender(notes, node, signal, start));
        if how.is_none() {
            unexplained += 1;
        }
        if listed.len() < LISTED {
            listed.push(format!(
                "{} by {}{at}{}",
                who(node),
                signal_name(signal),
                how.map_or_else(String::new, |how| format!(" ({how})"))
            ));
        }
    }
    let more = killed.len().saturating_sub(listed.len());
    let mut text = format!(
        "{of}: {}{}.",
        listed.join("; "),
        if more > 0 {
            format!("; {more} more")
        } else {
            String::new()
        }
    );
    if unexplained == 0 {
        return Some(text);
    }
    if stopped {
        text.push_str(
            " A Stop was requested for this run, which sends SIGTERM and then SIGKILL to what is still alive.",
        );
    } else if notes.run_flags.is_some() {
        text.push_str(" No Stop was requested for this run, so the app did not send it.");
    }
    text.push_str(if recorded_any {
        " No recorded kill, tkill, tgkill or pidfd_send_signal call names the unexplained ones, and the guest recorded no sender for them. Inference: the signal came from outside the recorded calls (the guest kernel, for example a resource limit; a timer the program armed; or a process outside the recorded tree)."
    } else {
        " No recorded kill, tkill, tgkill or pidfd_send_signal call names the unexplained ones, and the recording does not carry who sent a signal (a guest before revision 21). Inference: the signal came from outside the recorded calls (the guest kernel, for example its out-of-memory killer or a resource limit; a timer the program armed; or a process outside the recorded tree)."
    });
    if tasks
        .iter()
        .any(|node| node.argv.iter().any(|arg| arg.contains("@reboot")))
    {
        text.push_str(
            " The tree wrote an @reboot cron entry for itself. When a run starts before the guest's cron is up (a VM still booting, slow on a busy host), cron's start runs that entry as a second copy outside the recorded tree, and a program that keeps one instance alive ends the first. The guest journal shows it as \"CRON ... CMD (<path>)\" a moment before the signal.",
        );
    }
    if notes.omitted > 0 {
        text.push_str(&format!(
            " {} signal calls beyond the first {SENT_LIMIT} were not examined.",
            notes.omitted
        ));
    }
    Some(text)
}

/// What the guest's record says of the signal that ended `node`: the
/// out-of-memory killer with its log line, the kernel, or the sending task
/// (named, and whether it is in the recorded tree). A recorded call by the
/// same sender says more (the call and its time), so it is preferred.
fn recorded(
    process: &[ProcessNode],
    notes: &SignalNotes,
    node: &ProcessNode,
    record: &FatalSignal,
    start: u64,
) -> Option<String> {
    if record.oom {
        return Some(match &record.kernel_log {
            Some(line) => format!("the guest kernel's out-of-memory killer: \"{line}\""),
            None => "the guest kernel's out-of-memory killer".into(),
        });
    }
    if let Some(sender) = &record.sender {
        if sender.pid == node.pid {
            return Some(format!(
                "sent by the process itself ({}), by a call of its own or the kernel's signal for one, such as SIGPIPE",
                record.code_name()
            ));
        }
        if let Some(call) =
            sender_call(notes, node, record.signal).filter(|call| call.sender == sender.pid)
        {
            return Some(format!(
                "sent by pid {} with {} at +{}",
                call.sender,
                call.call,
                millis(call.time_ns.saturating_sub(start))
            ));
        }
        let traced = process
            .iter()
            .find(|other| !other.thread && other.pid == sender.pid);
        let name = if sender.comm.is_empty() {
            format!("pid {}", sender.pid)
        } else {
            format!("pid {} \"{}\"", sender.pid, sender.comm)
        };
        return Some(format!(
            "sent by {name} (uid {}, {}; {})",
            sender.uid,
            if traced.is_some() {
                "in the recorded tree"
            } else {
                "a process outside the recorded tree"
            },
            record.code_name()
        ));
    }
    if let Some(fault) = record.fault() {
        return Some(format!(
            "raised by the guest kernel for the task's own action: {fault}"
        ));
    }
    if record.from_kernel() {
        return Some(
            "sent by the guest kernel (SI_KERNEL: a resource limit, a Stop of the run or another kernel action)".into(),
        );
    }
    if record.code == fatal_signal::SI_TIMER {
        return Some("a timer the program armed (SI_TIMER)".into());
    }
    (record.pid != 0).then(|| {
        format!(
            "sent by pid {} (uid {}, {}, as the task saw it)",
            record.pid,
            record.uid,
            record.code_name()
        )
    })
}

/// The recorded call that sent `signal` to `node`: "sent by pid 12 with kill at +40 ms".
fn sender(notes: &SignalNotes, node: &ProcessNode, signal: u8, start: u64) -> Option<String> {
    let call = sender_call(notes, node, signal)?;
    Some(format!(
        "sent by pid {} with {} at +{}",
        call.sender,
        call.call,
        millis(call.time_ns.saturating_sub(start))
    ))
}

/// A task that asked for the signal when its parent exits, whose parent had exited.
fn parent_exit(
    scan: &ArchiveScan,
    notes: &SignalNotes,
    node: &ProcessNode,
    signal: u8,
) -> Option<String> {
    if !notes.parent_death.contains(&(node.pid, signal)) {
        return None;
    }
    let key = node.parent.as_ref()?;
    let parent = scan
        .process
        .iter()
        .find(|other| !other.thread && other.pid == key.pid && other.cookie == key.cookie)?;
    let (parent_end, own_end) = (parent.last_ns?, node.last_ns?);
    (parent.state.starts_with("task exit") && parent_end <= own_end).then(|| {
        format!(
            "it had asked for {} when its parent exits (prctl PR_SET_PDEATHSIG) and pid {} had exited",
            signal_name(signal),
            parent.pid
        )
    })
}

/// The first recorded call that sent `signal` to `node`.
fn sender_call<'a>(
    notes: &'a SignalNotes,
    node: &ProcessNode,
    signal: u8,
) -> Option<&'a SignalCall> {
    notes.sent.iter().find(|call| {
        call.signal == signal
            && call.targets.iter().any(|target| {
                *target > 0 && (*target == i64::from(node.pid) || *target == i64::from(node.tid))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::fatal_signal::SignalSender;

    fn process(pid: u32, comm: &str) -> ProcessNode {
        ProcessNode {
            parent: None,
            call_id: None,
            depth: 0,
            pid,
            cookie: u64::from(pid),
            comm: comm.into(),
            parent_missing: false,
            tid: pid,
            argv: Vec::new(),
            first_ns: Some(0),
            last_ns: Some(1),
            state: "task exit, killed by SIGKILL".into(),
            end_signal: Some(9),
            end_sender: None,
            exec_history: Vec::new(),
            thread: false,
            renames: Vec::new(),
            in_call: None,
            forked: false,
        }
    }

    fn killed_by(sender: Option<SignalSender>, code: i32) -> FatalSignal {
        FatalSignal {
            signal: 9,
            code,
            pid: sender.as_ref().map_or(0, |sender| sender.pid as i32),
            uid: 0,
            at_send: true,
            sender,
            oom: false,
            kernel_log: None,
        }
    }

    #[test]
    fn a_sender_outside_the_recorded_tree_is_named() {
        let tree = [process(986, "sshd")];
        let record = killed_by(
            Some(SignalSender {
                pid: 1203,
                uid: 0,
                comm: "redtail".into(),
            }),
            fatal_signal::SI_USER,
        );
        let text = recorded(&tree, &SignalNotes::default(), &tree[0], &record, 0).unwrap();
        assert_eq!(
            text,
            "sent by pid 1203 \"redtail\" (uid 0, a process outside the recorded tree; SI_USER)"
        );
    }

    #[test]
    fn a_recorded_call_by_the_same_sender_gives_the_call_and_time() {
        let tree = [process(986, "sshd"), process(990, "killer")];
        let mut notes = SignalNotes::default();
        notes.sent.push(SignalCall {
            time_ns: 40_000_000,
            sender: 990,
            call: "kill",
            targets: [986; 2],
            signal: 9,
        });
        let record = killed_by(
            Some(SignalSender {
                pid: 990,
                uid: 0,
                comm: "killer".into(),
            }),
            fatal_signal::SI_USER,
        );
        let text = recorded(&tree, &notes, &tree[0], &record, 0).unwrap();
        assert_eq!(text, "sent by pid 990 with kill at +40 ms");
    }

    #[test]
    fn the_oom_killer_and_the_kernel_are_said_as_such() {
        let tree = [process(77, "hog")];
        let mut record = killed_by(None, fatal_signal::SI_KERNEL);
        record.oom = true;
        record.kernel_log = Some("Out of memory: Killed process 77 (hog)".into());
        let notes = SignalNotes::default();
        assert_eq!(
            recorded(&tree, &notes, &tree[0], &record, 0).unwrap(),
            "the guest kernel's out-of-memory killer: \"Out of memory: Killed process 77 (hog)\""
        );
        record.oom = false;
        record.kernel_log = None;
        assert!(recorded(&tree, &notes, &tree[0], &record, 0)
            .unwrap()
            .starts_with("sent by the guest kernel (SI_KERNEL"));
        let mut fault = killed_by(None, 1);
        fault.signal = 11;
        fault.at_send = false;
        assert_eq!(
            recorded(&tree, &notes, &tree[0], &fault, 0).unwrap(),
            "raised by the guest kernel for the task's own action: SEGV_MAPERR, an access to unmapped memory"
        );
    }
}
