// SPDX-License-Identifier: GPL-3.0-only
//! What the Process tree keeps of a task besides its image: the environment of
//! its last exec, the execs with their times, the credentials it ran with, its
//! working directory, how many calls it made and the signals it sent.
use super::*;
use antinomie_monitor_core::kernel_notes::{self, CredentialChange, Credentials};

/// Signals one task is remembered to have sent; the rest are not matched.
pub const SENT_LIMIT: usize = 32;
/// Credential records kept per task.
pub const CREDENTIAL_LIMIT: usize = 32;
/// Execs kept with their times per task (the tree's history keeps its own cap).
pub const EXEC_LIMIT: usize = 128;

/// The ids of a task at one moment, as the kernel recorded them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredStep {
    pub ns: u64,
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    pub change: CredentialChange,
}

#[derive(Clone, Default)]
pub struct ProcessRecord {
    /// The environment strings of the last exec that were captured whole.
    pub envp: Vec<String>,
    /// Each exec's image and when it ran.
    pub execs: Vec<(String, u64)>,
    /// The credentials the guest recorded, each change once.
    pub creds: Vec<CredStep>,
    /// Set by a `chdir` of this task to an absolute path.
    pub cwd: Option<String>,
    /// System calls the task made.
    pub calls: u64,
    /// `(target, signal)` of each kill, tkill or tgkill this task made.
    pub sent: Vec<(i64, u8)>,
    /// The process that sent the fatal signal, when a recorded call did.
    pub killed_by: Option<u32>,
}

impl ProcessRecord {
    /// Take what one call of this task shows.
    pub fn observe(&mut self, invocation: &InvocationSummary, event: &EventSummary) {
        self.calls += 1;
        for creds in invocation
            .kernel_notes
            .iter()
            .filter_map(kernel_notes::credentials)
        {
            self.credentials(event.timestamp_ns, &creds);
        }
        let succeeded = invocation
            .exit
            .as_ref()
            .and_then(|exit| exit.result)
            .is_none_or(|result| result >= 0);
        let args = findings::call_args(invocation);
        match (event.syscall_name.as_str(), args) {
            ("chdir", _) if succeeded => {
                let path = program_name(invocation.entry.as_ref(), invocation.exit.as_ref());
                if let Some(path) = path.filter(|path| path.starts_with('/')) {
                    self.cwd = Some(path);
                }
            }
            ("kill" | "tkill", Some(args)) if succeeded => {
                self.sent(i64::from(args[0] as u32 as i32), args[1]);
            }
            ("tgkill", Some(args)) if succeeded => {
                self.sent(i64::from(args[1] as u32 as i32), args[2]);
            }
            _ => {}
        }
    }

    pub fn sent(&mut self, target: i64, signal: u64) {
        if target > 0 && (1..=64).contains(&signal) && self.sent.len() < SENT_LIMIT {
            self.sent.push((target, signal as u8));
        }
    }

    pub fn credentials(&mut self, ns: u64, creds: &Credentials) {
        let step = CredStep {
            ns,
            uid: creds.uid,
            euid: creds.euid,
            gid: creds.gid,
            egid: creds.egid,
            change: creds.change,
        };
        let same = self.creds.last().is_some_and(|last| {
            (last.uid, last.euid, last.gid, last.egid) == (step.uid, step.euid, step.gid, step.egid)
        });
        if !same && self.creds.len() < CREDENTIAL_LIMIT {
            self.creds.push(step);
        }
    }

    /// A committed exec: its environment and image replace the old ones.
    pub fn exec(&mut self, image: Option<&str>, ns: u64, envp: Vec<String>) {
        self.envp = envp;
        if let Some(image) = image {
            if self.execs.len() < EXEC_LIMIT {
                self.execs.push((image.to_owned(), ns));
            }
        }
    }
}

/// The environment strings an exec call carried that were captured whole.
pub fn exec_envp(invocation: &InvocationSummary, name: &str) -> Vec<String> {
    let Some(argument) = syscalls::native().argument(name, "envp") else {
        return Vec::new();
    };
    let fields: Vec<_> = invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|event| &event.fields)
        .collect();
    let mut found = Vec::new();
    for index in 0..512 {
        let key = format!("arg{argument}.string[{index}]");
        let Some(field) = fields.iter().find(|field| field.key == key) else {
            break;
        };
        let bytes = trace::covered_preview(field);
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        found.push(String::from_utf8_lossy(&bytes[..end]).into_owned());
    }
    found
}

/// Who sent each task its fatal signal, from the kill calls the run recorded.
pub fn match_killers(nodes: &mut std::collections::BTreeMap<TaskKey, TaskNode>) {
    let mut sent: Vec<(u32, i64, u8)> = Vec::new();
    for (key, node) in nodes.iter() {
        for (target, signal) in &node.record.sent {
            sent.push((key.pid, *target, *signal));
        }
    }
    if sent.is_empty() {
        return;
    }
    for (key, node) in nodes.iter_mut() {
        let Some(signal) = node.end_signal else {
            continue;
        };
        let (pid, tid) = (key.pid, node.tid);
        node.record.killed_by = sent
            .iter()
            .find(|(sender, target, sig)| {
                *sig == signal
                    && *sender != pid
                    && (*target == i64::from(pid) || (tid != 0 && *target == i64::from(tid)))
            })
            .map(|(sender, _, _)| *sender);
    }
}
