// SPDX-License-Identifier: GPL-3.0-only
//! Copies of a run's program that run outside its recorded tree.
//!
//! Malware that persists (a cron entry, a systemd unit, an init script) has
//! its copy started by cron or systemd: a process outside the run's tree,
//! which the guest does not trace. Such a copy can end the recorded processes
//! (Mirai's `.e` kills the original) or keep running as a service after the
//! tree exited, and the run then ended "exited" while the malware was alive.
//!
//! The host follows such copies without a guest change:
//!
//! * Before the launch it lists the guest's processes (PROCESS_LIST): what
//!   runs then is not the run's.
//! * While the run goes on it lists them again every few seconds. A process
//!   that is not in that first list and not in the recorded tree (its task
//!   cookie never sent a packet of the run) is a candidate.
//! * A candidate's program is read through ACQUIRE of `/proc/<pid>/exe` (the
//!   guest kernel opens the executable the process runs, as static analysis
//!   does for the sample) and hashed on the host. It is a copy when its
//!   SHA-256 is the launched program's (the guest's hash of the run's own
//!   image) or that of a file the run wrote (the guest's hash at the last
//!   close of each written file). Nothing is guessed from names.
//! * When the guest says the tree ended, one last look is taken before the run
//!   reads as ended (it reads as held meanwhile, at most 30 s), so a copy
//!   started just before the end is found too.
//! * When the tree ends while a copy is alive the run is held open: its
//!   network capture and route go on until the copy exits, the run is
//!   stopped, the VM stops, or [`HOLD_MAX`] has passed. The copy's own system
//!   calls are not recorded (the guest traces only the launched tree).
//!
//! `run.json` keeps what was found (`persisted`), and Triage lists each copy
//! as a HIGH finding.
use crate::{kernel_notes, observation::GuestProcess};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// How often a run's guest processes are listed.
pub const POLL: Duration = Duration::from_secs(3);
/// The longest a run is held open after its tree ended.
pub const HOLD_MAX: Duration = Duration::from_secs(600);
/// Programs read per run at most (a fork storm outside the tree cannot keep
/// the control channel busy).
pub const CHECKS_PER_RUN: u32 = 64;
/// Distinct images a run remembers.
const KNOWN_MAX: usize = 64;
/// Processes a run remembers having looked at.
const LOOKED_MAX: usize = 4096;
/// Copies listed in `run.json`; more are counted.
pub const COPIES_MAX: usize = 16;

/// What a process outside the tree turned out to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyOf {
    /// The program the run launched (the sample), byte for byte.
    Sample,
    /// A file the run wrote, as it was when its last writer closed it.
    Written,
}

impl CopyOf {
    pub fn label(self) -> &'static str {
        match self {
            CopyOf::Sample => "a copy of the sample",
            CopyOf::Written => "a file the run wrote",
        }
    }
}

/// One process outside the recorded tree that runs the sample or a file the
/// run wrote.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistedCopy {
    pub pid: u32,
    /// Its command name (at most 15 characters, as the kernel keeps it).
    pub name: String,
    pub uid: u32,
    /// Its parent when it was found: who started it (systemd as pid 1, cron).
    pub parent_pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_name: Option<String>,
    pub copy_of: Option<CopyOf>,
    /// SHA-256 of its program, lowercase hex.
    pub sha256: String,
    pub size: u64,
    /// Guest boot clock of its start (from the process list).
    pub start_boot_ns: u64,
    /// Host Unix milliseconds when it was first and last seen alive.
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    /// A later process list no longer had it.
    pub ended: bool,
    /// Processes forked from it under the same name, not read again.
    pub children: u32,
}

impl PersistedCopy {
    /// `pid 1050 ".e"`.
    pub fn who(&self) -> String {
        if self.name.is_empty() {
            format!("pid {}", self.pid)
        } else {
            format!("pid {} \"{}\"", self.pid, self.name)
        }
    }

    /// "started by pid 1 \"systemd\"", or by the pid alone.
    pub fn started_by(&self) -> String {
        match &self.parent_name {
            Some(name) if !name.is_empty() => {
                format!("started by pid {} \"{name}\"", self.parent_pid)
            }
            _ if self.parent_pid != 0 => format!("started by pid {}", self.parent_pid),
            _ => "started by a process the guest did not name".into(),
        }
    }
}

/// What `run.json` keeps of the copies (`persisted`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistedCopies {
    pub copies: Vec<PersistedCopy>,
    /// Copies beyond [`COPIES_MAX`].
    pub more: u32,
    /// The run is held open: its tree ended while a copy was alive.
    pub holding: bool,
    /// Host Unix milliseconds when the hold began.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_started_ms: Option<u64>,
    /// Why the hold ended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_ended: Option<String>,
}

impl PersistedCopies {
    pub fn alive(&self) -> impl Iterator<Item = &PersistedCopy> {
        self.copies.iter().filter(|copy| !copy.ended)
    }

    /// The copy with this pid, if one was found.
    pub fn by_pid(&self, pid: u32) -> Option<&PersistedCopy> {
        self.copies.iter().find(|copy| copy.pid == pid)
    }
}

/// An image the run is known to have: its size and SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Known {
    sha256: [u8; 32],
    size: u64,
    of: CopyOf,
}

/// What the host learned about one process outside the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Looked {
    NotACopy,
    Copy,
    /// The guest could not read its program; tried again while checks last.
    Unreadable(u8),
}

/// A program outside the tree being read and hashed, a few chunks per turn of
/// the worker loop.
pub(crate) struct Reading {
    pub(crate) process: GuestProcess,
    pub(crate) parent_name: Option<String>,
    /// The guest's specimen handle.
    pub(crate) id: u64,
    pub(crate) size: u64,
    pub(crate) offset: u64,
    pub(crate) hasher: sha2::Sha256,
}

/// The last look for copies once the guest said the tree ended: a copy
/// started just before the end (a short-lived installer) is found before the
/// run is let end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum FinalLook {
    #[default]
    NotYet,
    /// Since when; the run reads as held open meanwhile.
    Pending(std::time::Instant),
    Done,
}

/// The live part of a run's watch; nothing of it is saved.
#[derive(Default)]
pub(crate) struct Watch {
    known: Vec<Known>,
    /// The launched program is the run's own (a library sample, not a shell
    /// a desktop run starts or the loader of a library).
    launched_is_sample: bool,
    /// Images the tree executed: a written file with one of these digests is
    /// a copy of a program the guest already had (BusyBox's `cp` copying
    /// busybox), not the run's.
    ran: HashSet<[u8; 32]>,
    /// `(tgid, task cookie)` of every process alive before the launch;
    /// `None` when the list could not be read (then nothing is followed).
    baseline: Option<HashSet<(u32, u64)>>,
    looked: HashMap<(u32, u64), Looked>,
    pub(crate) checks_left: u32,
    pub(crate) last_poll: Option<std::time::Instant>,
    /// Host time the tree was seen ended while a copy was alive.
    pub(crate) hold_since: Option<std::time::Instant>,
    /// The last look for copies after the tree's end.
    pub(crate) final_look: FinalLook,
    pub(crate) reading: Option<Reading>,
}

/// Unreadable attempts per process before it is left alone.
const UNREADABLE_TRIES: u8 = 3;

impl Watch {
    /// A watch that follows what was alive before the launch.
    pub(crate) fn with_baseline(
        processes: Option<&[GuestProcess]>,
        launched_is_sample: bool,
    ) -> Self {
        Self {
            launched_is_sample,
            baseline: processes.map(|list| {
                list.iter()
                    .map(|process| (process.identity.tgid, process.identity.task_cookie))
                    .collect()
            }),
            checks_left: CHECKS_PER_RUN,
            ..Self::default()
        }
    }

    /// Remember the images a hash record of the run names: the launched
    /// program's own (call 0) and every file it wrote. Other execs (`sh`,
    /// `cp`) are not images of the run's own, so they are not copies.
    pub(crate) fn learn(&mut self, call_id: u64, hash: &kernel_notes::FileHash) {
        if hash.status != kernel_notes::HashStatus::Ok || hash.changed || hash.size == 0 {
            return;
        }
        let Some(sha256) = hash.sha256 else {
            return;
        };
        let of = match hash.kind {
            kernel_notes::HashKind::Exec if call_id == 0 => {
                if !self.launched_is_sample || hash.interpreter {
                    return;
                }
                CopyOf::Sample
            }
            kernel_notes::HashKind::Exec => {
                if self.ran.len() < LOOKED_MAX {
                    self.ran.insert(sha256);
                }
                return;
            }
            kernel_notes::HashKind::Write if self.ran.contains(&sha256) => return,
            kernel_notes::HashKind::Write => CopyOf::Written,
            kernel_notes::HashKind::Delete => return,
        };
        if let Some(known) = self.known.iter_mut().find(|known| known.sha256 == sha256) {
            // The sample wins over a written copy of it.
            if of == CopyOf::Sample {
                known.of = of;
            }
            return;
        }
        if self.known.len() < KNOWN_MAX {
            self.known.push(Known {
                sha256,
                size: hash.size,
                of,
            });
        }
    }

    /// The watch has something to compare with and a list to compare against.
    pub(crate) fn armed(&self) -> bool {
        self.baseline.is_some() && !self.known.is_empty()
    }

    /// The largest image the run knows: a larger program is not read.
    pub(crate) fn max_size(&self) -> u64 {
        self.known.iter().map(|known| known.size).max().unwrap_or(0)
    }

    /// A program of this size could be one of the run's images.
    pub(crate) fn size_known(&self, size: u64) -> bool {
        self.known.iter().any(|known| known.size == size)
    }

    /// What a program with this digest is to the run.
    pub(crate) fn matches(&self, sha256: &[u8; 32], size: u64) -> Option<CopyOf> {
        self.known
            .iter()
            .find(|known| known.sha256 == *sha256 && known.size == size)
            .map(|known| known.of)
    }

    /// The processes worth reading, oldest first: alive now, not before the
    /// launch, not in the recorded tree, not looked at already.
    pub(crate) fn candidates<'a>(
        &self,
        processes: &'a [GuestProcess],
        tree: &HashSet<u64>,
    ) -> Vec<&'a GuestProcess> {
        let Some(baseline) = &self.baseline else {
            return Vec::new();
        };
        let mut found: Vec<&GuestProcess> = processes
            .iter()
            .filter(|process| {
                let key = (process.identity.tgid, process.identity.task_cookie);
                !baseline.contains(&key)
                    && !tree.contains(&process.identity.task_cookie)
                    && match self.looked.get(&key) {
                        None => true,
                        Some(Looked::Unreadable(tries)) => *tries < UNREADABLE_TRIES,
                        Some(_) => false,
                    }
            })
            .collect();
        found.sort_by_key(|process| process.identity.start_boot_ns);
        found
    }

    pub(crate) fn note(&mut self, process: &GuestProcess, looked: Looked) {
        let key = (process.identity.tgid, process.identity.task_cookie);
        let looked = match (looked, self.looked.get(&key)) {
            (Looked::Unreadable(_), Some(Looked::Unreadable(tries))) => {
                Looked::Unreadable(tries.saturating_add(1))
            }
            (Looked::Unreadable(_), _) => Looked::Unreadable(1),
            (other, _) => other,
        };
        if self.looked.len() < LOOKED_MAX || self.looked.contains_key(&key) {
            self.looked.insert(key, looked);
        }
    }
}

/// Fold one process list into the copies found so far: a copy no longer
/// listed has ended; a process forked from a copy under the copy's name
/// counts as that copy's child and is not read again. Returns the children
/// absorbed, so the caller does not read them.
pub(crate) fn refresh(
    copies: &mut PersistedCopies,
    watch: &mut Watch,
    processes: &[GuestProcess],
    now_ms: u64,
) -> usize {
    let mut absorbed = 0;
    for copy in copies.copies.iter_mut().filter(|copy| !copy.ended) {
        match processes
            .iter()
            .find(|process| process.identity.tgid == copy.pid)
        {
            Some(process) if process.identity.start_boot_ns == copy.start_boot_ns => {
                copy.last_seen_ms = now_ms;
            }
            _ => copy.ended = true,
        }
    }
    for process in processes {
        let key = (process.identity.tgid, process.identity.task_cookie);
        if watch.looked.contains_key(&key) {
            continue;
        }
        let parent = copies.copies.iter_mut().find(|copy| {
            !copy.ended && copy.pid == process.parent_tgid && copy.name == process.command
        });
        if let Some(parent) = parent {
            parent.children = parent.children.saturating_add(1);
            watch.note(process, Looked::Copy);
            absorbed += 1;
        }
    }
    absorbed
}

/// Record a process found to run a copy.
pub(crate) fn found(
    copies: &mut PersistedCopies,
    process: &GuestProcess,
    parent_name: Option<String>,
    (of, sha256, size): (CopyOf, &[u8; 32], u64),
    now_ms: u64,
) {
    if copies.copies.len() >= COPIES_MAX {
        copies.more = copies.more.saturating_add(1);
        return;
    }
    copies.copies.push(PersistedCopy {
        pid: process.identity.tgid,
        name: process.command.clone(),
        uid: process.uid,
        parent_pid: process.parent_tgid,
        parent_name,
        copy_of: Some(of),
        sha256: sha256.iter().map(|byte| format!("{byte:02x}")).collect(),
        size,
        start_boot_ns: process.identity.start_boot_ns,
        first_seen_ms: now_ms,
        last_seen_ms: now_ms,
        ended: false,
        children: 0,
    });
}

/// The run note said when a copy is found.
pub fn found_note(copy: &PersistedCopy) -> String {
    format!(
        "{} runs {} outside the recorded tree ({}, uid {}, SHA-256 {}). The guest does not trace it, so its calls are not in this recording.",
        copy.who(),
        copy.copy_of.unwrap_or(CopyOf::Sample).label(),
        copy.started_by(),
        copy.uid,
        copy.sha256
    )
}

/// The run note said when the hold begins.
pub fn hold_note(copies: &PersistedCopies) -> String {
    let names: Vec<String> = copies.alive().map(PersistedCopy::who).collect();
    format!(
        "The recorded tree ended while {} still ran outside it; the run is kept open (its network capture and route go on) until {} exits, the run is stopped or {} min have passed.",
        names.join(", "),
        if names.len() == 1 { "it" } else { "they" },
        HOLD_MAX.as_secs() / 60
    )
}

/// Whether the hold goes on, and if not why it ended.
pub fn hold_end(copies: &PersistedCopies, held_for: Duration) -> Option<&'static str> {
    if copies.alive().next().is_none() {
        Some("every copy outside the tree exited")
    } else if held_for >= HOLD_MAX {
        Some("the hold limit passed while a copy still ran; it may still run in the guest")
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
