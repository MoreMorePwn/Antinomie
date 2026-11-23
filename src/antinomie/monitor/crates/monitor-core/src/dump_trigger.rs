// SPDX-License-Identifier: GPL-3.0-only
//! Dump on suspicious activity: a run can ask for a memory dump, a process
//! core, or both, the moment a Triage rule of a chosen tier matches while the
//! program is still running.
//!
//! The rules live in the UI crate (`triage::rules`); there is no second list
//! here. The UI registers a [`LiveJudge`] factory at start, and the recorder
//! feeds each run that asked for a trigger the calls it has just finished
//! assembling, one by one, as they arrive. The judge is the same rule engine
//! the saved-recording index uses, run incrementally, so a finding appears as
//! soon as the call that causes it has been received (a few milliseconds
//! after it; entries without an exit, such as a successful `execve`, wait at
//! most [`ENTRY_GRACE`]). The worker then takes the dump on its next turn.
//!
//! Only rules that read one call, or follow one task across calls, can fire
//! live. Rules that need the whole run (the packed-image check, the DNS
//! generation rule over many names, anything read from the network capture or
//! from the file index after the run) fire only in the index, never here.
//!
//! The plan bounds what a trigger may do: at most `max_cores` cores and
//! `max_memory_dumps` memory dumps per run, no two triggers closer than
//! `cooldown_secs`, and a failed dump is recorded and not retried.
use crate::api::{EventSummary, InvocationSummary, pair_events};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// How long a call's entry waits for its exit before it is judged alone.
const ENTRY_GRACE: Duration = Duration::from_millis(250);
/// Entries held while they wait for an exit.
const PENDING_MAX: usize = 4096;
/// Findings waiting for the worker.
const QUEUE_MAX: usize = 64;
/// The trigger records one run keeps.
pub const RECORDS_MAX: usize = 32;
/// How long a process the guest holds at its exit (contract revision 22) is
/// kept for a match that may still arrive before it is let go: calls of one
/// process can reach the host through more than one ring.
pub(crate) const HOLD_GRACE: Duration = Duration::from_millis(15);
/// How long a match at an exec call waits for the new program's first call
/// before its core is asked for anyway (a failed exec never makes one).
pub(crate) const EXEC_WAIT: Duration = Duration::from_millis(1500);
/// The note of a run whose base cannot hold a process at its exit.
pub const NO_EXIT_HOLD: &str = "Dump trigger: this base cannot hold a process at its exit (that needs a base of guest contract revision 22), so a process that exits within milliseconds of a match ends before its core can be taken.";

/// How unusual a match must be to trigger: the Triage tiers, lowest first.
/// (Triage has no tier above High.)
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TriggerTier {
    Low,
    Medium,
    #[default]
    High,
}

impl TriggerTier {
    pub const ALL: [TriggerTier; 3] = [Self::Low, Self::Medium, Self::High];
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
        }
    }

    /// The tier spelled `low`, `medium` or `high` in any case.
    pub fn from_name(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|tier| tier.label().eq_ignore_ascii_case(text.trim()))
    }
}

/// What a run does when suspicious activity is seen. Part of the run plan
/// (`ExecRequest`), so `run.json` records what was asked.
///
/// The core and the memory dump each have their own count. A plan saved
/// before they were separate has one `max_dumps`, which reads as the count of
/// both; a plan is still written with `max_dumps` (the larger count) so an
/// older release reads a count it knows.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(from = "TriggerWire", into = "TriggerWire")]
pub struct DumpTrigger {
    /// Triggers at this tier and above.
    pub min_tier: TriggerTier,
    /// Take the VM's memory (QEMU `dump-guest-memory`).
    pub memory: bool,
    /// Take a core of the process that made the call. Its budget and
    /// deadline are the run's `core_max_size` and `core_timeout_ms`.
    pub core: bool,
    /// Cores the trigger may take during this run.
    pub max_cores: u32,
    /// Memory dumps the trigger may take during this run.
    pub max_memory_dumps: u32,
    /// Quiet time after a trigger during which another is only counted.
    pub cooldown_secs: u32,
    /// A memory dump is skipped when the VM has more RAM than this, MiB.
    pub memory_max_mib: u32,
}

/// [`DumpTrigger`] as `run.json` holds it, old and new counts alike.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct TriggerWire {
    min_tier: TriggerTier,
    memory: bool,
    core: bool,
    /// The one count of a plan saved before the counts were separate.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_dumps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_cores: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_memory_dumps: Option<u32>,
    cooldown_secs: u32,
    memory_max_mib: u32,
}

impl Default for TriggerWire {
    /// A field that is absent reads as the default plan's; the counts stay
    /// unset so an old plan's `max_dumps` can stand for both.
    fn default() -> Self {
        Self {
            max_dumps: None,
            max_cores: None,
            max_memory_dumps: None,
            ..TriggerWire::from(DumpTrigger::default())
        }
    }
}

impl From<DumpTrigger> for TriggerWire {
    fn from(plan: DumpTrigger) -> Self {
        Self {
            min_tier: plan.min_tier,
            memory: plan.memory,
            core: plan.core,
            max_dumps: Some(plan.max_cores.max(plan.max_memory_dumps)),
            max_cores: Some(plan.max_cores),
            max_memory_dumps: Some(plan.max_memory_dumps),
            cooldown_secs: plan.cooldown_secs,
            memory_max_mib: plan.memory_max_mib,
        }
    }
}

impl From<TriggerWire> for DumpTrigger {
    fn from(wire: TriggerWire) -> Self {
        // An old plan's one count is the count of both.
        let both = wire.max_dumps.unwrap_or(1);
        Self {
            min_tier: wire.min_tier,
            memory: wire.memory,
            core: wire.core,
            max_cores: wire.max_cores.unwrap_or(both),
            max_memory_dumps: wire.max_memory_dumps.unwrap_or(both),
            cooldown_secs: wire.cooldown_secs,
            memory_max_mib: wire.memory_max_mib,
        }
    }
}

impl Default for DumpTrigger {
    fn default() -> Self {
        Self {
            min_tier: TriggerTier::High,
            memory: false,
            core: true,
            max_cores: 1,
            max_memory_dumps: 1,
            cooldown_secs: 30,
            memory_max_mib: 4096,
        }
    }
}

impl DumpTrigger {
    pub const MAX_DUMPS: u32 = 8;
    pub fn validate(&self) -> Result<(), String> {
        if !self.memory && !self.core {
            return Err("a dump trigger needs a memory dump, a core, or both".into());
        }
        for (what, count) in [
            ("cores", self.max_cores),
            ("memory dumps", self.max_memory_dumps),
        ] {
            if !(1..=Self::MAX_DUMPS).contains(&count) {
                return Err(format!(
                    "a dump trigger takes 1 to {} {what} per run",
                    Self::MAX_DUMPS
                ));
            }
        }
        if self.cooldown_secs > 3600 {
            return Err("the dump trigger cooldown is at most one hour".into());
        }
        Ok(())
    }

    /// What the next match may still take, given what `log` holds: a core
    /// while fewer than `max_cores` were taken, a memory dump while fewer
    /// than `max_memory_dumps` were. `(core, memory)`.
    pub fn room(&self, log: &TriggerLog) -> (bool, bool) {
        let limit = |count: u32| count.min(RECORDS_MAX as u32) as usize;
        let cores = log.records.iter().filter(|r| r.core_counts()).count();
        let memory = log.records.iter().filter(|r| r.memory.is_some()).count();
        (
            self.core && cores < limit(self.max_cores),
            self.memory && memory < limit(self.max_memory_dumps),
        )
    }
}

/// One match of a rule, as the judge reports it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveFinding {
    pub rule: String,
    pub summary: String,
    pub tier: TriggerTier,
    pub pid: u32,
    pub tid: u32,
    pub task_cookie: u64,
    pub stream_id: u64,
    pub call_id: u64,
    pub guest_ns: u64,
    pub syscall: String,
}

/// The words for a dump that came after its process was gone; `exit_ns` is
/// when the process exited on the guest clock, if it was seen.
pub fn too_late_text(finding: &LiveFinding, exit_ns: Option<u64>) -> String {
    match exit_ns {
        Some(exit) => format!(
            "The process exited {} ms after the match, before the core could be taken.",
            exit.saturating_sub(finding.guest_ns) / 1_000_000
        ),
        None => {
            "The process had already exited when the core was requested, before it could be taken."
                .into()
        }
    }
}

#[cfg(test)]
mod late_tests {
    use super::*;

    fn finding(pid: u32, guest_ns: u64) -> LiveFinding {
        LiveFinding {
            rule: "persistence.cron".into(),
            summary: String::new(),
            tier: TriggerTier::High,
            pid,
            tid: pid,
            task_cookie: 1,
            stream_id: 1,
            call_id: 1,
            guest_ns,
            syscall: "openat".into(),
        }
    }

    #[test]
    fn a_late_dump_says_how_late() {
        let found = finding(7, 5_000_000_000);
        assert_eq!(
            too_late_text(&found, Some(5_189_000_000)),
            "The process exited 189 ms after the match, before the core could be taken."
        );
        assert!(too_late_text(&found, None).contains("had already exited"));
        // An exit stamped before the match never reads as negative.
        assert!(too_late_text(&found, Some(1)).contains("exited 0 ms after"));
    }
}

/// The Triage rule engine, fed one call at a time. Implemented by the UI.
pub trait LiveJudge: Send {
    /// Judge one call; returns the rows that are new, or that a repeat raised
    /// to a higher tier.
    fn judge(&mut self, call: &InvocationSummary) -> Vec<LiveFinding>;
    /// The `persistence.*` rows judged since the last call, with the path
    /// each names and whether all its calls failed, whatever their tier
    /// (starting what a run persisted, ANT-T0608). A judge without them has
    /// none.
    fn written(&mut self) -> Vec<crate::persist_start::Written> {
        Vec::new()
    }
}

pub type JudgeFactory = fn() -> Box<dyn LiveJudge>;
static FACTORY: OnceLock<JudgeFactory> = OnceLock::new();

/// Register the rule engine; the first call wins.
pub fn set_judge(factory: JudgeFactory) {
    let _ = FACTORY.set(factory);
}

/// True when no rule engine was registered.
pub(crate) fn judge_missing() -> bool {
    FACTORY.get().is_none()
}

/// True once a rule engine was registered (by the UI at start, or by the
/// service's run lane before a launch that asks for a dump trigger).
pub fn judge_registered() -> bool {
    !judge_missing()
}

/// What became of one dump of a trigger.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TriggerDump {
    pub state: crate::api::RunArtifactState,
    /// The memory dump folder, or the core's folder.
    pub path: Option<PathBuf>,
    /// The core's capture id.
    pub capture_id: Option<String>,
    pub size: Option<u64>,
    pub error: Option<String>,
    /// What a complete core still lacks, in the words a user reads: a live
    /// core whose only gap is pages that were not in memory (Read
    /// non-resident pages off), with the rule that took it. Absent otherwise
    /// and in records saved before it existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The guest could not pause the process just then (it was replacing its
    /// program, or waiting for a program it started, or busy, or out of
    /// time): that is not a core taken, so it does not use up the trigger's
    /// cores and does not start its cooldown; the next match may try again.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub refused: bool,
}

/// One trigger that took (or tried to take) dumps.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TriggerRecord {
    pub at_ms: u64,
    pub finding: LiveFinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<TriggerDump>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core: Option<TriggerDump>,
    /// The process was held at its exit for the dump (revision-22 bases):
    /// it had ended when the match was handled. The trigger log says so.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
}

impl LiveFinding {
    /// "c2.bpf_backdoor (High)".
    pub fn rule_with_tier(&self) -> String {
        format!("{} ({})", self.rule, self.tier.label())
    }
}

impl TriggerRecord {
    /// The provenance of this trigger's dumps: the run, the finding and the
    /// process that made it; exact, since the run asked for them.
    pub fn provenance(
        &self,
        vm_id: &str,
        boot_id: &str,
        run_id: &str,
    ) -> crate::provenance::Provenance {
        crate::provenance::Provenance::trigger(vm_id, boot_id, run_id, &self.finding, self.at_ms)
    }

    /// This record's core is one the trigger's `max_cores` counts: asked for
    /// and not refused for a reason that may pass.
    pub fn core_counts(&self) -> bool {
        self.core.as_ref().is_some_and(|core| !core.refused)
    }

    /// This record used up something of the trigger: a core that counts, or
    /// a memory dump. The cooldown runs from the last such record.
    pub fn counts(&self) -> bool {
        self.core_counts() || self.memory.is_some()
    }

    pub fn pending(&self) -> bool {
        [&self.memory, &self.core]
            .into_iter()
            .flatten()
            .any(|dump| dump.state.in_progress())
    }
}

/// A match that took no dump because it was too late, with the reason in the
/// words a user reads ("The process exited 120 ms after the match, before the
/// core could be taken.").
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TriggerMiss {
    pub at_ms: u64,
    pub finding: LiveFinding,
    pub reason: String,
}

/// What a run's triggers did, in `run.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TriggerLog {
    pub records: Vec<TriggerRecord>,
    /// Matches whose dump came too late: the process (or the run) was gone.
    /// They are not attempts, so they do not use the budget.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missed: Vec<TriggerMiss>,
    /// Matches that reached the tier but took no dump: over the budget, or
    /// inside the cooldown.
    pub skipped: u64,
    /// Matches the queue could not hold.
    pub lost: u64,
}

/// The live judge of one run.
pub(crate) struct Watch {
    judge: Box<dyn LiveJudge>,
    plan: DumpTrigger,
    /// System calls the rules read; empty judges every call.
    keep: HashSet<u64>,
    pending: HashMap<(u64, u64, u64), EventSummary>,
    order: VecDeque<((u64, u64, u64), Instant)>,
    pub queue: VecDeque<LiveFinding>,
    pub lost: u64,
    /// When each process was last seen to exit, by thread group id, on the
    /// guest clock: says how late a dump was.
    exits: HashMap<u32, u64>,
    /// Processes the guest holds at their exit, by thread group id: the task
    /// cookie that sent the hold record, and when it came.
    pub(crate) held: HashMap<u32, (u64, Instant)>,
    /// How long a held process waits for a match before it is let go.
    pub(crate) hold_grace: Duration,
    /// The run is over and its notes say what the trigger did.
    pub settled: bool,
    /// The latest (call id, phase) seen from each process, whatever the call:
    /// says whether a process that executed a program has gone on to run it.
    seen: HashMap<u32, (u64, u8)>,
    /// The kind of program each process last called from (ANT-T0598).
    abis: HashMap<u32, ProgramAbi>,
    /// Matches at an exec call whose program has not started yet (ANT-T0591):
    /// a process inside `execve` cannot be paused for a core, so the match
    /// waits for the new image's first call, or for [`EXEC_WAIT`].
    deferred: VecDeque<(LiveFinding, Instant)>,
    exec_wait: Duration,
    /// The watch takes dumps (a dump trigger); a passive watch only lists
    /// what the run persisted (ANT-T0608).
    pub(crate) dumps: bool,
    /// The `persistence.*` rows of the run (bounded).
    pub(crate) written: Vec<crate::persist_start::Written>,
}

/// The calls a passive watch judges: those that name a file the run
/// creates, writes, moves or links, and what the rules need to resolve
/// their paths (the working directory, the process image).
pub(crate) const PASSIVE_CALLS: &[&str] = &[
    "open",
    "openat",
    "openat2",
    "creat",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "chdir",
    "fchdir",
    "clone",
    "clone3",
    "fork",
    "vfork",
    "execve",
    "execveat",
];

/// Persistence rows one run keeps.
const WRITTEN_MAX: usize = 256;

impl Watch {
    pub(crate) fn new(plan: &DumpTrigger, keep: &[String]) -> Option<Self> {
        let factory = FACTORY.get()?;
        Some(Self::with_judge(factory(), plan, keep))
    }

    /// A watch that takes no dump: it only lists what the run persisted.
    /// `None` when no rule engine was registered.
    pub(crate) fn passive() -> Option<Self> {
        let factory = FACTORY.get()?;
        let keep: Vec<String> = PASSIVE_CALLS
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        let mut watch = Self::with_judge(factory(), &DumpTrigger::default(), &keep);
        watch.dumps = false;
        Some(watch)
    }

    pub(crate) fn with_judge(
        judge: Box<dyn LiveJudge>,
        plan: &DumpTrigger,
        keep: &[String],
    ) -> Self {
        Self {
            judge,
            plan: plan.clone(),
            // By id on every ABI: an arm64 run's events carry aarch64 and
            // arm ids, which no x86-64 number matches.
            keep: crate::syscalls::ids_on_every_abi(keep),
            pending: HashMap::new(),
            order: VecDeque::new(),
            queue: VecDeque::new(),
            lost: 0,
            exits: HashMap::new(),
            held: HashMap::new(),
            hold_grace: HOLD_GRACE,
            settled: false,
            seen: HashMap::new(),
            abis: HashMap::new(),
            deferred: VecDeque::new(),
            exec_wait: EXEC_WAIT,
            dumps: true,
            written: Vec::new(),
        }
    }

    /// The leader of thread group `pid` exited at `guest_ns`.
    pub(crate) fn exit(&mut self, pid: u32, guest_ns: u64) {
        if self.exits.len() >= PENDING_MAX {
            self.exits.clear();
        }
        self.exits.insert(pid, guest_ns);
    }

    /// A guest `scale` times slower than KVM (TCG) waits as much longer for a
    /// held process's last calls.
    pub(crate) fn scale_hold_grace(&mut self, scale: u32) {
        self.hold_grace = HOLD_GRACE * scale.max(1);
        self.exec_wait = EXEC_WAIT * scale.max(1);
    }

    /// The guest holds process `pid` at its exit (its task `cookie` said so):
    /// what of it still waits for an exit is judged now, since it is ending.
    pub(crate) fn hold(&mut self, pid: u32, cookie: u64) {
        if self.held.len() >= PENDING_MAX {
            self.held.clear();
        }
        self.held.insert(pid, (cookie, Instant::now()));
        // It is ending, not executing: nothing more to wait for.
        self.release_deferred(Some(pid));
        let mut entries: Vec<EventSummary> = Vec::new();
        self.pending.retain(|_, entry| {
            if entry.pid == pid {
                entries.push(entry.clone());
                false
            } else {
                true
            }
        });
        entries.sort_by_key(|entry| (entry.timestamp_ns, entry.call_id));
        for entry in entries {
            self.judge_events(&[entry]);
        }
    }

    /// The held processes no match came for within `grace`, to be let go: the
    /// task cookies of their hold records. A process with a match queued stays.
    pub(crate) fn releases(&mut self, grace: Duration) -> Vec<u64> {
        let wanted: HashSet<u32> = self.queue.iter().map(|finding| finding.pid).collect();
        let mut released = Vec::new();
        self.held.retain(|pid, (cookie, at)| {
            if wanted.contains(pid) || at.elapsed() < grace {
                return true;
            }
            released.push(*cookie);
            false
        });
        released
    }

    /// Why a dump of the process `finding` named came too late.
    pub(crate) fn too_late(&self, finding: &LiveFinding) -> String {
        too_late_text(finding, self.exits.get(&finding.pid).copied())
    }

    /// An entry or exit that has been received whole.
    pub(crate) fn event(&mut self, event: EventSummary) {
        if matches!(event.phase, 1 | 2) && event.pid != 0 {
            if self.seen.len() >= PENDING_MAX {
                self.seen.clear();
            }
            let at = self.seen.entry(event.pid).or_default();
            *at = (*at).max((event.call_id, event.phase));
            if self.abis.len() >= PENDING_MAX {
                self.abis.clear();
            }
            self.abis
                .insert(event.pid, ProgramAbi::of_call(event.syscall_nr));
        }
        if !matches!(event.phase, 1 | 2)
            || (!self.keep.is_empty() && !self.keep.contains(&event.syscall_nr))
        {
            return;
        }
        let key = (event.stream_id, event.task_cookie, event.call_id);
        if event.phase == 1 {
            if self.pending.len() >= PENDING_MAX
                && let Some((old, _)) = self.order.pop_front()
                && let Some(entry) = self.pending.remove(&old)
            {
                self.judge_events(&[entry]);
            }
            self.order.push_back((key, Instant::now()));
            self.pending.insert(key, event);
            return;
        }
        match self.pending.remove(&key) {
            Some(entry) => self.judge_events(&[entry, event]),
            None => self.judge_events(&[event]),
        }
    }

    /// The kind of program `pid` last called from, if the run saw it.
    pub(crate) fn program_abi(&self, pid: u32) -> Option<ProgramAbi> {
        self.abis.get(&pid).copied()
    }

    /// An exec call's match whose program has run on: the exec call returned
    /// (or failed) or the process made a later call.
    fn progressed(&self, finding: &LiveFinding) -> bool {
        self.seen
            .get(&finding.pid)
            .is_some_and(|at| *at >= (finding.call_id, 2))
    }

    /// The match is at an exec call that has not finished: the process is
    /// inside `execve`, which the guest cannot pause.
    pub(crate) fn exec_unfinished(&self, finding: &LiveFinding) -> bool {
        is_exec(finding) && !self.progressed(finding)
    }

    /// Move the deferred matches whose wait is over (all of `pid`'s when it is
    /// named, every one when the run is over) to the queue.
    fn release_deferred(&mut self, pid: Option<u32>) {
        let mut waiting = VecDeque::new();
        while let Some((finding, at)) = self.deferred.pop_front() {
            let due = pid.is_some_and(|pid| pid == finding.pid)
                || self.progressed(&finding)
                || at.elapsed() >= self.exec_wait
                || self.exits.contains_key(&finding.pid);
            if due {
                self.queue.push_back(finding);
            } else {
                waiting.push_back((finding, at));
            }
        }
        self.deferred = waiting;
    }

    /// Judge the entries whose exit did not come in time.
    pub(crate) fn tick(&mut self) {
        self.release_deferred(None);
        while let Some((key, at)) = self.order.front().copied() {
            if !self.pending.contains_key(&key) {
                self.order.pop_front();
                continue;
            }
            if at.elapsed() < ENTRY_GRACE {
                break;
            }
            self.order.pop_front();
            if let Some(entry) = self.pending.remove(&key) {
                self.judge_events(&[entry]);
            }
        }
    }

    /// Judge every entry still waiting for its exit: the run is over.
    pub(crate) fn flush(&mut self) {
        self.order.clear();
        let mut entries: Vec<EventSummary> = self.pending.drain().map(|(_, entry)| entry).collect();
        entries.sort_by_key(|entry| (entry.timestamp_ns, entry.call_id));
        for entry in entries {
            self.judge_events(&[entry]);
        }
        self.exec_wait = Duration::ZERO;
        self.release_deferred(None);
    }

    fn judge_events(&mut self, events: &[EventSummary]) {
        for call in pair_events(events) {
            let findings = self.judge.judge(&call);
            for row in self.judge.written() {
                if self.written.len() < WRITTEN_MAX {
                    self.written.push(row);
                }
            }
            for finding in findings {
                if !self.dumps || finding.tier < self.plan.min_tier {
                    continue;
                }
                if self.queue.len() + self.deferred.len() >= QUEUE_MAX {
                    self.lost += 1;
                } else if self.exec_unfinished(&finding) && !self.held.contains_key(&finding.pid) {
                    self.deferred.push_back((finding, Instant::now()));
                } else {
                    self.queue.push_back(finding);
                }
            }
        }
    }
}

/// Refused cores the log keeps, newest last; older ones are dropped, so a
/// process the guest keeps refusing cannot fill the log.
const REFUSED_KEPT: usize = 8;

/// Whether a core that failed for `code` was a refusal that may pass (the
/// process was busy, not pausable just then, or the guest ran out of time)
/// and so does not count as a core taken (ANT-T0591).
pub fn retryable_core_refusal(code: crate::core_limits::CoreReasonCode) -> bool {
    use crate::core_limits::CoreReasonCode::{Deadline, Interrupted, Unsupported};
    matches!(code, Unsupported | Interrupted | Deadline)
}

/// The words for a core the guest could not take just then. `exec`: the
/// process was inside `execve`. `started`: a program it started is running
/// (process id and name). `guest`: the core's own reason, which ends with the
/// guest's raw state and status; it is kept when nothing more is known.
pub fn refused_core_text(exec: bool, started: Option<(u32, &str)>, guest: &str) -> String {
    let raw = guest
        .rfind(" (guest state")
        .map_or("", |at| guest[at..].trim_end());
    let raw = raw.trim_end_matches('.');
    let kept = "This did not use up the trigger's cores: the next match may take one.";
    if exec {
        format!(
            "The process was replacing its program (execve) when the core was asked for, \
             so it could not be paused{raw}. {kept}"
        )
    } else if let Some((pid, name)) = started {
        format!(
            "The process had just started another program ({name}, process {pid}) and was \
             waiting for it: a program started with vfork or posix_spawn shares its \
             starter's memory until it runs, so the process could not be paused{raw}. {kept}"
        )
    } else {
        format!("{} {kept}", guest.trim_end())
    }
}

/// The kind of program a process runs, from the ABI of its calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramAbi {
    /// The guest's own ABI: x86-64 on x86-64, AArch64 on arm64.
    Native,
    /// A 32-bit x86 program on an x86-64 guest.
    Ia32,
    /// An x32 program (x86-64 instructions, 32-bit pointers).
    X32,
    /// An AArch32 program on an arm64 guest.
    Aarch32,
}

impl ProgramAbi {
    /// The program that made the call with host syscall id `id` (an event's
    /// `syscall_nr`).
    pub fn of_call(id: u64) -> Self {
        use crate::syscalls::Abi;
        /// `__X32_SYSCALL_BIT`: x32 calls are x86-64 numbers with it set.
        const X32_BIT: u64 = 0x4000_0000;
        match crate::syscalls::abi_of(id) {
            Some(Abi::I386) => Self::Ia32,
            Some(Abi::Arm) => Self::Aarch32,
            Some(Abi::X86_64) if crate::syscalls::wire_number(id) & X32_BIT != 0 => Self::X32,
            _ => Self::Native,
        }
    }
}

/// Whether a live core refused with -95 (unsupported) for a program of kind
/// `abi` can never pass, and if so the plain words for it. An ia32 or x32
/// program on an x86-64 guest never gets a core; an AArch32 program on an
/// arm64 guest gets one only from guest revision 21 on (`compat_elf32`).
/// Other programs, and a program whose kind the run did not see, may be
/// refused only for the moment (busy, not pausable, ANT-T0591).
pub fn permanent_core_refusal(abi: Option<ProgramAbi>, compat_elf32: bool) -> Option<String> {
    let kept = "This did not use up the trigger's cores: the next match may take one.";
    match abi? {
        ProgramAbi::Native => None,
        ProgramAbi::Ia32 => Some(format!(
            "The guest writes no core of an ia32 program (a 32-bit x86 program on an x86-64 guest). {kept}"
        )),
        ProgramAbi::X32 => Some(format!(
            "The guest writes no core of an x32 program (x86-64 with 32-bit pointers). {kept}"
        )),
        ProgramAbi::Aarch32 if !compat_elf32 => Some(format!(
            "The guest writes no core of an AArch32 program: this arm64 base is guest revision 20 \
             or older; use a base of revision 21 or later. {kept}"
        )),
        ProgramAbi::Aarch32 => None,
    }
}

/// Keep the newest [`REFUSED_KEPT`] refused cores of a log.
pub(crate) fn trim_refused(log: &mut TriggerLog) {
    let mut extra = log
        .records
        .iter()
        .filter(|record| record.memory.is_none() && record.core.as_ref().is_some_and(|c| c.refused))
        .count()
        .saturating_sub(REFUSED_KEPT);
    log.records.retain(|record| {
        let old = extra > 0
            && record.memory.is_none()
            && record.core.as_ref().is_some_and(|core| core.refused);
        if old {
            extra -= 1;
        }
        !old
    });
}

/// A match at `execve` or `execveat`.
fn is_exec(finding: &LiveFinding) -> bool {
    matches!(finding.syscall.as_str(), "execve" | "execveat")
}

/// The note of a run whose trigger never matched: a trigger that was armed
/// and stayed silent says so, so a run with no dump is not read as one whose
/// trigger was off. None when the trigger did something (a dump, a match
/// too late to dump, one over the budget, or one the queue lost).
pub fn silent_note(plan: &DumpTrigger, log: Option<&TriggerLog>) -> Option<String> {
    if log.is_some_and(|log| {
        !log.records.is_empty() || !log.missed.is_empty() || log.skipped > 0 || log.lost > 0
    }) {
        return None;
    }
    let what = match (plan.memory, plan.core) {
        (true, true) => "memory dump and core",
        (true, false) => "memory dump",
        _ => "core",
    };
    Some(format!(
        "Dump trigger armed ({what} at {} or higher), but no rule of that tier matched while the program ran: no dump was taken.",
        plan.min_tier.label()
    ))
}

/// Feed recorded entries and exits to `judge` the way a run's live watch
/// does, with the recorder's list of calls (`keep`, by name) as the filter, and
/// return what the watch would hand the worker at `plan`'s tier. For tests
/// and tools that check a judge against a recording of any architecture.
#[doc(hidden)]
pub fn replay(
    judge: Box<dyn LiveJudge>,
    plan: &DumpTrigger,
    keep: &[String],
    events: impl IntoIterator<Item = EventSummary>,
) -> Vec<LiveFinding> {
    let mut watch = Watch::with_judge(judge, plan, keep);
    let mut found = Vec::new();
    for event in events {
        watch.event(event);
        found.extend(watch.queue.drain(..));
    }
    watch.flush();
    found.extend(watch.queue.drain(..));
    found
}

/// The words for matches the recording ended on before they could be acted on.
pub(crate) const RECORDING_ENDED: &str = "The recording ended before the dump could be taken.";

impl crate::run::ProgramRun {
    /// Hand the run's live watch what the assembler just returned: a process
    /// exit, and an entry or exit once it is whole. Telemetry that came before
    /// the launch was acknowledged goes through here as well as live packets.
    pub(crate) fn watch_event(&mut self, event: Option<&EventSummary>) {
        let (Some(watch), Some(event)) = (self.watch.as_mut(), event) else {
            return;
        };
        if event.tid == event.pid
            && event
                .fields
                .iter()
                .any(|field| field.key == "lifecycle.task_exit")
        {
            watch.exit(event.pid, event.timestamp_ns);
        }
        if event
            .fields
            .iter()
            .any(|field| field.key == "lifecycle.exit_hold")
        {
            watch.hold(event.pid, event.task_cookie);
        }
        if self.assembler.just_finished {
            watch.event(event.clone());
        }
    }

    /// Once the run is over, say in its notes what its dump trigger did when
    /// it took nothing: matches the recording ended on are kept as misses,
    /// and a trigger that never matched says so. Once per run; true when the
    /// summary changed.
    pub(crate) fn settle_trigger(&mut self) -> bool {
        let Some(watch) = self.watch.as_mut() else {
            return false;
        };
        if watch.settled {
            return false;
        }
        watch.settled = true;
        watch.flush();
        let late: Vec<LiveFinding> = watch.queue.drain(..).collect();
        let lost = std::mem::take(&mut watch.lost);
        let Some(plan) = self.summary.request.dump_trigger.clone() else {
            return false;
        };
        if !late.is_empty() || lost > 0 {
            let at_ms = crate::disks::unix_ms();
            let log = self
                .summary
                .triggers
                .get_or_insert_with(TriggerLog::default);
            log.lost += lost;
            let count = late.len() as u64 + lost;
            for finding in late {
                if log.missed.len() < RECORDS_MAX {
                    log.missed.push(TriggerMiss {
                        at_ms,
                        finding,
                        reason: RECORDING_ENDED.into(),
                    });
                }
            }
            self.add_note(format!(
                "Dump trigger: {count} match{} came as the recording ended; no dump was taken.",
                if count == 1 { "" } else { "es" }
            ));
            return true;
        }
        match silent_note(&plan, self.summary.triggers.as_ref()) {
            Some(note) => {
                self.add_note(note);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
#[path = "dump_trigger_tests.rs"]
mod arch_tests;
