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
//! The plan bounds what a trigger may do: at most `max_dumps` triggers take
//! a dump per run, no two closer than `cooldown_secs`, and a failed dump is
//! recorded and not retried.
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DumpTrigger {
    /// Triggers at this tier and above.
    pub min_tier: TriggerTier,
    /// Take the VM's memory (QEMU `dump-guest-memory`).
    pub memory: bool,
    /// Take a core of the process that made the call. Its budget and
    /// deadline are the run's `core_max_size` and `core_timeout_ms`.
    pub core: bool,
    /// Triggers that may take a dump during this run.
    pub max_dumps: u32,
    /// Quiet time after a trigger during which another is only counted.
    pub cooldown_secs: u32,
    /// A memory dump is skipped when the VM has more RAM than this, MiB.
    pub memory_max_mib: u32,
}

impl Default for DumpTrigger {
    fn default() -> Self {
        Self {
            min_tier: TriggerTier::High,
            memory: false,
            core: true,
            max_dumps: 1,
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
        if !(1..=Self::MAX_DUMPS).contains(&self.max_dumps) {
            return Err(format!(
                "a dump trigger takes 1 to {} dumps per run",
                Self::MAX_DUMPS
            ));
        }
        if self.cooldown_secs > 3600 {
            return Err("the dump trigger cooldown is at most one hour".into());
        }
        Ok(())
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
    /// The run is over and its notes say what the trigger did.
    pub settled: bool,
}

impl Watch {
    pub(crate) fn new(plan: &DumpTrigger, keep: &[String]) -> Option<Self> {
        let factory = FACTORY.get()?;
        Some(Self::with_judge(factory(), plan, keep))
    }

    fn with_judge(judge: Box<dyn LiveJudge>, plan: &DumpTrigger, keep: &[String]) -> Self {
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
            settled: false,
        }
    }

    /// The leader of thread group `pid` exited at `guest_ns`.
    pub(crate) fn exit(&mut self, pid: u32, guest_ns: u64) {
        if self.exits.len() >= PENDING_MAX {
            self.exits.clear();
        }
        self.exits.insert(pid, guest_ns);
    }

    /// Why a dump of the process `finding` named came too late.
    pub(crate) fn too_late(&self, finding: &LiveFinding) -> String {
        too_late_text(finding, self.exits.get(&finding.pid).copied())
    }

    /// An entry or exit that has been received whole.
    pub(crate) fn event(&mut self, event: EventSummary) {
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

    /// Judge the entries whose exit did not come in time.
    pub(crate) fn tick(&mut self) {
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
    }

    fn judge_events(&mut self, events: &[EventSummary]) {
        for call in pair_events(events) {
            for finding in self.judge.judge(&call) {
                if finding.tier < self.plan.min_tier {
                    continue;
                }
                if self.queue.len() >= QUEUE_MAX {
                    self.lost += 1;
                } else {
                    self.queue.push_back(finding);
                }
            }
        }
    }
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
