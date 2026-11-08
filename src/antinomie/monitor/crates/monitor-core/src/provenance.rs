// SPDX-License-Identifier: GPL-3.0-only
//! Where a core or memory dump came from: its VM, boot and run, why it was
//! taken, the process it holds, and how sure the link to the run is.
//!
//! The record is written into the artifact's own metadata (`metadata.json` of
//! a core, `core.json` of a manual core, `dump.json` of a memory dump), so the
//! link between a run and its evidence reads both ways: a run lists its
//! dumps, and a dump says which run it belongs to. A record saved before this
//! field existed has none and reads as unknown.
use crate::dump_trigger::{LiveFinding, TriggerTier};
use serde::{Deserialize, Serialize};

/// Why the artifact was taken.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Not recorded (a record from before this field).
    #[default]
    Unknown,
    /// The run asked for it when its program exited (Core or Memory dump on
    /// exit).
    RunExit,
    /// A Triage rule of the run's dump trigger matched.
    Trigger,
    /// The analyst took it (Dump core, Dump memory).
    ByHand,
    /// A file made elsewhere that the analyst imported.
    Imported,
    /// A network capture segment a run started with its launch.
    RunCapture,
}

impl Origin {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown origin",
            Self::RunExit => "Run exit",
            Self::Trigger => "Trigger",
            Self::ByHand => "By hand",
            Self::Imported => "Imported",
            Self::RunCapture => "Run capture",
        }
    }
}

/// How sure the link to a run is.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Certainty {
    /// No link is known.
    #[default]
    Unknown,
    /// The run asked for the dump itself, or the core's task is in the run's
    /// process tree.
    Exact,
    /// A by-hand memory dump written while the run was live: the time is the
    /// only link.
    ByTime,
    /// The dump holds the whole VM and no run was live.
    VmWide,
}

impl Certainty {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Exact => "exact",
            Self::ByTime => "by time",
            Self::VmWide => "VM-wide",
        }
    }
}

/// The finding that made a trigger take the dump.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FoundBy {
    pub rule: String,
    pub tier: TriggerTier,
}

impl FoundBy {
    /// "c2.bpf_backdoor (High)".
    pub fn text(&self) -> String {
        format!("{} ({})", self.rule, self.tier.label())
    }
}

/// The provenance record of one core or memory dump.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Provenance {
    pub vm_id: String,
    pub boot_id: Option<String>,
    /// The run it belongs to; none for a dump no run owns.
    pub run_id: Option<String>,
    /// Runs that were live while a by-hand memory dump was written.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub live_runs: Vec<String>,
    pub origin: Origin,
    pub certainty: Certainty,
    /// The process of a core.
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub task_cookie: Option<u64>,
    /// The finding of a trigger dump.
    pub finding: Option<FoundBy>,
    /// The time window, wall clock ms since the epoch: when it was asked for
    /// and when it was written.
    pub from_ms: u64,
    pub to_ms: Option<u64>,
}

impl Provenance {
    /// A dump a run asked for when its program exited.
    pub fn run_exit(vm_id: &str, boot_id: &str, run_id: &str, now_ms: u64) -> Self {
        Self {
            vm_id: vm_id.into(),
            boot_id: Some(boot_id.into()),
            run_id: Some(run_id.into()),
            origin: Origin::RunExit,
            certainty: Certainty::Exact,
            from_ms: now_ms,
            ..Self::default()
        }
    }

    /// A dump a run's trigger took.
    pub fn trigger(
        vm_id: &str,
        boot_id: &str,
        run_id: &str,
        finding: &LiveFinding,
        now_ms: u64,
    ) -> Self {
        Self {
            vm_id: vm_id.into(),
            boot_id: Some(boot_id.into()),
            run_id: Some(run_id.into()),
            origin: Origin::Trigger,
            certainty: Certainty::Exact,
            pid: Some(finding.pid),
            tid: Some(finding.tid),
            task_cookie: Some(finding.task_cookie),
            finding: Some(FoundBy {
                rule: finding.rule.clone(),
                tier: finding.tier,
            }),
            from_ms: now_ms,
            ..Self::default()
        }
    }

    /// A dump the analyst took. `run_id` is the run whose process tree holds
    /// the core's task (exact); a memory dump has none and says which runs
    /// were live instead.
    pub fn by_hand(
        vm_id: &str,
        boot_id: &str,
        run_id: Option<&str>,
        live_runs: Vec<String>,
        now_ms: u64,
    ) -> Self {
        let certainty = if run_id.is_some() {
            Certainty::Exact
        } else if live_runs.is_empty() {
            Certainty::VmWide
        } else {
            Certainty::ByTime
        };
        Self {
            vm_id: vm_id.into(),
            boot_id: Some(boot_id.into()),
            run_id: run_id.map(str::to_owned),
            live_runs,
            origin: Origin::ByHand,
            certainty,
            from_ms: now_ms,
            ..Self::default()
        }
    }

    /// A capture segment the run started (the run lists it in its artifacts):
    /// exact. `live_runs` are the other runs that were live while it wrote.
    pub fn run_capture(
        vm_id: &str,
        boot_id: &str,
        run_id: &str,
        live_runs: Vec<String>,
        window: (u64, Option<u64>),
    ) -> Self {
        Self {
            vm_id: vm_id.into(),
            boot_id: Some(boot_id.into()),
            run_id: Some(run_id.into()),
            live_runs,
            origin: Origin::RunCapture,
            certainty: Certainty::Exact,
            from_ms: window.0,
            to_ms: window.1,
            ..Self::default()
        }
    }

    /// A dump made elsewhere and imported: no run is known.
    pub fn imported(vm_id: &str, now_ms: u64) -> Self {
        Self {
            vm_id: vm_id.into(),
            origin: Origin::Imported,
            from_ms: now_ms,
            ..Self::default()
        }
    }

    /// The same record with the process of a core.
    #[must_use]
    pub fn of_process(mut self, pid: u32, task_cookie: u64) -> Self {
        self.pid = Some(pid);
        self.task_cookie = Some(task_cookie);
        self
    }

    /// Whether `run_id` is the run this dump belongs to or may belong to.
    pub fn concerns(&self, run_id: &str) -> bool {
        self.run_id.as_deref() == Some(run_id) || self.live_runs.iter().any(|id| id == run_id)
    }

    /// The runs the dump is linked to, the exact one first.
    pub fn runs(&self) -> Vec<&str> {
        self.run_id
            .iter()
            .chain(&self.live_runs)
            .map(String::as_str)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding() -> LiveFinding {
        LiveFinding {
            rule: "c2.bpf_backdoor".into(),
            summary: String::new(),
            tier: TriggerTier::High,
            pid: 1352,
            tid: 1353,
            task_cookie: 2,
            stream_id: 1,
            call_id: 1,
            guest_ns: 1,
            syscall: "setsockopt".into(),
        }
    }

    #[test]
    fn a_trigger_dump_is_exact_and_names_its_finding_and_process() {
        let found = Provenance::trigger("vm", "boot", "run", &finding(), 10);
        assert_eq!(found.certainty, Certainty::Exact);
        assert_eq!(found.origin, Origin::Trigger);
        assert_eq!(found.pid, Some(1352));
        assert_eq!(found.tid, Some(1353));
        assert_eq!(found.task_cookie, Some(2));
        assert_eq!(
            found.finding.as_ref().unwrap().text(),
            "c2.bpf_backdoor (High)"
        );
    }

    #[test]
    fn by_hand_dumps_are_exact_by_time_or_vm_wide() {
        let exact = Provenance::by_hand("vm", "b", Some("r"), vec![], 1).of_process(7, 9);
        assert_eq!(exact.certainty, Certainty::Exact);
        assert_eq!(exact.task_cookie, Some(9));
        let timed = Provenance::by_hand("vm", "b", None, vec!["r1".into(), "r2".into()], 1);
        assert_eq!(timed.certainty, Certainty::ByTime);
        assert!(timed.concerns("r2") && !timed.concerns("r3"));
        let alone = Provenance::by_hand("vm", "b", None, vec![], 1);
        assert_eq!(alone.certainty, Certainty::VmWide);
        assert!(alone.runs().is_empty());
    }

    #[test]
    fn a_record_without_the_field_reads_as_unknown() {
        let old: Provenance = serde_json::from_str("{}").unwrap();
        assert_eq!(old.origin, Origin::Unknown);
        assert_eq!(old.certainty, Certainty::Unknown);
        assert!(old.run_id.is_none());
    }

    #[test]
    fn a_run_with_only_trigger_cores_still_has_cores_though_the_exit_core_is_disabled() {
        // The shape of the evaluation's BPFDoor run: no exit core, one trigger core.
        let artifacts: crate::RunArtifacts = serde_json::from_str(
            r#"{"run_id":"r","vm_id":"v","boot_id":"b","core_state":"disabled",
            "trigger_dumps":[{"at_ms":1,"finding":{"rule":"c2.bpf_backdoor","summary":"",
            "tier":"high","pid":1352,"tid":1352,"task_cookie":2,"stream_id":1,"call_id":19,
            "guest_ns":1,"syscall":"setsockopt"},
            "core":{"state":"partial","path":"/x/process.elf","capture_id":"c","size":115608}}]}"#,
        )
        .unwrap();
        assert_eq!(artifacts.core_state, crate::RunArtifactState::Disabled);
        assert!(artifacts.has_cores());
        assert_eq!(artifacts.trigger_cores().count(), 1);
        let bare: crate::RunArtifacts =
            serde_json::from_str(r#"{"core_state":"disabled"}"#).unwrap();
        assert!(!bare.has_cores());
    }

    #[test]
    fn dumps_saved_before_the_field_still_load_and_the_field_round_trips() {
        let old: crate::memory::MemoryDump =
            serde_json::from_str(r#"{"id":"d","vm_id":"v"}"#).unwrap();
        assert!(old.provenance.is_none());
        let mut dump = old;
        dump.provenance = Some(Provenance::trigger("v", "b", "r", &finding(), 5));
        let text = serde_json::to_string(&dump).unwrap();
        let back: crate::memory::MemoryDump = serde_json::from_str(&text).unwrap();
        assert_eq!(back.provenance, dump.provenance);
    }
}
