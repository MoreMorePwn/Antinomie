// SPDX-License-Identifier: GPL-3.0-only
//! The dump trigger in headless runs (ANT-T0439): the live judge a launch that
//! asks for a trigger needs, and what the trigger did, in the words of the job
//! API (`run exec`'s result, `job.trigger` events, `job.run.triggers`).
//!
//! The recorder judges each call with the Triage rule engine, which the UI
//! hands to the core at start. A headless process has no UI, so the run lane
//! registers the same engine (`antinomie_triage::live_judge`) the first time a
//! launch carries a trigger.
use crate::api::job::{JobDump, JobTrigger};
use antinomie_monitor_core::{
    RunArtifacts, RunSummary,
    dump_trigger::{self, DumpTrigger, TriggerDump, TriggerRecord},
};
use serde::Serialize;

/// Register the live judge; a second call changes nothing.
pub fn ensure_live_judge() {
    antinomie_triage::live_judge::register();
}

/// What the run's trigger was set to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Armed {
    pub tier: String,
    pub memory: bool,
    pub core: bool,
}

/// What a run's dump trigger did, for a run that asked for one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TriggerReport {
    pub armed: Armed,
    /// At least one match took (or tried to take) a dump.
    pub fired: bool,
    pub records: Vec<JobTrigger>,
    /// Matches that came too late for a dump (the process or the run was gone).
    pub missed: u64,
    /// Matches over the dump budget or inside the cooldown.
    pub skipped: u64,
    /// Matches the live queue could not hold.
    pub lost: u64,
    /// One sentence each: the "armed but never matched" note, the matches that
    /// came too late, the matches over the budget.
    pub notes: Vec<String>,
}

fn state_name(state: antinomie_monitor_core::RunArtifactState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn dump_of(dump: &TriggerDump) -> JobDump {
    JobDump {
        state: state_name(dump.state),
        size: dump.size,
        capture_id: dump.capture_id.clone(),
        error: dump.error.clone(),
        path: dump.path.as_ref().map(|path| path.display().to_string()),
    }
}

/// A trigger record as the job API words it.
pub fn job_trigger(record: &TriggerRecord) -> JobTrigger {
    JobTrigger {
        rule: record.finding.rule.clone(),
        tier: tier_name(&record.finding),
        summary: record.finding.summary.clone(),
        syscall: record.finding.syscall.clone(),
        pid: record.finding.pid,
        at_ms: record.at_ms,
        memory: record.memory.as_ref().map(dump_of),
        core: record.core.as_ref().map(dump_of),
    }
}

/// The same record with no host path, for an event.
pub fn without_paths(trigger: &JobTrigger) -> JobTrigger {
    let mut copy = trigger.clone();
    for dump in [&mut copy.memory, &mut copy.core].into_iter().flatten() {
        dump.path = None;
    }
    copy
}

fn tier_name(finding: &dump_trigger::LiveFinding) -> String {
    finding.tier.label().to_ascii_lowercase()
}

/// A trigger dump is still being written (the evidence is not complete yet).
pub fn dump_pending(artifacts: &RunArtifacts) -> bool {
    artifacts.trigger_dumps.iter().any(TriggerRecord::pending)
}

/// What `run`'s trigger did, `None` when the run asked for none. `artifacts`
/// (read once the evidence is complete) holds the final state of each dump;
/// without it the run's own log is used.
pub fn report(run: &RunSummary, artifacts: Option<&RunArtifacts>) -> Option<TriggerReport> {
    let plan: &DumpTrigger = run.request.dump_trigger.as_ref()?;
    let log = run.triggers.clone().unwrap_or_default();
    let taken: Vec<&TriggerRecord> = match artifacts {
        Some(artifacts) if !artifacts.trigger_dumps.is_empty() => {
            artifacts.trigger_dumps.iter().collect()
        }
        _ => log.records.iter().collect(),
    };
    let records: Vec<JobTrigger> = taken.into_iter().map(job_trigger).collect();
    let mut notes: Vec<String> = run
        .notes
        .iter()
        .filter(|note| note.starts_with("Dump trigger ") || note.starts_with("Dump trigger:"))
        .cloned()
        .collect();
    for miss in &log.missed {
        notes.push(format!(
            "{}: {}",
            miss.finding.rule_with_tier(),
            miss.reason
        ));
    }
    if log.skipped > 0 {
        notes.push(format!(
            "{} match{} reached the tier but took no dump (over the dump budget or inside the cooldown).",
            log.skipped,
            if log.skipped == 1 { "" } else { "es" }
        ));
    }
    Some(TriggerReport {
        armed: Armed {
            tier: plan.min_tier.label().to_ascii_lowercase(),
            memory: plan.memory,
            core: plan.core,
        },
        fired: !records.is_empty(),
        records,
        missed: log.missed.len() as u64,
        skipped: log.skipped,
        lost: log.lost,
        notes,
    })
}
