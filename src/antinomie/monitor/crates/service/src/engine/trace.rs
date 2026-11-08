// SPDX-License-Identifier: GPL-3.0-only
//! Build a [`FakeEngine`] from a trace the P0-1 spike recorded on a real VM
//! (`monitor-core/examples/auto-cycle.rs`, fixtures in
//! `tests/fixtures/auto-cycle/`).
//!
//! A trace is one JSON object per line. `command` rows carry the command's
//! variant name and the time it was sent; `note` rows carry what the engine
//! sent back (`command_result`, `snapshot` digests, and more) with the time
//! it arrived. The fake plays the notes that follow a command, with the same
//! delays, whenever the pipeline sends a command of that name, in the order
//! the trace recorded them.
//!
//! What a trace keeps of a [`Snapshot`] is its digest: the state, the active
//! VM, the boot id, whether the guest kernel answered, `last_error`, and the
//! recording flush counters. Runs, terminal bytes and disk layers are not in
//! the digest; a test that needs them adds them with
//! [`FakeEngine::on`] steps.
use super::fake::{Change, FakeEngine, Reply, Step};
use crate::clock::ManualClock;
use antinomie_monitor_core::{GuestKernel, RecordingFlushStatus, Snapshot, VmState};
use serde_json::Value;
use std::{sync::Arc, time::Duration};

/// Why a trace could not be read.
#[derive(Debug, PartialEq, Eq)]
pub struct TraceError(pub String);

impl std::fmt::Display for TraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TraceError {}

fn seconds(row: &Value) -> Result<f64, TraceError> {
    row["t"]
        .as_f64()
        .ok_or_else(|| TraceError(format!("row without a time: {row}")))
}

fn after(from: f64, to: f64) -> Duration {
    Duration::from_millis(((to - from).max(0.0) * 1000.0).round() as u64)
}

fn vm_state(name: &str) -> VmState {
    match name {
        "Starting" => VmState::Starting,
        "Running" => VmState::Running,
        "Stopping" => VmState::Stopping,
        "Failed" => VmState::Failed,
        _ => VmState::Stopped,
    }
}

/// Apply a trace digest to a snapshot.
pub fn apply_digest(snapshot: &mut Snapshot, digest: &Value) {
    snapshot.state = vm_state(digest["state"].as_str().unwrap_or("Stopped"));
    snapshot.active_vm = digest["active_vm"].as_str().map(str::to_owned);
    snapshot.boot_id = digest["boot_id"].as_str().map(str::to_owned);
    snapshot.guest_kernel = digest["guest_kernel"]
        .as_bool()
        .unwrap_or(false)
        .then(GuestKernel::default);
    snapshot.last_error = digest["last_error"].as_str().map(str::to_owned);
    snapshot.recording_flush =
        digest["recording_flush"]
            .as_object()
            .map(|flush| RecordingFlushStatus {
                boot_ids: Vec::new(),
                total_count: flush["total"].as_u64().unwrap_or(0) as usize,
                done_count: flush["done"].as_u64().unwrap_or(0) as usize,
                current: flush["current"].as_str().unwrap_or("").to_owned(),
                errors: vec![String::new(); flush["errors"].as_u64().unwrap_or(0) as usize],
            });
}

/// The trace rows of `text` (a `.trace.jsonl` file).
pub fn parse(text: &str) -> Result<Vec<Value>, TraceError> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|e| TraceError(e.to_string())))
        .collect()
}

/// A fake that replays `rows`. Commands the trace does not contain fail, as
/// for any unscripted command.
pub fn replay(rows: &[Value], clock: Arc<ManualClock>) -> Result<FakeEngine, TraceError> {
    let mut fake = FakeEngine::new(clock);
    // Notes before the first command are the engine's starting state.
    let first_command = rows.iter().position(|r| r["dir"] == "command");
    for row in &rows[..first_command.unwrap_or(rows.len())] {
        if row["dir"] == "note"
            && row["kind"] == "snapshot"
            && let Some(digest) = row.get("digest")
        {
            let digest = digest.clone();
            fake.start_with(|snapshot| apply_digest(snapshot, &digest));
        }
    }
    let Some(first) = first_command else {
        return Ok(fake);
    };
    let mut index = first;
    while index < rows.len() {
        let command = &rows[index];
        let (id, name, sent_at) = (
            command["id"]
                .as_u64()
                .ok_or_else(|| TraceError(format!("command without an id: {command}")))?,
            command["name"]
                .as_str()
                .ok_or_else(|| TraceError(format!("command without a name: {command}")))?
                .to_owned(),
            seconds(command)?,
        );
        let mut step = Step::new(Reply::Silent);
        index += 1;
        while index < rows.len() && rows[index]["dir"] != "command" {
            let row = &rows[index];
            index += 1;
            if row["dir"] != "note" {
                continue;
            }
            let delay = after(sent_at, seconds(row)?);
            match row["kind"].as_str() {
                Some("command_result") if row["id"].as_u64() == Some(id) => {
                    let message = row["message"].as_str().unwrap_or("").to_owned();
                    step.reply = if row["success"].as_bool().unwrap_or(false) {
                        Reply::Ok(message)
                    } else {
                        Reply::Fail(message)
                    };
                    step.after = delay;
                }
                Some("snapshot") => {
                    if let Some(digest) = row.get("digest") {
                        let digest = digest.clone();
                        step.changes.push((
                            delay,
                            Change::snapshot(move |snapshot| apply_digest(snapshot, &digest)),
                        ));
                    }
                }
                _ => {}
            }
        }
        fake.push_step(&name, step);
    }
    Ok(fake)
}
