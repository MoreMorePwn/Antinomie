// SPDX-License-Identifier: GPL-3.0-only
//! What happens to a sample, as events a custody log can record.
//!
//! The library reports every change to a sample through a [`CustodySink`].
//! The sink the library opens with, [`super::chain::ChainedEvents`], appends
//! each event to the sample's hash chain and to the library index chain (see
//! [`super::chain`]). Nothing here is secret: an event never carries raw
//! events of a run (only hashes) and the text an analyst typed into a guest
//! terminal has no field to be stored in, only how many bytes were typed.
use serde::{Deserialize, Serialize};

/// The longest free text an event keeps; longer text is cut.
pub const MAX_TEXT: usize = 2000;

/// What an analyst did to a running guest, other than typing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    NetworkChange,
    ClockMove,
    Kill,
    SnapshotRestore,
}

impl ActionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::NetworkChange => "Network changed",
            Self::ClockMove => "Clock moved",
            Self::Kill => "Run killed",
            Self::SnapshotRestore => "Snapshot restored",
        }
    }
}

/// One thing that happened to a sample.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CustodyEvent {
    /// The archive was written: where the bytes came from.
    Added { origin: String },
    /// The same bytes arrived by another route.
    OriginAdded { origin: String },
    /// The archive was read back and its SHA-256 compared.
    Verified { ok: bool, detail: String },
    /// The sample was sent into a VM.
    Sent { vm: String, path: String },
    /// A run started the sample.
    SeenInRun { vm: String, run: String },
    /// Tags, name or description changed.
    Edited { what: String },
    /// The archive was deleted; the record stays.
    Removed,
    /// The analyst asked for the file that was added to be deleted after the
    /// archive was read back and matched.
    OriginalDeleted { path: String },
    /// A record made before the custody log existed was brought in.
    Migrated { from: String },
    /// Static analysis ran over the archive.
    StaticAnalysis { summary: String },
    /// A run of the sample started, in this VM, with this setup.
    RunStarted {
        vm: String,
        run: String,
        detail: String,
    },
    /// A run ended: how, and what it left (hashes of artefacts, event counts).
    RunEnded {
        vm: String,
        run: String,
        detail: String,
    },
    /// The analyst typed into the guest terminal. Only the size is kept:
    /// what was typed may be a password.
    TerminalInput { run: String, bytes: u64 },
    /// The analyst changed something about a running guest.
    Action {
        run: String,
        what: ActionKind,
        detail: String,
    },
    /// The sample did something a rule or the recorder saw (a dropped or
    /// fetched file, a self-delete), by hash.
    Activity { run: String, detail: String },
    /// A custody record was exported; `head` is the chain head it contains.
    Exported {
        format: String,
        signed: String,
        head: String,
    },
}

/// Every kind with its list name, for the filters and the export.
pub const KINDS: [(&str, &str); 16] = [
    ("added", "Added"),
    ("origin_added", "Origin added"),
    ("verified", "Verified"),
    ("sent", "Sent into VM"),
    ("seen_in_run", "Seen in a run"),
    ("edited", "Edited"),
    ("removed", "Removed"),
    ("original_deleted", "Original deleted"),
    ("migrated", "Migrated"),
    ("static_analysis", "Static analysis"),
    ("run_started", "Run started"),
    ("run_ended", "Run ended"),
    ("terminal_input", "Terminal input"),
    ("action", "Your action"),
    ("activity", "Sample activity"),
    ("exported", "Exported"),
];

impl CustodyEvent {
    /// The terminal-input event for `typed`: the bytes themselves are dropped
    /// here, only their number is kept.
    pub fn terminal_input(run: &str, typed: &[u8]) -> Self {
        Self::TerminalInput {
            run: run.into(),
            bytes: typed.len() as u64,
        }
    }

    /// The stable name stored with the entry and used by the filters.
    pub fn key(&self) -> &'static str {
        match self {
            Self::Added { .. } => "added",
            Self::OriginAdded { .. } => "origin_added",
            Self::Verified { .. } => "verified",
            Self::Sent { .. } => "sent",
            Self::SeenInRun { .. } => "seen_in_run",
            Self::Edited { .. } => "edited",
            Self::Removed => "removed",
            Self::OriginalDeleted { .. } => "original_deleted",
            Self::Migrated { .. } => "migrated",
            Self::StaticAnalysis { .. } => "static_analysis",
            Self::RunStarted { .. } => "run_started",
            Self::RunEnded { .. } => "run_ended",
            Self::TerminalInput { .. } => "terminal_input",
            Self::Action { .. } => "action",
            Self::Activity { .. } => "activity",
            Self::Exported { .. } => "exported",
        }
    }

    /// The short name the list shows.
    pub fn label(&self) -> &'static str {
        label_of(self.key())
    }

    /// What the list shows beside the name.
    pub fn detail(&self) -> String {
        match self {
            Self::Added { origin } | Self::OriginAdded { origin } => origin.clone(),
            Self::Verified { ok, detail } => {
                if *ok {
                    "SHA-256 matches".into()
                } else {
                    detail.clone()
                }
            }
            Self::Sent { vm, path } => format!("{vm}: {path}"),
            Self::SeenInRun { vm, run } => format!("{vm}, run {run}"),
            Self::Edited { what } => what.clone(),
            Self::Removed => String::new(),
            Self::OriginalDeleted { path } => path.clone(),
            Self::Migrated { from } => format!("recorded before the custody log ({from})"),
            Self::StaticAnalysis { summary } => summary.clone(),
            Self::RunStarted { vm, run, detail } => format!("Run {run} on {vm}: {detail}"),
            Self::RunEnded { vm, run, detail } => format!("Run {run} on {vm} ended: {detail}"),
            Self::TerminalInput { run, bytes } => {
                format!("Run {run}: {bytes} bytes typed in the guest terminal (not recorded)")
            }
            Self::Action { run, what, detail } => {
                format!("Run {run}: {}: {detail}", what.label())
            }
            Self::Activity { run, detail } => format!("Run {run}: {detail}"),
            Self::Exported {
                format,
                signed,
                head,
            } => format!("{format}, {signed}; head {}", head.get(..8).unwrap_or(head)),
        }
    }

    /// The event as stored: the JSON text that is hashed, with control
    /// characters taken out of every text and long texts cut.
    pub fn stored(&self) -> Result<String, String> {
        let mut value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        clean(&mut value);
        serde_json::to_string(&value).map_err(|e| e.to_string())
    }
}

/// The list name of a stored kind key; an unknown key is shown as it is.
pub fn label_of(key: &str) -> &'static str {
    KINDS
        .iter()
        .find(|(known, _)| *known == key)
        .map_or("Unknown event", |(_, label)| label)
}

fn clean(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            let mut kept: String = text
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
            if kept.chars().count() > MAX_TEXT {
                kept = kept.chars().take(MAX_TEXT).collect::<String>() + "…";
            }
            *text = kept;
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(clean),
        serde_json::Value::Object(map) => map.values_mut().for_each(clean),
        _ => {}
    }
}

/// Where the library reports events. An implementation must not call back
/// into the library from `record`.
pub trait CustodySink: Send + Sync {
    /// Note `event` for the sample with this SHA-256, made by `by` (the app,
    /// or the analyst). A failure is reported to the caller, which decides
    /// whether the change it made stands.
    fn record(
        &self,
        sha256: &str,
        by: &str,
        at_ms: u64,
        event: &CustodyEvent,
    ) -> Result<(), String>;

    /// Called once when the library opens, after its tables exist: a sink
    /// that keeps its own state brings it up to date here.
    fn prepare(&self) -> Result<(), String> {
        Ok(())
    }
}

/// The sink that keeps no custody: events are dropped. For tests.
pub struct NoCustody;

impl CustodySink for NoCustody {
    fn record(&self, _: &str, _: &str, _: u64, _: &CustodyEvent) -> Result<(), String> {
        Ok(())
    }
}
