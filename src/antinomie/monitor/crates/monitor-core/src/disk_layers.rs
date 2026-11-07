// SPDX-License-Identifier: GPL-3.0-only
//! What a reader can tell about the automatic disk layer of a recording
//! (design 5.12.2): the phase marker the engine keeps in `run-layer.json`,
//! the engine's own list in `Snapshot.disk_layers`, and the pure rule that
//! turns a marker into the phase a reader reports.
//!
//! A boot's recording is not final when QEMU stops: it is saved in the
//! background, then the earlier bytes of the changed files are copied into it
//! and the layer is merged down. The marker says which of those the engine is
//! in (`live`, `saving`, `finalizing`; no file means done), who wrote it, and
//! whether that writer is still there.
use crate::snapshots::RunLayerRecord as Record;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The stage the writer of a pending layer is in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerPhase {
    /// The boot is running.
    #[default]
    Live,
    /// QEMU stopped and the recording is being saved.
    Saving,
    /// The recording is saved; the earlier-bytes copy or the merge is under way.
    Finalizing,
}

impl LayerPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Saving => "saving",
            Self::Finalizing => "finalizing",
        }
    }
}

/// One entry of `Snapshot.disk_layers`: a VM whose automatic layer is
/// pending. `interrupted` never appears here: the engine that publishes the
/// snapshot is the owner, and a record a dead process left is adopted at start
/// and shows as `finalizing`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskLayer {
    pub vm_id: String,
    pub boot_id: String,
    pub phase: LayerPhase,
    /// Host Unix ms the boot's layer began.
    pub started_ms: u64,
    /// Host Unix ms of the last phase change.
    pub phase_ms: u64,
}

/// Who wrote the marker, so a reader can tell a living writer from a gone one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Owner {
    /// The writer's process id.
    #[serde(skip_serializing_if = "Option::is_none", rename = "owner_pid")]
    pub pid: Option<u32>,
    /// Field 22 of `/proc/<pid>/stat`: a reused pid has another value.
    #[serde(skip_serializing_if = "Option::is_none", rename = "owner_start_ticks")]
    pub start_ticks: Option<u64>,
    /// `/proc/sys/kernel/random/boot_id`: another value means the host rebooted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_boot: Option<String>,
    /// The link text of `/proc/self/ns/pid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid_ns: Option<String>,
}

impl Owner {
    /// This process.
    pub fn current() -> Self {
        let pid = std::process::id();
        Self {
            pid: Some(pid),
            start_ticks: process_start_ticks(pid),
            host_boot: host_boot_id(),
            pid_ns: own_pid_namespace(),
        }
    }
}

/// The marker fields a `run-layer.json` carries since 0.9.0. A file written by
/// 0.8.x has none of them and reads as `live` until the owner test says
/// otherwise. `format` stays 1; an older engine ignores the fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Marker {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<LayerPhase>,
    /// Host Unix ms of the last phase change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase_ms: Option<u64>,
    /// Host Unix ms the layer began (not in the design's field list; the
    /// snapshot entry needs it and a restarted engine cannot know it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_ms: Option<u64>,
    #[serde(flatten)]
    pub owner: Owner,
}

/// What the reader decides about a recording.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingPhase {
    /// The boot runs, or ended and the recording is still being saved.
    Live,
    /// The recording is saved and final; the earlier-bytes copy or merge is pending.
    Finalizing,
    /// No layer is pending for this recording.
    Complete,
    /// The writer is gone and the recording is as it left it.
    Interrupted,
}

/// Whether the writer of a marker is still there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerState {
    Alive,
    Gone,
    /// The reader is in another pid namespace (a CLI on the host, a daemon in
    /// a container), or the marker names no owner (written by 0.8.x).
    Unknown,
}

/// What a reader knows about the machine it reads on.
pub struct ReaderContext<'a> {
    pub host_boot: Option<String>,
    pub pid_ns: Option<String>,
    /// Field 22 of `/proc/<pid>/stat`, or `None` when there is no such process.
    pub start_ticks: &'a dyn Fn(u32) -> Option<u64>,
    /// Whether `run-layer.lock` is free (a non-blocking shared `flock`,
    /// released at once); `None` when it could not be probed. Asked only for
    /// a `finalizing` marker.
    pub finalizer_lock_free: &'a dyn Fn() -> Option<bool>,
}

/// The reading of one recording.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PhaseReading {
    pub phase: RecordingPhase,
    pub owner: OwnerState,
    /// `finalizing` with a finalizer that is gone: the recording is whole and
    /// only the earlier-bytes copy is missing until the next engine start.
    pub orphaned: bool,
}

/// The owner test of 5.12.2.
pub fn owner_state(marker: &Marker, reader: &ReaderContext<'_>) -> OwnerState {
    let owner = &marker.owner;
    let Some(pid) = owner.pid else {
        return OwnerState::Unknown;
    };
    if let (Some(recorded), Some(current)) = (&owner.host_boot, &reader.host_boot)
        && recorded != current
    {
        return OwnerState::Gone;
    }
    match (&owner.pid_ns, &reader.pid_ns) {
        (Some(recorded), Some(current)) if recorded == current => {}
        _ => return OwnerState::Unknown,
    }
    match ((reader.start_ticks)(pid), owner.start_ticks) {
        (None, _) => OwnerState::Gone,
        (Some(now), Some(then)) if now == then => OwnerState::Alive,
        (Some(_), Some(_)) => OwnerState::Gone,
        (Some(_), None) => OwnerState::Unknown,
    }
}

/// The phase a reader reports for the recording of `boot_id`, given the
/// pending record of its VM (`None`: no `run-layer.json`).
///
/// No record, or one that names another boot (a later boot began, which
/// settles this one first), is `Complete`. A `live` or `saving` marker whose
/// owner is gone is `Interrupted`; with a living or unknown owner it is
/// `Live`. A `finalizing` marker stays `Finalizing`, and is `orphaned` when its
/// finalizer is gone. A record with no phase (0.8.x) is `live`.
pub fn recording_phase(
    record: Option<&Record>,
    boot_id: &str,
    reader: &ReaderContext<'_>,
) -> PhaseReading {
    let complete = PhaseReading {
        phase: RecordingPhase::Complete,
        owner: OwnerState::Unknown,
        orphaned: false,
    };
    let Some(record) = record.filter(|record| record.boot_id == boot_id) else {
        return complete;
    };
    let owner = owner_state(&record.marker, reader);
    match record.marker.phase.unwrap_or(LayerPhase::Live) {
        LayerPhase::Live | LayerPhase::Saving => PhaseReading {
            phase: if owner == OwnerState::Gone {
                RecordingPhase::Interrupted
            } else {
                RecordingPhase::Live
            },
            owner,
            orphaned: false,
        },
        LayerPhase::Finalizing => PhaseReading {
            phase: RecordingPhase::Finalizing,
            owner,
            orphaned: owner == OwnerState::Gone || (reader.finalizer_lock_free)() == Some(true),
        },
    }
}

/// Read the pending record of the VM folder `directory` and apply
/// [`recording_phase`] on this machine.
pub fn read_phase(directory: &Path, boot_id: &str) -> PhaseReading {
    let record = Record::load(directory);
    let lock_free = || crate::snapshots::run_layer_lock_free(directory);
    recording_phase(
        record.as_ref(),
        boot_id,
        &ReaderContext {
            host_boot: host_boot_id(),
            pid_ns: own_pid_namespace(),
            start_ticks: &process_start_ticks,
            finalizer_lock_free: &lock_free,
        },
    )
}

/// `/proc/sys/kernel/random/boot_id`.
pub fn host_boot_id() -> Option<String> {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    Some(text.trim().to_owned()).filter(|text| !text.is_empty())
}

/// The link text of `/proc/self/ns/pid` (`pid:[4026531836]`).
pub fn own_pid_namespace() -> Option<String> {
    let link = std::fs::read_link("/proc/self/ns/pid").ok()?;
    Some(link.to_string_lossy().into_owned())
}

/// Field 22 (`starttime`) of `/proc/<pid>/stat`, or `None` when the process
/// does not exist. The command name may hold spaces and parentheses, so the
/// fields are counted after its last `)`.
pub fn process_start_ticks(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    start_ticks_of(&text)
}

fn start_ticks_of(stat: &str) -> Option<u64> {
    let after = stat.rsplit_once(')')?.1;
    // After the name the fields run from 3 (state), so field 22 is the 20th.
    after.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests;
