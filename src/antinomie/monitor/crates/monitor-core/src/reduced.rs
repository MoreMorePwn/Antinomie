// SPDX-License-Identifier: GPL-3.0-only
//! Reduced recording: what the recorder does when the quota is nearly full.
//!
//! A boot's recording quota bounds everything it saves. A noisy program can
//! fill it in a minute with calls nobody will read, and then nothing is saved
//! and the evidence that matters (the call that starts a miner, the connection
//! to its pool) is lost with the rest. So the last tenth of the quota is kept
//! for the calls the Triage suspicious-activity rules read:
//!
//! * Until the boot has used nine tenths of the quota everything is saved.
//! * From then on a call is saved only when its system call is on the list the
//!   UI built from those rules (see `triage::rules::calls`), or when it is
//!   process lifecycle. Every other call is dropped and counted per system
//!   call. Lifecycle events of a task (phase 3: its exit, its exec) are always
//!   kept, and so is anything the list cannot name (another ABI, an unknown
//!   number).
//! * The network capture keeps running too, but only up to half of that last
//!   tenth; the other half is left for the calls.
//! * The quota itself stays the hard ceiling: when it is full, saving stops as
//!   it always did, and the recording says so.
//!
//! The switch is boot-wide. Each run that was going on records it in
//! `run.json` (`reduced`), with its own dropped counts.
use crate::parser::Header;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// The part of the quota kept for the reduced mode, as a divisor.
const RESERVE_DIVISOR: u64 = 10;

/// What a run's recording says about the reduced mode.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReducedRecording {
    /// Host Unix milliseconds when the recorder switched.
    pub at_ms: u64,
    /// The guest clock of the packet that caused the switch.
    #[serde(default)]
    pub at_guest_ns: u64,
    /// The boot's quota and how much of it was used at the switch, in bytes.
    pub quota_bytes: u64,
    #[serde(default)]
    pub used_bytes: u64,
    /// Packets of this run that arrived after the switch and were saved.
    #[serde(default)]
    pub kept_packets: u64,
    /// Packets of this run dropped by the reduced mode. Packets saved plus
    /// packets dropped is what arrived after the switch.
    #[serde(default)]
    pub dropped_packets: u64,
    /// Calls dropped, by system call name (one per call, counted at its entry).
    #[serde(default)]
    pub dropped_calls: BTreeMap<String, u64>,
    /// Host Unix milliseconds when the quota itself was full and saving
    /// stopped, if it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_at_ms: Option<u64>,
    /// Host Unix milliseconds when the network capture was stopped to leave
    /// the rest of the reserve for system calls, if it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_stopped_ms: Option<u64>,
}

impl ReducedRecording {
    /// All calls dropped.
    pub fn dropped_total(&self) -> u64 {
        self.dropped_calls.values().sum()
    }

    /// The dropped calls, most numerous first.
    pub fn dropped_ranked(&self) -> Vec<(&str, u64)> {
        let mut ranked: Vec<_> = self
            .dropped_calls
            .iter()
            .map(|(name, count)| (name.as_str(), *count))
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        ranked
    }
}

/// What the recorder does with one packet.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Keep,
    /// Dropped; the name is set for the first packet of a call.
    Drop(Option<&'static str>),
}

/// The reduced mode of one boot.
#[derive(Default)]
pub(crate) struct Reducer {
    /// Syscall numbers kept; empty disables the mode.
    keep: HashSet<u64>,
    /// The boot's own record: what no run owns is counted here.
    pub active: Option<ReducedRecording>,
}

impl Reducer {
    pub(crate) fn new(calls: &[String]) -> Self {
        Self {
            keep: calls
                .iter()
                .filter_map(|name| crate::syscalls::number(name))
                .collect(),
            active: None,
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        !self.keep.is_empty()
    }

    /// The part of the quota the reduced mode owns.
    pub(crate) fn reserve(quota: u64) -> u64 {
        quota / RESERVE_DIVISOR
    }

    /// True when `used` bytes of the quota leave only the reserve.
    pub(crate) fn due(&self, used: u64, quota: u64) -> bool {
        self.enabled() && self.active.is_none() && used >= quota - Self::reserve(quota)
    }

    /// The network capture's room: it stops with half of the reserve left.
    pub(crate) fn network_floor(&self, quota: u64) -> u64 {
        if self.active.is_some() {
            Self::reserve(quota) / 2
        } else {
            0
        }
    }

    pub(crate) fn begin(&mut self, quota: u64, used: u64, at_ms: u64, at_guest_ns: u64) {
        self.active = Some(ReducedRecording {
            at_ms,
            at_guest_ns,
            quota_bytes: quota,
            used_bytes: used,
            ..Default::default()
        });
    }

    /// Whether a packet is kept. Only the entry and exit of a call whose
    /// syscall is known and not on the list are dropped.
    pub(crate) fn verdict(&self, header: &Header) -> Verdict {
        if header.record_type != 1 || !matches!(header.phase, 1 | 2) || header.abi != 1 {
            return Verdict::Keep;
        }
        let Some(name) = crate::syscalls::known_name(header.syscall_nr) else {
            return Verdict::Keep;
        };
        if self.keep.contains(&header.syscall_nr) {
            return Verdict::Keep;
        }
        let begin = header.phase == 1 && header.fragment == 1;
        Verdict::Drop(begin.then_some(name))
    }
}

/// Count one verdict in a record.
pub(crate) fn count(record: &mut ReducedRecording, verdict: &Verdict) {
    match verdict {
        Verdict::Keep => record.kept_packets += 1,
        Verdict::Drop(name) => {
            record.dropped_packets += 1;
            if let Some(name) = name {
                *record.dropped_calls.entry((*name).to_owned()).or_default() += 1;
            }
        }
    }
}

/// The reduced recording of a run's folder, with when the run started, from
/// its `run.json`; `None` for a run it did not touch and for runs saved before
/// it existed.
pub fn read(directory: &std::path::Path) -> Option<(ReducedRecording, Option<u64>)> {
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("run.json")).ok()?).ok()?;
    let reduced = serde_json::from_value(run.get("reduced")?.clone()).ok()?;
    Some((
        reduced,
        run.get("started_ms").and_then(|value| value.as_u64()),
    ))
}
