// SPDX-License-Identifier: GPL-3.0-only
//! How long each part of `collect` took (ANT-T0612): the evidence wait, the
//! telemetry that still came in after the program ended, the VM's stop,
//! saving the recording and the disk layer. Each part is a `run.collect`
//! event and the job's daemon log gets one INFO line with all of them, so a
//! long collect says where its time went.
//!
//! The parts are read off the engine's snapshot while `collect` waits:
//! `health.received_packets` and `health.write_backlog` for the telemetry,
//! the VM state, `recording_flush` and `disk_layers` for the rest. A part the
//! wait never saw (a VM that was already stopped) is left out.
use crate::api::{event::CollectPart, run::Run};
use antinomie_monitor_core::{Snapshot, VmState, disk_layers::LayerPhase};

/// What the wait after `Stop` saw, with the times (service clock, ms).
#[derive(Clone, Debug, Default)]
pub(crate) struct SettleSeen {
    pub stopped_ms: Option<u64>,
    /// The recording flush was seen running.
    pub flushing: bool,
    /// The VM's disk layer entered `finalizing` (the recording is saved).
    pub finalizing_ms: Option<u64>,
    /// Stopped, saved, and no layer pending.
    pub settled_ms: Option<u64>,
}

impl SettleSeen {
    pub fn see(&mut self, now: u64, snapshot: &Snapshot, vm: &str) {
        if self.stopped_ms.is_none() && snapshot.state == VmState::Stopped {
            self.stopped_ms = Some(now);
        }
        self.flushing |= snapshot.recording_flush.is_some();
        let layer = snapshot.disk_layers.iter().find(|layer| layer.vm_id == vm);
        if self.finalizing_ms.is_none()
            && layer.is_some_and(|layer| layer.phase == LayerPhase::Finalizing)
        {
            self.finalizing_ms = Some(now);
        }
        if self.settled_ms.is_none() && crate::waiter::settled_after_stop(snapshot, vm) {
            self.settled_ms = Some(now);
        }
    }
}

/// The clock of one `collect`.
#[derive(Clone, Debug)]
pub(crate) struct CollectClock {
    began_ms: u64,
    packets: u64,
    taken: u64,
    last_packet_ms: Option<u64>,
    start_backlog: u64,
    backlog_empty_ms: Option<u64>,
    stop_ms: Option<u64>,
    pub settle: SettleSeen,
    parts: Vec<(CollectPart, u64, Option<String>)>,
}

const MIB: u64 = 1 << 20;

fn seconds(ms: u64) -> String {
    format!("{:.1} s", ms as f64 / 1000.0)
}

impl CollectClock {
    pub fn new(now: u64, snapshot: &Snapshot) -> Self {
        let backlog = snapshot.health.write_backlog;
        Self {
            began_ms: now,
            packets: snapshot.health.received_packets,
            taken: 0,
            last_packet_ms: None,
            start_backlog: backlog,
            backlog_empty_ms: (backlog == 0).then_some(now),
            stop_ms: None,
            settle: SettleSeen::default(),
            parts: Vec::new(),
        }
    }

    /// The telemetry figures, until `Stop` is sent.
    pub fn observe(&mut self, now: u64, snapshot: &Snapshot) {
        if self.stop_ms.is_some() {
            return;
        }
        let received = snapshot.health.received_packets;
        if received > self.packets {
            self.taken += received - self.packets;
            self.packets = received;
            self.last_packet_ms = Some(now);
        }
        if self.backlog_empty_ms.is_none() && snapshot.health.write_backlog == 0 {
            self.backlog_empty_ms = Some(now);
        }
    }

    pub fn part(&mut self, part: CollectPart, duration_ms: u64, detail: Option<String>) {
        self.parts.push((part, duration_ms, detail));
    }

    /// The evidence wait is over at `now`; `waited` names what was pending.
    pub fn evidence(&mut self, now: u64, waited: &[&str]) {
        let detail = if waited.is_empty() {
            "nothing was still being written".to_owned()
        } else {
            format!("waited for: {}", waited.join(", "))
        };
        self.part(
            CollectPart::Evidence,
            now.saturating_sub(self.began_ms),
            Some(detail),
        );
    }

    /// `Stop` is about to be sent: the telemetry part ends here.
    pub fn stop_sent(&mut self, now: u64) {
        self.stop_ms = Some(now);
        let last = self.last_packet_ms.unwrap_or(self.began_ms);
        let mut detail = format!(
            "{} packets taken after the program ended; the recording writer had {} MiB queued",
            self.taken,
            self.start_backlog.div_ceil(MIB)
        );
        match self.backlog_empty_ms {
            Some(empty) => detail.push_str(&format!(
                ", empty after {}",
                seconds(empty.saturating_sub(self.began_ms))
            )),
            None => detail.push_str(", still not empty at the stop"),
        }
        self.part(
            CollectPart::Telemetry,
            last.saturating_sub(self.began_ms),
            Some(detail),
        );
    }

    /// The wait after `Stop` ended at `now`: the stop, saving and disk layer
    /// parts from what it saw.
    pub fn settled(&mut self, now: u64) {
        let Some(sent) = self.stop_ms else {
            return;
        };
        let seen = self.settle.clone();
        let Some(stopped) = seen.stopped_ms else {
            self.part(
                CollectPart::Stop,
                now.saturating_sub(sent),
                Some("the VM was not seen stopped".into()),
            );
            return;
        };
        self.part(CollectPart::Stop, stopped.saturating_sub(sent), None);
        let end = seen.settled_ms.unwrap_or(now);
        let saved = seen.finalizing_ms.unwrap_or(end).max(stopped);
        let saving = if seen.flushing {
            "the recording's writes, fsync, SHA-256 and final files"
        } else {
            "the recording was already saved"
        };
        self.part(
            CollectPart::Saving,
            saved.saturating_sub(stopped),
            Some(saving.into()),
        );
        let layer = if seen.settled_ms.is_none() {
            "the disk layer was still pending at the wait's end"
        } else if seen.finalizing_ms.is_some() {
            "the earlier bytes of changed files (a scan of the recording) and the merge"
        } else {
            "no disk layer was pending"
        };
        self.part(
            CollectPart::DiskLayer,
            end.saturating_sub(saved),
            Some(layer.into()),
        );
    }

    /// One INFO line for the daemon log.
    pub fn line(&self, job: &Run, now: u64) -> String {
        let parts: Vec<String> = self
            .parts
            .iter()
            .map(|(part, ms, _)| format!("{} {}", name(*part), seconds(*ms)))
            .collect();
        format!(
            "run={} collect took {}: {}",
            job.id,
            seconds(now.saturating_sub(self.began_ms)),
            parts.join(", ")
        )
    }

    pub fn parts(&self) -> &[(CollectPart, u64, Option<String>)] {
        &self.parts
    }
}

/// The part's name in the daemon log.
pub(crate) fn name(part: CollectPart) -> &'static str {
    match part {
        CollectPart::Evidence => "evidence",
        CollectPart::Telemetry => "telemetry",
        CollectPart::Stop => "stop",
        CollectPart::Saving => "saving",
        CollectPart::DiskLayer => "disk layer",
    }
}
