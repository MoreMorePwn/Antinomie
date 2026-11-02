// SPDX-License-Identifier: GPL-3.0-only
//! The reduced recording on the session: the switch, the per-packet verdict and
//! the network capture's share of the reserve. See [`crate::reduced`].
use super::*;
use crate::reduced::{Verdict, count};

impl Session {
    /// Switch to the reduced recording when only the reserve is left, then
    /// decide the fate of `header`'s packet. True when the packet is dropped
    /// (and counted); it is then not saved, assembled or held.
    pub(super) fn reduce_packet(
        &mut self,
        header: &crate::parser::Header,
        packet_len: usize,
    ) -> bool {
        if !self.quota.reduced.enabled() {
            return false;
        }
        let quota = self.capture.quota();
        if self.quota.reduced.due(
            self.stored_len().saturating_add(packet_len as u64 + 4),
            quota,
        ) {
            self.begin_reduced(header.timestamp_ns);
        }
        if self.quota.reduced.active.is_none() {
            return false;
        }
        let verdict = self.quota.reduced.verdict(header);
        let Some(boot) = self.quota.reduced.active.as_mut() else {
            return false;
        };
        let root = header.root_task_cookie;
        match self.runs.get_mut(&root) {
            Some(run) if !run.recording_complete() => {
                let record =
                    run.summary
                        .reduced
                        .get_or_insert_with(|| crate::reduced::ReducedRecording {
                            kept_packets: 0,
                            dropped_packets: 0,
                            dropped_calls: Default::default(),
                            ..boot.clone()
                        });
                count(record, &verdict);
            }
            _ => count(boot, &verdict),
        }
        matches!(verdict, Verdict::Drop(_))
    }

    fn begin_reduced(&mut self, guest_ns: u64) {
        let (quota, used) = (self.capture.quota(), self.stored_len());
        self.quota.reduced.begin(quota, used, unix_ms(), guest_ns);
        let Some(boot) = self.quota.reduced.active.clone() else {
            return;
        };
        for run in self
            .runs
            .values_mut()
            .filter(|run| !run.recording_complete())
        {
            run.summary.reduced = Some(boot.clone());
            let _ = run.persist_summary();
        }
    }

    /// The network capture stops with this much of the quota left.
    pub(super) fn network_floor(&self) -> u64 {
        self.quota.reduced.network_floor(self.capture.quota())
    }

    /// The network capture was stopped for lack of room: say so in every run
    /// it hurt. True when that was the reduced mode's share, not a full quota.
    pub(super) fn note_network_stopped(&mut self) -> bool {
        let reduced = self.quota.reduced.active.is_some() && self.available() > 0;
        if reduced {
            let now = unix_ms();
            if let Some(boot) = self.quota.reduced.active.as_mut() {
                boot.network_stopped_ms.get_or_insert(now);
            }
            for run in self
                .runs
                .values_mut()
                .filter(|run| !run.recording_complete())
            {
                if let Some(record) = run.summary.reduced.as_mut() {
                    record.network_stopped_ms.get_or_insert(now);
                }
            }
        }
        reduced
    }

    /// The quota itself is full: the reduced recording ends with it.
    pub(super) fn note_reduced_full(&mut self) {
        let now = unix_ms();
        if let Some(boot) = self.quota.reduced.active.as_mut() {
            boot.full_at_ms.get_or_insert(now);
        }
        for run in self.runs.values_mut() {
            if let Some(record) = run.summary.reduced.as_mut() {
                record.full_at_ms.get_or_insert(now);
            }
        }
    }

    /// Write the summaries of runs whose reduced counts moved.
    pub(super) fn persist_reduced(&self) {
        for run in self.runs.values() {
            if run.summary.reduced.is_some() && !run.recording_complete() {
                let _ = run.persist_summary();
            }
        }
    }
}
