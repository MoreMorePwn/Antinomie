// SPDX-License-Identifier: GPL-3.0-only
//! How much of one run's telemetry never reached the host, counted from the
//! packets that did.
//!
//! The guest numbers every packet a task tries to send, whether or not it is
//! sent (`packet_seq`, one counter per task). A number missing between two
//! that arrived is a packet the guest dropped: a full ring it gave up on, a
//! full async staging queue, or a packet that waited for a launch's
//! acknowledgement too long. Packets after a task's last arrived one, and
//! tasks none of whose packets arrived, leave no gap, so the count is a lower
//! bound. Packets without a task (cookie 0, io_uring workers) are not counted.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Starts the note of a run some of whose telemetry was seen missing.
pub const TELEMETRY_LOSS_NOTE_PREFIX: &str = "Telemetry lost";

/// Tasks whose numbers are followed; packets of further tasks are counted as
/// received and their gaps are not looked for.
const MAX_TASKS: usize = 1 << 20;

/// One run's telemetry loss as far as the arrived packets show it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryLoss {
    /// Packets of the run the host received.
    pub received_packets: u64,
    /// Packets the run's tasks numbered that never arrived: at least this
    /// many were lost.
    pub lost_packets: u64,
    /// Packets of tasks past the tracking bound, whose gaps were not counted.
    pub untracked_packets: u64,
}

impl TelemetryLoss {
    /// The lost share of every packet the run's tasks numbered, in percent.
    pub fn percent(&self) -> f64 {
        let total = self.received_packets.saturating_add(self.lost_packets);
        if total == 0 {
            0.0
        } else {
            self.lost_packets as f64 * 100.0 / total as f64
        }
    }

    /// The run note for a loss; `None` when nothing was seen missing. It
    /// starts with [`TELEMETRY_LOSS_NOTE_PREFIX`], which the views and the
    /// report look for.
    pub fn note(&self) -> Option<String> {
        (self.lost_packets > 0).then(|| {
            format!(
                "{TELEMETRY_LOSS_NOTE_PREFIX}: {} of this run's telemetry never reached the host, at \
                 least {} of {} packets ({}); calls that lost packets show as incomplete, and calls \
                 that lost every packet are missing from the trace, the findings and the counts",
                percent_text(self.percent()),
                self.lost_packets,
                self.received_packets.saturating_add(self.lost_packets),
                if self.untracked_packets > 0 {
                    "more tasks than could be followed; the count covers the first 1,048,576"
                } else {
                    "a lower bound: packets after a task's last delivered one cannot be seen"
                }
            )
        })
    }
}

/// `12.3 %`, with more digits for a share under one percent.
fn percent_text(percent: f64) -> String {
    if percent >= 1.0 {
        format!("{percent:.1} %")
    } else {
        format!("{percent:.3} %")
    }
}

/// Follows each task's packet numbers as the run's packets arrive.
#[derive(Default)]
pub(crate) struct LossTracker {
    /// Per task cookie: the number before its first counted packet, the
    /// highest number seen and the packets received.
    tasks: HashMap<u64, (u64, u64, u64)>,
    totals: TelemetryLoss,
    /// The run continues an earlier recording segment (a reconnect or a
    /// restore): a task's numbers before its first packet here belong to that
    /// segment, not to this one's loss.
    continued: bool,
}

impl LossTracker {
    /// A tracker for a run that continues an earlier recording segment.
    pub fn continuing() -> Self {
        Self {
            continued: true,
            ..Self::default()
        }
    }
    /// One packet of the run arrived.
    pub fn packet(&mut self, task_cookie: u64, packet_seq: u64) {
        self.totals.received_packets = self.totals.received_packets.saturating_add(1);
        if task_cookie == 0 || packet_seq == 0 {
            return;
        }
        let len = self.tasks.len();
        let task = match self.tasks.get_mut(&task_cookie) {
            Some(task) => task,
            None if len >= MAX_TASKS => {
                self.totals.untracked_packets = self.totals.untracked_packets.saturating_add(1);
                return;
            }
            None => {
                let base = if self.continued { packet_seq - 1 } else { 0 };
                self.tasks.entry(task_cookie).or_insert((base, base, 0))
            }
        };
        let (base, highest, received) = *task;
        // Lost = numbers after the base up to the highest seen minus packets
        // received, per task; a late packet (another CPU's ring) fills its
        // gap, and one from before a continued run's base moves the base.
        let before = highest.saturating_sub(base).saturating_sub(received);
        let base = base.min(packet_seq - 1);
        let highest = highest.max(packet_seq);
        let received = received.saturating_add(1);
        *task = (base, highest, received);
        let after = highest.saturating_sub(base).saturating_sub(received);
        self.totals.lost_packets = self
            .totals
            .lost_packets
            .saturating_add(after)
            .saturating_sub(before);
    }

    pub fn totals(&self) -> TelemetryLoss {
        self.totals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaps_between_delivered_numbers_are_lost_packets() {
        let mut tracker = LossTracker::default();
        for seq in [1, 2, 5, 6] {
            tracker.packet(7, seq);
        }
        // Another task with no gap, and one whose first packets were lost.
        for seq in 1..=3 {
            tracker.packet(8, seq);
        }
        tracker.packet(9, 4);
        let totals = tracker.totals();
        assert_eq!(totals.received_packets, 8);
        assert_eq!(totals.lost_packets, 2 + 3);
        assert!((totals.percent() - 5.0 * 100.0 / 13.0).abs() < 1e-9);
        let note = totals.note().unwrap();
        assert!(
            note.starts_with("Telemetry lost: 38.5 % of this run's telemetry"),
            "{note}"
        );
        assert!(note.contains("at least 5 of 13 packets"));
    }

    #[test]
    fn a_late_packet_fills_its_gap() {
        let mut tracker = LossTracker::default();
        tracker.packet(7, 1);
        tracker.packet(7, 3);
        assert_eq!(tracker.totals().lost_packets, 1);
        tracker.packet(7, 2);
        assert_eq!(tracker.totals().lost_packets, 0);
        assert_eq!(tracker.totals().note(), None);
    }

    #[test]
    fn a_continued_run_counts_only_its_own_gaps() {
        let mut tracker = LossTracker::continuing();
        for seq in [500, 501, 504] {
            tracker.packet(7, seq);
        }
        assert_eq!(tracker.totals().lost_packets, 2);
        // A late packet from before the segment's first one is not a gap.
        tracker.packet(7, 499);
        assert_eq!(tracker.totals().lost_packets, 2);
    }

    #[test]
    fn packets_without_a_task_are_received_but_not_followed() {
        let mut tracker = LossTracker::default();
        tracker.packet(0, 9);
        tracker.packet(4, 0);
        assert_eq!(tracker.totals().received_packets, 2);
        assert_eq!(tracker.totals().lost_packets, 0);
    }

    #[test]
    fn a_small_share_keeps_its_digits() {
        let loss = TelemetryLoss {
            received_packets: 99_990,
            lost_packets: 10,
            untracked_packets: 0,
        };
        assert!(
            loss.note()
                .unwrap()
                .starts_with("Telemetry lost: 0.010 % of this run's")
        );
    }
}
