// SPDX-License-Identifier: GPL-3.0-only
//! What a whole-run index is doing, for a screen that waits for it (the export
//! dialog): the phase and how far it has got. The worker writes it with plain
//! atomics; the screen reads it every frame. A large recording takes minutes,
//! and "Working" with a spinner says nothing about whether it is alive.
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Phase {
    Idle = 0,
    /// The telemetry is read once into the on-disk call index: bytes.
    Indexing = 1,
    /// First pass over the calls (processes, rules): calls.
    Reading = 2,
    /// Second pass over the calls (files): calls.
    Files = 3,
    /// The network capture, the datasets and the findings.
    Settling = 4,
}

impl Phase {
    fn of(value: u8) -> Self {
        match value {
            1 => Self::Indexing,
            2 => Self::Reading,
            3 => Self::Files,
            4 => Self::Settling,
            _ => Self::Idle,
        }
    }
}

#[derive(Default)]
pub(crate) struct ScanProgress {
    phase: AtomicU8,
    done: AtomicU64,
    total: AtomicU64,
}

impl ScanProgress {
    /// A phase begins with `total` units to do (0 when unknown).
    pub(crate) fn begin(&self, phase: Phase, total: u64) {
        self.done.store(0, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        self.phase.store(phase as u8, Ordering::Relaxed);
    }

    /// The next phase over the same units.
    pub(crate) fn next(&self, phase: Phase) {
        self.done.store(0, Ordering::Relaxed);
        self.phase.store(phase as u8, Ordering::Relaxed);
    }

    pub(crate) fn advance(&self, units: u64) {
        self.done.fetch_add(units, Ordering::Relaxed);
    }

    /// Index bytes: `done` of `total`.
    pub(crate) fn set(&self, phase: Phase, done: u64, total: u64) {
        self.phase.store(phase as u8, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        self.done.store(done, Ordering::Relaxed);
    }

    pub(crate) fn phase(&self) -> Phase {
        Phase::of(self.phase.load(Ordering::Relaxed))
    }

    /// The line for the dialog, or `None` before the first phase begins.
    pub(crate) fn text(&self) -> Option<String> {
        let done = self.done.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        let share = |done: u64, total: u64| {
            done.min(total)
                .checked_mul(100)
                .and_then(|scaled| scaled.checked_div(total))
                .map_or_else(String::new, |percent| format!(" ({percent}%)"))
        };
        match self.phase() {
            Phase::Idle => None,
            Phase::Indexing if total > 0 => Some(format!(
                "Indexing the telemetry: {} of {}{}",
                antinomie_monitor_core::byte_size::short_size(done),
                antinomie_monitor_core::byte_size::short_size(total),
                share(done, total)
            )),
            Phase::Indexing => Some("Indexing the telemetry".into()),
            Phase::Reading => Some(format!(
                "Reading the calls, pass 1 of 2: {} of {}{}",
                count(done),
                count(total),
                share(done, total)
            )),
            Phase::Files => Some(format!(
                "Reading the files, pass 2 of 2: {} of {}{}",
                count(done),
                count(total),
                share(done, total)
            )),
            Phase::Settling => Some("Reading the network capture and settling the findings".into()),
        }
    }
}

/// `1,234,567`.
fn count(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (at, digit) in digits.chars().enumerate() {
        if at > 0 && (digits.len() - at).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_names_the_phase_and_how_far_it_got() {
        let progress = ScanProgress::default();
        assert_eq!(progress.text(), None);
        progress.set(Phase::Indexing, 1_073_741_824, 3_221_225_472);
        assert_eq!(
            progress.text().unwrap(),
            "Indexing the telemetry: 1.0 GiB of 3.0 GiB (33%)"
        );
        progress.begin(Phase::Reading, 1_200_000);
        progress.advance(300_000);
        assert_eq!(
            progress.text().unwrap(),
            "Reading the calls, pass 1 of 2: 300,000 of 1,200,000 (25%)"
        );
        progress.next(Phase::Files);
        assert!(progress
            .text()
            .unwrap()
            .starts_with("Reading the files, pass 2 of 2: 0 of 1,200,000"));
        progress.begin(Phase::Settling, 0);
        assert!(progress.text().unwrap().contains("settling"));
    }

    #[test]
    fn counts_have_thousands_separators() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1000), "1,000");
        assert_eq!(count(1_234_567), "1,234,567");
    }
}
