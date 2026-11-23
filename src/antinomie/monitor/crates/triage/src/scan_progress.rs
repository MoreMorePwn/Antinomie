// SPDX-License-Identifier: GPL-3.0-only
//! What a whole-run index is doing, for a screen that waits for it (the export
//! dialog): the phase and how far it has got. The worker writes it with plain
//! atomics; the screen reads it every frame. A large recording takes minutes,
//! and "Working" with a spinner says nothing about whether it is alive.
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
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
pub struct ScanProgress {
    phase: AtomicU8,
    done: AtomicU64,
    total: AtomicU64,
    /// A read is waiting for the run's index (another reader or a build of
    /// it holds the index).
    waiting: AtomicBool,
}

impl ScanProgress {
    /// A phase begins with `total` units to do (0 when unknown).
    pub fn begin(&self, phase: Phase, total: u64) {
        self.done.store(0, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        self.phase.store(phase as u8, Ordering::Relaxed);
    }

    /// The next phase over the same units.
    pub fn next(&self, phase: Phase) {
        self.done.store(0, Ordering::Relaxed);
        self.phase.store(phase as u8, Ordering::Relaxed);
    }

    pub fn advance(&self, units: u64) {
        self.done.fetch_add(units, Ordering::Relaxed);
    }

    /// Index bytes: `done` of `total`.
    pub fn set(&self, phase: Phase, done: u64, total: u64) {
        self.phase.store(phase as u8, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        self.done.store(done, Ordering::Relaxed);
    }

    /// Units done and units in the phase (0 when unknown).
    pub fn counts(&self) -> (u64, u64) {
        (
            self.done.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
        )
    }

    /// A read of the run's index is waiting (`true`) or got in (`false`).
    pub fn set_waiting(&self, waiting: bool) {
        self.waiting.store(waiting, Ordering::Relaxed);
    }

    pub fn phase(&self) -> Phase {
        Phase::of(self.phase.load(Ordering::Relaxed))
    }

    /// The line for the dialog, or `None` before the first phase begins.
    pub fn text(&self) -> Option<String> {
        let done = self.done.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        let share = |done: u64, total: u64| {
            done.min(total)
                .checked_mul(100)
                .and_then(|scaled| scaled.checked_div(total))
                .map_or_else(String::new, |percent| format!(" ({percent}%)"))
        };
        if self.phase() != Phase::Idle && self.waiting.load(Ordering::Relaxed) {
            return Some("Waiting for the run's index".into());
        }
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

/// A size and time budget for one scan: the passes over the calls stop at
/// the first page past `max_calls` calls, or when the time runs out, and the
/// index says it is partial. Both passes read one prefix of the run: pass 1
/// has [`PASS_ONE_SHARE`] of the time (it reads about a quarter as fast per
/// call as pass 2 costs), and the call count it reached when its share ran
/// out is where pass 2 stops too, unless the whole time runs out first. The
/// background digest build and Auto Triage (ANT-T0612) use it so a recording
/// of millions of calls costs a bounded amount of time and memory.
#[derive(Debug)]
pub struct ScanStop {
    max_calls: std::sync::atomic::AtomicU64,
    started: std::time::Instant,
    limit: std::time::Duration,
    /// Pass 2 has begun: the whole time is its deadline.
    second: std::sync::atomic::AtomicBool,
    calls_hit: std::sync::atomic::AtomicBool,
    time_hit: std::sync::atomic::AtomicBool,
    /// What the budget is for, in the reason: "building the digest".
    what: &'static str,
}

/// The part of a time budget pass 1 may take.
pub const PASS_ONE_SHARE: f64 = 0.25;

impl ScanStop {
    pub fn new(max_calls: u64, limit: std::time::Duration) -> Self {
        Self {
            max_calls: max_calls.into(),
            started: std::time::Instant::now(),
            limit,
            second: Default::default(),
            calls_hit: Default::default(),
            time_hit: Default::default(),
            what: "building the digest",
        }
    }

    /// A time budget for Auto Triage.
    pub fn triage(limit: std::time::Duration) -> Self {
        Self {
            what: "Triage",
            ..Self::new(u64::MAX, limit)
        }
    }

    /// Pass 2 begins.
    pub fn second_pass(&self) {
        self.second.store(true, Ordering::Relaxed);
    }

    /// Whether a pass that has read `calls` calls is to stop; remembers why.
    pub fn reached(&self, calls: u64) -> bool {
        let max = self.max_calls.load(Ordering::Relaxed);
        if calls >= max {
            if !self.time_hit.load(Ordering::Relaxed) {
                self.calls_hit.store(true, Ordering::Relaxed);
            }
            return true;
        }
        let second = self.second.load(Ordering::Relaxed);
        let deadline = if second {
            self.limit
        } else {
            self.limit.mul_f64(PASS_ONE_SHARE)
        };
        if self.started.elapsed() >= deadline {
            self.time_hit.store(true, Ordering::Relaxed);
            if !second {
                // Pass 2 reads the same prefix.
                self.max_calls.fetch_min(calls, Ordering::Relaxed);
            }
            return true;
        }
        false
    }

    /// Why a pass stopped, in plain words; `None` when no pass did.
    pub fn reason(&self) -> Option<String> {
        if self.time_hit.load(Ordering::Relaxed) {
            Some(format!(
                "the time budget for {} ({}) ran out before the end of the recording",
                self.what,
                antinomie_monitor_core::time_span::seconds(self.limit.as_secs())
            ))
        } else if self.calls_hit.load(Ordering::Relaxed) {
            Some(format!(
                "the digest was built from the first {} calls of the recording (the size budget)",
                count(self.max_calls.load(Ordering::Relaxed))
            ))
        } else {
            None
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
    fn a_time_budget_ends_both_passes_at_one_prefix() {
        let stop = ScanStop::triage(std::time::Duration::from_millis(800));
        assert!(!stop.reached(10));
        // Pass 1's share runs out at call 500: pass 2 reads the same 500.
        std::thread::sleep(std::time::Duration::from_millis(250));
        assert!(stop.reached(500));
        stop.second_pass();
        assert!(!stop.reached(499));
        assert!(stop.reached(500));
        let reason = stop.reason().unwrap();
        assert!(reason.starts_with("the time budget for Triage"), "{reason}");
        // And the whole time ends pass 2 wherever it is.
        std::thread::sleep(std::time::Duration::from_millis(600));
        assert!(stop.reached(10));
    }

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
    fn a_read_waiting_for_the_index_says_so_instead_of_its_count() {
        let progress = ScanProgress::default();
        progress.begin(Phase::Reading, 1_527_986);
        progress.advance(1_024);
        progress.set_waiting(true);
        assert_eq!(progress.text().unwrap(), "Waiting for the run's index");
        progress.set_waiting(false);
        assert_eq!(
            progress.text().unwrap(),
            "Reading the calls, pass 1 of 2: 1,024 of 1,527,986 (0%)"
        );
    }

    #[test]
    fn counts_have_thousands_separators() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1000), "1,000");
        assert_eq!(count(1_234_567), "1,234,567");
    }
}
