// SPDX-License-Identifier: GPL-3.0-only
//! Gaps between the host's telemetry ring reads.
//!
//! A guest sender whose ring is full waits for the host to read; when the
//! host reads nothing for its whole send wait, the sender drops the record.
//! The recording writer's backlog explains some of those pauses (see
//! `Health::writer_held_ns`); the others are the transport thread itself being
//! away, busy elsewhere or not scheduled. [`ReadGapTracker`] times every pause
//! between two read attempts that exceeds a threshold and says what the thread
//! was doing meanwhile, so a dropped record can be tied to the pause that
//! caused it. The tracker reads the clock once per read attempt and keeps its
//! records in a fixed buffer: no allocation, locking or logging per read.
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    os::unix::fs::FileExt,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Pauses kept in full; past this the shortest are only counted.
pub const MAX_RECORDED_GAPS: usize = 256;
/// Longest threshold, and the shortest: half the guest's send wait in between.
const MAX_THRESHOLD: Duration = Duration::from_millis(50);
const MIN_THRESHOLD: Duration = Duration::from_millis(10);

/// What the transport thread was doing while it read nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapCause {
    #[default]
    Unknown,
    /// Telemetry was held back because the recording writer was behind the disk.
    WriterBacklog,
    /// The thread waited for the recording writer's queue or a barrier.
    WriterWait,
    /// Inside a drain pass: processing, flushing or saving, not reading.
    Pump,
    /// The host was reading, but not from this ring: its head packet waited
    /// while the rings were merged in timestamp order.
    RingStarved,
    /// Outside the drain pass, the thread was runnable but not given a CPU.
    Scheduler,
    /// Outside the drain pass, the thread ran other work (commands, publishing).
    Busy,
    /// Outside the drain pass, the thread slept or blocked (a lock, a disk).
    Blocked,
}

impl GapCause {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::WriterBacklog => "writer backlog",
            Self::WriterWait => "writer wait",
            Self::Pump => "drain pass work",
            Self::RingStarved => "ring not served",
            Self::Scheduler => "not scheduled",
            Self::Busy => "other host work",
            Self::Blocked => "blocked",
        }
    }
}

/// One pause between telemetry reads: of all the rings, or (`ring` set) of one
/// ring whose head packet waited while the host read other rings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReadGap {
    /// Guest time the pause started at, at the earliest: the newest packet
    /// timestamp read before it (a timestamp is when an event began, so the
    /// pause can have started a little later). For a ring pause, the newest
    /// timestamp read minus the wait.
    pub guest_ns: u64,
    /// Host wall clock at the start of the pause.
    pub start_unix_ms: u64,
    pub len_ns: u64,
    pub cause: GapCause,
    /// The vCPU ring a `RingStarved` pause is about.
    pub ring: Option<u32>,
    /// Of the pause: waiting for the writer, inside drain passes, and (for
    /// the part outside them) running on a CPU or runnable without one.
    pub blocked_ns: u64,
    pub pump_ns: u64,
    pub cpu_ns: u64,
    pub sched_delay_ns: u64,
}

/// The pauses of one boot's transport.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReadGapStats {
    /// Pauses at least this long are recorded.
    pub threshold_ns: u64,
    pub count: u64,
    pub total_ns: u64,
    pub longest_ns: u64,
    /// Pauses counted but not kept because the buffer held longer ones.
    pub unrecorded: u64,
    pub gaps: Vec<ReadGap>,
}

impl ReadGapStats {
    fn record(&mut self, gap: ReadGap) {
        self.count = self.count.saturating_add(1);
        self.total_ns = self.total_ns.saturating_add(gap.len_ns);
        self.longest_ns = self.longest_ns.max(gap.len_ns);
        if self.gaps.capacity() == 0 {
            self.gaps.reserve_exact(MAX_RECORDED_GAPS);
        }
        if self.gaps.len() < MAX_RECORDED_GAPS {
            self.gaps.push(gap);
            return;
        }
        let shortest = self
            .gaps
            .iter()
            .enumerate()
            .min_by_key(|(_, kept)| kept.len_ns)
            .map(|(index, _)| index)
            .unwrap_or_default();
        if self.gaps[shortest].len_ns < gap.len_ns {
            self.gaps[shortest] = gap;
        }
        self.unrecorded = self.unrecorded.saturating_add(1);
    }

    /// Pauses by cause: (cause, count, total ns), most time first.
    pub fn by_cause(&self) -> Vec<(GapCause, u64, u64)> {
        let mut causes: Vec<(GapCause, u64, u64)> = Vec::new();
        for gap in &self.gaps {
            match causes.iter_mut().find(|(cause, ..)| *cause == gap.cause) {
                Some(entry) => {
                    entry.1 += 1;
                    entry.2 = entry.2.saturating_add(gap.len_ns);
                }
                None => causes.push((gap.cause, 1, gap.len_ns)),
            }
        }
        causes.sort_by_key(|(_, _, total)| std::cmp::Reverse(*total));
        causes
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Run time and run-queue delay of a thread, from `/proc/.../schedstat`.
#[derive(Clone, Copy, Default)]
struct Sched {
    cpu_ns: u64,
    delay_ns: u64,
}

struct SchedFile(File);

impl SchedFile {
    fn open() -> Option<Self> {
        File::open("/proc/thread-self/schedstat").ok().map(Self)
    }

    fn sample(&self) -> Option<Sched> {
        let mut buffer = [0u8; 96];
        let length = self.0.read_at(&mut buffer, 0).ok()?;
        let mut fields = buffer[..length]
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .map(|field| {
                field.iter().try_fold(0u64, |value, digit| match digit {
                    b'0'..=b'9' => Some(
                        value
                            .checked_mul(10)?
                            .checked_add(u64::from(digit - b'0'))?,
                    ),
                    _ => None,
                })
            });
        Some(Sched {
            cpu_ns: fields.next()??,
            delay_ns: fields.next()??,
        })
    }
}

/// Follows the transport thread's drain passes and read attempts.
#[derive(Default)]
pub(crate) struct ReadGapTracker {
    last_read: Option<Instant>,
    /// The newest guest timestamp read from any ring.
    newest_guest_ns: u64,
    held: bool,
    blocked_at_read: Duration,
    /// Time inside finished drain passes, and the clock of the running one.
    pump_clock: Duration,
    pass_start: Option<Instant>,
    pump_at_read: Duration,
    sched: Option<Option<SchedFile>>,
    exit_sample: Option<Sched>,
    outside: Sched,
    threshold: Duration,
}

impl ReadGapTracker {
    /// A drain pass starts; `held` says it will not read for the writer.
    pub(crate) fn enter(&mut self, now: Instant, held: bool) {
        self.pass_start = Some(now);
        self.held |= held;
        if let (Some(before), Some(now)) = (self.exit_sample, self.sample()) {
            self.outside.cpu_ns += now.cpu_ns.saturating_sub(before.cpu_ns);
            self.outside.delay_ns += now.delay_ns.saturating_sub(before.delay_ns);
        }
    }

    /// The drain pass ended.
    pub(crate) fn exit(&mut self, now: Instant) {
        if let Some(start) = self.pass_start.take() {
            self.pump_clock += now.saturating_duration_since(start);
        }
        self.exit_sample = self.sample();
    }

    /// The pause length that is recorded follows the guest's send wait.
    pub(crate) fn set_send_wait(&mut self, send_wait_us: u32) {
        self.threshold = if send_wait_us == 0 {
            MAX_THRESHOLD
        } else {
            Duration::from_micros(u64::from(send_wait_us) / 2).clamp(MIN_THRESHOLD, MAX_THRESHOLD)
        };
    }

    /// The transport is new (a reconnect): nothing before it is a pause.
    pub(crate) fn reset(&mut self) {
        self.last_read = None;
        self.held = false;
        self.exit_sample = None;
        self.outside = Sched::default();
    }

    /// The timestamp of the packet just read.
    pub(crate) fn packet(&mut self, guest_ns: u64) {
        self.newest_guest_ns = self.newest_guest_ns.max(guest_ns);
    }

    /// The packet just read had waited `wait_ns` at the head of ring `ring`
    /// while the host took others (see `Transport::last_read`).
    pub(crate) fn ring_wait(&mut self, ring: u32, wait_ns: u64, stats: &mut ReadGapStats) {
        if wait_ns < stats.threshold_ns.max(1) {
            return;
        }
        stats.record(ReadGap {
            guest_ns: self.newest_guest_ns.saturating_sub(wait_ns),
            start_unix_ms: unix_ms().saturating_sub(wait_ns / 1_000_000),
            len_ns: wait_ns,
            cause: GapCause::RingStarved,
            ring: Some(ring),
            ..ReadGap::default()
        });
    }

    /// A read attempt at `now`; `blocked` is the thread's total time waiting
    /// for the recording writer.
    pub(crate) fn read(&mut self, now: Instant, blocked: Duration, stats: &mut ReadGapStats) {
        let threshold = if self.threshold.is_zero() {
            MAX_THRESHOLD
        } else {
            self.threshold
        };
        stats.threshold_ns = threshold.as_nanos() as u64;
        let pump = self.pump_clock
            + self
                .pass_start
                .map_or(Duration::ZERO, |start| now.saturating_duration_since(start));
        if let Some(last) = self.last_read {
            let length = now.saturating_duration_since(last);
            if length >= threshold {
                let gap = self.gap(length, blocked, pump);
                stats.record(gap);
            }
        }
        self.last_read = Some(now);
        self.blocked_at_read = blocked;
        self.pump_at_read = pump;
        self.held = false;
        self.outside = Sched::default();
    }

    fn gap(&self, length: Duration, blocked: Duration, pump: Duration) -> ReadGap {
        let blocked = blocked.saturating_sub(self.blocked_at_read);
        let pump = pump.saturating_sub(self.pump_at_read);
        let len_ns = length.as_nanos() as u64;
        let cause = if self.held {
            GapCause::WriterBacklog
        } else if blocked * 2 >= length {
            GapCause::WriterWait
        } else if pump * 2 >= length {
            GapCause::Pump
        } else if u128::from(self.outside.delay_ns) * 2 >= length.as_nanos() {
            GapCause::Scheduler
        } else if u128::from(self.outside.cpu_ns) * 2 >= length.as_nanos() {
            GapCause::Busy
        } else {
            GapCause::Blocked
        };
        ReadGap {
            guest_ns: self.newest_guest_ns,
            start_unix_ms: unix_ms().saturating_sub(length.as_millis() as u64),
            len_ns,
            cause,
            ring: None,
            blocked_ns: blocked.as_nanos() as u64,
            pump_ns: pump.as_nanos() as u64,
            cpu_ns: self.outside.cpu_ns,
            sched_delay_ns: self.outside.delay_ns,
        }
    }

    fn sample(&mut self) -> Option<Sched> {
        self.sched
            .get_or_insert_with(SchedFile::open)
            .as_ref()
            .and_then(SchedFile::sample)
    }
}

#[cfg(test)]
mod tests;
