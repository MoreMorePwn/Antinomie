// SPDX-License-Identifier: GPL-3.0-only
//! Capture All load shedding, only when the VM's transport settings allow it.
//!
//! Capture All of a busy guest (a desktop) can produce telemetry faster than
//! the host decodes and saves it. Never-drop sends then make every traced
//! system call wait for room and the guest slows down, a desktop to the point
//! of not responding. That lag is the price of losing nothing, so by default
//! nothing changes: the host only says that never-drop is slowing the guest.
//! With [`TransportSettings::capture_all_shed`] on, while Capture All runs and
//! the host falls behind, senders drop instead of waiting (each drop is counted
//! as lost telemetry); never-drop returns once the host has caught up.
//!
//! [`TransportSettings::capture_all_shed`]: crate::api::TransportSettings::capture_all_shed
use std::time::{Duration, Instant};

/// Shed when this much recording waits for the disk, or the guest's senders
/// together waited this share of the time; resume below the lower backlog.
const SHED_BACKLOG: usize = 64 * 1024 * 1024;
const RESUME_BACKLOG: usize = 16 * 1024 * 1024;
const SHED_WAIT_SHARE: f64 = 0.5;
const SHED_MIN: Duration = Duration::from_secs(2);
/// How often the guest's send wait is turned into a share of wall time.
const SAMPLE: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug)]
pub(crate) struct Shed {
    active: bool,
    since: Instant,
    /// The guest's total send wait at `sampled`, and the share of wall time
    /// it spent waiting since the sample before.
    sampled: Instant,
    sampled_wait_ns: u64,
    wait_share: f64,
}

impl Default for Shed {
    fn default() -> Self {
        Self {
            active: false,
            since: Instant::now(),
            sampled: Instant::now(),
            sampled_wait_ns: 0,
            wait_share: 0.0,
        }
    }
}

/// What the host sees at one drain pass.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reading {
    pub now: Instant,
    /// The guest's total send wait so far.
    pub wait_ns: u64,
    /// The configured send wait, microseconds (0: drop mode).
    pub send_wait_us: u32,
    /// The VM's settings allow Capture All to shed.
    pub allowed: bool,
    /// Capture All is running.
    pub capture_all: bool,
    /// Recording bytes queued for the disk writer.
    pub backlog: usize,
}

/// A send-wait change the host has to publish to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    /// Drop instead of waiting (send wait 0).
    Start,
    /// Wait again (the configured send wait), after a spell this long.
    Stop(Duration),
}

impl Shed {
    pub(crate) fn active(&self) -> bool {
        self.active
    }

    /// Takes one reading and says whether the send wait must change; the
    /// change counts once [`Self::apply`] is called after it was published.
    pub(crate) fn decide(&mut self, reading: Reading) -> Option<Change> {
        let elapsed = reading.now.saturating_duration_since(self.sampled);
        if elapsed >= SAMPLE {
            let waited = reading.wait_ns.saturating_sub(self.sampled_wait_ns);
            self.wait_share = waited as f64 / elapsed.as_nanos().max(1) as f64;
            self.sampled = reading.now;
            self.sampled_wait_ns = reading.wait_ns;
        }
        let behind = reading.backlog > SHED_BACKLOG || self.wait_share > SHED_WAIT_SHARE;
        if !self.active
            && reading.allowed
            && reading.send_wait_us > 0
            && reading.capture_all
            && behind
        {
            Some(Change::Start)
        } else if self.active
            && (!reading.allowed
                || !reading.capture_all
                || (reading.backlog < RESUME_BACKLOG
                    && reading.now.saturating_duration_since(self.since) >= SHED_MIN))
        {
            Some(Change::Stop(
                reading.now.saturating_duration_since(self.since),
            ))
        } else {
            None
        }
    }

    /// Records a change the guest has been told about.
    pub(crate) fn apply(&mut self, change: Change, now: Instant) {
        match change {
            Change::Start => {
                self.active = true;
                self.since = now;
            }
            Change::Stop(_) => {
                self.active = false;
                self.wait_share = 0.0;
            }
        }
    }

    /// Never-drop is holding the guest back under Capture All: its senders
    /// waited more than half the time and nothing is being shed.
    pub(crate) fn slowing(&self, reading: &Reading) -> bool {
        !self.active
            && reading.capture_all
            && reading.send_wait_us > 0
            && self.wait_share > SHED_WAIT_SHARE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Capture All whose guest senders wait 80 % of the time for a second.
    fn behind(shed: &mut Shed, allowed: bool) -> (Option<Change>, Reading) {
        let start = Instant::now();
        *shed = Shed {
            sampled: start,
            since: start,
            ..Shed::default()
        };
        let reading = Reading {
            now: start + Duration::from_secs(1),
            wait_ns: 800_000_000,
            send_wait_us: 5_000_000,
            allowed,
            capture_all: true,
            backlog: 0,
        };
        (shed.decide(reading), reading)
    }

    #[test]
    fn never_drop_is_kept_under_capture_all_unless_shedding_is_allowed() {
        let mut shed = Shed::default();
        let (change, reading) = behind(&mut shed, false);
        assert_eq!(change, None);
        assert!(!shed.active());
        assert!(shed.slowing(&reading), "the slowed guest is reported");
        // A backlog far past the writer's limit does not start it either.
        let backlog = Reading {
            backlog: SHED_BACKLOG * 4,
            ..reading
        };
        assert_eq!(shed.decide(backlog), None);
    }

    #[test]
    fn allowed_shedding_starts_when_behind_and_stops_after_catching_up() {
        let mut shed = Shed::default();
        let (change, reading) = behind(&mut shed, true);
        assert_eq!(change, Some(Change::Start));
        shed.apply(Change::Start, reading.now);
        assert!(shed.active());
        assert!(!shed.slowing(&reading), "it sheds instead");
        // Caught up, but not for the shortest spell yet.
        let early = Reading {
            now: reading.now + Duration::from_millis(100),
            ..reading
        };
        assert_eq!(shed.decide(early), None);
        let later = Reading {
            now: reading.now + SHED_MIN,
            ..reading
        };
        assert_eq!(shed.decide(later), Some(Change::Stop(SHED_MIN)));
        shed.apply(Change::Stop(SHED_MIN), later.now);
        assert!(!shed.active());
    }

    #[test]
    fn shedding_needs_capture_all_and_never_drop() {
        let mut shed = Shed::default();
        let (_, reading) = behind(&mut shed, true);
        let launch_only = Reading {
            capture_all: false,
            ..reading
        };
        assert_eq!(shed.decide(launch_only), None);
        assert!(!shed.slowing(&launch_only));
        let drop_mode = Reading {
            send_wait_us: 0,
            ..reading
        };
        assert_eq!(shed.decide(drop_mode), None);
        assert!(!shed.slowing(&drop_mode));
        // A spell under way ends when the setting is turned off.
        shed.apply(Change::Start, reading.now);
        let refused = Reading {
            allowed: false,
            ..reading
        };
        assert!(matches!(shed.decide(refused), Some(Change::Stop(_))));
    }
}
