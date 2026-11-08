// SPDX-License-Identifier: GPL-3.0-only
//! The watchdog of a lane job (design 4.7.1; card P3-4c).
//!
//! Four things can go wrong without any stage noticing, and each has a rule:
//!
//! | Trigger | Rule | Result |
//! |---|---|---|
//! | the whole job | `job_hard_s` = the run limit plus 1800 s, from the first stage | [`Trigger::JobHard`]: the job is cancelled by the watchdog, the VM stopped, the job ends `failed` (`internal`, detail `watchdog`) |
//! | a stage | its own deadline (4.1) | [`Trigger::StageDeadline`] |
//! | the engine | during `run` the lane reads the terminal every 200 ms, so every second is answered; 60 s with nothing from the engine means it is stuck | [`Trigger::EngineSilent`] (`internal`) |
//! | a stage that reports progress | `stall_s` 120 s with nothing heard is a warning, twice that is a deadline (`collect` waits on the engine's snapshots) | [`Trigger::Stalled`] after a [`Watchdog::stall_warning`] |
//!
//! The struct only decides; it reads the clock it is given, so a test moves a
//! manual clock past each limit. The job deadline is enforced through the
//! waiter ([`crate::waiter::Waiter::deadline_in`]) so that it also ends the
//! waits of the stages that have no loop of their own.
use crate::api::job::Stage;
use std::time::Duration;

/// `job_hard_s` is the run limit plus this (design 4.7.1).
pub const JOB_HARD_EXTRA: Duration = Duration::from_secs(1800);
/// `stall_s` (design 4.7.1).
pub const STALL: Duration = Duration::from_secs(120);
/// The engine answers a terminal read every 200 ms during `run`.
pub use crate::waiter::LANE_SILENCE as ENGINE_SILENCE;
/// How long a hard path (killing the recorded QEMU) waits for the engine to
/// notice that the VM is gone.
pub const HARD_PATH_WAIT: Duration = Duration::from_secs(30);

/// `job_hard_s` for a job with this run limit.
pub fn job_hard(run_limit: Duration) -> Duration {
    run_limit + JOB_HARD_EXTRA
}

/// What the watchdog found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// The whole job passed `job_hard_s`.
    JobHard,
    StageDeadline(Stage),
    /// Nothing at all from the engine for [`ENGINE_SILENCE`].
    EngineSilent,
    /// Nothing heard for twice [`STALL`].
    Stalled,
}

#[derive(Clone, Debug)]
pub struct Watchdog {
    stage: Stage,
    stage_deadline_ms: Option<u64>,
    last_heard_ms: u64,
    silence_ms: Option<u64>,
    warned: bool,
}

fn ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl Watchdog {
    /// Watch `stage`, which may last `deadline` (none: no stage deadline) and
    /// during which the engine is expected to speak at least every `silence`
    /// (none: the stall rule applies instead).
    pub fn new(
        stage: Stage,
        now_ms: u64,
        deadline: Option<Duration>,
        silence: Option<Duration>,
    ) -> Self {
        Self {
            stage,
            stage_deadline_ms: deadline.map(|d| now_ms + ms(d)),
            last_heard_ms: now_ms,
            silence_ms: silence.map(ms),
            warned: false,
        }
    }

    /// The engine said something (any notification).
    pub fn heard(&mut self, now_ms: u64) {
        self.last_heard_ms = now_ms;
        self.warned = false;
    }

    /// True once, when nothing was heard for [`STALL`]: a warning for the job.
    pub fn stall_warning(&mut self, now_ms: u64) -> bool {
        if self.silence_ms.is_none()
            && !self.warned
            && now_ms.saturating_sub(self.last_heard_ms) >= ms(STALL)
        {
            self.warned = true;
            return true;
        }
        false
    }

    /// Whether a limit has passed.
    pub fn check(&self, now_ms: u64) -> Option<Trigger> {
        if self.stage_deadline_ms.is_some_and(|d| now_ms >= d) {
            return Some(Trigger::StageDeadline(self.stage));
        }
        let quiet = now_ms.saturating_sub(self.last_heard_ms);
        match self.silence_ms {
            Some(limit) if quiet >= limit => Some(Trigger::EngineSilent),
            None if quiet >= 2 * ms(STALL) => Some(Trigger::Stalled),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1000;

    #[test]
    fn the_job_limit_is_the_run_limit_plus_half_an_hour() {
        assert_eq!(
            job_hard(Duration::from_secs(300)),
            Duration::from_secs(2100)
        );
    }

    #[test]
    fn a_stage_past_its_deadline_is_found() {
        let mut dog = Watchdog::new(Stage::Collect, 0, Some(Duration::from_secs(300)), None);
        dog.heard(290 * S);
        assert_eq!(dog.check(299 * S), None);
        assert_eq!(
            dog.check(300 * S),
            Some(Trigger::StageDeadline(Stage::Collect))
        );
    }

    #[test]
    fn sixty_seconds_without_the_engine_is_silence_but_hearing_it_resets() {
        let mut dog = Watchdog::new(Stage::Run, 0, None, Some(ENGINE_SILENCE));
        assert_eq!(dog.check(59 * S), None);
        dog.heard(59 * S);
        assert_eq!(dog.check(118 * S), None);
        assert_eq!(dog.check(119 * S), Some(Trigger::EngineSilent));
    }

    #[test]
    fn a_quiet_stage_warns_at_the_stall_period_and_is_past_deadline_at_twice_it() {
        let mut dog = Watchdog::new(Stage::Collect, 0, None, None);
        assert!(!dog.stall_warning(119 * S));
        assert!(dog.stall_warning(120 * S));
        assert!(!dog.stall_warning(121 * S), "one warning per quiet period");
        assert_eq!(dog.check(239 * S), None);
        assert_eq!(dog.check(240 * S), Some(Trigger::Stalled));
        dog.heard(240 * S);
        assert_eq!(dog.check(241 * S), None);
        assert!(dog.stall_warning(360 * S), "a new quiet period warns again");
    }

    #[test]
    fn the_stall_warning_belongs_to_stages_without_a_silence_rule() {
        let mut dog = Watchdog::new(Stage::Run, 0, None, Some(ENGINE_SILENCE));
        assert!(!dog.stall_warning(200 * S));
    }
}
