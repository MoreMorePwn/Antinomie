// SPDX-License-Identifier: GPL-3.0-only
//! `collect` (design 4.1; card P3-4c): make the recording complete and end the
//! boot.
//!
//! 1. Wait until no part of the run's evidence is still being written
//!    (network, memory, core; the rule of `guest-run.rs`, `pending_parts`),
//!    for at most `collect_s` (300 s). A part left `Partial`, `Interrupted` or
//!    `Failed` is not a failure: the job becomes `partial` with a warning
//!    (audit G6). Nothing heard from the engine for twice `stall_s` ends the
//!    wait early.
//! 2. `Stop`, answered within `stop_s` (120 s); an unanswered stop is the hard
//!    path (see [`super::cleanup`]) and the job `recording_failed`.
//! 3. Wait until the VM is stopped, the recording flush is over and the VM has
//!    no pending disk layer (`layer_s`, 1800 s). **Only then is the lane
//!    free**, because Triage reads the earlier bytes the layer copies.
//!
//! A cancel during step 1 skips the rest of the evidence wait; steps 2 and 3
//! always run, so the recording is kept. The caller labels the job
//! `cancelled`.
use super::{LaneStages, Launched, STOP_WAIT, StageStop, cleanup::Stopped};
use crate::{
    api::{
        failure::{Failure, FailureCode},
        job::{Job, Outcome, RecordingPhase, Stage},
    },
    engine::Engine,
    waiter::{EVIDENCE_WAIT, Warning, incomplete_parts, pending_parts},
    watchdog::{Trigger, Watchdog},
};
use antinomie_monitor_core::{RunArtifacts, VmState};
use std::time::Duration;

/// What `collect` leaves for the host stages.
#[derive(Clone, Debug)]
pub struct CollectEnd {
    /// `succeeded`, or `partial` when evidence is incomplete.
    pub outcome: Outcome,
    pub warnings: Vec<Warning>,
    pub artifacts: Option<RunArtifacts>,
    /// A cancel came in: the recording is kept, the job ends `cancelled`.
    pub cancelled: bool,
}

fn fail(code: FailureCode, message: &str, detail: Option<&str>) -> StageStop {
    StageStop::Failed(Failure::new(code, Stage::Collect, message, detail))
}

impl<E: Engine> LaneStages<'_, E> {
    pub fn collect(&mut self, job: &Job, launched: &Launched) -> Result<CollectEnd, StageStop> {
        let run_id = launched.run.id.clone();
        let vm = launched.run.vm_id.clone();
        self.waiter.set_cancel_interrupts(false);
        self.progress(job, Stage::Collect, "waiting for the evidence to complete");
        let began = self.waiter.now_ms();
        let mut dog = Watchdog::new(Stage::Collect, began, Some(EVIDENCE_WAIT), None);
        let mut cancelled = false;
        let mut warnings = Vec::new();
        let mut artifacts = None;
        loop {
            while self.waiter.pump(Duration::ZERO)?.is_some() {
                dog.heard(self.waiter.now_ms());
            }
            if self.waiter.cancel_requested() {
                cancelled = true;
                break;
            }
            let Some(run) = self.waiter.run_of(&run_id) else {
                return Err(fail(
                    FailureCode::GuestLost,
                    "the run disappeared from the engine",
                    None,
                ));
            };
            if self.waiter.snapshot().state == VmState::Failed {
                return Err(fail(
                    FailureCode::GuestLost,
                    "the VM failed before the evidence was complete",
                    self.waiter.snapshot().last_error.as_deref(),
                ));
            }
            let evidence = (self.env.evidence)(&run.directory).map_err(|error| {
                fail(
                    FailureCode::RecordingFailed,
                    "the run's evidence could not be read",
                    Some(&error),
                )
            })?;
            let pending = pending_parts(&run, evidence.as_ref());
            if pending.is_empty() {
                warnings = incomplete_parts(&run, evidence.as_ref());
                artifacts = evidence;
                break;
            }
            let now = self.waiter.now_ms();
            if dog.stall_warning(now) {
                self.warn(
                    job,
                    "collect_stalled",
                    "nothing from the engine for 120 seconds",
                );
            }
            match dog.check(now) {
                Some(Trigger::StageDeadline(_)) => {
                    return Err(fail(
                        FailureCode::RecordingFailed,
                        "the evidence did not complete in time",
                        Some(&format!("still pending: {}", pending.join(", "))),
                    ));
                }
                Some(Trigger::Stalled | Trigger::EngineSilent | Trigger::JobHard) => {
                    return Err(fail(
                        FailureCode::RecordingFailed,
                        "the engine went quiet while the evidence was being written",
                        Some(&format!("still pending: {}", pending.join(", "))),
                    ));
                }
                None => {}
            }
            self.tick(&mut dog, Duration::from_millis(100))?;
        }

        self.progress(
            job,
            Stage::Collect,
            "stopping the VM and saving the recording",
        );
        match self.stop_lane_vm(job, &vm, STOP_WAIT)? {
            Stopped::Settled => {}
            Stopped::Killed(how) => {
                return Err(fail(
                    FailureCode::RecordingFailed,
                    "the VM did not stop; it was ended by force",
                    Some(&how),
                ));
            }
            Stopped::Unsettled(why) => {
                return Err(fail(
                    FailureCode::RecordingFailed,
                    "the recording did not settle",
                    Some(&why),
                ));
            }
        }
        self.set_recording_phase(job, RecordingPhase::Complete)
            .map_err(|e| self.store_error(Stage::Collect, e))?;
        for warning in &warnings {
            let _ = self
                .env
                .store
                .add_warning(&job.id, &warning.code, &warning.text);
        }
        Ok(CollectEnd {
            outcome: if warnings.is_empty() {
                Outcome::Succeeded
            } else {
                Outcome::Partial
            },
            warnings,
            artifacts,
            cancelled,
        })
    }
}
