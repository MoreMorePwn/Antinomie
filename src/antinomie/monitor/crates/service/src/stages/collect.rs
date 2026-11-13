// SPDX-License-Identifier: GPL-3.0-only
//! `collect` (design 4.1; card P3-4c): make the recording complete and end the
//! boot.
//!
//! 1. Wait until no part of the run's evidence is still being written
//!    (network, memory, core; the rule of `guest-run.rs`, `pending_parts`),
//!    for at most `collect_s` (300 s). A part left `Partial`, `Interrupted` or
//!    `Failed` is not a failure: the job becomes `partial` with a warning
//!    (audit G6). Nothing heard from the engine for twice `stall_s` ends the
//!    wait early. After a run stopped for the disk floor, a VM that failed or
//!    evidence still pending at `collect_s` is the warning
//!    `evidence_incomplete`, not a failure: the job is `partial` (4.6.3).
//! 2. `Stop`, answered within `stop_s` (120 s); an unanswered stop is the hard
//!    path (see [`super::cleanup`]) and the job `recording_failed`.
//! 3. Wait until the VM is stopped, the recording flush is over and the VM has
//!    no pending disk layer (`layer_s`, 1800 s). **Only then is the lane
//!    free**, because Triage reads the earlier bytes the layer copies. With
//!    the disk below its floor the wait ends after a minute and the job is
//!    `recording_failed` (see [`super::cleanup`]).
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
    waiter::{EVIDENCE_WAIT, Warning, incomplete_parts, may_stay_pending, pending_parts, trigger},
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
    /// Evidence saved without: `analysis` still running at the wait's end.
    pub pending: Vec<String>,
    pub artifacts: Option<RunArtifacts>,
    /// A cancel came in: the recording is kept, the job ends `cancelled`.
    pub cancelled: bool,
}

fn fail(code: FailureCode, message: &str, detail: Option<&str>) -> StageStop {
    StageStop::Failed(Failure::new(code, Stage::Collect, message, detail))
}

impl<E: Engine> LaneStages<'_, E> {
    /// What the policy's dump trigger did goes into the job's run and on the
    /// event stream (best effort: the evidence itself is already kept).
    fn record_triggers(&self, job: &Job, run_id: &str, artifacts: Option<&RunArtifacts>) {
        let Some(run) = self.waiter.run_of(run_id) else {
            return;
        };
        let Some(report) = trigger::report(&run, artifacts) else {
            return;
        };
        let _ = self.patch_run(job, |job_run| {
            job_run.triggers = report.records.clone();
            job_run.trigger_notes = report.notes.clone();
        });
        let _ = self.env.store.emit_triggers(&job.id, &report);
    }

    pub fn collect(&mut self, job: &Job, launched: &Launched) -> Result<CollectEnd, StageStop> {
        let run_id = launched.run.id.clone();
        let vm = launched.run.vm_id.clone();
        self.waiter.set_cancel_interrupts(false);
        self.progress(job, Stage::Collect, "waiting for the evidence to complete");
        let began = self.waiter.now_ms();
        let mut dog = Watchdog::new(Stage::Collect, began, Some(EVIDENCE_WAIT), None);
        let mut cancelled = false;
        let mut warnings = Vec::new();
        let mut left_pending: Vec<String> = Vec::new();
        let mut artifacts = None;
        // A run stopped for the disk floor ends the job `partial` (design
        // 4.6.3): a VM that failed on the full disk after the stop, or
        // evidence the full disk kept from completing, are warnings then.
        let floor_stopped = self.floor_stopped(job);
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
            let vm_failed = self.waiter.snapshot().state == VmState::Failed;
            if vm_failed && !floor_stopped {
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
            let late = self.waiter.now_ms() >= began + EVIDENCE_WAIT.as_millis() as u64;
            let cut_by_floor = floor_stopped && (vm_failed || late) && !pending.is_empty();
            if pending.is_empty() || (late && may_stay_pending(&pending)) || cut_by_floor {
                left_pending = pending.iter().map(|part| (*part).to_owned()).collect();
                warnings = incomplete_parts(&run, evidence.as_ref());
                if cut_by_floor {
                    let why = if vm_failed {
                        let error = self.waiter.snapshot().last_error.clone();
                        format!(
                            "the VM failed after the run was stopped for the disk floor ({})",
                            error.as_deref().unwrap_or("no error given")
                        )
                    } else {
                        "the run was stopped for the disk floor".to_owned()
                    };
                    warnings.push(Warning {
                        code: "evidence_incomplete".into(),
                        text: format!("{why}; saved without: {}", pending.join(", ")),
                    });
                }
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

        if !left_pending.is_empty() {
            self.progress(
                job,
                Stage::Collect,
                &format!(
                    "saving the recording without: {} (still running after the collect wait)",
                    left_pending.join(", ")
                ),
            );
        }
        // A guest kernel that crashed and went on (an oops) still answers:
        // the console says so, and the job does not pass for a clean one.
        if let Some(line) = self.waiter.kernel_crash() {
            warnings.push(Warning {
                code: "guest_kernel_crashed".into(),
                text: format!("the guest kernel crashed during the run: {line}"),
            });
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
            Stopped::Deferred(words) => {
                return Err(fail(
                    FailureCode::RecordingFailed,
                    "the recording could not be finished: the disk is below its floor",
                    Some(&words),
                ));
            }
        }
        self.record_triggers(job, &run_id, artifacts.as_ref());
        self.set_recording_phase(job, RecordingPhase::Complete)
            .map_err(|e| self.store_error(Stage::Collect, e))?;
        if !left_pending.is_empty() {
            let _ = self.patch_run(job, |job_run| job_run.pending = left_pending.clone());
        }
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
            pending: left_pending,
            artifacts,
            cancelled,
        })
    }
}
