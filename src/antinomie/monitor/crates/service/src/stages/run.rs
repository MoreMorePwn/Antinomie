// SPDX-License-Identifier: GPL-3.0-only
//! `run` (design 4.1, 4.7; card P3-4c): let the program go until it ends or
//! the run limit, with cancellation and the watchdog.
//!
//! * The loop reads the run's state every 200 ms (and reads its terminal, or
//!   the engine drops the output, audit E17) and classifies it by
//!   [`phase`](crate::waiter::phase): `Ended` is the end of the stage;
//!   `FailedToStart` and `LaunchUnconfirmed` are `launch_failed`;
//!   `Interrupted`, a run that vanished, and a VM that stopped or failed
//!   under the program are `guest_lost`. So is a run the engine `Finalized`
//!   with the VM before the guest reported the program's end (QEMU killed),
//!   unless the stage had sent `StopRun` itself.
//! * At the limit (`run_s`, the spec's `timeout_s`) it sends `StopRun` once:
//!   SIGTERM, then SIGKILL after the engine's grace. **That is not a failure**:
//!   the run ends with `end_reason = time_limit`. A run that is still going
//!   120 s after `StopRun` is `guest_lost`.
//! * A cancel (polled through the waiter's hook) sends `StopRun` too and waits
//!   for the run to end, up to the same 120 s, then returns
//!   [`StageStop::Cancelled`]; the caller still stops the VM and flushes the
//!   recording.
//! * The engine answers a terminal read every 200 ms, so 60 s with nothing
//!   from it is a stuck engine: `internal`, the watchdog's silence rule.
use super::{LaneStages, Launched, Prepared, StageStop};
use crate::{
    api::{
        failure::{Failure, FailureCode},
        run::{EndReason, RecordingPhase, Run, RunProgram, Stage},
    },
    engine::Engine,
    store::JobPatch,
    waiter::{Phase, STOP_RUN_GRACE, phase},
    watchdog::{ENGINE_SILENCE, Watchdog},
};
use antinomie_monitor_core::{Command, RunSummary, WaitStatus};
use std::time::Duration;

/// How often the run is looked at.
const POLL: Duration = Duration::from_millis(200);

/// How often the disk floor is looked at while the program runs (4.6.3).
const FLOOR_EVERY_MS: u64 = 60_000;

/// How the run ended.
#[derive(Clone, Debug)]
pub struct RunEnd {
    pub run: RunSummary,
    pub reason: EndReason,
    pub exit: Option<i32>,
    pub signal: Option<i32>,
    pub core_dumped: bool,
}

fn fail(code: FailureCode, stage: Stage, message: &str, detail: Option<&str>) -> StageStop {
    StageStop::Failed(Failure::new(code, stage, message, detail))
}

impl<E: Engine> LaneStages<'_, E> {
    /// Take what the engine has said, noting that it spoke.
    fn listen(&mut self, dog: &mut Watchdog) -> Result<(), StageStop> {
        while self.waiter.pump(Duration::ZERO)?.is_some() {
            dog.heard(self.waiter.now_ms());
        }
        Ok(())
    }

    /// Listen to the engine for `every`, however many notifications arrive:
    /// the loops that poll the run and the evidence keep a steady pace.
    pub(crate) fn tick(&mut self, dog: &mut Watchdog, every: Duration) -> Result<(), StageStop> {
        let until = self.waiter.now_ms() + crate::waiter::millis(every);
        loop {
            let now = self.waiter.now_ms();
            if now >= until {
                return Ok(());
            }
            if self
                .waiter
                .pump(Duration::from_millis(until - now))?
                .is_some()
            {
                dog.heard(self.waiter.now_ms());
            }
        }
    }

    pub fn run(
        &mut self,
        job: &Run,
        prepared: &Prepared,
        launched: &Launched,
    ) -> Result<RunEnd, StageStop> {
        let run_id = launched.run.id.clone();
        let vm = launched.run.vm_id.clone();
        // The stage acts on a cancel itself: it must stop the run first.
        self.waiter.set_cancel_interrupts(false);
        let begun = self.waiter.now_ms();
        let limit_ms = crate::waiter::millis(prepared.effective.run_limit);
        let grace_ms = crate::waiter::millis(STOP_RUN_GRACE);
        // ENGINE_SILENCE stretched for a TCG boot, as the guest commands are.
        let silence = self.waiter.guest_wait(ENGINE_SILENCE);
        let mut dog = Watchdog::new(Stage::Run, begun, None, Some(silence));
        let mut stop_sent_ms: Option<u64> = None;
        let mut limit_stop = false;
        let mut floor_stop: Option<String> = None;
        let mut next_floor_ms = begun + FLOOR_EVERY_MS;
        let mut cancelled = false;

        let ended = loop {
            self.listen(&mut dog)?;
            let now = self.waiter.now_ms();
            if let Some(trigger) = dog.check(now) {
                self.mark_run_lost(job);
                return Err(fail(
                    FailureCode::Internal,
                    Stage::Run,
                    "the engine went silent while the program was running",
                    Some(&format!("{trigger:?}: nothing from the engine for 60 s")),
                ));
            }
            let Some(run) = self.waiter.run_of(&run_id) else {
                self.mark_run_lost(job);
                return Err(fail(
                    FailureCode::GuestLost,
                    Stage::Run,
                    "the run disappeared from the engine",
                    None,
                ));
            };
            match phase(&run) {
                Phase::Ended => break run,
                Phase::LaunchFailed => {
                    self.mark_run_lost(job);
                    return Err(fail(
                        FailureCode::LaunchFailed,
                        Stage::Launch,
                        "the program never started",
                        run.recording_error.as_deref(),
                    ));
                }
                // A run finalized with no task left after this stage sent
                // `StopRun` (limit, cancel, disk floor) ended as asked, as
                // before.
                Phase::Lost
                    if stop_sent_ms.is_some()
                        && run.state == antinomie_monitor_core::RunState::Finalized
                        && !run.held_open()
                        && run
                            .execution
                            .as_ref()
                            .is_none_or(|execution| execution.live_task_count == 0) =>
                {
                    break run;
                }
                Phase::Lost if self.vm_gone(&vm) => {
                    // The engine finalized the run because QEMU ended (killed,
                    // crashed): the guest is lost (P2, ANT-T0473).
                    return Err(self.vm_lost(job));
                }
                Phase::Lost => {
                    self.mark_run_lost(job);
                    return Err(fail(
                        FailureCode::GuestLost,
                        Stage::Run,
                        "the recording ended while the program was going",
                        run.recording_error.as_deref(),
                    ));
                }
                Phase::Live => {}
            }
            if self.vm_gone(&vm) {
                return Err(self.vm_lost(job));
            }
            if !cancelled && self.waiter.cancel_requested() {
                cancelled = true;
                self.progress(job, Stage::Run, "cancelled; stopping the run");
                if stop_sent_ms.is_none() {
                    stop_sent_ms = Some(now);
                    self.waiter.send(Command::StopRun {
                        run_id: run_id.clone(),
                    })?;
                }
            }
            // The disk floor (4.6.3) is looked at once a minute.
            if stop_sent_ms.is_none() && now >= next_floor_ms {
                next_floor_ms = now + FLOOR_EVERY_MS;
                if let Some(words) = self.env.host.low_disk() {
                    floor_stop = Some(words.clone());
                    stop_sent_ms = Some(now);
                    self.progress(
                        job,
                        Stage::Run,
                        "the disk is below its floor; stopping the run",
                    );
                    self.warn(job, "low_disk", &format!("the run was stopped: {words}"));
                    crate::resources::pause_for_low_disk(self.env.store, &words);
                    self.waiter.send(Command::StopRun {
                        run_id: run_id.clone(),
                    })?;
                }
            }
            let elapsed = now.saturating_sub(begun);
            if stop_sent_ms.is_none() && elapsed >= limit_ms {
                stop_sent_ms = Some(now);
                limit_stop = true;
                self.progress(
                    job,
                    Stage::Run,
                    "the run limit is reached; stopping the run",
                );
                self.waiter.send(Command::StopRun {
                    run_id: run_id.clone(),
                })?;
            }
            if stop_sent_ms.is_some_and(|sent| now >= sent + grace_ms) {
                self.mark_run_lost(job);
                if cancelled {
                    return Err(StageStop::Cancelled);
                }
                return Err(fail(
                    FailureCode::GuestLost,
                    Stage::Run,
                    "the run did not end after it was told to stop",
                    None,
                ));
            }
            // The terminal is dropped when nobody reads it (audit E17).
            self.waiter.send(Command::TerminalRead {
                run_id: run_id.clone(),
            })?;
            self.tick(&mut dog, POLL)?;
            self.waiter.discard_results();
        };

        // One last read so the tail holds the program's final lines.
        self.waiter.send(Command::TerminalRead {
            run_id: run_id.clone(),
        })?;
        self.waiter.pump(POLL)?;
        self.waiter.drain()?;
        self.waiter.discard_results();

        let (reason, exit, signal, core_dumped) = if cancelled || floor_stop.is_some() {
            (EndReason::Stopped, None, None, false)
        } else if limit_stop {
            (EndReason::TimeLimit, None, None, false)
        } else {
            match ended.execution.as_ref().and_then(|e| e.root_exit.as_ref()) {
                Some(WaitStatus::Exited { code }) => {
                    (EndReason::Exited, Some(i32::from(*code)), None, false)
                }
                Some(WaitStatus::Signaled {
                    signal,
                    core_dumped,
                }) => (
                    EndReason::Signaled,
                    None,
                    Some(i32::from(*signal)),
                    *core_dumped,
                ),
                None if ended.state == antinomie_monitor_core::RunState::Stopped => {
                    (EndReason::Stopped, None, None, false)
                }
                None => (EndReason::Exited, None, None, false),
            }
        };
        let end = RunEnd {
            run: ended,
            reason,
            exit,
            signal,
            core_dumped,
        };
        self.record_run_end(job, &end)?;
        if let Some(words) = floor_stop {
            // The warning made when the floor was hit is lost if the database
            // was full then; the job's `partial` rests on it.
            let stored = self
                .env
                .store
                .get(&job.id)
                .map_err(|e| self.store_error(Stage::Run, e))?;
            if !stored.warnings.iter().any(|w| w.code == "low_disk") {
                self.warn(job, "low_disk", &format!("the run was stopped: {words}"));
            }
        }
        if cancelled {
            return Err(StageStop::Cancelled);
        }
        Ok(end)
    }

    /// The lane VM is no longer the engine's running VM.
    fn vm_gone(&self, vm: &str) -> bool {
        let snapshot = self.waiter.snapshot();
        snapshot.active_vm.as_deref() != Some(vm)
            || matches!(
                snapshot.state,
                antinomie_monitor_core::VmState::Failed | antinomie_monitor_core::VmState::Stopped
            )
    }

    /// `guest_lost` for a VM that ended under the program.
    fn vm_lost(&self, job: &Run) -> StageStop {
        let detail = self.waiter.snapshot().last_error.clone();
        self.mark_run_lost(job);
        fail(
            FailureCode::GuestLost,
            Stage::Run,
            "the VM stopped while the program was running",
            detail.as_deref(),
        )
    }

    /// `run.program` gets its end, and the recording leaves `live`. On a full
    /// disk this waits for room (the run is over; the job's limit still
    /// holds), so a run stopped for the disk floor keeps its end.
    fn record_run_end(&mut self, job: &Run, end: &RunEnd) -> Result<(), StageStop> {
        let now = self.waiter.now_ms();
        let written = self.until_written(job, "the run's end", |this| {
            this.patch_run(job, |run| {
                run.ended_ms = Some(now);
                run.end_reason = Some(end.reason);
                run.exit = end.exit;
                run.signal = end.signal;
                run.core_dumped = end.core_dumped;
            })
            .and_then(|()| this.set_recording_phase(job, RecordingPhase::Finalizing))
        })?;
        written.map_err(|e| self.store_error(Stage::Run, e))
    }

    /// The program is gone with the guest: say so in the job's run record
    /// (best effort: the failure is the caller's).
    fn mark_run_lost(&self, job: &Run) {
        let now = self.waiter.now_ms();
        let _ = self.patch_run(job, |run| {
            run.ended_ms = Some(now);
            run.end_reason = Some(EndReason::GuestLost);
        });
        let _ = self.set_recording_phase(job, RecordingPhase::Interrupted);
    }

    pub(super) fn patch_run(
        &self,
        job: &Run,
        change: impl FnOnce(&mut RunProgram),
    ) -> Result<(), crate::api::error::ApiError> {
        let store = self.env.store;
        let Some(mut run) = store.get(&job.id)?.program else {
            return Ok(());
        };
        change(&mut run);
        store.patch(
            &job.id,
            JobPatch {
                run: Some(run),
                ..JobPatch::default()
            },
        )?;
        Ok(())
    }

    pub(crate) fn set_recording_phase(
        &self,
        job: &Run,
        phase: RecordingPhase,
    ) -> Result<(), crate::api::error::ApiError> {
        let store = self.env.store;
        let Some(mut recording) = store.get(&job.id)?.recording else {
            return Ok(());
        };
        recording.phase = phase;
        store.patch(
            &job.id,
            JobPatch {
                recording: Some(recording),
                ..JobPatch::default()
            },
        )?;
        Ok(())
    }

    /// A progress warning of the watchdog (one per quiet period).
    pub(crate) fn warn(&self, job: &Run, code: &str, text: &str) {
        let _ = self.env.store.add_warning(&job.id, code, text);
    }
}
