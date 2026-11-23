// SPDX-License-Identifier: GPL-3.0-only
//! `launch` (design 4.1, audit G7): `Execute` with the exact request of
//! [`plan::effective`] and the library sample linked, then the run appears in
//! the snapshot (`launch_s` 30). A run that the engine already reports as
//! `FailedToStart` or `LaunchUnconfirmed` is `launch_failed`.
use super::{LaneStages, Launched, Prepared, Provisioned, StageStop};
use crate::waiter::WaitError;
use crate::{
    api::spec::Route,
    api::{
        failure::{Failure, FailureCode},
        run::{RecordingPhase, Run, RunProgram, RunRecording, Stage},
    },
    engine::Engine,
    query::key::RecordingKey,
    store::JobPatch,
    waiter::{Phase, phase, route_of},
};
use antinomie_monitor_core::{ExecRequest, RunSummary, samples::SampleRef};
use std::time::Duration;

/// How long a launch that needs the guest's process-core limits waits for
/// them on a guest the KVM speed boots: the guest reports them a moment after
/// it is up, on the first run after a boot just ahead of the launch (T0611,
/// F10). Under TCG the wait is stretched by the engine's multiplier.
const CORE_LIMITS_WAIT_S: f64 = 10.0;
/// The longest the wait gets, whatever the multiplier.
const CORE_LIMITS_WAIT_MAX_S: f64 = 120.0;

/// Whether a request needs the guest's process-core limits to be checked.
fn wants_core(request: &ExecRequest) -> bool {
    request.core_dump_on_exit || request.dump_trigger.as_ref().is_some_and(|plan| plan.core)
}

/// How long to wait for the guest's process-core limits before the launch:
/// none when the request takes no core or the limits are known.
pub(super) fn core_limits_wait(
    request: &ExecRequest,
    known: bool,
    tcg_factor: f64,
) -> Option<Duration> {
    (wants_core(request) && !known).then(|| {
        Duration::from_secs_f64(
            (CORE_LIMITS_WAIT_S * tcg_factor.max(1.0)).min(CORE_LIMITS_WAIT_MAX_S),
        )
    })
}

fn fail(message: &str, detail: Option<&str>) -> StageStop {
    StageStop::Failed(Failure::new(
        FailureCode::LaunchFailed,
        Stage::Launch,
        message,
        detail,
    ))
}

impl<E: Engine> LaneStages<'_, E> {
    pub fn launch(
        &mut self,
        job: &Run,
        prepared: &Prepared,
        provisioned: &Provisioned,
    ) -> Result<Launched, StageStop> {
        let guest_path = self.sample_path(job, prepared)?;
        let sample = job.sample.as_ref().expect("sample_path checked it");
        // A guest kernel that crashed while the VM booted (a clean snapshot
        // with a half-grown file system, ANT-T0476) still answers; the
        // program is not started in it.
        self.waiter.drain()?;
        if let Some(line) = self.waiter.kernel_crash() {
            return Err(StageStop::Failed(Failure::new(
                FailureCode::GuestUnreachable,
                Stage::Launch,
                crate::waiter::console::BOOT_CRASH,
                Some(&line),
            )));
        }
        let mut request = prepared.effective.request.clone();
        request.path = guest_path.clone();
        request.sample = Some(SampleRef {
            sha256: sample.sha256.to_string(),
            name: sample.name.clone(),
        });
        request
            .validate()
            .map_err(|message| fail("the launch request is refused", Some(&message)))?;
        // The library's copy vouches for the host copy and gives a refused
        // launch its static analysis (T0344); it is gone when the launch ends.
        let staged = crate::host_copy::StagedCopy::stage(self.env.data_dir, sample.sha256.as_str());
        request.host_copy = staged.as_ref().map(|copy| copy.path().to_owned());
        // The engine refuses a core it cannot check against the guest's
        // limits, and the guest reports them a moment after it is up: wait
        // for them (bounded) instead of failing the first run of a lane.
        if let Some(limit) = core_limits_wait(
            &request,
            self.waiter.snapshot().guest_core_limits.is_some(),
            self.env.triage.tcg_factor(),
        ) {
            match self.waiter.wait_until(
                "the guest's process-core limits",
                Some(limit),
                |snapshot| snapshot.guest_core_limits.is_some(),
            ) {
                // Past the limit the engine's own refusal says what is missing.
                Ok(()) | Err(WaitError::TimedOut { .. }) => {}
                Err(other) => {
                    drop(staged);
                    return Err(StageStop::Abort(other));
                }
            }
        }
        let launched = self.waiter.launch_request(request.clone());
        drop(staged);
        let run = launched?;
        if phase(&run) == Phase::LaunchFailed {
            return Err(StageStop::Failed(
                Failure::new(
                    FailureCode::LaunchFailed,
                    Stage::Launch,
                    "the program never started",
                    run.recording_error.as_deref(),
                )
                .with_run(&run.id),
            ));
        }
        let route = route_of(&request, &run);
        self.link_run(job, &run, route, RecordingPhase::Live)?;
        let _ = provisioned;
        Ok(Launched { run, guest_path })
    }

    /// A launch given up as silent that started the program after all (the
    /// lane has stopped the VM since, which ended it): the job names the run
    /// and says what happened, instead of leaving the recording unreported.
    pub(super) fn link_late_launch(&mut self, job: &Run) {
        let Some(run) = self.waiter.late_launch() else {
            return;
        };
        let route = route_of(&run.request, &run);
        let _ = self.link_run(job, &run, route, RecordingPhase::Interrupted);
        let warning = crate::waiter::late_launch_warning(&run.id);
        self.warn(job, &warning.code, &warning.text);
    }

    /// Record `run` as the job's run and recording, and say so on the stream.
    fn link_run(
        &mut self,
        job: &Run,
        run: &RunSummary,
        route: Route,
        phase: RecordingPhase,
    ) -> Result<(), StageStop> {
        let store = self.env.store;
        let now = self.waiter.now_ms();
        let key = RecordingKey::new(&run.vm_id, &run.boot_id, &run.id).map_err(|e| {
            self.internal(
                FailureCode::Internal,
                Stage::Launch,
                "the run has no usable key",
                Some(&e.to_string()),
            )
        })?;
        store
            .patch(
                &job.id,
                JobPatch {
                    run: Some(RunProgram {
                        id: run.id.clone(),
                        started_ms: Some(run.started_ms.unwrap_or(now)),
                        ended_ms: None,
                        end_reason: None,
                        exit: None,
                        signal: None,
                        core_dumped: false,
                        triggers: Vec::new(),
                        trigger_notes: Vec::new(),
                        pending: Vec::new(),
                    }),
                    recording: Some(RunRecording {
                        vm_id: run.vm_id.clone(),
                        boot_id: run.boot_id.clone(),
                        run_id: run.id.clone(),
                        recording_key: key.as_str().to_owned(),
                        phase,
                        directory: Some(run.directory.display().to_string()),
                    }),
                    ..JobPatch::default()
                },
            )
            .map_err(|e| self.store_error(Stage::Launch, e))?;
        store
            .emit_run_started(&job.id, &run.id, Some(run.pid).filter(|p| *p != 0), route)
            .map_err(|e| self.store_error(Stage::Launch, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::dump_trigger::DumpTrigger as DumpTriggerPlan;

    fn core_on_exit() -> ExecRequest {
        ExecRequest {
            core_dump_on_exit: true,
            ..ExecRequest::default()
        }
    }

    #[test]
    fn a_core_request_waits_for_limits_the_guest_has_not_reported() {
        let wait = core_limits_wait(&core_on_exit(), false, 1.0).unwrap();
        assert_eq!(wait, Duration::from_secs(10));
        let trigger = ExecRequest {
            dump_trigger: Some(DumpTriggerPlan {
                core: true,
                ..DumpTriggerPlan::default()
            }),
            ..ExecRequest::default()
        };
        assert!(core_limits_wait(&trigger, false, 1.0).is_some());
    }

    #[test]
    fn nothing_waits_when_no_core_is_asked_or_the_limits_are_known() {
        assert_eq!(core_limits_wait(&ExecRequest::default(), false, 1.0), None);
        assert_eq!(core_limits_wait(&core_on_exit(), true, 1.0), None);
        let memory_only = ExecRequest {
            dump_trigger: Some(DumpTriggerPlan {
                core: false,
                ..DumpTriggerPlan::default()
            }),
            ..ExecRequest::default()
        };
        assert_eq!(core_limits_wait(&memory_only, false, 1.0), None);
    }

    #[test]
    fn the_wait_stretches_under_tcg_up_to_a_bound() {
        assert_eq!(
            core_limits_wait(&core_on_exit(), false, 4.0),
            Some(Duration::from_secs(40))
        );
        assert_eq!(
            core_limits_wait(&core_on_exit(), false, 50.0),
            Some(Duration::from_secs(120))
        );
        // A factor under 1 never shortens it.
        assert_eq!(
            core_limits_wait(&core_on_exit(), false, 0.0),
            Some(Duration::from_secs(10))
        );
    }
}
