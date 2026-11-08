// SPDX-License-Identifier: GPL-3.0-only
//! `launch` (design 4.1, audit G7): `Execute` with the exact request of
//! [`plan::effective`] and the library sample linked, then the run appears in
//! the snapshot (`launch_s` 30). A run that the engine already reports as
//! `FailedToStart` or `LaunchUnconfirmed` is `launch_failed`.
use super::{LaneStages, Launched, Prepared, Provisioned, StageStop};
use crate::{
    api::{
        failure::{Failure, FailureCode},
        job::{Job, JobRecording, JobRun, RecordingPhase, Stage},
    },
    engine::Engine,
    query::key::RunKey,
    store::JobPatch,
    waiter::{Phase, phase, route_of},
};
use antinomie_monitor_core::samples::SampleRef;

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
        job: &Job,
        prepared: &Prepared,
        provisioned: &Provisioned,
    ) -> Result<Launched, StageStop> {
        let guest_path = self.sample_path(job, prepared)?;
        let sample = job.sample.as_ref().expect("sample_path checked it");
        let mut request = prepared.effective.request.clone();
        request.path = guest_path.clone();
        request.sample = Some(SampleRef {
            sha256: sample.sha256.to_string(),
            name: sample.name.clone(),
        });
        request
            .validate()
            .map_err(|message| fail("the launch request is refused", Some(&message)))?;
        let run = self.waiter.launch_request(request.clone())?;
        if phase(&run) == Phase::LaunchFailed {
            return Err(fail(
                "the program never started",
                run.recording_error.as_deref(),
            ));
        }
        let route = route_of(&request, &run);
        let store = self.env.store;
        let now = self.waiter.now_ms();
        let key = RunKey::new(&run.vm_id, &run.boot_id, &run.id).map_err(|e| {
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
                    run: Some(JobRun {
                        run_id: run.id.clone(),
                        started_ms: Some(run.started_ms.unwrap_or(now)),
                        ended_ms: None,
                        end_reason: None,
                        exit: None,
                        signal: None,
                        core_dumped: false,
                    }),
                    recording: Some(JobRecording {
                        vm_id: run.vm_id.clone(),
                        boot_id: run.boot_id.clone(),
                        run_id: run.id.clone(),
                        run_key: key.as_str().to_owned(),
                        phase: RecordingPhase::Live,
                        directory: Some(run.directory.display().to_string()),
                    }),
                    ..JobPatch::default()
                },
            )
            .map_err(|e| self.store_error(Stage::Launch, e))?;
        store
            .emit_run_started(&job.id, &run.id, Some(run.pid).filter(|p| *p != 0), route)
            .map_err(|e| self.store_error(Stage::Launch, e))?;
        let _ = provisioned;
        Ok(Launched { run, guest_path })
    }
}
