// SPDX-License-Identifier: GPL-3.0-only
//! What a running job learns on its way: the VM, the run, the recording, the
//! sample, warnings and the assessment (design 5.4.2).

use super::{
    R, Store, db,
    lifecycle::{conflict, current},
    model::{load_job, name_of, to_json},
};
use crate::api::{
    assessment::Assessment,
    event::EventBody,
    ids::RunId,
    run::{Run, RunProgram, RunRecording, RunSample, RunState, RunVm, Warning},
    spec::Route,
};

/// A warning list holds at most this many entries; the next is replaced by
/// one `warnings_truncated` entry (design 5.4.2).
pub const MAX_WARNINGS: usize = 1000;

/// Fields of the job a stage fills in. Absent members stay as they are.
#[derive(Clone, Debug, Default)]
pub struct JobPatch {
    pub sample: Option<RunSample>,
    pub vm: Option<RunVm>,
    pub run: Option<RunProgram>,
    pub recording: Option<RunRecording>,
}

fn live(id: &RunId, state: RunState, what: &str) -> R<()> {
    if matches!(state, RunState::Running | RunState::Cancelling) {
        Ok(())
    } else {
        Err(conflict(id, state, what))
    }
}

impl Store {
    /// Record the sample, VM, run or recording of a running job. No event:
    /// `run.program`, `run.artifact` and the others have their own calls.
    pub fn patch(&self, id: &RunId, patch: JobPatch) -> R<Run> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            live(id, cur.state, "be updated")?;
            if let Some(sample) = &patch.sample {
                tx.tx
                    .execute(
                        "UPDATE jobs SET sample_json = ?2, sha256 = ?3 WHERE id = ?1",
                        rusqlite::params![id.as_str(), to_json(sample)?, sample.sha256.as_str()],
                    )
                    .map_err(db)?;
            }
            if let Some(vm) = &patch.vm {
                tx.tx
                    .execute(
                        "UPDATE jobs SET vm_json = ?2, vm_id = ?3 WHERE id = ?1",
                        rusqlite::params![id.as_str(), to_json(vm)?, vm.id],
                    )
                    .map_err(db)?;
            }
            if let Some(run) = &patch.run {
                tx.tx
                    .execute(
                        "UPDATE jobs SET run_json = ?2 WHERE id = ?1",
                        rusqlite::params![id.as_str(), to_json(run)?],
                    )
                    .map_err(db)?;
            }
            if let Some(recording) = &patch.recording {
                tx.tx
                    .execute(
                        "UPDATE jobs SET recording_json = ?2, run_key = ?3 WHERE id = ?1",
                        rusqlite::params![
                            id.as_str(),
                            to_json(recording)?,
                            recording.recording_key
                        ],
                    )
                    .map_err(db)?;
                super::recordings::remember(tx, id, recording)?;
            }
            load_job(&tx.tx, id.as_str())
        })
    }

    /// The program started: `run.program`.
    pub fn emit_run_started(
        &self,
        id: &RunId,
        run_id: &str,
        pid: Option<u32>,
        route: Route,
    ) -> R<()> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            live(id, cur.state, "start a run")?;
            tx.emit(
                Some(id),
                EventBody::RunProgram {
                    program_id: run_id.to_owned(),
                    pid,
                    route,
                },
            )
        })
    }

    /// What the run's dump trigger did: one `run.trigger` event per dump and
    /// one per note (no host paths).
    pub fn emit_triggers(
        &self,
        id: &RunId,
        report: &crate::waiter::trigger::TriggerReport,
    ) -> R<()> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            live(id, cur.state, "report a dump trigger")?;
            for record in &report.records {
                tx.emit(
                    Some(id),
                    EventBody::RunTrigger {
                        trigger: Some(Box::new(crate::waiter::trigger::without_paths(record))),
                        note: None,
                    },
                )?;
            }
            for note in &report.notes {
                tx.emit(
                    Some(id),
                    EventBody::RunTrigger {
                        trigger: None,
                        note: Some(note.clone()),
                    },
                )?;
            }
            Ok(())
        })
    }

    /// A non-fatal note: appended to `warnings` and sent as `run.warning`.
    pub fn add_warning(&self, id: &RunId, code: &str, text: &str) -> R<()> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            live(id, cur.state, "take a warning")?;
            let stored: String = tx
                .tx
                .query_row(
                    "SELECT warnings_json FROM jobs WHERE id = ?1",
                    [id.as_str()],
                    |r| r.get(0),
                )
                .map_err(db)?;
            let mut warnings: Vec<Warning> = super::model::from_json(&stored)?;
            if warnings.len() > MAX_WARNINGS {
                return Ok(());
            }
            let warning = if warnings.len() == MAX_WARNINGS {
                Warning {
                    code: "warnings_truncated".into(),
                    text: format!("more than {MAX_WARNINGS} warnings; the rest are in job.log"),
                }
            } else {
                Warning {
                    code: code.to_owned(),
                    text: text.chars().take(1024).collect(),
                }
            };
            warnings.push(warning.clone());
            tx.tx
                .execute(
                    "UPDATE jobs SET warnings_json = ?2 WHERE id = ?1",
                    rusqlite::params![id.as_str(), to_json(&warnings)?],
                )
                .map_err(db)?;
            tx.emit(
                Some(id),
                EventBody::RunWarning {
                    code: warning.code,
                    text: warning.text,
                },
            )
        })
    }

    /// Triage finished: store the assessment and send `run.assessment`.
    pub fn set_assessment(&self, id: &RunId, assessment: &Assessment) -> R<Run> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            live(id, cur.state, "take an assessment")?;
            tx.tx
                .execute(
                    "UPDATE jobs SET assessment_json = ?2 WHERE id = ?1",
                    rusqlite::params![id.as_str(), to_json(assessment)?],
                )
                .map_err(db)?;
            tx.emit(
                Some(id),
                EventBody::RunAssessment {
                    assessment: Box::new(assessment.clone()),
                },
            )?;
            load_job(&tx.tx, id.as_str())
        })
    }

    /// `name_of` for the callers that store a label beside a job.
    pub fn wire_name<T: serde::Serialize>(value: &T) -> String {
        name_of(value)
    }
}
