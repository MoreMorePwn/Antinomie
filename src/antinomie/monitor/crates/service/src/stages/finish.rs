// SPDX-License-Identifier: GPL-3.0-only
//! `cleanup` (design 4.1; card P3-5): the end of a job that went through the
//! host stages.
//!
//! The lane forgets the job's `collected` entry, the job becomes terminal with
//! the outcome the stages settled (`job.finished`), and its `job.json` copy is
//! written into the job directory (4.9.3). Retention, notifications and the
//! result drop belong to the daemon cards; this stage never fails a job: a
//! file that cannot be written is left out and the job is final all the same.
//! (A warning cannot be added after the job is terminal, so the problem is
//! returned to the caller for its log.)
use super::{LaneStages, StageStop};
use crate::{
    api::{
        failure::Failure,
        job::{Job, Outcome, Stage},
    },
    engine::Engine,
    store::mirror::write_private,
};

impl<E: Engine> LaneStages<'_, E> {
    /// Release the lane's entry for `job` and end the job with `outcome`.
    /// The terminal job is returned with the problem, if any, of the copy
    /// written to its directory.
    pub(crate) fn end_job(
        &mut self,
        job: &Job,
        outcome: Outcome,
        failure: Option<Failure>,
    ) -> Result<(Job, Option<String>), StageStop> {
        let done = self
            .env
            .store
            .finish(&job.id, outcome, failure)
            .map_err(|e| self.store_error(Stage::Cleanup, e))?;
        // The job is final; a stale entry is dropped by recovery anyway.
        let now = self.waiter.now_ms();
        let _ = self.update_lane(|file| file.release(&job.id, now));
        let problem = serde_json::to_vec_pretty(&done)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                let dir = self.env.store.job_dir(&done.id);
                std::fs::create_dir_all(&dir)
                    .and_then(|()| write_private(&dir.join("job.json"), &bytes))
                    .map_err(|e| format!("job.json: {e}"))
            })
            .err();
        Ok((done, problem))
    }
}
