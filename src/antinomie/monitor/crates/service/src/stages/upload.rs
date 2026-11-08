// SPDX-License-Identifier: GPL-3.0-only
//! `upload` (design 4.1): the library sample goes into the guest, decrypted in
//! memory only, to `<guest_dir>/<sha8>-<name>`. The first upload after boot
//! fails for about a second while the disk mounts and is retried inside
//! `upload_s` (60 s plus one second per 10 MiB).
use super::{
    LaneStages, Prepared, StageStop,
    plan::{guest_path, upload_wait},
};
use crate::{
    api::{
        failure::{Failure, FailureCode},
        job::{Job, Stage},
    },
    engine::Engine,
};

impl<E: Engine> LaneStages<'_, E> {
    /// The guest path the job's sample takes.
    pub fn sample_path(&self, job: &Job, prepared: &Prepared) -> Result<String, StageStop> {
        let sample = job.sample.as_ref().ok_or_else(|| {
            StageStop::Failed(Failure::new(
                FailureCode::Internal,
                Stage::Upload,
                "the job has no library sample",
                None,
            ))
        })?;
        Ok(guest_path(
            &prepared.effective.guest_dir,
            sample.sha256.as_str(),
            &sample.name,
        ))
    }

    pub fn upload(&mut self, job: &Job, prepared: &Prepared) -> Result<(), StageStop> {
        let destination = self.sample_path(job, prepared)?;
        let sample = job.sample.as_ref().expect("sample_path checked it");
        let store = self.env.store;
        let id = job.id.clone();
        let mut sink = |body: crate::api::event::EventBody| {
            if matches!(body, crate::api::event::EventBody::JobProgress { .. }) {
                store.publish_ephemeral(&id, body);
            }
        };
        let message = self.waiter.upload_sample(
            sample.sha256.as_str(),
            &destination,
            upload_wait(sample.size),
            &mut sink,
        )?;
        // "uploaded N bytes to PATH": a different size is a damaged transfer.
        if let Some(sent) = message
            .strip_prefix("uploaded ")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok())
            && sent != sample.size
        {
            return Err(StageStop::Failed(Failure::new(
                FailureCode::UploadFailed,
                Stage::Upload,
                "the guest holds a different number of bytes than the sample has",
                Some(&format!(
                    "{sent} bytes sent, the sample has {}",
                    sample.size
                )),
            )));
        }
        Ok(())
    }
}
