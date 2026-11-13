// SPDX-License-Identifier: GPL-3.0-only
//! The job store as the query reads' job index (design 5.12.1): the job that
//! made a run, from `jobs.recording_key`, which the pipeline sets with the job's
//! `recording`. The daemon and the CLI's direct mode use the same index, so
//! `run list` shows the same `job_id` and `--job` finds the same runs.

use super::Store;
use crate::{
    api::ids::RunId,
    query::{JobIndex, key::RecordingKey},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// A [`JobIndex`] over a job store.
pub struct StoreJobIndex {
    store: Arc<Store>,
}

impl StoreJobIndex {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// The index of the store under `<data>/service`, opened for reading, or
    /// `None` when the data directory has no job store (nothing was ever
    /// submitted) or it cannot be read. Creates nothing.
    pub fn open_read_only(data_dir: &Path) -> Option<Self> {
        let service = data_dir.join("service");
        if !service.join("jobs.sqlite").is_file() {
            return None;
        }
        Store::open_read_only(&service)
            .ok()
            .map(|store| Self::new(Arc::new(store)))
    }
}

impl JobIndex for StoreJobIndex {
    fn job_of_run(&self, vm_id: &str, boot_id: &str, run_id: &str) -> Option<RunId> {
        let key = RecordingKey::new(vm_id, boot_id, run_id).ok()?;
        let conn = self.store.conn();
        // A run belongs to one attempt; if a repeat ever shares it, the newest
        // job (ids are time-ordered) is the one named.
        let id: String = conn
            .query_row(
                "SELECT id FROM jobs WHERE run_key = ?1 ORDER BY id DESC LIMIT 1",
                [key.as_str()],
                |row| row.get(0),
            )
            .ok()?;
        RunId::try_from(id).ok()
    }

    fn analysis_directory(&self, job: &RunId) -> Option<PathBuf> {
        let folder = self.store.job_dir(job).join("artifacts");
        folder.is_dir().then_some(folder)
    }
}
