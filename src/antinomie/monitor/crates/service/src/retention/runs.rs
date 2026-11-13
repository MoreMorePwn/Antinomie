// SPDX-License-Identifier: GPL-3.0-only
//! What retention needs to know about a job's recorded run, and how it
//! deletes one. [`Runs`] is the seam; [`RealRuns`] works on the data folder
//! through the engine's own run deletion (`samples::delete_run_as`).

use crate::{
    api::run::Run,
    query::{QueryService, key::RecordingKey},
};
use antinomie_monitor_core::{
    BackendOptions, RunArtifacts,
    recording::read_only_locations,
    samples::{delete_run_as, plan_run_deletion},
};
use std::{collections::BTreeSet, path::PathBuf};

/// Where a job's recording stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    /// Deleted already, or never there.
    Gone,
    Present {
        /// Bytes of the run's own folder.
        bytes: u64,
        /// A capture, dump or core is still being written.
        in_progress: bool,
    },
}

pub trait Runs: Send + Sync {
    fn inspect(&self, job: &Run) -> Result<RunState, String>;
    /// Whether a read of the run is open now.
    fn is_open(&self, job: &Run) -> bool;
    /// Delete the run through the engine's own deletion; the bytes freed.
    fn delete(&self, job: &Run, actor: &str) -> Result<u64, String>;
}

pub struct RealRuns<'a> {
    pub options: &'a BackendOptions,
    /// The daemon's reads (their leases); `None` when no daemon runs.
    pub query: Option<&'a QueryService>,
}

impl RealRuns<'_> {
    /// The engine options of the folder that holds `job`'s run: its lane's
    /// (`<data>/lanes/N/`, `daemon::lanes::lane_options`), else the data
    /// folder's. A run stays in the folder of the lane that recorded it.
    fn options_for(&self, job: &Run) -> BackendOptions {
        match &job.lane {
            Some(lane) => crate::daemon::lanes::lane_options(self.options, lane),
            None => self.options.clone(),
        }
    }

    /// The recording folders of the VM that recorded `job`'s run, as the
    /// engine knows them (a VM's `recording_root` may be outside the data
    /// folder), real paths.
    fn recording_roots(&self, job: &Run) -> Vec<PathBuf> {
        let Some(recording) = &job.recording else {
            return Vec::new();
        };
        read_only_locations(&self.options_for(job))
            .unwrap_or_default()
            .into_iter()
            .filter(|location| location.vm_id == recording.vm_id)
            .flat_map(|location| location.recording_directories)
            .filter_map(|root| std::fs::canonicalize(root).ok())
            .collect()
    }

    /// The run's folder as the job names it, only when it is a plain folder
    /// inside the data folder or inside a recording folder of its VM.
    fn run_dir(&self, job: &Run) -> Result<Option<PathBuf>, String> {
        let Some(recording) = &job.recording else {
            return Ok(None);
        };
        let Some(directory) = &recording.directory else {
            return Ok(None);
        };
        let path = PathBuf::from(directory);
        if !path.is_absolute()
            || path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || path
                .file_name()
                .is_none_or(|n| n != recording.run_id.as_str())
        {
            return Err("the recorded folder is not the run's".into());
        }
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.to_string()),
            Ok(meta) if meta.is_dir() => {
                // The data folder may itself be reached through a link; what
                // matters is where the run's folder really is.
                let real = std::fs::canonicalize(&path).map_err(|e| e.to_string())?;
                let data =
                    std::fs::canonicalize(&self.options.data_dir).map_err(|e| e.to_string())?;
                if real.file_name() != path.file_name()
                    || !(real.starts_with(&data)
                        || self
                            .recording_roots(job)
                            .iter()
                            .any(|root| real.starts_with(root)))
                {
                    return Err(
                        "the run's folder is outside the data folder and its VM's recordings"
                            .into(),
                    );
                }
                Ok(Some(path))
            }
            Ok(_) => Err("the run's folder is a link or a file".into()),
        }
    }
}

impl Runs for RealRuns<'_> {
    fn inspect(&self, job: &Run) -> Result<RunState, String> {
        let Some(dir) = self.run_dir(job)? else {
            return Ok(RunState::Gone);
        };
        let in_progress = match RunArtifacts::load(&dir) {
            Ok(Some(artifacts)) => [
                artifacts.network_state,
                artifacts.memory_state,
                artifacts.core_state,
            ]
            .iter()
            .any(|state| state.in_progress()),
            Ok(None) => false,
            // Unreadable: treat as unfinished and leave it.
            Err(_) => true,
        };
        Ok(RunState::Present {
            bytes: crate::store::remove::folder_bytes(&dir),
            in_progress,
        })
    }

    fn is_open(&self, job: &Run) -> bool {
        let (Some(query), Some(recording)) = (self.query, &job.recording) else {
            return false;
        };
        RecordingKey::new(&recording.vm_id, &recording.boot_id, &recording.run_id)
            .map(|key| query.run_is_open(&key))
            // A key that cannot be built cannot be deleted either.
            .unwrap_or(true)
    }

    fn delete(&self, job: &Run, actor: &str) -> Result<u64, String> {
        let recording = job.recording.as_ref().ok_or("the job has no recording")?;
        let sample = job.sample.as_ref().ok_or("the job has no sample")?;
        let options = self.options_for(job);
        let plan = plan_run_deletion(
            &options,
            sample.sha256.as_str(),
            &recording.vm_id,
            &recording.run_id,
        )?;
        let vm_name = job
            .vm
            .as_ref()
            .map_or_else(|| recording.vm_id.clone(), |vm| vm.name.clone());
        delete_run_as(&options, &plan, &BTreeSet::new(), &vm_name, false, actor)
            .map(|done| done.freed)
    }
}
