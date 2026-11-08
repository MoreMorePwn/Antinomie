// SPDX-License-Identifier: GPL-3.0-only
//! What the host stages touch outside the engine and the store (design 4.1
//! `analyse`, `report`; card P3-5).
//!
//! [`HostTriage`] is the seam to the Triage crate: the same builders the GUI
//! and `antinomie-cli triage/detect/report` call (`SavedRun`, the scan, the
//! detection request, the report builder and writer). The real one is
//! [`RealTriage`]; a test can wrap it and replace one step (a scan that never
//! ends, a report that cannot be written). [`SampleTags`] is the seam to the
//! library for the one thing the service writes there on its own.
use crate::{api::job::Job, custody};
use antinomie_monitor_core::{
    BackendOptions,
    analysis::detection::Engine,
    ioc::feeds,
    recording::{find_run_read_only, read_only_locations},
    report::{Choices, Report, Summary, export::Written},
    samples::{Library, Tag, TagKind},
};
use antinomie_triage::{
    ArchiveScan, SavedRun,
    detection::{self, Keep, Outcome},
    report_export, time_format,
};
use std::sync::{Arc, atomic::AtomicBool};

/// The library tag a sample gets when it ended the guest twice (design 4.7.2).
pub const CRASHES_GUEST_TAG: &str = "auto:crashes-guest";

/// The built report: what the assessment reads, and what the writer needs.
pub struct Built {
    /// Kept for [`HostTriage::write`].
    pub job: report_export::Job,
    pub built: report_export::build::Built,
}

impl Built {
    pub fn report(&self) -> &Report {
        &self.built.report
    }

    pub fn summary(&self) -> Summary {
        self.built.report.summary.clone().unwrap_or_default()
    }
}

pub trait HostTriage: Send + Sync {
    /// The saved run of the job's recording, read without writing into it.
    fn open_run(&self, job: &Job) -> Result<SavedRun, String>;
    /// Index the whole run (the GUI's scan).
    fn index(&self, saved: &SavedRun, cancel: &Arc<AtomicBool>) -> Result<ArchiveScan, String>;
    /// Run the engines over the run and keep their results in the recording.
    fn detect(
        &self,
        saved: &SavedRun,
        scan: &ArchiveScan,
        engines: &[Engine],
        cancel: &Arc<AtomicBool>,
    ) -> Result<Vec<(Engine, Outcome)>, String>;
    /// Write the run's digest (behaviour, lineage, files, indicators and the
    /// engines' matches).
    fn save_digest(
        &self,
        saved: &SavedRun,
        scan: &ArchiveScan,
        outcomes: &[(Engine, Outcome)],
    ) -> Result<(), String>;
    /// Build the report for `choices`.
    fn build(
        &self,
        saved: &SavedRun,
        scan: &ArchiveScan,
        choices: Choices,
        now_ms: u64,
    ) -> Result<Built, String>;
    /// Write what [`build`](Self::build) built into the choices' folder.
    fn write(&self, built: Built, cancel: &Arc<AtomicBool>) -> Result<Written, String>;
    /// How many stored indicator datasets are switched on and usable.
    fn ioc_datasets(&self) -> u32;
}

/// The Triage crate itself, on the data directory of `options`.
pub struct RealTriage {
    pub options: BackendOptions,
}

impl RealTriage {
    pub fn new(options: BackendOptions) -> Self {
        Self { options }
    }
}

impl HostTriage for RealTriage {
    fn open_run(&self, job: &Job) -> Result<SavedRun, String> {
        let recording = job
            .recording
            .as_ref()
            .ok_or("the job has no recording to read")?;
        let location = read_only_locations(&self.options)
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|location| location.vm_id == recording.vm_id)
            .ok_or_else(|| format!("the data directory has no VM {}", recording.vm_id))?;
        let run = find_run_read_only(&location, &recording.boot_id, &recording.run_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("the recording of run {} is gone", recording.run_id))?;
        if run.root_task_cookie == 0 {
            return Err(
                "the run has no recorded program (it never started): there is nothing to triage"
                    .into(),
            );
        }
        SavedRun::open(run, &self.options)
    }

    fn index(&self, saved: &SavedRun, cancel: &Arc<AtomicBool>) -> Result<ArchiveScan, String> {
        saved.scan(cancel)
    }

    fn detect(
        &self,
        saved: &SavedRun,
        _scan: &ArchiveScan,
        engines: &[Engine],
        cancel: &Arc<AtomicBool>,
    ) -> Result<Vec<(Engine, Outcome)>, String> {
        let settings = detection::headless_settings(&self.options.data_dir)?;
        detection::detect_saved(saved, engines, &settings, Keep::Save, cancel, &|_| {})
    }

    fn save_digest(
        &self,
        saved: &SavedRun,
        scan: &ArchiveScan,
        outcomes: &[(Engine, Outcome)],
    ) -> Result<(), String> {
        let settings = detection::headless_settings(&self.options.data_dir)?;
        detection::save_digest(saved, scan, &settings, outcomes)
    }

    fn build(
        &self,
        saved: &SavedRun,
        scan: &ArchiveScan,
        choices: Choices,
        now_ms: u64,
    ) -> Result<Built, String> {
        let job = report_export::Job::for_saved(saved, choices, now_ms);
        let (job, built) = report_export::build_report(&job, scan)?;
        Ok(Built { job, built })
    }

    fn write(&self, built: Built, cancel: &Arc<AtomicBool>) -> Result<Written, String> {
        std::fs::create_dir_all(&built.job.folder)
            .map_err(|e| format!("{}: {e}", built.job.folder.display()))?;
        report_export::write_built(&built.job, built.built, cancel, &|_| {})
    }

    fn ioc_datasets(&self) -> u32 {
        feeds::status(&self.options.data_dir)
            .iter()
            .filter(|feed| feed.usable())
            .count() as u32
    }
}

/// The wall-clock time Triage stamps a report with.
pub fn now_ms() -> u64 {
    time_format::now_ms()
}

/// Tags a library sample on the service's own account.
pub trait SampleTags: Send + Sync {
    /// Add `tag` to the sample of `job`, under `actor` in the custody log.
    /// Returns whether it was added (false: it was there already).
    fn add_tag(&self, job: &Job, tag: &str) -> Result<bool, String>;
}

/// The library of a data directory.
pub struct LibraryTags {
    pub data_dir: std::path::PathBuf,
}

impl SampleTags for LibraryTags {
    fn add_tag(&self, job: &Job, tag: &str) -> Result<bool, String> {
        let sample = job.sample.as_ref().ok_or("the job has no sample")?;
        let mut library =
            Library::open(&self.data_dir)?.with_actor(&custody::automation_actor(job))?;
        library.add_tag(sample.sha256.as_str(), Tag::new(TagKind::Custom, tag))
    }
}

/// No library: tags are not written.
pub struct NoTags;

impl SampleTags for NoTags {
    fn add_tag(&self, _: &Job, _: &str) -> Result<bool, String> {
        Ok(false)
    }
}
