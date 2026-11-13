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
use super::online::OnlineAccess;
use crate::{api::run::Run, custody};
use antinomie_monitor_core::{
    BackendOptions,
    analysis::detection::Engine,
    api_keys::{self, ApiKey},
    ioc::{feeds, online},
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
    fn open_run(&self, job: &Run) -> Result<SavedRun, String>;
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
    /// Make the run's digest when it has none, from a budgeted read of the
    /// recording (`antinomie_triage::digest_job`): the scan did not leave one
    /// (Triage was not planned, it failed or ran out of time). `Some` says what
    /// is missing from it (partial, unreadable); `None` means it is whole or
    /// was there already. The same build the window and `antinomie-cli digest`
    /// make.
    fn ensure_digest(
        &self,
        _job: &Run,
        _cancel: &Arc<AtomicBool>,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }
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
    /// How much a busy host stretches the static tools' time (1 when idle):
    /// the same factor the guest waits use. Fakes keep the default so tests
    /// do not depend on the load of the machine they run on.
    fn load_scale(&self) -> f64 {
        1.0
    }
    /// The key and the sender of Check online ([`super::online`]). The
    /// default has no key, so a fake sends nothing unless it says so.
    fn online_access(&self) -> OnlineAccess {
        OnlineAccess::none()
    }
}

/// The Triage crate itself, on the data directory of `options`.
pub struct RealTriage {
    pub options: BackendOptions,
    /// `service.toml [privacy] address_lookup`.
    pub address_lookup: antinomie_monitor_core::settings::AddressLookup,
    /// The engine options of the other lanes (several lanes, ANT-T0455 card
    /// C): a job's run is in the data folder of the lane that ran it.
    pub lanes: Vec<(crate::api::ids::LaneId, BackendOptions)>,
}

impl RealTriage {
    pub fn new(options: BackendOptions) -> Self {
        Self {
            options,
            address_lookup: antinomie_monitor_core::settings::AddressLookup::Tshark,
            lanes: Vec::new(),
        }
    }

    pub fn with_lanes(mut self, lanes: Vec<(crate::api::ids::LaneId, BackendOptions)>) -> Self {
        self.lanes = lanes;
        self
    }

    /// The options of the data folder that holds `job`'s run: its lane's,
    /// else lane 1's.
    pub fn options_for(&self, job: &Run) -> &BackendOptions {
        job.lane
            .as_ref()
            .and_then(|lane| self.lanes.iter().find(|(id, _)| id == lane))
            .map_or(&self.options, |(_, options)| options)
    }

    pub fn with_address_lookup(
        mut self,
        mode: antinomie_monitor_core::settings::AddressLookup,
    ) -> Self {
        self.address_lookup = mode;
        self
    }
}

impl HostTriage for RealTriage {
    fn open_run(&self, job: &Run) -> Result<SavedRun, String> {
        let recording = job
            .recording
            .as_ref()
            .ok_or("the job has no recording to read")?;
        let options = self.options_for(job);
        let location = read_only_locations(options)
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
        SavedRun::open_with(run, options, self.address_lookup)
    }

    fn index(&self, saved: &SavedRun, cancel: &Arc<AtomicBool>) -> Result<ArchiveScan, String> {
        saved.scan(cancel)
    }

    fn detect(
        &self,
        saved: &SavedRun,
        scan: &ArchiveScan,
        engines: &[Engine],
        cancel: &Arc<AtomicBool>,
    ) -> Result<Vec<(Engine, Outcome)>, String> {
        let settings = detection::headless_settings(&self.options.data_dir)?;
        detection::detect_saved(saved, scan, engines, &settings, Keep::Save, cancel, &|_| {})
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

    fn ensure_digest(&self, job: &Run, cancel: &Arc<AtomicBool>) -> Result<Option<String>, String> {
        use antinomie_triage::digest_job::{self, Built};
        let saved = self.open_run(job)?;
        let built = digest_job::queue().build_blocking(
            digest_job::Job {
                run: saved.run,
                options: self.options_for(job).clone(),
                budget: digest_job::Budget::default(),
            },
            cancel,
        )?;
        Ok(match built {
            Built::Partial(reasons) => Some(format!(
                "the run's digest was built from part of the recording: {}",
                reasons.join("; ")
            )),
            Built::Failed(reason) => Some(format!("the run has no usable digest: {reason}")),
            Built::Whole | Built::Current | Built::Busy => None,
        })
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

    fn load_scale(&self) -> f64 {
        antinomie_monitor_core::accel::host_load_scale()
    }

    /// The abuse.ch Auth-Key of the node's data directory (lane 1's, where
    /// `antinomie-cli config api-key set` and the desktop's Tools > API keys
    /// keep it), read at each run, and the system `curl`.
    fn online_access(&self) -> OnlineAccess {
        let dir = &self.options.data_dir;
        OnlineAccess {
            key: api_keys::get(dir, ApiKey::Abusech),
            transport: Box::new(online::CurlTransport {
                curl: self.options.curl.clone(),
            }),
            key_dir: Some(dir.clone()),
        }
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
    fn add_tag(&self, job: &Run, tag: &str) -> Result<bool, String>;
}

/// The library of a data directory.
pub struct LibraryTags {
    pub data_dir: std::path::PathBuf,
}

impl SampleTags for LibraryTags {
    fn add_tag(&self, job: &Run, tag: &str) -> Result<bool, String> {
        let sample = job.sample.as_ref().ok_or("the job has no sample")?;
        let mut library =
            Library::open_patient(&self.data_dir)?.with_actor(&custody::automation_actor(job))?;
        library.add_tag(sample.sha256.as_str(), Tag::new(TagKind::Custom, tag))
    }
}

/// No library: tags are not written.
pub struct NoTags;

impl SampleTags for NoTags {
    fn add_tag(&self, _: &Run, _: &str) -> Result<bool, String> {
        Ok(false)
    }
}
