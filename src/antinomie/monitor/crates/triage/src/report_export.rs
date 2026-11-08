// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The exported report of a run, without a window: the job that indexes the
//! whole run again with no filter, builds the report from that index and
//! writes the files. The GUI's Export report dialog and the command line's
//! `report` run the same job, so they write the same report. The formats
//! themselves are `antinomie_monitor_core::report`.
use super::*;
use crate::archive_scan::scan_archive_query;
use antinomie_monitor_core::report::{self, export::Written, Choices};
use std::path::PathBuf;

pub mod build;
pub mod build_sources;
#[cfg(any(test, feature = "test-support"))]
pub mod fixtures;
pub mod not_started;
pub mod rows;
pub mod run_facts;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod timing;

pub use not_started::NotStartedRun;

/// The Triage context of `input`: equal keys are the same run in the same folder.
pub fn context_key(input: &TriageInput<'_>) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        input.vm_id.unwrap_or(""),
        input.boot_id.unwrap_or(""),
        input.run_id.unwrap_or(""),
        input
            .archive
            .map(|path| path.display().to_string())
            .unwrap_or_default()
    )
}

/// The sample the static analysis of the run in `input` opened, as the
/// report's first guess; the run's record corrects it ([`run_facts::apply`]).
pub fn sample_of(input: &TriageInput<'_>) -> Option<report::SampleInfo> {
    input.analysis.and_then(|analysis| {
        let sha256 = analysis.specimen_sha256.clone()?;
        Some(report::SampleInfo {
            name: Path::new(&analysis.source_path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            sha256,
            size: analysis.specimen_len,
            role: String::new(),
        })
    })
}

/// The run block of the report for the run in `input`, before its record is
/// read ([`run_facts::apply`]).
pub fn run_info_of(input: &TriageInput<'_>) -> report::RunInfo {
    report::RunInfo {
        vm_id: input.vm_id.unwrap_or_default().into(),
        boot_id: input.boot_id.unwrap_or_default().into(),
        run_id: input.run_id.unwrap_or_default().into(),
        started_ms: input.started_ms,
        finished: input.run_finished,
        ..Default::default()
    }
}

/// The request a report of the run in `input` reads: the screen's request
/// (`screen`) with every filter, sort and page cleared.
pub fn report_request(screen: &ScanRequest, input: &TriageInput<'_>) -> ScanRequest {
    let mut request = whole_run_request(screen);
    request.run_finished = input.run_finished;
    request
}

/// Where the files go: the chosen folder, else the recording's `report`.
pub fn folder_of(choices: &Choices, archive: &Path) -> PathBuf {
    if choices.folder.trim().is_empty() {
        archive.join("report")
    } else {
        PathBuf::from(choices.folder.trim())
    }
}

/// Everything the worker needs, owned.
#[derive(Clone)]
pub struct Job {
    pub archive: PathBuf,
    pub pcap: Option<PathBuf>,
    /// The scan's request with every filter, sort and page cleared.
    pub request: ScanRequest,
    pub choices: Choices,
    pub run: report::RunInfo,
    pub sample: Option<report::SampleInfo>,
    pub clock: Option<antinomie_monitor_core::HostClockAnchor>,
    pub data_dir: Option<PathBuf>,
    pub now_ms: u64,
    pub folder: PathBuf,
}

impl Job {
    /// The job for a saved run (design 1.4 U2): what the GUI's dialog makes
    /// when it exports the run on screen, with `choices` and the time `now_ms`.
    pub fn for_saved(saved: &SavedRun, choices: Choices, now_ms: u64) -> Self {
        let input = saved.input();
        let request = report_request(&saved.request(), &input);
        Self {
            archive: saved.run.directory.clone(),
            pcap: saved.pcap.clone(),
            data_dir: request.data_dir.clone(),
            request,
            folder: folder_of(&choices, &saved.run.directory),
            choices,
            run: run_info_of(&input),
            sample: sample_of(&input),
            clock: input.clock_anchor,
            now_ms,
        }
    }
}

/// Index the whole run, build the report and write it.
pub fn run_job(
    job: &Job,
    cancel: &Arc<AtomicBool>,
    status: &dyn Fn(&str),
) -> Result<Written, String> {
    status(if job.request.reuse.is_some() {
        "Using the index Triage already made..."
    } else {
        "Indexing the whole run..."
    });
    let scan = scan_archive_query(
        &job.archive,
        job.pcap.as_deref(),
        false,
        cancel,
        &job.request,
    )?;
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    status("Building the report...");
    let (job, built) = build_report(job, &scan)?;
    write_built(&job, built, cancel, status)
}

/// The report of `scan` for `job`, and the bundle's inputs when asked for.
/// The run's state, command, sample and environment come from its record:
/// the job returned is `job` with them.
pub fn build_report(job: &Job, scan: &ArchiveScan) -> Result<(Job, build::Built), String> {
    let job = run_facts::apply(job, scan);
    let built = build::build(scan, &job)?;
    Ok((job, built))
}

/// Write `built` into the job's folder (`job` as [`build_report`] returned
/// it): the custody export for the bundle, then the files of every chosen
/// format.
pub fn write_built(
    job: &Job,
    mut built: build::Built,
    cancel: &Arc<AtomicBool>,
    status: &dyn Fn(&str),
) -> Result<Written, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let mut scratch = None;
    if let Some(input) = &mut built.bundle {
        status("Reading the custody log...");
        if let Some((sample, data_dir)) = job.sample.as_ref().zip(job.data_dir.as_ref()) {
            let temp = job.folder.join(format!(".custody-{}", std::process::id()));
            let exported = std::fs::create_dir_all(&temp)
                .map_err(|e| e.to_string())
                .and_then(|()| {
                    let mut library = antinomie_monitor_core::samples::Library::open(data_dir)?;
                    library.export_custody(
                        &sample.sha256,
                        antinomie_monitor_core::samples::ExportFormat::Json,
                        &temp.join(format!(
                            "custody-{}.json",
                            &sample.sha256[..8.min(sample.sha256.len())]
                        )),
                        None,
                    )
                });
            match exported {
                Ok(done) => {
                    input.custody.push(done.path);
                    input.custody.extend(done.verifier);
                }
                Err(error) => input.skipped.push(("custody export".into(), error)),
            }
            scratch = Some(temp);
        } else {
            input.skipped.push((
                "custody export".into(),
                "the run has no sample record".into(),
            ));
        }
    }
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    status("Writing the files...");
    let written = report::export::write(&built.report, &job.choices, &job.folder, built.bundle);
    if let Some(temp) = scratch {
        let _ = std::fs::remove_dir_all(temp);
    }
    written
}
