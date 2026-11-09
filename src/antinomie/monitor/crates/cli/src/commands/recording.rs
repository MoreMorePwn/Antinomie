// SPDX-License-Identifier: GPL-3.0-only
//! The saved run a `triage`, `detect` or `report` command names, read without
//! the lock and without writing into any run folder, and its Triage index
//! (`antinomie_triage::SavedRun`): the index the GUI makes when the run is
//! selected.
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    signals,
};
use antinomie_monitor_core::{
    RunSummary,
    recording::{find_run_read_only, list_runs_read_only, read_only_locations},
};
use antinomie_service::query::key::RunKey;
use antinomie_triage::{ArchiveScan, SavedRun, scan_progress::ScanProgress};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// The help text of the RUN argument.
pub const RUN_HELP: &str = "The run: its id or the first characters of it (see `antinomie-cli run exec`'s result), vm:boot:run, a run key, or the run's folder";

/// Shortest run-id prefix that is looked up.
pub const RUN_PREFIX: usize = 4;

/// Every saved run of the data directory, deleted VMs with kept recordings
/// included. A VM that cannot be read does not hide the others.
pub fn list_all_runs(context: &Context) -> Result<Vec<RunSummary>, CliError> {
    let locations = read_only_locations(&context.options)
        .map_err(|error| CliError::internal(format!("cannot list the recordings: {error}")))?;
    let mut runs = Vec::new();
    for location in &locations {
        if let Ok(found) = list_runs_read_only(location) {
            runs.extend(found);
        }
    }
    Ok(runs)
}

/// The saved run `text` names. Every VM of the data directory is searched,
/// deleted ones with kept recordings included.
pub fn find_run(context: &Context, text: &str) -> Result<RunSummary, CliError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(CliError::invalid("RUN is empty").with_field("run"));
    }
    let locations = read_only_locations(&context.options)
        .map_err(|error| CliError::internal(format!("cannot list the recordings: {error}")))?;
    let key = RunKey::try_from(text.to_owned()).ok().or_else(|| {
        text.contains(':')
            .then(|| RunKey::from_triple(text).ok())
            .flatten()
    });
    if let Some(key) = key {
        let (vm_id, boot_id, run_id) = key.parts();
        let run = locations
            .iter()
            .filter(|location| location.vm_id == vm_id)
            .find_map(|location| {
                find_run_read_only(location, &boot_id, &run_id)
                    .ok()
                    .flatten()
            });
        return run.ok_or_else(|| {
            CliError::not_found(format!("no run {run_id} of VM {vm_id} in boot {boot_id}"))
                .with_field("run")
        });
    }
    let mut runs = Vec::new();
    for location in &locations {
        // One VM that cannot be read must not hide the others.
        if let Ok(found) = list_runs_read_only(location) {
            runs.extend(found);
        }
    }
    let path = Path::new(text);
    if path.join("run.json").is_file() {
        let wanted = std::fs::canonicalize(path).map_err(|error| CliError::io(path, &error))?;
        return runs
            .into_iter()
            .find(|run| std::fs::canonicalize(&run.directory).is_ok_and(|dir| dir == wanted))
            .ok_or_else(|| {
                CliError::not_found(format!(
                    "{} is not a recording of the data directory {}",
                    path.display(),
                    context.data_dir().display()
                ))
                .with_field("run")
            });
    }
    let exact: Vec<&RunSummary> = runs.iter().filter(|run| run.id == text).collect();
    let found: Vec<&RunSummary> = if exact.is_empty() && text.len() >= RUN_PREFIX {
        runs.iter().filter(|run| run.id.starts_with(text)).collect()
    } else {
        exact
    };
    match found.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(CliError::not_found(format!(
            "no run {text:?} in {}{}",
            context.data_dir().display(),
            if text.len() < RUN_PREFIX {
                format!(" (give at least {RUN_PREFIX} characters of the id)")
            } else {
                String::new()
            }
        ))
        .with_field("run")),
        many => Err(CliError::invalid(format!(
            "{text:?} names {} runs; give more of the id, or vm:boot:run",
            many.len()
        ))
        .with_field("run")
        .with_details(json!({
            "runs": many
                .iter()
                .map(|run| format!("{}:{}:{}", run.vm_id, run.boot_id, run.id))
                .collect::<Vec<_>>()
        }))),
    }
}

/// The run `text` names with the settings of the data directory: what its
/// index needs. A run with no root process has no recording to read.
pub fn open_saved(context: &Context, text: &str) -> Result<SavedRun, CliError> {
    let run = find_run(context, text)?;
    if run.root_task_cookie == 0 {
        return Err(CliError::new(
            ErrorCode::PreconditionFailed,
            format!(
                "run {} has no recorded program (it never started, or it was recorded before runs had a root): there is nothing to triage",
                run.id
            ),
        )
        .with_field("run"));
    }
    SavedRun::open(run, &context.options).map_err(|error| {
        CliError::new(
            ErrorCode::PreconditionFailed,
            format!("settings.json cannot be read: {error}"),
        )
    })
}

/// The run block every result starts with.
pub fn run_value(saved: &SavedRun) -> Value {
    let run = &saved.run;
    json!({
        "run_key": RunKey::new(&run.vm_id, &run.boot_id, &run.id).ok().map(|key| key.as_str().to_owned()),
        "vm_id": run.vm_id,
        "boot_id": run.boot_id,
        "run_id": run.id,
        "program": run.request.path,
        "started_ms": run.started_ms,
        "directory": run.directory,
        "capture": saved.pcap,
    })
}

/// Index the whole run as the GUI does when it is selected, with progress
/// lines on standard error; Ctrl-C cancels (exit 130).
pub fn index(context: &Context, saved: &SavedRun) -> Result<ArchiveScan, CliError> {
    signals::install();
    let progress = Arc::new(ScanProgress::default());
    let mut request = saved.request();
    request.progress = Some(Arc::clone(&progress));
    let cancel = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let watcher = {
        let (cancel, done, progress) = (cancel.clone(), done.clone(), progress.clone());
        let logger = context.logger;
        std::thread::spawn(move || {
            let mut last = String::new();
            let mut waited = Duration::ZERO;
            while !done.load(Ordering::Relaxed) {
                if signals::interrupted() {
                    cancel.store(true, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(100));
                waited += Duration::from_millis(100);
                if waited >= Duration::from_secs(2) {
                    waited = Duration::ZERO;
                    if let Some(text) = progress.text().filter(|text| *text != last) {
                        logger.info(&format!("indexing: {text}"));
                        last = text;
                    }
                }
            }
        })
    };
    context
        .logger
        .info(&format!("indexing run {}", saved.run.id));
    let result = saved.scan_with(request, &cancel);
    done.store(true, Ordering::Relaxed);
    let _ = watcher.join();
    match result {
        Ok(scan) => Ok(scan),
        Err(_) if signals::interrupted() => Err(CliError::new(
            ErrorCode::Internal,
            "interrupted while indexing the run",
        )
        .with_exit(crate::exit::Exit::Interrupted)),
        Err(error) => Err(CliError::new(
            ErrorCode::Internal,
            format!("cannot index run {}: {error}", saved.run.id),
        )),
    }
}
