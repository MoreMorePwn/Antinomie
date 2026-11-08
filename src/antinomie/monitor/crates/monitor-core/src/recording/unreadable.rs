// SPDX-License-Identifier: GPL-3.0-only
//! A run whose record cannot be read still shows in the history, with the
//! reason, instead of vanishing from the list.
use super::*;

/// The run saved in `directory` for the listing: its summary, or when its
/// `run.json` cannot be read at all a stand-in that names the folder and the
/// reason. `None` only for a folder that holds no run record or one that
/// belongs to another VM.
pub(super) fn listed_run(
    root: &Path,
    directory: &Path,
    vm_id: &str,
    seal: bool,
) -> Option<RunSummary> {
    match saved_run_with(root, directory, vm_id, seal) {
        Ok(run) => run,
        Err(error) => Some(unreadable_run(directory, vm_id, &error)),
    }
}

/// The history row of a run folder whose `run.json` failed to load. Nothing
/// is written; the folder and its evidence stay as they were.
fn unreadable_run(directory: &Path, vm_id: &str, error: &RecordingError) -> RunSummary {
    let name = directory
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let reason = format!("run record unreadable: {error}");
    eprintln!("run {name} listed without its record: {error}");
    RunSummary {
        environment: None,
        reduced: None,
        boot_wait: None,
        triggers: None,
        stopped_by_user: false,
        stopped_at_ms: None,
        started_ms: None,
        clock_anchor: None,
        id: name.clone(),
        vm_id: vm_id.into(),
        boot_id: String::new(),
        session_id: 0,
        root_task_cookie: 0,
        pid: 0,
        request: ExecRequest {
            path: format!("[unreadable run record: {name}]"),
            ..ExecRequest::default()
        },
        directory: directory.to_path_buf(),
        terminal_eof: false,
        state: RunState::Interrupted,
        notes: Vec::new(),
        machine: None,
        route: None,
        recording_error: Some(reason),
        execution: None,
        analysis: None,
    }
}
