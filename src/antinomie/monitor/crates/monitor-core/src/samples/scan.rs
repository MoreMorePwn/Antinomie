// SPDX-License-Identifier: GPL-3.0-only
//! Runs of library samples found in the recordings of every VM, without the
//! Samples page: the command line, the daemon and the sidebar list runs the
//! window never opened (ANT-T0441). The scan writes nothing; the callers that
//! may write ([`Library::index_all_runs`], a run's end) put the result into the
//! seen-run index.
use super::{Library, SeenRun};
use crate::{
    BackendOptions, RunSummary, WaitStatus,
    recording::{list_runs_read_only, read_only_locations},
};
use std::collections::{BTreeMap, HashMap, HashSet};

/// How a run's root ended, as the run list words it ("Exit 0", "Signal 9").
pub fn root_exit_words(run: &RunSummary) -> String {
    // A program that never ran has no exit to be unknown.
    match run.state {
        crate::RunState::FailedToStart => return "Not started".into(),
        crate::RunState::LaunchUnconfirmed => return "Not recorded".into(),
        _ => {}
    }
    match run
        .execution
        .as_ref()
        .and_then(|status| status.root_exit.as_ref())
    {
        Some(WaitStatus::Exited { code }) => format!("Exit {code}"),
        Some(WaitStatus::Signaled {
            signal,
            core_dumped,
        }) => format!(
            "Signal {signal}{}",
            if *core_dumped { " (core)" } else { "" }
        ),
        None => "Unknown".into(),
    }
}

/// The exit column of a run: "Running" while it is live.
pub fn exit_label(run: &RunSummary) -> String {
    if run.state.is_live() {
        "Running".into()
    } else {
        root_exit_words(run)
    }
}

/// One entry per library sample the run is linked to: the sample it executed
/// and the libraries it loaded (every role of the T0398 preload record).
pub fn seen_runs_of(run: &RunSummary, vm_name: &str) -> Vec<SeenRun> {
    run.request
        .linked_hashes()
        .into_iter()
        .map(|sha256| SeenRun {
            sha256: sha256.to_owned(),
            vm_id: run.vm_id.clone(),
            vm_name: vm_name.to_owned(),
            run_id: run.id.clone(),
            started_ms: run.started_ms,
            exit: exit_label(run),
            directory: run.directory.display().to_string(),
        })
        .collect()
}

fn vm_names(options: &BackendOptions) -> HashMap<String, String> {
    crate::storage::load_vms(options)
        .unwrap_or_default()
        .into_iter()
        .map(|vm| (vm.id, vm.name))
        .collect()
}

/// Every run of every VM, newest first per VM, read without writing. A VM
/// whose recordings cannot be read is skipped.
fn all_runs(options: &BackendOptions) -> Vec<(String, RunSummary)> {
    let names = vm_names(options);
    let Ok(locations) = read_only_locations(options) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for location in locations {
        let name = names
            .get(&location.vm_id)
            .cloned()
            .unwrap_or_else(|| location.vm_id.clone());
        if let Ok(runs) = list_runs_read_only(&location) {
            found.extend(runs.into_iter().map(|run| (name.clone(), run)));
        }
    }
    found
}

/// The runs of library samples in all recordings (read only). The hashes are
/// not checked against the library here.
pub fn scan_runs(options: &BackendOptions) -> Vec<SeenRun> {
    all_runs(options)
        .iter()
        .flat_map(|(name, run)| seen_runs_of(run, name))
        .collect()
}

/// The newest run of each VM that has one, by VM id (the sidebar's last run
/// of a VM the window has not opened).
pub fn newest_run_per_vm(options: &BackendOptions) -> BTreeMap<String, RunSummary> {
    let mut newest: BTreeMap<String, RunSummary> = BTreeMap::new();
    for (_, run) in all_runs(options) {
        let replace = newest
            .get(&run.vm_id)
            .is_none_or(|known| run.started_ms > known.started_ms);
        if replace {
            newest.insert(run.vm_id.clone(), run);
        }
    }
    newest
}

/// The indexed runs of `sha256` and those only the scan found, newest first.
/// Retained runs of deleted recordings stay from the index.
pub fn merged_runs(indexed: Vec<SeenRun>, scanned: &[SeenRun], sha256: &str) -> Vec<SeenRun> {
    let mut merged = indexed;
    for run in scanned
        .iter()
        .filter(|run| run.sha256.eq_ignore_ascii_case(sha256))
    {
        match merged
            .iter_mut()
            .find(|known| known.vm_id == run.vm_id && known.run_id == run.run_id)
        {
            Some(known) => *known = run.clone(),
            None => merged.push(run.clone()),
        }
    }
    merged.sort_by(|a, b| {
        b.started_ms
            .cmp(&a.started_ms)
            .then_with(|| b.run_id.cmp(&a.run_id))
    });
    merged
}

impl Library {
    /// Run counts per sample, the index and the scan together (read only).
    pub fn run_counts_with(&self, scanned: &[SeenRun]) -> Result<HashMap<String, usize>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT sha256, vm_id, run_id FROM seen_run")
            .map_err(|e| e.to_string())?;
        let mut keys: HashMap<String, HashSet<(String, String)>> = HashMap::new();
        for row in statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| e.to_string())?
        {
            let (sha, vm, run): (String, String, String) = row.map_err(|e| e.to_string())?;
            keys.entry(sha).or_default().insert((vm, run));
        }
        for run in scanned {
            keys.entry(run.sha256.to_ascii_lowercase())
                .or_default()
                .insert((run.vm_id.clone(), run.run_id.clone()));
        }
        Ok(keys
            .into_iter()
            .map(|(sha, set)| (sha, set.len()))
            .collect())
    }

    /// Put the runs of every VM into the seen-run index, whether or not the
    /// window opened them. Writes: call it from a write path.
    pub fn index_all_runs(&mut self, options: &BackendOptions) -> Result<usize, String> {
        self.index_runs(&scan_runs(options))
    }
}
