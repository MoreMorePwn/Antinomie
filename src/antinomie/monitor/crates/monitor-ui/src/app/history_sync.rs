// SPDX-License-Identifier: GPL-3.0-only
//! Keeps Run History complete while the backend's live snapshot changes.
//!
//! The snapshot lists only the runs of the current boot. A run that leaves it
//! (the VM stopped or restarted) is moved into `history` here, and the list on
//! disk is fetched again when a boot starts or ends and when a run ends, so a
//! run is never listed only by a snapshot that no longer has it.
use super::*;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Limit the number of carried directories sent to the archive worker per
/// history refresh. Larger sets are checked in successive bounded batches.
const CARRIED_PATH_BUDGET: usize = 256;

#[derive(Default)]
pub(super) struct HistorySync {
    /// The listing is out of date and no request for it has been made yet
    /// (or the request was replaced before it ran).
    pub(super) refresh_due: bool,
    /// Runs taken from the snapshot that no disk listing has confirmed yet.
    carried: BTreeSet<String>,
    /// Carried paths confirmed in the current bounded validation cycle.
    checked: BTreeSet<String>,
    /// A capture listing was replaced before it reached the worker.
    pub(super) captures_refresh_due: bool,
}

fn ended(state: &RunState) -> bool {
    matches!(
        state,
        RunState::Finished | RunState::Stopped | RunState::Finalized
    )
}

impl MonitorApp {
    /// Called with each new snapshot before it replaces `self.snapshot`.
    pub(super) fn follow_runs(&mut self, next: &Snapshot) {
        let previous = &self.snapshot;
        let previous_states: HashMap<_, _> = previous
            .runs
            .iter()
            .map(|run| (run.id.as_str(), &run.state))
            .collect();
        let next_ids: HashSet<_> = next.runs.iter().map(|run| run.id.as_str()).collect();
        let mut due = previous.boot_id != next.boot_id
            || previous.active_vm != next.active_vm
            || (previous.state != next.state && next.state == VmState::Stopped);
        due |= next.runs.iter().any(|run| {
            ended(&run.state)
                && previous_states
                    .get(run.id.as_str())
                    .is_none_or(|old_state| *old_state != &run.state)
        });
        let leaving: Vec<RunSummary> = previous
            .runs
            .iter()
            .filter(|run| {
                Some(run.vm_id.as_str()) == self.selected.as_deref()
                    && !next_ids.contains(run.id.as_str())
            })
            .cloned()
            .collect();
        for run in leaving {
            self.history_sync.carried.insert(run.id.clone());
            match self.history.iter_mut().find(|listed| listed.id == run.id) {
                Some(listed) => *listed = run,
                None => self.history.push(run),
            }
            due = true;
        }
        self.history_sync.refresh_due |= due;
    }

    /// Asks for deferred run or capture listings once the archive slot is free.
    pub(super) fn refresh_history_when_idle(&mut self) {
        if self.pending_archive.is_none() && self.history_sync.refresh_due {
            self.history_sync.refresh_due = false;
            self.refresh_run_history();
        } else if self.pending_archive.is_none() && self.history_sync.captures_refresh_due {
            self.history_sync.captures_refresh_due = false;
            self.refresh_captures();
        }
    }

    /// Paths whose directory validity the archive worker should confirm.
    pub(super) fn carried_run_directories(&self) -> Vec<(String, PathBuf)> {
        self.history
            .iter()
            .filter(|run| {
                self.history_sync.carried.contains(&run.id)
                    && !self.history_sync.checked.contains(&run.id)
            })
            .take(CARRIED_PATH_BUDGET)
            .map(|run| (run.id.clone(), run.directory.clone()))
            .collect()
    }

    /// A VM listing arrived: it replaces the list, retaining carried runs until
    /// a listing confirms them or the VM is deleted.
    pub(super) fn accept_run_listing(
        &mut self,
        mut listed: Vec<RunSummary>,
        checked: Vec<String>,
        retained: Vec<String>,
    ) {
        self.activity_notices_due = true;
        let sync = &mut self.history_sync;
        let listed_ids: HashSet<_> = listed.iter().map(|run| run.id.as_str()).collect();
        let checked: HashSet<_> = checked.into_iter().collect();
        let retained: HashSet<_> = retained.into_iter().collect();
        sync.carried.retain(|id| !listed_ids.contains(id.as_str()));
        sync.checked.retain(|id| sync.carried.contains(id));
        for id in checked {
            if listed_ids.contains(id.as_str()) {
                sync.carried.remove(&id);
                sync.checked.remove(&id);
            } else if retained.contains(&id) {
                sync.carried.insert(id.clone());
                sync.checked.insert(id);
            } else {
                sync.carried.remove(&id);
                sync.checked.remove(&id);
            }
        }
        if sync.carried.iter().any(|id| !sync.checked.contains(id)) {
            // The next idle slot checks another bounded batch.
            sync.refresh_due = true;
        } else {
            sync.checked.clear();
        }
        let kept: Vec<_> = std::mem::take(&mut self.history)
            .into_iter()
            .filter(|run| sync.carried.contains(&run.id))
            .collect();
        sync.carried = kept.iter().map(|run| run.id.clone()).collect();
        listed.extend(kept);
        self.history = listed;
    }

    /// Forgets everything listed for a VM that is no longer selected.
    pub(super) fn clear_history(&mut self) {
        self.history.clear();
        self.history_sync = HistorySync::default();
    }

    /// The selected VM was deleted: nothing of it stays selected, listed or open.
    pub(super) fn forget_deleted_vm(&mut self, vm_id: &str) {
        let reports: BTreeSet<String> = self
            .snapshot
            .runs
            .iter()
            .chain(&self.history)
            .filter(|run| run.vm_id == vm_id)
            .filter_map(|run| run.analysis.as_ref().map(|report| report.id.clone()))
            .collect();
        self.pending_analysis_sections
            .retain(|(id, _)| !reports.contains(id));
        self.analysis_windows.retain(|id, _| !reports.contains(id));
        self.analysis_directories
            .retain(|id, _| !reports.contains(id));
        self.analysis_views.retain(|key, view| {
            !reports.contains(key)
                && view
                    .report_id
                    .as_ref()
                    .is_none_or(|id| !reports.contains(id))
        });
        // A terminal window the user still has open keeps its screen.
        self.terminals
            .retain(|_, terminal| terminal.open || terminal.run.vm_id != vm_id);
        self.clear_history();
        self.capture_history
            .retain(|capture| capture.vm_id != vm_id);
        self.archived_processes = None;
        self.select_run(None);
    }
}
