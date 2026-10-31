// SPDX-License-Identifier: GPL-3.0-only
//! Deleting a saved network capture, core, disk dump or failed run: the confirmation, the backend
//! command and what the app forgets once the files are gone.
use super::*;
use crate::evidence_delete::{Deletion, Kind};

/// Deletions kept while the backend answers; older ones are dropped.
const PENDING_LIMIT: usize = 16;

impl MonitorApp {
    /// Ask before deleting; the dialog names the item and its size.
    pub(super) fn ask_delete_evidence(&mut self, deletion: Deletion) {
        self.confirm = Some(Confirm::DeleteEvidence(deletion));
    }

    /// The confirmed deletion goes to the backend, which does the file work.
    pub(super) fn submit_delete_evidence(&mut self, deletion: Deletion) {
        let Some(vm_id) = self.selected.clone() else {
            return;
        };
        let command = Command::DeleteEvidence {
            vm_id,
            item: deletion.item.clone(),
            confirmed: true,
        };
        if let Some(id) = self.send_request(command) {
            if self.pending_deletions.len() >= PENDING_LIMIT {
                self.pending_deletions.remove(0);
            }
            self.pending_deletions.push((id, deletion));
        }
    }

    pub(super) fn take_pending_deletion(&mut self, id: u64) -> Option<Deletion> {
        let index = self
            .pending_deletions
            .iter()
            .position(|(pending, _)| *pending == id)?;
        Some(self.pending_deletions.remove(index).1)
    }

    /// The files are gone: the lists, the viewer and Details forget the item,
    /// and Triage and Run History read their evidence again.
    pub(super) fn evidence_deleted(&mut self, deletion: &Deletion) {
        match deletion.kind {
            Kind::Network => self.network_view.forget_capture(deletion.path()),
            Kind::Core | Kind::ImportedCore => self.core_view.forget_core(deletion.path()),
            Kind::Disk | Kind::ImportedDisk => {
                // Nothing in Triage or Run History names a disk dump.
                self.disk_view.forget_dump(deletion.path());
                return;
            }
            Kind::Run => {
                let gone = self
                    .history
                    .iter()
                    .find(|run| run.directory == deletion.path())
                    .map(|run| run.id.clone());
                if gone.is_some() && self.selected_run == gone {
                    self.select_run(None);
                }
                self.history.retain(|run| run.directory != deletion.path());
            }
        }
        *self.triage_pcap.borrow_mut() = Default::default();
        self.run_labels.invalidate();
        self.triage.evidence_deleted();
        self.refresh_history();
    }
}
