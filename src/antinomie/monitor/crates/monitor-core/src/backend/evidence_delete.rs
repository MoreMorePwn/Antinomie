// SPDX-License-Identifier: MIT
//! Deleting saved evidence: the backend decides what is still being written,
//! removes the files inside the VM's recording folders and gives the freed
//! bytes back to the boot's recording quota.
use super::*;
use crate::{EvidenceItem, evidence_delete as files};
use std::path::Path;

impl Worker {
    pub(super) fn delete_evidence(
        &mut self,
        vm_id: &str,
        item: EvidenceItem,
    ) -> Result<String, String> {
        let roots = crate::locations::locations(&self.options, vm_id)?.recording_directories;
        match item {
            EvidenceItem::NetworkCapture { file } => {
                self.network_capture_busy(&file)?;
                let removed = files::remove_network_capture(&roots, &file)?;
                if let Some(session) = self.session.as_mut()
                    && removed.boot_id.as_deref() == Some(session.boot_id.as_str())
                {
                    removed.release_network(
                        &mut session.network_bytes_done,
                        &mut session.network_bytes,
                    );
                }
                self.publish();
                Ok(format!(
                    "Deleted network capture {} ({}): the pcap and {} related file(s)",
                    removed.name,
                    crate::byte_size::file_size(removed.bytes),
                    removed.entries.saturating_sub(1)
                ))
            }
            EvidenceItem::ProcessCore { directory } => {
                self.core_busy(&directory)?;
                let removed = files::remove_process_core(&roots, &directory)?;
                if let Some(session) = self.session.as_mut()
                    && removed.boot_id.as_deref() == Some(session.boot_id.as_str())
                {
                    let mut owned = session.run_artifacts.values_mut().find(|owner| {
                        Some(owner.summary.run_id.as_str()) == removed.run_id.as_deref()
                    });
                    removed.release_core(
                        &mut session.core_stored_len,
                        owned.as_mut().map(|owner| &mut owner.core_stored_len),
                    );
                }
                self.publish();
                Ok(format!(
                    "Deleted core {} ({}, {} file(s))",
                    removed.name,
                    crate::byte_size::file_size(removed.bytes),
                    removed.entries
                ))
            }
        }
    }

    /// A capture the running boot still writes: the manual one, or one a run owns.
    fn network_capture_busy(&self, file: &Path) -> Result<(), String> {
        let same = |capture: &crate::network::NetworkCapture| capture.file == file;
        let writing = self.snapshot.network_capture.as_ref().is_some_and(same)
            || self.session.as_ref().is_some_and(|session| {
                session
                    .run_artifacts
                    .values()
                    .filter_map(|owner| owner.network.as_ref())
                    .any(same)
            });
        if writing {
            Err("this network capture is still being written; stop it first".into())
        } else {
            Ok(())
        }
    }

    /// A core the running boot still captures, manual or on exit.
    fn core_busy(&self, directory: &Path) -> Result<(), String> {
        let Some(session) = self.session.as_ref() else {
            return Ok(());
        };
        let manual = session.manual_cores.values().any(|owner| {
            owner.summary.directory == directory
                && owner.summary.phase != crate::ProcessCorePhase::Finished
        });
        let on_exit = session.run_artifacts.values().any(|owner| {
            owner.directory.join("core") == directory
                && (owner.core.is_some() || owner.summary.core_state.in_progress())
        });
        if manual || on_exit {
            Err("this core is still being captured; wait for it or cancel it first".into())
        } else {
            Ok(())
        }
    }
}
