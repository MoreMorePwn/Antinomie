// SPDX-License-Identifier: GPL-3.0-only
//! Deleting saved evidence: the backend decides what is still being written,
//! removes the files inside the VM's recording folders and gives the freed
//! bytes back to the boot's recording quota.
use super::*;
use crate::{EvidenceItem, evidence_delete as files};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, SyncSender},
    thread::{self, JoinHandle},
};

/// Deletions queued at once; more are refused rather than waited for.
const QUEUE_CAPACITY: usize = 16;

/// One deletion handed to the deletion thread.
struct DeleteJob {
    id: u64,
    roots: Vec<PathBuf>,
    item: EvidenceItem,
}

/// A finished deletion, applied to the backend's state on the worker thread.
struct DeleteDone {
    id: u64,
    item: EvidenceItem,
    result: Result<files::Removed, String>,
}

/// The thread that removes evidence, so the worker that drains telemetry and
/// answers commands never waits for an unlink or an `fsync`. Deletions run in
/// the order they were accepted and each answers its own command.
#[derive(Default)]
pub(super) struct EvidenceDeleter {
    jobs: Option<SyncSender<DeleteJob>>,
    done: Option<Receiver<DeleteDone>>,
    thread: Option<JoinHandle<()>>,
    /// Accepted deletions whose result has not been applied yet.
    in_flight: usize,
}

impl EvidenceDeleter {
    fn submit(&mut self, job: DeleteJob) -> Result<(), String> {
        if self.jobs.is_none() {
            let (jobs, queued) = mpsc::sync_channel::<DeleteJob>(QUEUE_CAPACITY);
            let (finished, done) = mpsc::sync_channel::<DeleteDone>(QUEUE_CAPACITY);
            let thread = thread::Builder::new()
                .name("evidence-delete".into())
                .spawn(move || {
                    for job in queued {
                        let DeleteJob { id, roots, item } = job;
                        let work = std::panic::AssertUnwindSafe(|| match &item {
                            EvidenceItem::NetworkCapture { file } => {
                                files::remove_network_capture(&roots, file)
                            }
                            EvidenceItem::ProcessCore { directory } => {
                                files::remove_process_core(&roots, directory)
                            }
                            EvidenceItem::DiskDump { directory } => {
                                files::remove_disk_dump(&roots, directory)
                            }
                        });
                        let result = std::panic::catch_unwind(work)
                            .unwrap_or_else(|_| Err("evidence deletion panicked".into()));
                        if finished.send(DeleteDone { id, item, result }).is_err() {
                            break;
                        }
                    }
                })
                .map_err(|error| format!("evidence deletion thread: {error}"))?;
            self.jobs = Some(jobs);
            self.done = Some(done);
            self.thread = Some(thread);
        }
        let sender = self.jobs.as_ref().ok_or("evidence deletion is closed")?;
        match sender.try_send(job) {
            Ok(()) => {
                self.in_flight += 1;
                Ok(())
            }
            Err(mpsc::TrySendError::Full(_)) => {
                Err("too many evidence deletions are waiting; try again shortly".into())
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                Err("the evidence deletion thread stopped".into())
            }
        }
    }

    fn try_finished(&mut self) -> Option<DeleteDone> {
        let done = self.done.as_ref()?.try_recv().ok()?;
        self.in_flight = self.in_flight.saturating_sub(1);
        Some(done)
    }
}

impl Worker {
    /// Check a deletion and hand it to the deletion thread. `Ok` means the
    /// result arrives later, through [`Worker::poll_evidence_deletes`]; `Err`
    /// is the command's immediate failure.
    pub(super) fn start_evidence_delete(
        &mut self,
        id: u64,
        vm_id: &str,
        item: EvidenceItem,
        confirmed: bool,
    ) -> Result<(), String> {
        if !confirmed {
            return Err("deleting evidence requires confirmation".into());
        }
        let roots = crate::locations::locations(&self.options, vm_id)?.recording_directories;
        match &item {
            EvidenceItem::NetworkCapture { file } => self.network_capture_busy(file)?,
            EvidenceItem::ProcessCore { directory } => self.core_busy(directory)?,
            EvidenceItem::DiskDump { directory } => self.disk_dump_busy(directory)?,
        }
        self.evidence.submit(DeleteJob { id, roots, item })
    }

    /// Apply every deletion the thread has finished and answer its command.
    pub(super) fn poll_evidence_deletes(&mut self) {
        while let Some(done) = self.evidence.try_finished() {
            self.finish_evidence_delete(done);
        }
    }

    /// Wait for the deletions still running (the backend is closing) and
    /// answer their commands.
    pub(super) fn finish_evidence_deletes(&mut self) {
        self.evidence.jobs = None;
        if let Some(thread) = self.evidence.thread.take()
            && thread.join().is_err()
        {
            self.snapshot.last_error = Some("evidence deletion thread panicked".into());
        }
        self.poll_evidence_deletes();
        self.evidence.done = None;
    }

    fn finish_evidence_delete(&mut self, done: DeleteDone) {
        let DeleteDone { id, item, result } = done;
        let result = result.map(|removed| self.evidence_deleted(&item, removed));
        let success = result.is_ok();
        let message = result.unwrap_or_else(|error| error);
        self.snapshot.last_error = (!success).then(|| message.clone());
        self.publish();
        self.emit(Notification::CommandResult {
            id,
            success,
            message,
        });
    }

    /// Give the freed bytes back to the running boot's quota and describe it.
    fn evidence_deleted(&mut self, item: &EvidenceItem, removed: files::Removed) -> String {
        match item {
            EvidenceItem::NetworkCapture { .. } => {
                if let Some(session) = self.session.as_mut()
                    && removed.boot_id.as_deref() == Some(session.boot_id.as_str())
                {
                    removed.release_network(
                        &mut session.network_bytes_done,
                        &mut session.network_bytes,
                    );
                }
                format!(
                    "Deleted network capture {} ({}): the pcap and {} related file(s)",
                    removed.name,
                    crate::byte_size::file_size(removed.bytes),
                    removed.entries.saturating_sub(1)
                )
            }
            EvidenceItem::ProcessCore { .. } => {
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
                format!(
                    "Deleted core {} ({}, {} file(s))",
                    removed.name,
                    crate::byte_size::file_size(removed.bytes),
                    removed.entries
                )
            }
            EvidenceItem::DiskDump { .. } => format!(
                "Deleted disk dump {} ({}, {} file(s))",
                removed.name,
                crate::byte_size::file_size(removed.bytes),
                removed.entries
            ),
        }
    }

    /// A dump the open Current disk view (kept as that dump) still reads.
    fn disk_dump_busy(&self, directory: &Path) -> Result<(), String> {
        let folder = fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
        let reads = self.snapshot.current_disk.as_ref().is_some_and(|view| {
            fs::canonicalize(&view.image)
                .unwrap_or_else(|_| view.image.clone())
                .starts_with(&folder)
        });
        if reads {
            Err("the open Current disk view reads this dump; close the view first".into())
        } else {
            Ok(())
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
