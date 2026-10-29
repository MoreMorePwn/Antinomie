// SPDX-License-Identifier: GPL-3.0-only
//! A stopped boot's evidence must be saved before its disk layer can be merged.
use super::*;

impl Worker {
    /// Cold restore already selected its disk. Finish sealing the old timeline
    /// before start() may settle its layer; do not turn a successful disk restore
    /// into a misleading failure merely because its asynchronous save is active.
    pub(super) fn start_restored_disk(&mut self, vm_id: &str) -> Result<String, String> {
        self.wait_snapshot_flush_until(vm_id, Instant::now() + Duration::from_secs(300))
            .map_err(|error| {
                format!("snapshot disk restored, but guest was not started: {error}; start the VM after saving finishes")
            })?;
        self.start(vm_id)
    }

    pub(super) fn wait_snapshot_recordings(&mut self, command: &Command) -> Result<(), String> {
        let vm_id = match command {
            Command::CreateVmSnapshot { vm_id, .. }
            | Command::RenameVmSnapshot { vm_id, .. }
            | Command::RestoreVmSnapshot {
                vm_id,
                confirmed: true,
                ..
            }
            | Command::DeleteVmSnapshot {
                vm_id,
                confirmed: true,
                ..
            } => vm_id,
            _ => return Ok(()),
        };
        if self.snapshot.active_vm.as_deref() == Some(vm_id)
            || crate::snapshots::run_layer::pending_record(&self.options, vm_id).is_none()
        {
            return Ok(());
        }
        // Waiting here while another VM runs would also stop draining its
        // telemetry. Its presence must not bypass the stopped target's flush.
        if self.snapshot.active_vm.is_some() {
            return Err(
                "stop the other VM before changing this VM's pending snapshot layer".into(),
            );
        }
        self.wait_snapshot_flush_until(vm_id, Instant::now() + Duration::from_secs(300))
    }

    fn wait_snapshot_flush_until(&mut self, vm_id: &str, deadline: Instant) -> Result<(), String> {
        if !self.flusher.is_busy() && self.deferred_flush.is_none() {
            return Ok(());
        }
        self.snapshot.vm_snapshot_progress = Some(VmSnapshotProgress {
            vm_id: vm_id.into(),
            stage: "Waiting for saved recordings".into(),
        });
        self.publish();
        let result = (|| {
            while self.flusher.is_busy() || self.deferred_flush.is_some() {
                if self.closing.load(Ordering::Acquire) {
                    return Err(
                        "saving wait cancelled while recordings are being saved; disk layers retained"
                            .into(),
                    );
                }
                if Instant::now() >= deadline {
                    return Err("recordings are still being saved; retry after saving finishes; disk layers retained".into());
                }
                // The flusher owns the files, so only collect its status. Once
                // it finishes, poll_flush may start the ordinary layer finalizer;
                // settle_stopped serializes the subsequent snapshot with that job.
                self.poll_flush();
                thread::sleep(Duration::from_millis(50));
            }
            Ok(())
        })();
        self.snapshot.vm_snapshot_progress = None;
        self.publish();
        result
    }
}

#[cfg(test)]
mod tests;
