// SPDX-License-Identifier: GPL-3.0-only
//! Analyses that outlive the VM session that acquired their specimen, and
//! the sealing of a finished job's specimen.
use super::*;

impl Jobs {
    /// A job is host-side when its specimen is whole on the host: nothing it
    /// still has to do reads the guest.
    fn host_side(job: &Job) -> bool {
        job.child.is_some()
            || (job.handle.is_none()
                && job.received_len >= job.total_len
                && matches!(
                    job.report.state,
                    AnalysisState::Queued | AnalysisState::Running
                ))
    }
    /// Take out the analyses that no longer need the guest (specimen already
    /// on the host: queued for a worker, or running one), so a VM stop or a
    /// transport reconnect does not invalidate them. What still reads the
    /// guest stays for `shutdown`. `None` when there is nothing to carry.
    pub(crate) fn detach_host_side(&mut self) -> Option<Jobs> {
        let mut carried = Jobs::default();
        carried.tools_dir = self.tools_dir.clone();
        carried.available = self.available;
        if self.active.as_ref().is_some_and(Self::host_side) {
            carried.active = self.active.take();
        }
        let (take, keep): (VecDeque<Job>, VecDeque<Job>) = std::mem::take(&mut self.queue)
            .into_iter()
            .partition(Self::host_side);
        self.queue = keep;
        carried.queue = take;
        if carried.active.is_none() && carried.queue.is_empty() {
            return None;
        }
        self.detached.extend(
            carried
                .active
                .iter()
                .chain(carried.queue.iter())
                .map(|job| job.report.id.clone()),
        );
        Some(carried)
    }
    /// Hand over the carried queues (after `adopt`), before the owner drops.
    pub(crate) fn take_carried(&mut self) -> Vec<Jobs> {
        std::mem::take(&mut self.carried)
    }
    /// Continue the analyses of a finished session beside this queue's own.
    pub(crate) fn adopt(&mut self, carried: Jobs) {
        self.carried.push(carried);
    }
    pub(super) fn tick_carried(&mut self) {
        for carried in &mut self.carried {
            // Carried jobs never ask for guest reads or handle releases.
            let _ = carried.next();
        }
        let updates: Vec<_> = self.carried.iter_mut().flat_map(Jobs::updates).collect();
        self.updates.extend(updates);
        self.carried
            .retain(|carried| carried.active.is_some() || !carried.queue.is_empty());
    }
}

impl Job {
    /// The analysis is over: keep the specimen only as its encrypted archive
    /// and drop a half-received transfer, so no plain copy of the program
    /// outlives the work on it.
    pub(super) fn seal_specimen(&mut self) {
        let _ = fs::remove_file(self.directory.join("specimen.partial"));
        if let Err(error) = sealed::seal(&self.directory) {
            let note = format!(
                "the retained specimen could not be encrypted ({error}); it is sealed when the run is opened again"
            );
            self.report.reason = Some(cleanup_message(
                self.report.reason.as_deref().unwrap_or_default(),
                &note,
            ));
        }
    }
}
