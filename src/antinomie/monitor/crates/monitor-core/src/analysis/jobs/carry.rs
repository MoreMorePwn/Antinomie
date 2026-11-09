// SPDX-License-Identifier: GPL-3.0-only
//! Analyses that outlive the VM session that acquired their specimen, and
//! the sealing of a finished job's specimen.
use super::*;

impl Jobs {
    /// A job is host-side when its specimen is whole on the host: nothing it
    /// still has to do reads the guest.
    fn host_side(job: &Job) -> bool {
        job.child.is_some()
            // The guest vouched for the host copy of the file: the transfer
            // it replaces is not needed, so a VM stop must not end the job.
            || (job.report.state == AnalysisState::Acquiring && job.host_copy_vouched())
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
        // No session takes the carried jobs' updates into its runs: each job
        // saves its final report into its run's record itself (`finish`).
        carried.session_ended = true;
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
        self.publish();
    }
    pub(super) fn tick_carried(&mut self) {
        for carried in &mut self.carried {
            // Carried jobs never ask for guest reads or handle releases.
            let _ = carried.next();
            // A job that still wanted the guest cannot go on without it.
            if let Some(mut job) = carried.acquiring.take() {
                fail(
                    &mut job.report,
                    AnalysisState::Unavailable,
                    "VM ended during specimen acquisition",
                );
                carried.finish(job);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The capa case of the Merlin run: the VM stopped while capa ran, the
    /// analysis finished later as a timeout, and the run's own record kept
    /// "running". The carried job's final report reaches both run files.
    #[test]
    fn a_finished_carried_analysis_replaces_the_running_one_in_the_run_record() {
        let directory = std::env::temp_dir().join(format!("ant-carry-{}", storage::unique_id()));
        fs::create_dir_all(&directory).unwrap();
        let selection = AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Capabilities],
            time_limit_minutes: 0,
            limits: Default::default(),
        };
        let mut running = new_report("/tmp/sample", &selection);
        running.state = AnalysisState::Running;
        let record = serde_json::json!({"id": "run1", "state": "Finished", "analysis": running});
        fs::write(directory.join("run.json"), record.to_string()).unwrap();
        fs::write(
            directory.join("manifest.json"),
            serde_json::json!({"run": record, "ended_ms": 5}).to_string(),
        )
        .unwrap();
        let mut settled = running.clone();
        settled.state = AnalysisState::Partial;
        settled.reason = Some("capa timed out after 240 s".into());
        save_run_analysis(&directory, "other", &settled).unwrap();
        let read = |name: &str| -> serde_json::Value {
            serde_json::from_slice(&fs::read(directory.join(name)).unwrap()).unwrap()
        };
        assert_eq!(read("run.json")["analysis"]["state"], "running");
        save_run_analysis(&directory, "run1", &settled).unwrap();
        assert_eq!(read("run.json")["analysis"]["state"], "partial");
        assert_eq!(read("run.json")["state"], "Finished");
        assert_eq!(read("manifest.json")["run"]["analysis"]["state"], "partial");
        assert_eq!(read("manifest.json")["ended_ms"], 5);
        fs::remove_dir_all(directory).unwrap();
    }
}
