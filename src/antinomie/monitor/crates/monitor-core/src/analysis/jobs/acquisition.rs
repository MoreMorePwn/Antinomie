// SPDX-License-Identifier: GPL-3.0-only
//! Drain expiring guest specimens independently of slow host analysis tools.
use super::*;

/// The part of the acquisition budget any transfer needs, whatever its size.
const TRANSFER_BASE: Duration = Duration::from_secs(120);
/// The acquisition budget grows by this much per MiB of specimen.
const TRANSFER_PER_MIB: Duration = Duration::from_secs(1);

/// Time a job has to receive a specimen of `total_len` bytes once it starts:
/// 120 s plus a second per MiB, so the largest one (128 MiB, 248 s) still
/// arrives when a loaded host reads it at about half a MiB a second. The guest
/// keeps a handle while it is read (its 180 s idle lifetime restarts at every
/// read), and transfers rotate chunk by chunk, so a waiting handle is read too.
pub(super) fn transfer_deadline(total_len: u64) -> Duration {
    let mib = total_len
        .min(u64::from(control::SPECIMEN_MAX_SIZE))
        .div_ceil(1024 * 1024);
    TRANSFER_BASE + TRANSFER_PER_MIB * mib as u32
}

impl Jobs {
    /// True while a guest specimen is still being read. Each chunk is one
    /// pass of the backend loop, which then waits less between passes, as it
    /// does for a core transfer.
    pub fn transferring(&self) -> bool {
        self.acquiring.iter().chain(self.queue.iter()).any(|job| {
            job.report.state == AnalysisState::Acquiring
                && job.handle.is_some()
                && job.received_len < job.total_len
        })
    }

    pub(super) fn acquire_next(&mut self) -> Option<Action> {
        if self.acquiring.is_none() {
            let index = self
                .queue
                .iter()
                .position(|job| job.report.state == AnalysisState::Acquiring)?;
            self.acquiring = self.queue.remove(index);
        }
        let mut job = self.acquiring.take()?;
        // This budget starts at acquisition, not at worker availability. Waiting
        // for a worker cannot extend the guest's 180-second idle lifetime.
        if job.specimen_publication.is_none() && Instant::now() >= job.deadline {
            fail(
                &mut job.report,
                AnalysisState::Unavailable,
                "specimen acquisition deadline exceeded; incomplete capture never analyzed",
            );
            self.finish(job);
            return None;
        }
        // An uploaded program's host copy may stand in for the transfer.
        if job.hold_for_host_copy() {
            self.queue.push_back(job);
            return None;
        }
        if job.received_len < job.total_len {
            let Some(id) = job.handle else {
                fail(
                    &mut job.report,
                    AnalysisState::Unavailable,
                    "specimen handle missing",
                );
                self.finish(job);
                return None;
            };
            let action = Action::Read {
                id,
                offset: job.received_len,
                total: job.total_len,
                capacity: (job.total_len - job.received_len)
                    .min(u64::from(control::SPECIMEN_CHUNK_SIZE)) as u32,
            };
            self.acquiring = Some(job);
            return Some(action);
        }
        if let Some(file) = job.file.take()
            && let Err(error) = file.sync_all().and_then(|_| {
                fs::rename(
                    job.directory.join("specimen.partial"),
                    job.directory.join("specimen"),
                )
            })
        {
            fail(
                &mut job.report,
                AnalysisState::Unavailable,
                format!("specimen publication: {error}"),
            );
            self.finish(job);
            return None;
        }
        let fetched = job.handle.is_some();
        if let Some(id) = job.handle.take() {
            self.release.push_back(id);
        }
        job.report.specimen_len = Some(job.total_len);
        // The identity is the guest's hash either way: a host copy is only
        // adopted when it equals the hash the guest recorded.
        job.report.specimen_sha256 = Some(
            job.adopted_sha256()
                .unwrap_or_else(|| format!("{:x}", job.digest.clone().finalize())),
        );
        job.record_specimen_source(fetched);
        // The transfer is over: publishing the report gets a budget of its
        // own, so a stalled disk ends the job instead of holding the slot.
        if job.specimen_publication.is_none() {
            job.deadline = Instant::now() + PUBLICATION_DEADLINE;
        }
        // The durable report must say Queued before the worker can see it.
        job.report.state = AnalysisState::Queued;
        match job.publish_specimen_report() {
            Ok(true) => {
                self.updates.push((job.run_id.clone(), job.report.clone()));
                self.queue.push_back(job);
            }
            Ok(false) if Instant::now() >= job.deadline => {
                fail(
                    &mut job.report,
                    AnalysisState::Unavailable,
                    format!(
                        "specimen report publication did not finish within {} seconds; the disk is not answering",
                        PUBLICATION_DEADLINE.as_secs()
                    ),
                );
                self.finish(job);
            }
            Ok(false) => {
                job.report.state = AnalysisState::Acquiring;
                self.queue.push_back(job);
            }
            Err(error) => {
                fail(&mut job.report, AnalysisState::Unavailable, error);
                self.finish(job);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submit(jobs: &mut Jobs, root: &Path, id: u64, len: u64) -> AnalysisReport {
        let selection = AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Metadata],
            time_limit_minutes: 0,
            limits: Default::default(),
        };
        jobs.submit(
            None,
            new_report("/tmp/original", &selection),
            root.join(id.to_string()),
            Ok((id, len)),
            u64::MAX,
        )
    }

    fn reply(offset: u64, total: u64, data: &[u8]) -> Vec<u8> {
        let mut reply = Vec::new();
        reply.extend_from_slice(&offset.to_le_bytes());
        reply.extend_from_slice(&total.to_le_bytes());
        reply.extend_from_slice(&(data.len() as u32).to_le_bytes());
        reply.extend_from_slice(&0u32.to_le_bytes());
        reply.extend_from_slice(data);
        reply
    }

    #[test]
    fn a_larger_specimen_gets_a_longer_transfer_and_a_faster_loop() {
        assert_eq!(transfer_deadline(0), Duration::from_secs(120));
        assert_eq!(transfer_deadline(3), Duration::from_secs(121));
        assert_eq!(transfer_deadline(100_378_920), Duration::from_secs(216));
        let largest = u64::from(control::SPECIMEN_MAX_SIZE);
        assert_eq!(transfer_deadline(largest), Duration::from_secs(248));
        assert_eq!(transfer_deadline(u64::MAX), Duration::from_secs(248));

        let root = std::env::temp_dir().join(format!("ant-acquisition-{}", storage::unique_id()));
        let mut jobs = Jobs::default();
        assert!(!jobs.transferring());
        submit(&mut jobs, &root, 1, 3);
        assert!(jobs.transferring());
        let before = Instant::now();
        let deadline = jobs.queue[0].deadline;
        assert!(deadline >= before + Duration::from_secs(120));
        let Some(Action::Read {
            offset,
            total,
            capacity,
            ..
        }) = jobs.next()
        else {
            panic!("no read");
        };
        jobs.chunk(Ok(reply(0, 3, b"abc")), offset, total, capacity);
        // Received whole: nothing left to read from the guest.
        assert!(!jobs.transferring());
        drop(jobs);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn acquisition_rotates_handles_while_a_worker_is_blocked() {
        let root = std::env::temp_dir().join(format!("ant-acquisition-{}", storage::unique_id()));
        let mut jobs = Jobs::default();
        submit(&mut jobs, &root, 1, 0);
        let mut worker = jobs.queue.pop_front().unwrap();
        worker.handle = None;
        worker.file = None;
        worker.report.state = AnalysisState::Running;
        let mut command = Command::new("/usr/bin/bwrap");
        command.args([
            "--unshare-pid",
            "--unshare-user",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
        ]);
        let launch = sandbox_process::prepare(&mut command).unwrap();
        command.args(["--", "/bin/sleep", "60"]);
        worker.child = Some(SandboxProcess::adopt(command.spawn().unwrap(), launch));
        drop(command);
        let worker_id = worker.report.id.clone();
        jobs.active = Some(worker);
        let a = submit(&mut jobs, &root, 2, 3);
        submit(&mut jobs, &root, 3, 6);
        assert!(matches!(
            jobs.next(),
            Some(Action::Read {
                id: 2,
                offset: 0,
                ..
            })
        ));
        jobs.chunk(Ok(reply(0, 3, b"abc")), 0, 3, 3);
        assert!(matches!(
            jobs.next(),
            Some(Action::Read {
                id: 3,
                offset: 0,
                ..
            })
        ));
        jobs.chunk(Ok(reply(0, 6, b"def")), 0, 6, 3);
        assert!(jobs.next().is_none());
        assert!(matches!(jobs.next(), Some(Action::Release(2))));
        assert!(matches!(
            jobs.next(),
            Some(Action::Read {
                id: 3,
                offset: 3,
                ..
            })
        ));
        assert_eq!(jobs.active.as_ref().unwrap().report.id, worker_id);
        assert_eq!(fs::read(root.join("2/specimen")).unwrap(), b"abc");
        let deadline = Instant::now() + Duration::from_secs(60);
        while open_report(&root.join("2"))
            .unwrap()
            .specimen_sha256
            .is_none()
        {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        let report = open_report(&root.join("2")).unwrap();
        assert_eq!(report.id, a.id);
        assert_eq!(
            report.specimen_sha256,
            Some(format!("{:x}", Sha256::digest(b"abc")))
        );
        drop(jobs);
        storage::settle_json_under(&root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expired_acquisition_is_not_restarted_or_analyzed() {
        let root =
            std::env::temp_dir().join(format!("ant-acquisition-expired-{}", storage::unique_id()));
        let mut jobs = Jobs::default();
        submit(&mut jobs, &root, 2, 3);
        jobs.queue[0].deadline = Instant::now() - Duration::from_secs(1);
        assert!(jobs.next().is_none());
        assert!(matches!(jobs.next(), Some(Action::Release(2))));
        let report = open_report(&root.join("2")).unwrap();
        assert_eq!(report.state, AnalysisState::Unavailable);
        assert!(report.specimen_sha256.is_none());
        assert!(!root.join("2/specimen").exists());
        assert!(jobs.active.is_none());
        drop(jobs);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_stalled_report_write_ends_the_job_and_frees_the_slot() {
        let disk = storage::slow_disk::SlowDisk::install();
        let root =
            std::env::temp_dir().join(format!("ant-acquisition-publish-{}", storage::unique_id()));
        let mut jobs = Jobs::default();
        submit(&mut jobs, &root, 4, 0);
        disk.pause();
        // The empty specimen is complete; its report write is held up.
        assert!(jobs.acquire_next().is_none());
        assert_eq!(jobs.queue[0].report.state, AnalysisState::Acquiring);
        assert!(jobs.queue[0].specimen_publication.is_some());
        // Within its budget the job keeps waiting.
        assert!(jobs.acquire_next().is_none());
        assert_eq!(jobs.queue.len(), 1);
        // Past it, the job fails with the reason.
        jobs.queue[0].deadline = Instant::now() - Duration::from_secs(1);
        assert!(jobs.acquire_next().is_none());
        assert!(jobs.queue.is_empty());
        assert!(jobs.acquiring.is_none());
        disk.resume();
        storage::settle_json_under(&root);
        let report = open_report(&root.join("4")).unwrap();
        assert_eq!(report.state, AnalysisState::Unavailable);
        assert!(report.reason.unwrap().contains("did not finish within"));
        // The next job is not stuck behind it.
        submit(&mut jobs, &root, 5, 3);
        assert!(matches!(
            jobs.acquire_next(),
            Some(Action::Read { id: 5, .. })
        ));
        drop(jobs);
        storage::settle_json_under(&root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_failed_fetch_frees_the_slot_for_the_next_job() {
        let root =
            std::env::temp_dir().join(format!("ant-acquisition-fail-{}", storage::unique_id()));
        let mut jobs = Jobs::default();
        let first = submit(&mut jobs, &root, 1, 3);
        submit(&mut jobs, &root, 2, 3);
        assert!(matches!(
            jobs.acquire_next(),
            Some(Action::Read { id: 1, .. })
        ));
        assert!(jobs.acquiring.is_some());
        jobs.chunk(Err("guest handle expired".into()), 0, 3, 3);
        assert!(jobs.acquiring.is_none());
        assert!(matches!(jobs.next(), Some(Action::Release(1))));
        assert!(matches!(jobs.next(), Some(Action::Read { id: 2, .. })));
        let report = open_report(&root.join("1")).unwrap();
        assert_eq!(report.id, first.id);
        assert_eq!(report.state, AnalysisState::Unavailable);
        assert!(report.reason.unwrap().contains("guest handle expired"));
        drop(jobs);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_job_that_lost_its_guest_handle_is_unavailable_with_a_reason() {
        let root =
            std::env::temp_dir().join(format!("ant-acquisition-lost-{}", storage::unique_id()));
        let mut jobs = Jobs::default();
        submit(&mut jobs, &root, 1, 3);
        jobs.queue[0].handle = None;
        assert!(jobs.acquire_next().is_none());
        assert!(!jobs.tracks(&open_report(&root.join("1")).unwrap().id));
        let report = open_report(&root.join("1")).unwrap();
        assert_eq!(report.state, AnalysisState::Unavailable);
        assert_eq!(report.reason.as_deref(), Some("specimen handle missing"));
        drop(jobs);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn abandoning_settles_only_work_that_has_not_finished() {
        let selection = AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Metadata],
            time_limit_minutes: 0,
            limits: Default::default(),
        };
        let mut report = new_report("/tmp/sample", &selection);
        assert!(abandon(&mut report, "the run did not start: boom"));
        assert_eq!(report.state, AnalysisState::Unavailable);
        assert_eq!(
            report.reason.as_deref(),
            Some("the run did not start: boom")
        );
        assert_eq!(report.sections[0].summary, "the run did not start: boom");
        // Settled once; a second cause does not overwrite the first.
        assert!(!abandon(&mut report, "later"));
        assert_eq!(
            report.reason.as_deref(),
            Some("the run did not start: boom")
        );
        let mut running = new_report("/tmp/sample", &selection);
        running.state = AnalysisState::Running;
        assert!(abandon(&mut running, "gone"));
        assert_eq!(running.state, AnalysisState::Partial);
    }
}
