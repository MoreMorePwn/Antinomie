// SPDX-License-Identifier: GPL-3.0-only
//! Drain expiring guest specimens independently of slow host analysis tools.
use super::*;

impl Jobs {
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
        if Instant::now() >= job.deadline {
            fail(
                &mut job.report,
                AnalysisState::Unavailable,
                "specimen acquisition deadline exceeded; incomplete capture never analyzed",
            );
            self.finish(job);
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
        if let Some(id) = job.handle.take() {
            self.release.push_back(id);
        }
        job.report.specimen_len = Some(job.total_len);
        job.report.specimen_sha256 = Some(format!("{:x}", job.digest.clone().finalize()));
        // The durable report must say Queued before the worker can see it.
        job.report.state = AnalysisState::Queued;
        match job.publish_specimen_report() {
            Ok(true) => {
                self.updates.push((job.run_id.clone(), job.report.clone()));
                self.queue.push_back(job);
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
        let deadline = Instant::now() + Duration::from_secs(5);
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
}
