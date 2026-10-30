// SPDX-License-Identifier: GPL-3.0-only
//! Static analysis of a file on the host (one the Disks tab extracted from a
//! VM's disk), with no VM running: the specimen is copied from the file where
//! a guest transfer would write it, and the rest of the job (isolated worker,
//! report, quota accounting) is the ordinary one.
use super::*;

/// The guest handle a host job reserves; there is no guest to release it.
const NO_HANDLE: u64 = 0;

impl Jobs {
    /// Queue an analysis of the regular file `source`. `directory` is the
    /// report's own folder under the VM's recordings. The returned report is
    /// `Unavailable` when the file cannot be analyzed.
    pub(crate) fn submit_host_file(
        &mut self,
        report: AnalysisReport,
        directory: PathBuf,
        source: &Path,
        available: u64,
    ) -> AnalysisReport {
        let opened = File::open(source)
            .and_then(|file| file.metadata().map(|metadata| (file, metadata)))
            .map_err(|error| format!("{}: {error}", source.display()))
            .and_then(|(file, metadata)| {
                if metadata.is_file() {
                    Ok((file, metadata.len()))
                } else {
                    Err(format!("{} is not a regular file", source.display()))
                }
            });
        match opened {
            Ok((file, total_len)) => {
                self.submit_host_opened(report, directory, file, total_len, available)
            }
            Err(error) => self.submit(None, report, directory, Err(error), available),
        }
    }

    /// [`submit_host_file`](Self::submit_host_file) for a file the caller has
    /// opened and checked itself.
    pub(crate) fn submit_host_opened(
        &mut self,
        report: AnalysisReport,
        directory: PathBuf,
        input: File,
        total_len: u64,
        available: u64,
    ) -> AnalysisReport {
        self.submit_host_opened_for(None, report, directory, input, total_len, available)
    }

    /// [`submit_host_opened`](Self::submit_host_opened) for the analysis of a run.
    pub(super) fn submit_host_opened_for(
        &mut self,
        run_id: Option<String>,
        report: AnalysisReport,
        directory: PathBuf,
        mut input: File,
        total_len: u64,
        available: u64,
    ) -> AnalysisReport {
        let mut report = self.submit(
            run_id.clone(),
            report,
            directory.clone(),
            Ok((NO_HANDLE, total_len)),
            available,
        );
        if report.state == AnalysisState::Unavailable {
            return report;
        }
        let copied = self.copy_specimen(&report.id, &mut input, total_len);
        if let Err(error) = copied {
            if let Some(index) = self.queue.iter().position(|job| job.report.id == report.id) {
                self.queue.remove(index);
            }
            fail(&mut report, AnalysisState::Unavailable, error);
            let _ = persist_report(&directory, &report);
            self.updates.push((run_id, report.clone()));
        }
        report
    }

    fn copy_specimen(&mut self, id: &str, input: &mut File, total_len: u64) -> Result<(), String> {
        let job = self
            .queue
            .iter_mut()
            .find(|job| job.report.id == id)
            .ok_or("the analysis job was not queued")?;
        let output = job.file.as_mut().ok_or("specimen file missing")?;
        let mut buffer = vec![0u8; 256 * 1024];
        let mut received = 0u64;
        while received < total_len {
            let want = (total_len - received).min(buffer.len() as u64) as usize;
            let count = input.read(&mut buffer[..want]).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            output
                .write_all(&buffer[..count])
                .map_err(|e| e.to_string())?;
            job.digest.update(&buffer[..count]);
            received += count as u64;
        }
        if received != total_len {
            return Err("the file changed while it was copied".into());
        }
        job.received_len = received;
        job.disk_len = job.disk_len.saturating_add(received);
        job.handle = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection() -> AnalysisSelection {
        AnalysisSelection {
            enabled: true,
            checks: AnalysisKind::TRIAGE.to_vec(),
            time_limit_minutes: 0,
        }
    }

    fn scratch() -> PathBuf {
        let root = std::env::temp_dir().join(format!("ant-host-analysis-{}", storage::unique_id()));
        storage::private_dir(&root).unwrap();
        root
    }

    #[test]
    fn a_host_file_becomes_the_queued_specimen_byte_for_byte() {
        let root = scratch();
        let source = root.join("extracted.bin");
        let content: Vec<u8> = (0..700_000u32).map(|n| (n % 251) as u8).collect();
        fs::write(&source, &content).unwrap();
        let mut jobs = Jobs::default();
        let report = new_report(&source.display().to_string(), &selection());
        let directory = root.join("analyses").join(&report.id);
        let report = jobs.submit_host_file(report, directory.clone(), &source, u64::MAX);
        assert_eq!(
            report.state,
            AnalysisState::Acquiring,
            "{:?}",
            report.reason
        );
        assert_eq!(jobs.pending_count(), 1);
        assert_eq!(
            fs::read(directory.join("specimen.partial")).unwrap(),
            content
        );
        // The job needs no guest: it holds no handle, so nothing is released.
        assert!(jobs.release.is_empty());
        let queued = jobs.queue.front().unwrap();
        assert_eq!(queued.received_len, content.len() as u64);
        assert_eq!(
            format!("{:x}", queued.digest.clone().finalize()),
            format!("{:x}", Sha256::digest(&content))
        );
        assert!(queued.handle.is_none());
        // It can be cancelled like any other job.
        jobs.cancel(&report.id).unwrap();
        assert_eq!(
            jobs.updates().last().unwrap().1.state,
            AnalysisState::Cancelled
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unusable_files_and_a_full_quota_are_reported_unavailable() {
        let root = scratch();
        let source = root.join("sample.bin");
        fs::write(&source, vec![1u8; 4096]).unwrap();
        let mut jobs = Jobs::default();
        for (path, available, reason) in [
            (root.clone(), u64::MAX, "not a regular file"),
            (root.join("missing"), u64::MAX, "missing"),
            (source.clone(), 1000, "quota"),
        ] {
            let report = new_report(&path.display().to_string(), &selection());
            let directory = root.join("analyses").join(&report.id);
            let report = jobs.submit_host_file(report, directory, &path, available);
            assert_eq!(report.state, AnalysisState::Unavailable);
            assert!(report.reason.unwrap().contains(reason));
        }
        assert_eq!(jobs.pending_count(), 0);
        fs::remove_dir_all(root).unwrap();
    }
}
