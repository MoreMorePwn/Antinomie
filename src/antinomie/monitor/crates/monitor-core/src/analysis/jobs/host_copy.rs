// SPDX-License-Identifier: GPL-3.0-only
//! Static analysis of an uploaded program from the host's own copy of the
//! file. The copy is staged in the run's specimen store and hashed there; it
//! replaces the guest transfer only when that hash equals the one the guest
//! recorded for the file it executed. Anything else goes on with the guest
//! fetch, so the evidence is always a file the guest vouched for.
use super::*;

/// How long the guest's hash of the executed file is awaited before the guest
/// transfer goes ahead.
const HASH_WAIT: Duration = Duration::from_secs(10);

/// How long copying and hashing the host file may hold the backend worker. A
/// slow or stalled mount ends the offer and the guest transfer goes ahead.
const COPY_BUDGET: Duration = Duration::from_secs(10);

/// Copy up to `len` bytes of `input` to `output`, and hash what is written,
/// giving up when `deadline` passes.
fn copy_within(
    input: &mut impl Read,
    output: &mut impl Write,
    len: u64,
    deadline: Instant,
) -> std::io::Result<(u64, Sha256)> {
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    let mut copied = 0u64;
    while copied < len {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "copying the host file took too long",
            ));
        }
        let want = buffer.len().min((len - copied) as usize);
        let read = input.read(&mut buffer[..want])?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
        copied += read as u64;
    }
    Ok((copied, digest))
}

/// Where a staged host copy stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// The guest's hash has not arrived yet; the guest transfer waits for it.
    Waiting(Instant),
    /// The guest's hash equals the hash of the staged copy.
    Matched,
    /// The staged copy is the specimen: the guest transfer was dropped.
    Adopted,
    /// No hash arrived in time, it was not usable or it differs.
    Rejected,
}

/// The uploaded file as copied into the specimen store.
pub(super) struct HostCopy {
    /// SHA-256 of the store copy, not of the original path.
    sha256: String,
    path: PathBuf,
    len: u64,
    verdict: Verdict,
}

impl Jobs {
    /// Copy `source`, the file just uploaded to the guest, into the specimen
    /// store of the acquiring job `report_id` and hash the store copy. The
    /// job keeps its guest handle but does not read from it until the guest's
    /// hash is known ([`guest_hash`](Self::guest_hash)) or the wait ends.
    pub(crate) fn offer_host_copy(&mut self, report_id: &str, source: &Path) -> Result<(), String> {
        self.offer_host_copy_within(report_id, source, COPY_BUDGET)
    }

    fn offer_host_copy_within(
        &mut self,
        report_id: &str,
        source: &Path,
        budget: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + budget;
        let job = self
            .queue
            .iter_mut()
            .chain(self.acquiring.iter_mut())
            .find(|job| job.report.id == report_id)
            .ok_or("the analysis job is not waiting for its specimen")?;
        if job.host_copy.is_some() || job.report.state != AnalysisState::Acquiring {
            return Err("the analysis job is not waiting for its specimen".into());
        }
        let mut input = File::open(source).map_err(|e| format!("{}: {e}", source.display()))?;
        let metadata = input.metadata().map_err(|e| e.to_string())?;
        // A file of another size cannot be the one that ran.
        if !metadata.is_file() || metadata.len() != job.total_len {
            return Err("the host file is not the size of the executed file".into());
        }
        let path = job.directory.join("specimen.host");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| e.to_string())?;
        let staged = (|| -> std::io::Result<String> {
            let (copied, _) = copy_within(&mut input, &mut output, job.total_len, deadline)?;
            output.sync_all()?;
            if copied != job.total_len {
                return Err(std::io::Error::other(
                    "the file changed while it was copied",
                ));
            }
            // Hash what is in the store, so the file cannot change between
            // the check and the analysis.
            let (hashed, digest) = copy_within(
                &mut File::open(&path)?,
                &mut std::io::sink(),
                copied,
                deadline,
            )?;
            if hashed != copied {
                return Err(std::io::Error::other(
                    "the staged copy changed while hashed",
                ));
            }
            Ok(format!("{:x}", digest.finalize()))
        })();
        match staged {
            Ok(sha256) => {
                job.disk_len = job.disk_len.saturating_add(job.total_len);
                job.host_copy = Some(HostCopy {
                    sha256,
                    path,
                    len: job.total_len,
                    verdict: Verdict::Waiting(Instant::now() + HASH_WAIT),
                });
                Ok(())
            }
            Err(error) => {
                let _ = fs::remove_file(&path);
                Err(error.to_string())
            }
        }
    }

    /// The guest's hash of the file run `run_id` executed, or `None` when it
    /// recorded none that names the file (too large, a script's interpreter,
    /// changed while read).
    pub(crate) fn guest_hash(&mut self, run_id: &str, sha256: Option<&str>) {
        let waiting = self
            .queue
            .iter_mut()
            .chain(self.acquiring.iter_mut())
            .filter(|job| job.run_id.as_deref() == Some(run_id))
            .filter_map(|job| job.host_copy.as_mut())
            .find(|host| matches!(host.verdict, Verdict::Waiting(_)));
        if let Some(host) = waiting {
            host.verdict = match sha256 {
                Some(hash) if hash.eq_ignore_ascii_case(&host.sha256) => Verdict::Matched,
                _ => Verdict::Rejected,
            };
        }
    }
}

impl Job {
    /// Settle a staged host copy before the guest transfer reads. True means
    /// the transfer waits for the guest's hash.
    pub(super) fn hold_for_host_copy(&mut self) -> bool {
        let Some(verdict) = self.host_copy.as_ref().map(|host| host.verdict) else {
            return false;
        };
        match verdict {
            Verdict::Waiting(until) if Instant::now() < until => true,
            Verdict::Matched => {
                if self.adopt_host_copy().is_err() {
                    self.discard_host_copy();
                }
                false
            }
            Verdict::Waiting(_) => {
                self.discard_host_copy();
                self.note_pending(&format!(
                    "the guest did not report the executed file's hash within {} seconds; fetching the file from the guest",
                    HASH_WAIT.as_secs()
                ));
                false
            }
            Verdict::Rejected => {
                self.discard_host_copy();
                self.note_pending(
                    "the guest's hash does not match the host copy; fetching the file from the guest",
                );
                false
            }
            Verdict::Adopted => false,
        }
    }

    /// The staged copy becomes the specimen and the partial guest transfer is
    /// dropped. The guest handle is released by the usual end of acquisition.
    fn adopt_host_copy(&mut self) -> Result<(), String> {
        let host = self.host_copy.as_mut().ok_or("no host copy")?;
        fs::rename(&host.path, self.directory.join("specimen")).map_err(|e| e.to_string())?;
        host.verdict = Verdict::Adopted;
        self.file = None;
        let _ = fs::remove_file(self.directory.join("specimen.partial"));
        self.disk_len = self.disk_len.saturating_sub(self.received_len);
        self.received_len = self.total_len;
        Ok(())
    }

    /// Say why acquisition is taking the guest transfer, on every section
    /// that still waits for the specimen.
    fn note_pending(&mut self, why: &str) {
        for section in &mut self.report.sections {
            if section.state == AnalysisSectionState::Pending {
                section.summary = format!("pending acquisition; {why}");
            }
        }
    }

    /// Forget a staged copy that did not match, or was never needed.
    pub(super) fn discard_host_copy(&mut self) {
        if let Some(host) = self
            .host_copy
            .take_if(|host| host.verdict != Verdict::Adopted)
        {
            let _ = fs::remove_file(&host.path);
            self.disk_len = self.disk_len.saturating_sub(host.len);
        }
    }

    /// SHA-256 of the specimen when the host copy is it.
    pub(super) fn adopted_sha256(&self) -> Option<String> {
        self.host_copy
            .as_ref()
            .filter(|host| host.verdict == Verdict::Adopted)
            .map(|host| host.sha256.clone())
    }

    /// Say where the specimen came from; `fetched` is whether a guest handle
    /// was in use, which a file read on the host never has.
    pub(super) fn record_specimen_source(&mut self, fetched: bool) {
        // The end of acquisition can run again while the report is written.
        if self.adopted_sha256().is_some() {
            self.report.specimen_source = Some(SpecimenSource::HostCopy);
        } else if fetched {
            self.report.specimen_source = Some(SpecimenSource::Guest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "run-1";

    fn directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ant-host-copy-{name}-{}", storage::unique_id()))
    }

    /// An acquiring job of a run, whose guest file is `len` bytes long.
    fn submit(jobs: &mut Jobs, root: &Path, len: u64) -> String {
        let selection = AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Metadata],
            time_limit_minutes: 0,
            limits: Default::default(),
        };
        jobs.submit(
            Some(RUN.into()),
            new_report("/tmp/uploaded", &selection),
            root.join("analysis"),
            Ok((7, len)),
            u64::MAX,
        )
        .id
    }

    fn reply(data: &[u8]) -> Vec<u8> {
        let mut reply = Vec::new();
        reply.extend_from_slice(&0u64.to_le_bytes());
        reply.extend_from_slice(&(data.len() as u64).to_le_bytes());
        reply.extend_from_slice(&(data.len() as u32).to_le_bytes());
        reply.extend_from_slice(&0u32.to_le_bytes());
        reply.extend_from_slice(data);
        reply
    }

    /// Step acquisition until the job has its report published as queued.
    fn until_queued(jobs: &mut Jobs) -> AnalysisReport {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            jobs.acquire_next();
            if let Some(job) = jobs
                .queue
                .iter()
                .find(|job| job.report.state == AnalysisState::Queued)
            {
                return job.report.clone();
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn settle(jobs: Jobs, root: &Path) {
        drop(jobs);
        storage::settle_json_under(root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_matching_guest_hash_makes_the_host_copy_the_specimen() {
        let root = directory("match");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("uploaded"), b"abc").unwrap();
        let mut jobs = Jobs::default();
        let id = submit(&mut jobs, &root, 3);
        jobs.offer_host_copy(&id, &root.join("uploaded")).unwrap();
        assert_eq!(
            fs::read(root.join("analysis/specimen.host")).unwrap(),
            b"abc"
        );
        // Nothing is read from the guest while its hash is awaited.
        assert!(jobs.acquire_next().is_none());
        assert!(jobs.queue.iter().all(|job| job.received_len == 0));
        let guest = format!("{:x}", Sha256::digest(b"abc"));
        jobs.guest_hash(RUN, Some(&guest.to_uppercase()));
        let report = until_queued(&mut jobs);
        assert_eq!(report.specimen_sha256.as_deref(), Some(guest.as_str()));
        assert_eq!(report.specimen_len, Some(3));
        assert_eq!(report.specimen_source, Some(SpecimenSource::HostCopy));
        assert_eq!(fs::read(root.join("analysis/specimen")).unwrap(), b"abc");
        assert!(!root.join("analysis/specimen.host").exists());
        assert!(!root.join("analysis/specimen.partial").exists());
        // The guest handle is released unread.
        assert!(matches!(jobs.next(), Some(Action::Release(7))));
        settle(jobs, &root);
    }

    #[test]
    fn a_different_guest_hash_falls_back_to_the_guest_fetch() {
        let root = directory("differs");
        fs::create_dir_all(&root).unwrap();
        // The program rewrote itself: the guest ran other bytes.
        fs::write(root.join("uploaded"), b"abc").unwrap();
        let mut jobs = Jobs::default();
        let id = submit(&mut jobs, &root, 3);
        jobs.offer_host_copy(&id, &root.join("uploaded")).unwrap();
        jobs.guest_hash(RUN, Some(&format!("{:x}", Sha256::digest(b"xyz"))));
        assert!(matches!(
            jobs.acquire_next(),
            Some(Action::Read {
                id: 7,
                offset: 0,
                ..
            })
        ));
        assert!(!root.join("analysis/specimen.host").exists());
        jobs.chunk(Ok(reply(b"xyz")), 0, 3, 3);
        let report = until_queued(&mut jobs);
        assert_eq!(
            report.specimen_sha256,
            Some(format!("{:x}", Sha256::digest(b"xyz")))
        );
        assert_eq!(report.specimen_source, Some(SpecimenSource::Guest));
        assert_eq!(fs::read(root.join("analysis/specimen")).unwrap(), b"xyz");
        settle(jobs, &root);
    }

    #[test]
    fn no_usable_hash_or_none_in_time_goes_on_with_the_guest_fetch() {
        let root = directory("unusable");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("uploaded"), b"abc").unwrap();
        let mut jobs = Jobs::default();
        let id = submit(&mut jobs, &root, 3);
        jobs.offer_host_copy(&id, &root.join("uploaded")).unwrap();
        // The guest recorded no hash that names the file.
        jobs.guest_hash(RUN, None);
        assert!(matches!(jobs.acquire_next(), Some(Action::Read { .. })));
        settle(jobs, &root);

        let root = directory("late");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("uploaded"), b"abc").unwrap();
        let mut jobs = Jobs::default();
        let id = submit(&mut jobs, &root, 3);
        jobs.offer_host_copy(&id, &root.join("uploaded")).unwrap();
        jobs.queue[0].host_copy.as_mut().unwrap().verdict =
            Verdict::Waiting(Instant::now() - Duration::from_secs(1));
        assert!(matches!(jobs.acquire_next(), Some(Action::Read { .. })));
        let job = jobs.acquiring.as_ref().unwrap();
        assert!(job.host_copy.is_none());
        // The wait ended without a hash, and the report says so.
        assert!(
            job.report.sections[0]
                .summary
                .contains("did not report the executed file's hash within 10 seconds")
        );
        settle(jobs, &root);
    }

    #[test]
    fn a_mismatching_hash_is_said_on_the_waiting_sections() {
        let root = directory("said");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("uploaded"), b"abc").unwrap();
        let mut jobs = Jobs::default();
        let id = submit(&mut jobs, &root, 3);
        jobs.offer_host_copy(&id, &root.join("uploaded")).unwrap();
        jobs.guest_hash(RUN, Some(&format!("{:x}", Sha256::digest(b"xyz"))));
        assert!(matches!(jobs.acquire_next(), Some(Action::Read { .. })));
        assert!(
            jobs.acquiring.as_ref().unwrap().report.sections[0]
                .summary
                .contains("does not match the host copy")
        );
        settle(jobs, &root);
    }

    #[test]
    fn copying_the_host_file_has_a_budget_and_leaves_nothing_behind() {
        let root = directory("budget");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("uploaded"), b"abc").unwrap();
        let mut jobs = Jobs::default();
        let id = submit(&mut jobs, &root, 3);
        let error = jobs
            .offer_host_copy_within(&id, &root.join("uploaded"), Duration::ZERO)
            .unwrap_err();
        assert!(error.contains("took too long"), "{error}");
        assert!(!root.join("analysis/specimen.host").exists());
        assert!(jobs.queue[0].host_copy.is_none());
        // The guest transfer starts at once.
        assert!(matches!(jobs.acquire_next(), Some(Action::Read { .. })));
        settle(jobs, &root);
    }

    #[test]
    fn a_host_file_of_another_size_or_a_job_without_a_wait_is_refused() {
        let root = directory("refused");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("uploaded"), b"abcd").unwrap();
        let mut jobs = Jobs::default();
        let id = submit(&mut jobs, &root, 3);
        assert!(
            jobs.offer_host_copy(&id, &root.join("uploaded"))
                .unwrap_err()
                .contains("size")
        );
        assert!(!root.join("analysis/specimen.host").exists());
        assert!(
            jobs.offer_host_copy("unknown", &root.join("uploaded"))
                .is_err()
        );
        assert!(jobs.offer_host_copy(&id, &root.join("missing")).is_err());
        // Without an offer the guest transfer starts at once.
        assert!(matches!(jobs.acquire_next(), Some(Action::Read { .. })));
        settle(jobs, &root);
    }

    #[test]
    fn the_store_copy_is_the_one_that_is_hashed_and_cleaned_up_with_the_job() {
        let root = directory("store");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("uploaded"), b"abc").unwrap();
        let mut jobs = Jobs::default();
        let id = submit(&mut jobs, &root, 3);
        jobs.offer_host_copy(&id, &root.join("uploaded")).unwrap();
        // The original changes after the copy was made.
        fs::write(root.join("uploaded"), b"zzz").unwrap();
        assert_eq!(
            jobs.queue[0].host_copy.as_ref().unwrap().sha256,
            format!("{:x}", Sha256::digest(b"abc"))
        );
        // A cancelled job leaves no staged copy behind.
        jobs.cancel(&id).unwrap();
        assert!(!root.join("analysis/specimen.host").exists());
        settle(jobs, &root);
    }

    #[test]
    fn the_source_is_saved_with_the_report_and_an_older_report_has_none() {
        let mut report = new_report("/tmp/uploaded", &AnalysisSelection::default());
        report.specimen_source = Some(SpecimenSource::HostCopy);
        let saved = serde_json::to_value(&report).unwrap();
        assert_eq!(saved["specimen_source"], "host_copy");
        let mut older = saved;
        older.as_object_mut().unwrap().remove("specimen_source");
        let reopened: AnalysisReport = serde_json::from_value(older).unwrap();
        assert_eq!(reopened.specimen_source, None);
        report.specimen_source = None;
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("specimen_source")
        );
    }
}
