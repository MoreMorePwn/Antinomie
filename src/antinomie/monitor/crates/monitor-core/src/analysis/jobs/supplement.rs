// SPDX-License-Identifier: GPL-3.0-only
//! Checks added to a finished analysis. The report keeps what it has; the
//! checks that were not requested run in a worker of their own over a copy of
//! the retained specimen, and their sections join the report when it ends.
use super::*;

/// What a job that adds checks to a finished analysis remembers.
pub(crate) struct Supplement {
    /// The finished analysis' folder; the job itself works in a folder under it.
    base: PathBuf,
    /// Size of that folder before the job, to count only what the job adds.
    base_len: u64,
    /// The categories the report already had; the worker leaves them alone.
    pub(super) carried: Vec<AnalysisKind>,
}

/// The categories a supplement job did not make.
pub(in crate::analysis) fn carried(supplement: &Option<Supplement>) -> &[AnalysisKind] {
    supplement.as_ref().map_or(&[], |s| &s.carried)
}

/// Move every entry of `from` into `to` (created private); an entry that is
/// already there is an error, not overwritten.
fn move_entries(from: &Path, to: &Path) -> Result<(), String> {
    let Ok(entries) = fs::read_dir(from) else {
        return Ok(());
    };
    storage::private_dir(to).map_err(|e| e.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let target = to.join(entry.file_name());
        if fs::symlink_metadata(&target).is_ok() {
            return Err(format!("{} already exists", target.display()));
        }
        fs::rename(entry.path(), &target).map_err(|e| e.to_string())?;
    }
    Ok(())
}

impl Jobs {
    /// Whether a job of report `id` is waiting or running.
    fn holds(&self, id: &str) -> bool {
        self.queue
            .iter()
            .chain(self.active.iter())
            .chain(self.acquiring.iter())
            .any(|job| job.report.id == id)
    }

    /// Run `kinds`, checks the finished analysis in `base` does not have (or
    /// could not run), and add them to its report. The returned report is the
    /// analysis with the new sections pending; it is `Err` when nothing could
    /// be queued.
    pub(crate) fn analyze_more(
        &mut self,
        run_id: Option<String>,
        base: &Path,
        kinds: &[AnalysisKind],
        available: u64,
    ) -> Result<AnalysisReport, String> {
        let saved = open_report(base)?;
        if !matches!(
            saved.state,
            AnalysisState::Complete | AnalysisState::Partial
        ) {
            return Err("the analysis has not finished".into());
        }
        if self.holds(&saved.id) {
            return Err("this analysis is already running".into());
        }
        if kinds.is_empty() {
            return Err("no check was chosen".into());
        }
        let mut report = saved.clone();
        for (index, kind) in kinds.iter().enumerate() {
            if kinds[..index].contains(kind) {
                return Err("a check was chosen twice".into());
            }
            let section = AnalysisSection {
                kind: *kind,
                state: AnalysisSectionState::Pending,
                summary: "pending acquisition".into(),
                tools: Vec::new(),
                listing: None,
                entries: Vec::new(),
            };
            match report.sections.iter_mut().find(|s| s.kind == *kind) {
                // A check that could not run may be tried again.
                Some(old) if old.state == AnalysisSectionState::Unavailable => *old = section,
                Some(_) => return Err(format!("{} is already in the analysis", kind.label())),
                None => report.sections.push(section),
            }
        }
        let selection = AnalysisSelection {
            enabled: true,
            checks: report.sections.iter().map(|s| s.kind).collect(),
        };
        selection.validate()?;
        let carried: Vec<_> = saved
            .sections
            .iter()
            .map(|s| s.kind)
            .filter(|kind| !kinds.contains(kind))
            .collect();
        let specimen = crate::archive_io::open_regular(base, &base.join("specimen"))
            .map_err(|error| format!("the retained specimen cannot be opened: {error}"))?;
        let size = specimen.metadata().map_err(|e| e.to_string())?.len();
        if saved.specimen_len != Some(size) {
            return Err("the retained specimen is not the size the report says".into());
        }
        report.state = AnalysisState::Acquiring;
        report.reason = None;
        report.specimen_sha256 = None;
        let base_len = directory_len(base).map_err(|e| e.to_string())?;
        let directory = base.join("extra").join(storage::unique_id());
        let retained = self.retained_len;
        let queued = self.submit_host_opened_for(
            run_id,
            report,
            directory.clone(),
            specimen,
            size,
            available,
        );
        if queued.state == AnalysisState::Unavailable {
            // The folder of a job that was never queued holds nothing to keep.
            let _ = fs::remove_dir_all(&directory);
            self.retained_len = retained;
            return Err(queued
                .reason
                .unwrap_or_else(|| "the checks could not be queued".into()));
        }
        if let Some(job) = self.queue.iter_mut().find(|job| job.report.id == queued.id) {
            job.supplement = Some(Supplement {
                base: base.to_path_buf(),
                base_len,
                carried,
            });
        }
        Ok(queued)
    }
}

impl Job {
    /// At the end of a job that added checks: the new categories' listings and
    /// artifacts go into the finished analysis' folder, the job's own folder
    /// is removed and the report is the finished analysis' with the new
    /// sections. The report is then saved there like the original was.
    pub(super) fn merge_supplement(&mut self) {
        let Some(supplement) = self.supplement.as_ref() else {
            return;
        };
        let base = supplement.base.clone();
        let carried = supplement.carried.clone();
        let moved = open_report(&base).and_then(|saved| {
            // The worker's copy must be the specimen the report is of.
            if self.report.specimen_sha256.is_some()
                && saved.specimen_sha256 != self.report.specimen_sha256
            {
                return Err("the retained specimen no longer matches the report".into());
            }
            // Carried sections are the saved ones, with their listings.
            for section in &mut self.report.sections {
                if carried.contains(&section.kind)
                    && let Some(old) = saved.sections.iter().find(|s| s.kind == section.kind)
                {
                    *section = old.clone();
                }
            }
            move_entries(&self.directory.join("listings"), &base.join("listings"))?;
            move_entries(
                &self.directory.join("output/artifacts"),
                &base.join("output/artifacts"),
            )
        });
        if let Err(error) = moved {
            fail(
                &mut self.report,
                AnalysisState::Unavailable,
                format!("added checks: {error}"),
            );
        }
        // The analysis was finished before; a check that failed makes it partial.
        if !matches!(
            self.report.state,
            AnalysisState::Complete | AnalysisState::Partial
        ) {
            self.report.state = AnalysisState::Partial;
        }
        let _ = fs::remove_dir_all(&self.directory);
        self.directory = base;
    }

    /// What the job adds to the retained recordings.
    pub(super) fn retained_len(&self) -> u64 {
        match &self.supplement {
            Some(supplement) => directory_len(&supplement.base)
                .unwrap_or(self.reserved_len)
                .saturating_sub(supplement.base_len),
            None => directory_len(&self.directory).unwrap_or(self.reserved_len),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "run-1";

    /// A finished analysis of a 3-byte specimen with Metadata, and the
    /// listing and artifact folders a worker leaves.
    fn finished(root: &Path, sections: &[AnalysisKind]) -> (PathBuf, AnalysisReport) {
        let base = root.join("analysis");
        storage::private_dir(&base).unwrap();
        let selection = AnalysisSelection {
            enabled: true,
            checks: sections.to_vec(),
        };
        let mut report = new_report("/tmp/sample", &selection);
        report.state = AnalysisState::Complete;
        report.specimen_len = Some(3);
        report.specimen_sha256 = Some(format!("{:x}", Sha256::digest(b"abc")));
        for section in &mut report.sections {
            section.state = AnalysisSectionState::Complete;
            section.summary = format!("{:?} done", section.kind);
        }
        report.specimen_source = Some(SpecimenSource::Guest);
        fs::write(base.join("specimen"), b"abc").unwrap();
        persist_report(&base, &report).unwrap();
        (base, report)
    }

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ant-supplement-{name}-{}", storage::unique_id()))
    }

    /// Step the job until its specimen copy is queued, then take it.
    fn queued(jobs: &mut Jobs) -> Job {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            jobs.acquire_next();
            if let Some(index) = jobs
                .queue
                .iter()
                .position(|job| job.report.state == AnalysisState::Queued)
            {
                return jobs.queue.remove(index).unwrap();
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_check_added_later_joins_the_report_and_is_saved_with_it() {
        let root = scratch("join");
        let (base, saved) = finished(&root, &[AnalysisKind::Metadata]);
        fs::create_dir_all(base.join("listings")).unwrap();
        fs::write(base.join("listings/metadata.jsonl"), b"old").unwrap();
        let mut jobs = Jobs::default();
        let report = jobs
            .analyze_more(Some(RUN.into()), &base, &[AnalysisKind::Strings], u64::MAX)
            .unwrap();
        // It is the same analysis, with the new check waiting.
        assert_eq!(report.id, saved.id);
        assert_eq!(report.state, AnalysisState::Acquiring);
        let kinds: Vec<_> = report.sections.iter().map(|s| (s.kind, s.state)).collect();
        assert_eq!(
            kinds,
            [
                (AnalysisKind::Metadata, AnalysisSectionState::Complete),
                (AnalysisKind::Strings, AnalysisSectionState::Pending),
            ]
        );
        assert_eq!(jobs.updates()[0].0.as_deref(), Some(RUN));
        let mut job = queued(&mut jobs);
        assert_eq!(job.report.specimen_sha256, saved.specimen_sha256);
        // The worker's part: the strings section, its listing and an artifact.
        let work = job.directory.clone();
        assert!(work.starts_with(base.join("extra")));
        fs::create_dir_all(work.join("listings")).unwrap();
        fs::write(work.join("listings/strings.jsonl"), b"new").unwrap();
        fs::create_dir_all(work.join("output/artifacts/unpack")).unwrap();
        fs::write(work.join("output/artifacts/unpack/layer"), b"x").unwrap();
        job.report.sections[1].state = AnalysisSectionState::Complete;
        job.report.sections[1].summary = "found strings".into();
        job.report.state = AnalysisState::Complete;
        jobs.finish(job);
        let merged = open_report(&base).unwrap();
        assert_eq!(merged.id, saved.id);
        assert_eq!(merged.state, AnalysisState::Complete);
        assert_eq!(merged.specimen_source, Some(SpecimenSource::Guest));
        assert_eq!(merged.sections.len(), 2);
        assert_eq!(merged.sections[0], saved.sections[0]);
        assert_eq!(merged.sections[1].summary, "found strings");
        assert_eq!(
            fs::read(base.join("listings/metadata.jsonl")).unwrap(),
            b"old"
        );
        assert_eq!(
            fs::read(base.join("listings/strings.jsonl")).unwrap(),
            b"new"
        );
        assert!(base.join("output/artifacts/unpack/layer").is_file());
        assert!(!work.exists() && !base.join("extra").read_dir().unwrap().any(|_| true));
        // The window hears of the finished report as the run's.
        let (run, update) = jobs.updates().pop().unwrap();
        assert_eq!(run.as_deref(), Some(RUN));
        assert_eq!(update, merged);
        assert!(jobs.retained_len > 0);
        assert!(
            jobs.analyze_more(None, &base, &[AnalysisKind::Strings], u64::MAX)
                .is_err()
        );
        drop(jobs);
        storage::settle_json_under(&root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_failed_added_check_keeps_the_analysis_and_says_why() {
        let root = scratch("failed");
        let (base, saved) = finished(&root, &[AnalysisKind::Metadata]);
        let mut jobs = Jobs::default();
        let before = jobs.retained_len;
        jobs.analyze_more(None, &base, &[AnalysisKind::Capabilities], u64::MAX)
            .unwrap();
        let mut job = queued(&mut jobs);
        fail(
            &mut job.report,
            AnalysisState::Unavailable,
            "capa is not installed",
        );
        jobs.finish(job);
        let merged = open_report(&base).unwrap();
        assert_eq!(merged.state, AnalysisState::Partial);
        assert_eq!(merged.reason.as_deref(), Some("capa is not installed"));
        assert_eq!(merged.sections[0], saved.sections[0]);
        assert_eq!(merged.sections[1].state, AnalysisSectionState::Unavailable);
        assert_eq!(merged.sections[1].summary, "capa is not installed");
        assert!(!base.join("extra").read_dir().unwrap().any(|_| true));
        assert!(jobs.retained_len >= before);
        // A check that could not run may be asked for again; one that did run may not.
        assert!(
            jobs.analyze_more(None, &base, &[AnalysisKind::Capabilities], u64::MAX)
                .is_ok()
        );
        drop(jobs);
        storage::settle_json_under(&root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn only_a_finished_analysis_gets_checks_it_does_not_have() {
        let root = scratch("refused");
        let (base, mut saved) = finished(&root, &[AnalysisKind::Metadata]);
        let mut jobs = Jobs::default();
        let refuse = |jobs: &mut Jobs, kinds: &[AnalysisKind], word: &str| {
            let error = jobs.analyze_more(None, &base, kinds, u64::MAX).unwrap_err();
            assert!(error.contains(word), "{error}");
        };
        refuse(&mut jobs, &[], "no check");
        refuse(&mut jobs, &[AnalysisKind::Metadata], "already in");
        refuse(
            &mut jobs,
            &[AnalysisKind::Strings, AnalysisKind::Strings],
            "twice",
        );
        // Not while it is still being made.
        saved.state = AnalysisState::Running;
        persist_report(&base, &saved).unwrap();
        refuse(&mut jobs, &[AnalysisKind::Strings], "not finished");
        saved.state = AnalysisState::Complete;
        persist_report(&base, &saved).unwrap();
        // Nor while another run of checks is waiting.
        jobs.analyze_more(None, &base, &[AnalysisKind::Strings], u64::MAX)
            .unwrap();
        refuse(&mut jobs, &[AnalysisKind::Entropy], "already running");
        // Nor over a specimen that is not the one the report is of.
        jobs.cancel(&saved.id).unwrap();
        fs::write(base.join("specimen"), b"abcd").unwrap();
        refuse(&mut jobs, &[AnalysisKind::Entropy], "size");
        // Nor without room.
        fs::write(base.join("specimen"), b"abc").unwrap();
        let error = jobs
            .analyze_more(None, &base, &[AnalysisKind::Entropy], 1000)
            .unwrap_err();
        assert!(error.contains("quota"), "{error}");
        drop(jobs);
        storage::settle_json_under(&root);
        fs::remove_dir_all(root).unwrap();
    }
}
