// SPDX-License-Identifier: GPL-3.0-only
//! Publish acquired specimen identity before exposing it to archive readers.
use super::*;

impl Job {
    pub(super) fn publish_specimen_report(&mut self) -> Result<bool, String> {
        if self.specimen_publication.is_none() {
            self.specimen_publication = Some(storage::queue_json_observed(
                &self.directory.join("report.json"),
                &self.report,
            )?);
        }
        match self
            .specimen_publication
            .as_ref()
            .map(storage::JsonReceipt::status)
        {
            Some(storage::JsonWriteStatus::Pending) => Ok(false),
            Some(storage::JsonWriteStatus::Complete) => {
                let report_len = fs::metadata(self.directory.join("report.json"))
                    .map_err(|error| format!("specimen report publication: {error}"))?
                    .len();
                self.disk_len = self
                    .disk_len
                    .saturating_sub(self.report_len)
                    .saturating_add(report_len);
                self.report_len = report_len;
                Ok(true)
            }
            Some(storage::JsonWriteStatus::Failed(error)) => {
                Err(format!("specimen report publication: {error}"))
            }
            Some(storage::JsonWriteStatus::Superseded) => Err(
                "specimen report publication was superseded before acquisition became visible"
                    .into(),
            ),
            None => Err("specimen report publication receipt missing".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acquired_job() -> Job {
        let directory =
            std::env::temp_dir().join(format!("ant-specimen-publication-{}", storage::unique_id()));
        storage::private_dir(&directory).unwrap();
        let mut report = new_report("/tmp/sample", &AnalysisSelection::default());
        persist_report(&directory, &report).unwrap();
        let data = b"retained specimen";
        fs::write(directory.join("specimen"), data).unwrap();
        report.state = AnalysisState::Queued;
        report.specimen_sha256 = Some(format!("{:x}", Sha256::digest(data)));
        report.specimen_len = Some(data.len() as u64);
        Job {
            run_id: None,
            report,
            directory,
            handle: None,
            total_len: data.len() as u64,
            received_len: data.len() as u64,
            file: None,
            deadline: Instant::now() + Duration::from_secs(5),
            child: None,
            cleanup_reason: None,
            reserved_len: 0,
            digest: Sha256::new(),
            disk_len: 0,
            worker_len: 0,
            report_len: 0,
            specimen_publication: None,
            progress: Default::default(),
            host_copy: None,
        }
    }

    #[test]
    fn acquired_specimen_is_readable_before_analysis_finishes() {
        let mut job = acquired_job();
        assert!(
            open_report(&job.directory)
                .unwrap()
                .specimen_sha256
                .is_none()
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !job.publish_specimen_report().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        let saved = open_report(&job.directory).unwrap();
        assert_eq!(saved.state, AnalysisState::Queued);
        assert_eq!(saved.specimen_sha256, job.report.specimen_sha256);
        let (_, data) =
            super::super::super::specimen::read_all(&job.directory, &job.report.id).unwrap();
        assert_eq!(data, b"retained specimen");
        assert!(job.report_len > 0);
        storage::settle_json_under(&job.directory);
        fs::remove_dir_all(&job.directory).unwrap();
    }

    #[test]
    fn failed_or_superseded_publication_never_advertises_readiness() {
        let mut job = acquired_job();
        fs::remove_file(job.directory.join("report.json")).unwrap();
        fs::create_dir(job.directory.join("report.json")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match job.publish_specimen_report() {
                Err(error) => {
                    assert!(error.contains("specimen report publication"));
                    break;
                }
                Ok(false) => {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(true) => panic!("failed report became ready"),
            }
        }
        storage::settle_json_under(&job.directory);
        fs::remove_dir_all(&job.directory).unwrap();

        let mut job = acquired_job();
        let _ = job.publish_specimen_report().unwrap();
        let mut cancelled = job.report.clone();
        cancelled.state = AnalysisState::Cancelled;
        persist_report(&job.directory, &cancelled).unwrap();
        assert!(
            job.publish_specimen_report()
                .unwrap_err()
                .contains("superseded")
        );
        assert_eq!(
            open_report(&job.directory).unwrap().state,
            AnalysisState::Cancelled
        );
        storage::settle_json_under(&job.directory);
        fs::remove_dir_all(&job.directory).unwrap();
    }
}
