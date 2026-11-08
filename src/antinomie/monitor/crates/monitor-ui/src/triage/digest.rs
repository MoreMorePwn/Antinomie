// SPDX-License-Identifier: GPL-3.0-only
//! The run's Triage digest, written when the scan of a finished run on screen
//! changed. What it holds is `antinomie_triage::digest`.
use super::*;
pub(super) use antinomie_triage::digest::*;

impl TriageView {
    /// Write the digest of the run on screen when its scan of a finished run
    /// changed. Cheap while nothing changed: one fingerprint comparison.
    pub(super) fn digest_tick(&mut self) {
        if !self.scan_began_finished || self.scan_rx.is_some() {
            return;
        }
        // A narrowed table holds only the rows it shows; the digest is of the run.
        if self.findings_narrowed() {
            return;
        }
        let (Some(directory), Some(scan)) = (self.details_directory.clone(), self.scan.as_ref())
        else {
            return;
        };
        let fingerprint = format!(
            "{}|{}|{}|{:?}",
            directory.display(),
            scan.stamp,
            scan.findings.len(),
            self.detection
                .results
                .iter()
                .map(|result| match result {
                    Some(Ok(report)) => (report.findings.len(), format!("{:?}", report.state)),
                    _ => (0, String::new()),
                })
                .collect::<Vec<_>>()
        );
        if self.digested.as_deref() == Some(fingerprint.as_str()) {
            return;
        }
        self.digested = Some(fingerprint);
        let update = Update::of(scan, detections(&self.detection.results));
        // Off the UI thread: the write is a synced file.
        let _ = std::thread::Builder::new()
            .name("triage-digest".into())
            .spawn(move || {
                let _ = update.write(&directory);
            });
    }
}
