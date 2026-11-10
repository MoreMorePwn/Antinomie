// SPDX-License-Identifier: GPL-3.0-only
//! The run's Triage digest, written when the scan of a finished run on screen
//! changed. What it holds is `antinomie_triage::digest`.
use super::*;
pub(super) use antinomie_triage::digest::*;

impl TriageView {
    /// While the run's digest builds in the background: the line of how far,
    /// and the way to read the run here at once (which cancels that build; the
    /// window then writes the digest itself).
    pub(super) fn digest_banner(&mut self, ui: &mut egui::Ui) {
        let Some(line) = self.digest_wait.clone() else {
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.spinner();
            ui.label(format!(
                "Building this run's digest in the background. {line}. The tables fill when it is done."
            ));
            if ui.button("Read it here now").clicked() {
                if let Some(directory) = &self.details_directory {
                    antinomie_triage::digest_job::queue().release(directory);
                }
            }
        });
        ui.ctx().request_repaint_after(Duration::from_millis(500));
        ui.separator();
    }

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
