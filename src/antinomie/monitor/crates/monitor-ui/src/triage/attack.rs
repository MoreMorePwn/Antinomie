// SPDX-License-Identifier: GPL-3.0-only
//! The ATT&CK list of the Summary: the list and what produced each technique
//! are `antinomie_triage::attack`'s, which every export format lists too.
use antinomie_monitor_core::report::Technique;
pub(super) use antinomie_triage::attack::*;

impl super::TriageView {
    /// Whether the Suspicious activity table is narrowed by a filter or a tier
    /// or category chip, so `scan.findings` holds only the rows it shows.
    pub(super) fn findings_narrowed(&self) -> bool {
        let view = &self.scan_request.finding_view;
        !self.scan_request.filters[0].is_empty() || view.tiers != 0 || view.categories != 0
    }

    /// The list and, beside each technique in the same order, what produced it.
    /// While the table is narrowed the list stays as it was, so a filter set to
    /// look at one technique does not shrink the list it came from.
    pub(super) fn attack_list(&mut self) -> (&[Technique], &[Detail]) {
        let Some(scan) = self.scan.as_ref() else {
            return (&[], &[]);
        };
        // The run the list is of leads the key, so a narrowed table of another
        // run is not given this run's list.
        let run = self
            .details_directory
            .as_ref()
            .map_or_else(String::new, |directory| directory.display().to_string());
        let fingerprint = format!(
            "{run}|{}|{}|{:?}",
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
        let kept = self.findings_narrowed()
            && self
                .attacked
                .as_ref()
                .is_some_and(|(key, ..)| key.split('|').next() == Some(run.as_str()));
        if kept {
            return self
                .attacked
                .as_ref()
                .map_or((&[], &[]), |(_, list, details)| (list, details));
        }
        if self.attacked.as_ref().map(|(key, ..)| key) != Some(&fingerprint) {
            let behaviour = super::digest::behaviour(&scan.findings);
            let detections = super::digest::detections(&self.detection.results);
            let detections = detections.as_deref().unwrap_or_default();
            let list = techniques(&behaviour, detections);
            let details = details(&list, &behaviour, detections);
            self.attacked = Some((fingerprint, list, details));
        }
        self.attacked
            .as_ref()
            .map_or((&[], &[]), |(_, list, details)| (list, details))
    }
}

impl super::TriageView {
    /// The first Suspicious activity row that cites `id`: the calls behind it.
    pub(super) fn technique_finding(&self, id: &str) -> Option<&super::Finding> {
        self.scan.as_ref()?.findings.iter().find(|finding| {
            finding.values.iter().any(|(key, value)| {
                *key == "finding.technique"
                    && matches!(value, super::RowValue::List(ids) if ids.iter().any(|t| t == id))
            })
        })
    }
}
