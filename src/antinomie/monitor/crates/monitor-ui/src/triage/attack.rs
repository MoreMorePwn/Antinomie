// SPDX-License-Identifier: GPL-3.0-only
//! The ATT&CK techniques of a run, in one place: the Summary on screen and
//! every export format list what this function returns, so they cannot differ.
//! A technique comes from the behaviour rules (named by rule) and from the
//! detection engines (named by engine and rule title).
use antinomie_monitor_core::{
    mitre,
    report::Technique,
    run_digest::{Behaviour, DetectionHit},
};
use std::collections::{BTreeMap, BTreeSet};

impl super::TriageView {
    /// What the Summary shows: the same list the export builds from the same
    /// findings and detections, made again only when either changed.
    pub(super) fn attack_techniques(&mut self) -> &[Technique] {
        let Some(scan) = self.scan.as_ref() else {
            return &[];
        };
        let fingerprint = format!(
            "{}|{}|{:?}",
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
        if self.attacked.as_ref().map(|(key, _)| key) != Some(&fingerprint) {
            let behaviour = super::digest::behaviour(&scan.findings);
            let detections = super::digest::detections(&self.detection.results);
            let list = techniques(&behaviour, detections.as_deref().unwrap_or_default());
            self.attacked = Some((fingerprint, list));
        }
        self.attacked.as_ref().map_or(&[], |(_, list)| list)
    }
}

pub(super) fn technique_id(id: &str) -> bool {
    let rest = id.strip_prefix('T').unwrap_or("");
    let (main, sub) = rest
        .split_once('.')
        .map_or((rest, None), |(a, b)| (a, Some(b)));
    main.len() == 4
        && main.bytes().all(|b| b.is_ascii_digit())
        && sub.is_none_or(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
}

/// The union of the techniques the behaviour rules and the detection hits cite,
/// in id order, each with the rules that cite it (`rule` for behaviour,
/// `Engine: title` for a detection) and how many times they matched.
pub(super) fn techniques(behaviour: &Behaviour, detections: &[DetectionHit]) -> Vec<Technique> {
    let mut found: BTreeMap<String, (BTreeSet<String>, u64)> = BTreeMap::new();
    for hit in &behaviour.rules {
        for id in hit.attack.iter().filter(|id| technique_id(id)) {
            let entry = found.entry(id.clone()).or_default();
            entry.0.insert(hit.rule.clone());
            entry.1 += hit.count.max(1);
        }
    }
    for hit in detections {
        let name = if hit.title.is_empty() {
            &hit.rule_id
        } else {
            &hit.title
        };
        for id in hit.mitre.iter().filter(|id| technique_id(id)) {
            let entry = found.entry(id.clone()).or_default();
            entry.0.insert(format!("{}: {name}", hit.engine));
            entry.1 += hit.count.max(1);
        }
    }
    found
        .into_iter()
        .map(|(id, (rules, count))| Technique {
            name: mitre::technique_name(&id).unwrap_or_default(),
            id,
            rules: rules.into_iter().collect(),
            count,
        })
        .collect()
}
