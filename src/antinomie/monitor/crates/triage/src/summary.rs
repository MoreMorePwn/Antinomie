// SPDX-License-Identifier: GPL-3.0-only
//! The model of Triage > Summary: key findings and behaviour tags, the
//! indicators the Summary lists and exports, the sample facts, rule texts,
//! and the Relationships graph built from the scan. The boxes that draw them
//! are the GUI's.
pub mod indicators;
pub mod insight;
pub mod relations;
pub mod rule_text;
pub mod sample;

use crate::{query::RowValue, Finding};

/// The sentences of the Summary's Key findings, one per finding (LOW and
/// above, worst first, at most `limit`): "MEDIUM Waiting for chosen packets:
/// BPF on raw socket - pid 1352 (x2)". For the exported report.
pub fn key_finding_lines(findings: &[Finding], limit: usize) -> Vec<String> {
    insight::key_findings(findings, limit)
        .1
        .into_iter()
        .map(|key| {
            let mut line = format!("{} {}", key.tier.tag().to_uppercase(), key.title);
            if !key.target.is_empty() {
                line.push_str(&format!(" - {}", key.target));
            }
            if key.pid != 0 {
                line.push_str(&format!(" (pid {})", key.pid));
            }
            if key.count > 1 {
                line.push_str(&format!(" x{}", key.count));
            }
            if !key.why.is_empty() {
                line.push_str(&format!(". {}", key.why.trim_end_matches('.')));
            }
            line
        })
        .collect()
}

/// The Summary's Key findings for the exported report: (place in `findings`,
/// tier tag, rule, title, object, pid, cookie, executable, count, first ns,
/// why), worst first, at most `limit`, and how many there are in all.
pub fn key_findings_for_report(findings: &[Finding], limit: usize) -> (usize, Vec<KeyFindingRow>) {
    let (total, keys) = insight::key_findings(findings, limit);
    let rows = keys
        .into_iter()
        .map(|key| KeyFindingRow {
            index: key.index,
            tier: key.tier.tag().to_owned(),
            rule: key.rule,
            title: key.title,
            target: key.target,
            pid: key.pid,
            cookie: key.cookie,
            exe: key.exe,
            count: key.count,
            first_ns: key.first_ns,
            why: key.why,
        })
        .collect();
    (total, rows)
}

/// One of [`key_findings_for_report`].
pub struct KeyFindingRow {
    pub index: usize,
    pub tier: String,
    pub rule: String,
    pub title: String,
    pub target: String,
    pub pid: u32,
    pub cookie: u64,
    pub exe: String,
    pub count: u64,
    pub first_ns: u64,
    pub why: String,
}

/// How many findings each tier has (high, medium, low, info), hidden ones left
/// out, as the Summary's tier chips count them.
pub fn tier_counts(findings: &[Finding]) -> [u64; 4] {
    let mut counts = [0u64; 4];
    for finding in findings {
        if let Some(tier) = insight::tier_of(finding) {
            let hidden = finding.values.iter().any(|(name, value)| {
                *name == "finding.hidden" && matches!(value, RowValue::Bool(true))
            });
            if !hidden {
                counts[tier.index()] += 1;
            }
        }
    }
    counts
}
