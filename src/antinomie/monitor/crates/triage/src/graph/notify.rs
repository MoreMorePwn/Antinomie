// SPDX-License-Identifier: GPL-3.0-only
//! The live HIGH toast: one toast per rule per run when a HIGH finding first
//! shows in a run that is still going, `×N` when the rule matches again.
use super::*;
use std::collections::BTreeMap;

/// A rule with a HIGH row that is shown by default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HighRule {
    pub rule: String,
    /// Occurrences folded into its rows.
    pub count: u64,
    pub first_ns: u64,
    /// The process and summary of its earliest row.
    pub detail: String,
}

/// Collects HIGH rows by rule while a scan reads the engine's output.
#[derive(Default)]
pub struct HighRules {
    pub rules: BTreeMap<String, HighRule>,
}

impl HighRules {
    pub fn observe(&mut self, finding: &Finding) {
        let text = |key: &str| {
            finding.values.iter().find_map(|(name, value)| match value {
                RowValue::Text(text) if *name == key => Some(text.as_str()),
                _ => None,
            })
        };
        if text("finding.tier") != Some(rules::Tier::High.tag()) {
            return;
        }
        let rule = text("finding.rule").unwrap_or_default().to_owned();
        let count = files::number(&finding.values, "finding.count").unwrap_or(1);
        let first = files::number(&finding.values, "finding.first_ns").unwrap_or(0);
        let cell = |column: usize| {
            finding
                .cells
                .get(column)
                .map_or("", |cell| cell.text.as_str())
        };
        let detail = format!(
            "{} · {}",
            cell(rules::COL_PROCESS),
            cell(rules::COL_SUMMARY)
        );
        let entry = self.rules.entry(rule.clone()).or_insert(HighRule {
            rule,
            count: 0,
            first_ns: first,
            detail,
        });
        entry.count += count;
        if first != 0 && (entry.first_ns == 0 || first < entry.first_ns) {
            entry.first_ns = first;
        }
    }

    pub fn finish(self) -> Vec<HighRule> {
        let mut rules: Vec<HighRule> = self.rules.into_values().collect();
        rules.sort_by_key(|rule| (rule.first_ns, rule.rule.clone()));
        rules
    }
}
