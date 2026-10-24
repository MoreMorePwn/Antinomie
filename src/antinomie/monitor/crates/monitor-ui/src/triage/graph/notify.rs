// SPDX-License-Identifier: GPL-3.0-only
//! The live HIGH toast: one toast per rule per run when a HIGH finding first
//! shows in a run that is still going, `×N` when the rule matches again.
use super::*;
use crate::activity::Level;
use std::collections::BTreeMap;

/// A rule with a HIGH row that is shown by default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::triage) struct HighRule {
    pub rule: String,
    /// Occurrences folded into its rows.
    pub count: u64,
    pub first_ns: u64,
    /// The process and summary of its earliest row.
    pub detail: String,
}

/// Collects HIGH rows by rule while a scan reads the engine's output.
#[derive(Default)]
pub(super) struct HighRules {
    rules: BTreeMap<String, HighRule>,
}

impl HighRules {
    pub(super) fn observe(&mut self, finding: &Finding) {
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

    pub(super) fn finish(self) -> Vec<HighRule> {
        let mut rules: Vec<HighRule> = self.rules.into_values().collect();
        rules.sort_by_key(|rule| (rule.first_ns, rule.rule.clone()));
        rules
    }
}

/// What the toast stack was told about the run on screen.
#[derive(Default)]
pub(in crate::triage) struct HighWatch {
    run: Option<String>,
    /// Occurrences already announced, by rule.
    seen: BTreeMap<String, u64>,
    /// The title and detail each rule's toast was raised with.
    raised: BTreeMap<String, (String, String)>,
}

/// The longest detail a toast takes.
const DETAIL_CHARS: usize = 110;

impl HighWatch {
    /// A scan of `run` arrived. `live` is whether the run was still going when
    /// the scan began; `enabled` is the Settings switch.
    pub(in crate::triage) fn observe(
        &mut self,
        ctx: &egui::Context,
        run: &str,
        live: bool,
        enabled: bool,
        high: &[HighRule],
    ) {
        if self.run.as_deref() != Some(run) {
            *self = Self {
                run: Some(run.to_owned()),
                ..Self::default()
            };
        }
        for rule in high {
            let before = self.seen.insert(rule.rule.clone(), rule.count);
            if !(live && enabled) {
                continue;
            }
            match before {
                None => {
                    let title = format!("High-severity activity: {}", rule.rule);
                    let detail: String = rule.detail.chars().take(DETAIL_CHARS).collect();
                    crate::toasts::push(
                        ctx,
                        Level::Warn,
                        &title,
                        &detail,
                        Some(crate::toasts::Action::open_activity()),
                    );
                    self.raised.insert(rule.rule.clone(), (title, detail));
                }
                Some(known) if rule.count > known => {
                    if let Some((title, detail)) = self.raised.get(&rule.rule) {
                        let more = u32::try_from(rule.count - known).unwrap_or(u32::MAX);
                        crate::toasts::bump(ctx, Level::Warn, title, detail, more);
                    }
                }
                Some(_) => {}
            }
        }
    }

    #[cfg(test)]
    pub(in crate::triage) fn seen(&self) -> &BTreeMap<String, u64> {
        &self.seen
    }
}
