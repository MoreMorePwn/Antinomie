// SPDX-License-Identifier: GPL-3.0-only
//! The live HIGH toast: one toast per rule per run when a HIGH finding first
//! shows in a run that is still going, `×N` when the rule matches again.
use super::*;
use crate::activity::Level;
use antinomie_triage::graph::notify::HighRule;
use std::collections::BTreeMap;

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
