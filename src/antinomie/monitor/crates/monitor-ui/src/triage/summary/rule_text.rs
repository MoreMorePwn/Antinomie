// SPDX-License-Identifier: GPL-3.0-only
//! The words of a rule for the Summary's Key findings, from the rule texts
//! (ANT-T0308, `rules::texts`).

/// The Behaviour title of a rule.
pub(super) fn rule_title(id: &str) -> String {
    crate::triage::rules::rule_title(id).to_owned()
}

/// A sentence on what the rule observes; empty when none is written.
pub(super) fn rule_description(id: &str) -> String {
    crate::triage::rules::rule_description(id).to_owned()
}
