// SPDX-License-Identifier: GPL-3.0-only
//! The words of a rule for the Summary's Key findings. ANT-T0308 provides
//! these two functions in `rules`; until it is merged they say the rule id and
//! nothing more, and the coordinator swaps them for the real ones.

/// The Behaviour title of a rule. // ANT-T0308 provides these
pub(super) fn rule_title(id: &str) -> String {
    id.to_owned()
}

/// A sentence on what the rule observes; empty when none is written.
/// // ANT-T0308 provides these
pub(super) fn rule_description(_id: &str) -> String {
    String::new()
}
