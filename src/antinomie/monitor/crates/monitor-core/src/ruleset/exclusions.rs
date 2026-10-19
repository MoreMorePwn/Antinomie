// SPDX-License-Identifier: MIT
//! Reads a selection warning back as a rule that did not apply. The wording is
//! produced in this module's neighbours from the constants used here, so a scan
//! can count these rules without the UI reading warning text.
use super::ids::{IDS_DATASET_REASON, IDS_TLS_REASON};
use crate::analysis::detection::{CoverageReason, Engine};

pub(super) const DUPLICATE_RULE_REASON: &str =
    "duplicate rule id; the later copy was not evaluated";

/// The rule and the reason of a selection warning that names one rule this
/// engine could not use, or None for any other warning (a missing pack, an
/// empty source, a disabled helper).
pub(crate) fn selection_exclusion(
    engine: Engine,
    warning: &str,
) -> Option<(CoverageReason, String, String)> {
    let (rule, reason) = warning.split_once(": ")?;
    let kind = match engine {
        Engine::Ids if reason == IDS_DATASET_REASON => CoverageReason::Dataset,
        Engine::Ids if reason == IDS_TLS_REASON => CoverageReason::TlsFingerprint,
        Engine::Ids if reason.starts_with("duplicate rule id") => CoverageReason::DuplicateSid,
        Engine::Sigma
            if reason.starts_with("product ")
                || reason.starts_with("service ")
                || reason.starts_with("category ") =>
        {
            CoverageReason::UnsupportedCategory
        }
        Engine::Sigma
            if reason.starts_with("correlation rules")
                || reason.starts_with("fields outside the captured schema") =>
        {
            CoverageReason::Backend
        }
        _ => return None,
    };
    Some((kind, rule.to_owned(), reason.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_single_rule_exclusions_are_read_back() {
        let ids = |text: &str| selection_exclusion(Engine::Ids, text).map(|found| found.0);
        assert_eq!(
            ids(&format!("2001: {IDS_DATASET_REASON}")),
            Some(CoverageReason::Dataset)
        );
        assert_eq!(
            ids(&format!("2002: {IDS_TLS_REASON}")),
            Some(CoverageReason::TlsFingerprint)
        );
        assert_eq!(
            ids(&format!("2003: {DUPLICATE_RULE_REASON}")),
            Some(CoverageReason::DuplicateSid)
        );
        assert_eq!(ids("pack:x was not evaluated: missing"), None);
        let sigma = |text: &str| selection_exclusion(Engine::Sigma, text).map(|found| found.0);
        assert_eq!(
            sigma("r1: category registry_set is not a captured event category"),
            Some(CoverageReason::UnsupportedCategory)
        );
        assert_eq!(
            sigma("r2: fields outside the captured schema: Foo"),
            Some(CoverageReason::Backend)
        );
        assert_eq!(sigma("r3: helper r3 is disabled"), None);
        assert_eq!(
            selection_exclusion(Engine::Yara, "a: duplicate rule id"),
            None
        );
    }
}
