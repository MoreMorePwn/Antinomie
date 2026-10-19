// SPDX-License-Identifier: MIT
//! Rule coverage of one IDS or Sigma scan: how many rules the engine could use
//! and why the others did not apply to this run. A rule that does not apply is a
//! coverage limit, not an incomplete scan, so none of this changes the state.
use super::Engine;
use serde::{Deserialize, Serialize};

/// Individual rules kept in [`Coverage::listed`]; the counts always cover all of them.
pub const COVERAGE_LIST_LIMIT: usize = 200;

/// Why one rule did not apply. The first four are IDS rules that could not be
/// loaded; the rest are Sigma rules that could not be evaluated against this run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageReason {
    /// Needs a ja3, ja3s or ja4 keyword this configuration does not enable.
    TlsFingerprint,
    /// Needs an external `dataset:`.
    Dataset,
    /// The SID was already loaded; the later copy is not.
    DuplicateSid,
    NoSid,
    /// Sigma: no captured event carries every field the rule uses.
    NoMatchingEvents,
    /// Sigma: the logsource is outside what Antinomie captures.
    UnsupportedCategory,
    /// Sigma: the backend or the captured field schema rejected the rule.
    Backend,
    /// Sigma: the rule file does not parse.
    Syntax,
}

impl CoverageReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::TlsFingerprint => "TLS fingerprint",
            Self::Dataset => "dataset",
            Self::DuplicateSid => "duplicate",
            Self::NoSid => "no SID",
            Self::NoMatchingEvents => "no matching events",
            Self::UnsupportedCategory => "unsupported category",
            Self::Backend => "backend",
            Self::Syntax => "syntax",
        }
    }
}

pub const IDS_REASONS: [CoverageReason; 4] = [
    CoverageReason::TlsFingerprint,
    CoverageReason::Dataset,
    CoverageReason::DuplicateSid,
    CoverageReason::NoSid,
];
pub const SIGMA_REASONS: [CoverageReason; 4] = [
    CoverageReason::NoMatchingEvents,
    CoverageReason::UnsupportedCategory,
    CoverageReason::Backend,
    CoverageReason::Syntax,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageItem {
    pub reason: CoverageReason,
    /// SID, rule id, title or file name.
    pub rule: String,
    pub detail: String,
}

/// Counts are explicit fields so nothing has to read them back out of warning text.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Coverage {
    /// IDS: rules the engine loaded. Sigma: rules evaluated against the events.
    pub evaluated: u64,
    pub tls_fingerprint: u64,
    pub dataset: u64,
    pub duplicate_sid: u64,
    pub no_sid: u64,
    pub no_matching_events: u64,
    pub unsupported_category: u64,
    pub backend: u64,
    pub syntax: u64,
    /// The first rules behind the counts, at most [`COVERAGE_LIST_LIMIT`].
    pub listed: Vec<CoverageItem>,
    /// Rules counted above but not in `listed`.
    pub unlisted: u64,
    /// Set when the evidence preview cap hid locations. Match counts stay complete.
    pub evidence_preview_limit: Option<u64>,
}

impl Coverage {
    pub fn count_of(&self, reason: CoverageReason) -> u64 {
        match reason {
            CoverageReason::TlsFingerprint => self.tls_fingerprint,
            CoverageReason::Dataset => self.dataset,
            CoverageReason::DuplicateSid => self.duplicate_sid,
            CoverageReason::NoSid => self.no_sid,
            CoverageReason::NoMatchingEvents => self.no_matching_events,
            CoverageReason::UnsupportedCategory => self.unsupported_category,
            CoverageReason::Backend => self.backend,
            CoverageReason::Syntax => self.syntax,
        }
    }

    /// IDS rules that were not loaded.
    pub fn not_loadable(&self) -> u64 {
        IDS_REASONS
            .iter()
            .map(|reason| self.count_of(*reason))
            .sum()
    }

    /// Sigma rules that did not apply to this run.
    pub fn not_applicable(&self) -> u64 {
        SIGMA_REASONS
            .iter()
            .map(|reason| self.count_of(*reason))
            .sum()
    }

    /// Count one rule, and list it while the list has room.
    pub fn add(
        &mut self,
        reason: CoverageReason,
        rule: impl Into<String>,
        detail: impl Into<String>,
    ) {
        let slot = match reason {
            CoverageReason::TlsFingerprint => &mut self.tls_fingerprint,
            CoverageReason::Dataset => &mut self.dataset,
            CoverageReason::DuplicateSid => &mut self.duplicate_sid,
            CoverageReason::NoSid => &mut self.no_sid,
            CoverageReason::NoMatchingEvents => &mut self.no_matching_events,
            CoverageReason::UnsupportedCategory => &mut self.unsupported_category,
            CoverageReason::Backend => &mut self.backend,
            CoverageReason::Syntax => &mut self.syntax,
        };
        *slot += 1;
        if self.listed.len() < COVERAGE_LIST_LIMIT {
            self.listed.push(CoverageItem {
                reason,
                rule: rule.into(),
                detail: detail.into(),
            });
        } else {
            self.unlisted += 1;
        }
    }

    /// Count the rules a managed selection already left out for this engine.
    pub(super) fn add_selection_exclusions(&mut self, engine: Engine, warnings: &[String]) {
        for warning in warnings {
            if let Some((reason, rule, detail)) =
                crate::ruleset::selection_exclusion(engine, warning)
            {
                self.add(reason, rule, detail);
            }
        }
    }

    /// True when the lists and strings fit what a worker may report.
    pub(super) fn bounded(&self) -> bool {
        self.listed.len() <= COVERAGE_LIST_LIMIT
            && self
                .listed
                .iter()
                .all(|item| item.rule.len() <= 8192 && item.detail.len() <= 16384)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_cover_every_rule_while_the_list_stays_bounded() {
        let mut coverage = Coverage::default();
        for index in 0..COVERAGE_LIST_LIMIT + 30 {
            coverage.add(
                CoverageReason::Dataset,
                format!("{index}"),
                "needs a dataset",
            );
        }
        coverage.add(CoverageReason::NoSid, "(no SID)", "");
        assert_eq!(coverage.dataset, COVERAGE_LIST_LIMIT as u64 + 30);
        assert_eq!(coverage.not_loadable(), COVERAGE_LIST_LIMIT as u64 + 31);
        assert_eq!(coverage.listed.len(), COVERAGE_LIST_LIMIT);
        assert_eq!(coverage.unlisted, 31);
        assert_eq!(coverage.not_applicable(), 0);
        assert!(coverage.bounded());
    }

    #[test]
    fn an_empty_stored_coverage_loads_with_defaults() {
        let coverage: Coverage = serde_json::from_str(r#"{"evaluated":3,"syntax":1}"#).unwrap();
        assert_eq!((coverage.evaluated, coverage.syntax), (3, 1));
        assert!(coverage.listed.is_empty() && coverage.evidence_preview_limit.is_none());
    }
}
