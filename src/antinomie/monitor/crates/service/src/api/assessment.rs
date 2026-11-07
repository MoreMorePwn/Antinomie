// SPDX-License-Identifier: GPL-3.0-only
//! `Assessment` (design 5.4.3): the Triage summary plus the policy label and
//! score, always with the `basis` sentence.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// `report::Summary.assessment`, or `inconclusive` when the run or triage did
/// not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentKind {
    MatchedIndicators,
    SuspiciousBehaviour,
    ObservedOnly,
    NoFindings,
    Inconclusive,
}

/// A finding or detection tier; `none` for no finding.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    High,
    Medium,
    Low,
    Info,
    None,
}

/// The policy label (design 4.9.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Malicious,
    Suspicious,
    CleanObserved,
    Inconclusive,
}

/// The `report::Counts` fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Counts {
    pub processes: u64,
    pub findings: u64,
    pub indicators: u64,
    pub indicators_matched: u64,
    pub techniques: u64,
    pub files_changed: u64,
    pub files_opened: u64,
    pub endpoints: u64,
    pub domains: u64,
}

/// One of at most 25 key behaviours.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct KeyBehaviour {
    pub rule: String,
    pub tier: Tier,
    pub category: String,
    pub count: u64,
}

/// A hit of a detection engine (YARA, IDS, Sigma).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DetectionHit {
    pub engine: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Assessment {
    pub assessment: AssessmentKind,
    pub highest_tier: Tier,
    /// Null only when the policy explicitly disables the mapping.
    pub label: Option<Label>,
    /// 0 to 100 from the policy formula; null when no rule sets one.
    pub score: Option<u8>,
    pub families: Vec<String>,
    pub counts: Counts,
    pub key_behaviours: Vec<KeyBehaviour>,
    pub detections: Vec<DetectionHit>,
    /// ATT&CK ids.
    pub techniques: Vec<String>,
    /// Loaded indicator datasets. With zero, indicators cannot produce
    /// `malicious` and `basis` says so.
    pub ioc_dataset_count: u32,
    /// One sentence stating why (the summary's `statement`).
    pub basis: String,
}
