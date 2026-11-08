// SPDX-License-Identifier: GPL-3.0-only
//! The assessment and the label (design 4.9): the facts a finished job has,
//! the default mapping to a label, and the policy's own rules.
//!
//! `clean_observed` is deliberately not "clean": it says that nothing was seen
//! in this run. The `basis` sentence always carries the reason for the label,
//! and the raw `assessment` is always kept beside it (decision D5).

pub mod expr;
#[cfg(test)]
mod tests;

use crate::{
    api::{
        assessment::{Assessment, AssessmentKind, Counts, DetectionHit, KeyBehaviour, Label, Tier},
        job::EndReason,
    },
    config::policy::{VerdictMapping, VerdictPolicy},
};
use antinomie_monitor_core::report::{Detection, Technique};
pub use expr::{Expr, ExprError};

/// The facts a mapping reads: the Triage summary, the detections, the run's
/// end and what was available to judge with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    pub assessment: AssessmentKind,
    pub highest_tier: Tier,
    pub counts: Counts,
    pub detections: Vec<DetectionHit>,
    pub families: Vec<String>,
    pub techniques: Vec<String>,
    pub end_reason: Option<EndReason>,
    /// The Triage scan ran and the summary was built.
    pub triage_ran: bool,
    /// Stored indicator datasets that were usable.
    pub ioc_datasets: u32,
    /// The summary's own statement, quoted in the basis.
    pub statement: String,
    pub key_behaviours: Vec<KeyBehaviour>,
}

fn name_of<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

impl Facts {
    /// What a mapping can say when Triage did not run.
    pub fn without_triage(end_reason: Option<EndReason>, ioc_datasets: u32) -> Self {
        Self {
            assessment: AssessmentKind::Inconclusive,
            highest_tier: Tier::None,
            counts: Counts::default(),
            detections: Vec::new(),
            families: Vec::new(),
            techniques: Vec::new(),
            end_reason,
            triage_ran: false,
            ioc_datasets,
            statement: String::new(),
            key_behaviours: Vec::new(),
        }
    }

    /// The facts of a built report summary and its detection rows.
    pub fn of_report(
        summary: &antinomie_monitor_core::report::Summary,
        detections: &[Detection],
        attack: &[Technique],
        end_reason: Option<EndReason>,
        ioc_datasets: u32,
    ) -> Self {
        let tier = |text: &str| match text.to_ascii_lowercase().as_str() {
            "high" => Tier::High,
            "medium" => Tier::Medium,
            "low" => Tier::Low,
            "info" => Tier::Info,
            _ => Tier::None,
        };
        let assessment = match summary.assessment.as_str() {
            "matched_indicators" => AssessmentKind::MatchedIndicators,
            "suspicious_behaviour" => AssessmentKind::SuspiciousBehaviour,
            "observed_only" => AssessmentKind::ObservedOnly,
            "no_findings" => AssessmentKind::NoFindings,
            _ => AssessmentKind::Inconclusive,
        };
        let counts = &summary.counts;
        Self {
            assessment,
            highest_tier: tier(&summary.highest_tier),
            counts: Counts {
                processes: counts.processes,
                findings: counts.findings,
                indicators: counts.indicators,
                indicators_matched: counts.indicators_matched,
                techniques: counts.techniques,
                files_changed: counts.files_changed,
                files_opened: counts.files_opened,
                endpoints: counts.endpoints,
                domains: counts.domains,
            },
            detections: detections
                .iter()
                .map(|d| DetectionHit {
                    engine: d.engine.clone(),
                    rule_id: d.rule_id.clone(),
                    title: d.title.clone(),
                    severity: d.severity.clone(),
                    count: d.count,
                })
                .collect(),
            families: summary.families.clone(),
            techniques: attack.iter().map(|t| t.id.clone()).collect(),
            end_reason,
            triage_ran: true,
            ioc_datasets,
            statement: summary.statement.clone(),
            key_behaviours: summary
                .key_behaviours
                .iter()
                .take(25)
                .map(|b| KeyBehaviour {
                    rule: b.rule.clone(),
                    tier: tier(&b.tier),
                    category: b.category.clone(),
                    count: b.count,
                })
                .collect(),
        }
    }

    /// The run reached its own end or the time limit; a lost guest or a stop
    /// for a safety rule is not a completed run.
    pub fn run_completed(&self) -> bool {
        matches!(
            self.end_reason,
            Some(EndReason::Exited | EndReason::Signaled | EndReason::TimeLimit)
        )
    }

    pub(crate) fn read(&self, field: &str) -> expr_value::Value {
        use expr_value::Value;
        let count = |n: u64| Value::Ints(vec![i64::try_from(n).unwrap_or(i64::MAX)]);
        match field {
            "assessment" => Value::Strs(vec![name_of(&self.assessment)]),
            "highest_tier" => Value::Strs(vec![name_of(&self.highest_tier)]),
            "counts.processes" => count(self.counts.processes),
            "counts.findings" => count(self.counts.findings),
            "counts.indicators" => count(self.counts.indicators),
            "counts.indicators_matched" => count(self.counts.indicators_matched),
            "counts.techniques" => count(self.counts.techniques),
            "counts.files_changed" => count(self.counts.files_changed),
            "counts.files_opened" => count(self.counts.files_opened),
            "counts.endpoints" => count(self.counts.endpoints),
            "counts.domains" => count(self.counts.domains),
            "detections.engine" => {
                Value::Strs(self.detections.iter().map(|d| d.engine.clone()).collect())
            }
            "detections.severity" => {
                Value::Strs(self.detections.iter().map(|d| d.severity.clone()).collect())
            }
            "families" => Value::Strs(self.families.clone()),
            "techniques" => Value::Strs(self.techniques.clone()),
            "run.end_reason" => Value::Strs(self.end_reason.iter().map(name_of).collect()),
            _ => Value::Strs(Vec::new()),
        }
    }
}

/// The value type `expr` evaluates over (kept apart so `expr` stays the
/// grammar and nothing more).
pub(crate) mod expr_value {
    pub enum Value {
        Strs(Vec<String>),
        Ints(Vec<i64>),
    }
}

/// A label with its score and the sentence that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub label: Label,
    pub score: Option<u8>,
    pub basis: String,
}

/// A policy's mapping, compiled: the default of 4.9.2 or the rules.
#[derive(Clone, Debug)]
pub struct Mapping {
    rules: Vec<(Expr, Label, Option<u8>, String)>,
}

/// Why a policy's mapping cannot be used.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MappingError {
    #[error("verdict.mapping: `{0}` is not a mapping; the only name is `default`")]
    UnknownName(String),
    #[error("verdict.mapping: a table is not a mapping; write rules as [[verdict.rule]]")]
    Table,
    #[error("verdict.rule.{index}.when: {error}")]
    Rule { index: usize, error: ExprError },
    #[error("verdict.rule.{index}.score: 0 to 100")]
    Score { index: usize },
}

impl MappingError {
    /// The key a config error points at.
    pub fn key(&self) -> String {
        match self {
            Self::UnknownName(_) | Self::Table => "verdict.mapping".into(),
            Self::Rule { index, .. } => format!("verdict.rule.{index}.when"),
            Self::Score { index } => format!("verdict.rule.{index}.score"),
        }
    }
}

impl Mapping {
    /// Compile the policy's `[verdict]`. An empty rule list is the default
    /// mapping.
    pub fn compile(policy: &VerdictPolicy) -> Result<Self, MappingError> {
        match &policy.mapping {
            VerdictMapping::Name(name) if name == "default" => {}
            VerdictMapping::Name(name) => return Err(MappingError::UnknownName(name.clone())),
            VerdictMapping::Table(_) => return Err(MappingError::Table),
        }
        let mut rules = Vec::new();
        for (index, rule) in policy.rule.iter().enumerate() {
            if rule.score.is_some_and(|score| score > 100) {
                return Err(MappingError::Score { index });
            }
            let expr =
                Expr::parse(&rule.when).map_err(|error| MappingError::Rule { index, error })?;
            rules.push((expr, rule.label, rule.score, rule.when.clone()));
        }
        Ok(Self { rules })
    }

    pub fn is_default(&self) -> bool {
        self.rules.is_empty()
    }

    /// The label, score and basis for `facts`.
    pub fn judge(&self, facts: &Facts) -> Verdict {
        let mut verdict = if self.rules.is_empty() {
            default_label(facts)
        } else {
            self.by_rules(facts)
        };
        if facts.ioc_datasets == 0 && facts.triage_ran {
            verdict
                .basis
                .push_str(" No indicator datasets were loaded, so indicators were not checked.");
        }
        verdict
    }

    fn by_rules(&self, facts: &Facts) -> Verdict {
        if !facts.triage_ran {
            return Verdict {
                label: Label::Inconclusive,
                score: None,
                basis: "Triage did not run, so no rule could be applied.".into(),
            };
        }
        let mut label = None;
        let mut score: Option<u8> = None;
        let mut first = String::new();
        for (expr, rule_label, rule_score, text) in &self.rules {
            if expr.eval(facts) {
                if label.is_none() {
                    label = Some(*rule_label);
                    first = text.clone();
                }
                score = score.max(*rule_score);
            }
        }
        match label {
            Some(label) => Verdict {
                label,
                score,
                basis: format!(
                    "The policy rule `{first}` holds for this run. {}",
                    facts.statement
                )
                .trim_end()
                .to_owned(),
            },
            None => Verdict {
                label: Label::Inconclusive,
                score,
                basis: "No rule of the policy's verdict mapping holds for this run.".into(),
            },
        }
    }
}

fn severe(severity: &str) -> bool {
    matches!(severity.to_ascii_lowercase().as_str(), "critical" | "high")
}

/// The default mapping of design 4.9.2; the first condition that holds wins.
pub fn default_label(facts: &Facts) -> Verdict {
    let say = |label, text: String| Verdict {
        label,
        score: None,
        basis: text,
    };
    if !facts.triage_ran {
        return say(
            Label::Inconclusive,
            "Triage did not run, so the run could not be judged.".into(),
        );
    }
    if !facts.run_completed() {
        let how = facts
            .end_reason
            .map_or("did not report how it ended".to_owned(), |reason| {
                format!("ended as {}", name_of(&reason))
            });
        return say(
            Label::Inconclusive,
            format!("The run did not complete (it {how}), so it could not be judged."),
        );
    }
    // Without datasets, nothing can have matched an indicator: an assessment
    // that says so came from the online check and is not a dataset verdict.
    let matched = facts.assessment == AssessmentKind::MatchedIndicators;
    if matched && facts.counts.indicators_matched >= 1 && !facts.families.is_empty() {
        return say(
            Label::Malicious,
            format!(
                "{} indicator(s) matched stored datasets, and the family is named: {}.",
                facts.counts.indicators_matched,
                facts.families.join(", ")
            ),
        );
    }
    if let Some(hit) = facts
        .detections
        .iter()
        .find(|d| d.engine.eq_ignore_ascii_case("yara") && severe(&d.severity))
    {
        return say(
            Label::Malicious,
            format!(
                "The {} rule `{}` matched with severity {}.",
                hit.engine, hit.rule_id, hit.severity
            ),
        );
    }
    if matched {
        return say(
            Label::Malicious,
            format!(
                "{} indicator(s) matched stored datasets.",
                facts.counts.indicators_matched
            ),
        );
    }
    if facts.highest_tier == Tier::High || facts.assessment == AssessmentKind::SuspiciousBehaviour {
        return say(
            Label::Suspicious,
            format!(
                "The run shows suspicious behaviour (highest tier {}). {}",
                name_of(&facts.highest_tier),
                facts.statement
            )
            .trim_end()
            .to_owned(),
        );
    }
    match facts.assessment {
        AssessmentKind::ObservedOnly => say(
            Label::CleanObserved,
            "Only low-tier behaviour was observed in this run; this is not a statement that the sample is clean."
                .into(),
        ),
        AssessmentKind::NoFindings => say(
            Label::CleanObserved,
            "Nothing was seen in this run; this is not a statement that the sample is clean."
                .into(),
        ),
        _ => say(
            Label::Inconclusive,
            "The summary gave no assessment the mapping knows.".into(),
        ),
    }
}

/// The `Assessment` object of a finished job.
pub fn assessment_of(facts: &Facts, verdict: &Verdict) -> Assessment {
    Assessment {
        assessment: facts.assessment,
        highest_tier: facts.highest_tier,
        label: Some(verdict.label),
        score: verdict.score,
        families: facts.families.clone(),
        counts: facts.counts.clone(),
        key_behaviours: facts.key_behaviours.clone(),
        detections: facts.detections.clone(),
        techniques: facts.techniques.clone(),
        ioc_dataset_count: facts.ioc_datasets,
        basis: verdict.basis.clone(),
    }
}
