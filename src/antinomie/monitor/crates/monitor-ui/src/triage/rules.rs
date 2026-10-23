// SPDX-License-Identifier: GPL-3.0-only
//! Suspicious-activity rules and the pipeline that turns their hits into rows.
//!
//! A rule reads one call (with the descriptor and process state before it) or
//! follows one task across calls. Each match is a [`Hit`]; the engine lowers it
//! for failures and allow-listed programs, folds repeats into one row per key,
//! applies the row caps and scopes the rows to the run. A row says what was
//! observed, not that a sample is malicious.
use super::*;

mod ctx;
mod engine;
mod evasion;
mod exec;
mod network;
mod noise;
mod paths;
mod probes;
mod process;
mod rows;
mod state;
mod table;
mod tools;

#[cfg(test)]
mod tests;

/// Every hit the rules find in one call.
fn collect_hits(cx: &ctx::Ctx, st: &mut state::State) -> Vec<Hit> {
    let mut hits = Vec::new();
    paths::rules(cx, st, &mut hits);
    if !cx.via_async {
        exec::rules(cx, st, &mut hits);
        process::rules(cx, st, &mut hits);
        network::rules(cx, st, &mut hits);
        evasion::rules(cx, st, &mut hits);
    }
    hits
}

pub(super) use engine::{Engine, Options, Output};
pub(super) use rows::{view_keeps, View, COL_PROCESS, COL_SUMMARY, COL_TIER, COL_TIME, HEADERS};
pub(super) use table::{spec, Spec};

/// How unusual a behaviour is for ordinary software. The weight is what the
/// severity curve of the activity graph adds up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Tier {
    Info,
    Low,
    Medium,
    High,
}

impl Tier {
    pub(super) const ALL: [Tier; 4] = [Tier::High, Tier::Medium, Tier::Low, Tier::Info];

    /// The value of `finding.tier` and `finding.severity` in a filter.
    pub(super) fn tag(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// One tier lower; INFO stays INFO.
    pub(super) fn down(self) -> Self {
        match self {
            Self::High => Self::Medium,
            Self::Medium => Self::Low,
            Self::Low | Self::Info => Self::Info,
        }
    }

    pub(super) fn index(self) -> usize {
        match self {
            Self::High => 0,
            Self::Medium => 1,
            Self::Low => 2,
            Self::Info => 3,
        }
    }

    pub(super) fn color(self) -> egui::Color32 {
        match self {
            Self::High => theme::error(),
            Self::Medium => theme::warn(),
            Self::Low => theme::blue(),
            Self::Info => theme::muted(),
        }
    }
}

/// What a behaviour is for. The twelve ATT&CK-shaped groups of the brief, plus
/// Exfiltration, which has nowhere else to go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Category {
    Execution,
    Persistence,
    Privilege,
    /// Hiding, cleaning up, disabling tools and every anti-analysis check.
    Evasion,
    Credential,
    Discovery,
    Injection,
    Command,
    Rootkit,
    Impact,
    Collection,
    Lateral,
    Exfiltration,
}

impl Category {
    pub(super) const ALL: [Category; 13] = [
        Self::Execution,
        Self::Persistence,
        Self::Privilege,
        Self::Evasion,
        Self::Credential,
        Self::Discovery,
        Self::Injection,
        Self::Command,
        Self::Rootkit,
        Self::Impact,
        Self::Collection,
        Self::Lateral,
        Self::Exfiltration,
    ];

    /// The value of `finding.category` in a filter.
    pub(super) fn tag(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Persistence => "persistence",
            Self::Privilege => "privilege",
            Self::Evasion => "evasion",
            Self::Credential => "credential",
            Self::Discovery => "discovery",
            Self::Injection => "injection",
            Self::Command => "c2",
            Self::Rootkit => "rootkit",
            Self::Impact => "impact",
            Self::Collection => "collection",
            Self::Lateral => "lateral",
            Self::Exfiltration => "exfiltration",
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::Privilege => "Privilege escalation",
            Self::Evasion => "Defense evasion / anti-analysis",
            Self::Credential => "Credential access",
            Self::Discovery => "Discovery",
            Self::Injection => "Injection",
            Self::Command => "Command & control",
            Self::Rootkit => "Rootkit",
            Self::Impact => "Impact",
            Self::Collection => "Collection",
            Self::Lateral => "Lateral movement",
            Self::Exfiltration => "Exfiltration",
        }
    }

    /// The short chip text.
    pub(super) fn chip(self) -> &'static str {
        match self {
            Self::Privilege => "Privilege",
            Self::Evasion => "Evasion",
            Self::Credential => "Credentials",
            Self::Command => "C2",
            Self::Lateral => "Lateral",
            other => other.label(),
        }
    }
}

/// One match of a rule, before the pipeline has judged it.
pub(super) struct Hit {
    pub rule: &'static str,
    /// What rows of this rule are folded by: a path, an endpoint, a target.
    pub object: String,
    pub summary: String,
    /// A tier other than the rule's own, for a rule that depends on context.
    pub tier: Option<Tier>,
    /// Techniques other than the rule's own, for a rule with several.
    pub attack: Option<&'static [&'static str]>,
    /// Facts for Details, one per line.
    pub detail: Vec<String>,
}

impl Hit {
    pub(super) fn new(rule: &'static str, object: impl Into<String>, summary: String) -> Self {
        Self {
            rule,
            object: object.into(),
            summary,
            tier: None,
            attack: None,
            detail: Vec::new(),
        }
    }

    pub(super) fn tier(mut self, tier: Tier) -> Self {
        self.tier = Some(tier);
        self
    }

    pub(super) fn attack(mut self, attack: &'static [&'static str]) -> Self {
        self.attack = Some(attack);
        self
    }

    pub(super) fn detail(mut self, line: impl Into<String>) -> Self {
        self.detail.push(line.into());
        self
    }
}
