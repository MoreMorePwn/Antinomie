// SPDX-License-Identifier: GPL-3.0-only
//! The ATT&CK techniques of a run, in one place: the Summary on screen and
//! every export format list what this function returns, so they cannot differ.
//! A technique comes from the behaviour rules (named by rule) and from the
//! detection engines (named by engine and rule title).
use antinomie_monitor_core::{
    mitre::{self, Tactic},
    report::Technique,
    run_digest::{Behaviour, DetectionHit},
    samples::tactic_of,
};
use std::collections::{BTreeMap, BTreeSet};

/// Where a click in the Summary's ATT&CK list goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Jump {
    /// Suspicious activity, filtered to the technique.
    Suspicious(String),
    /// A detection engine's matches (`YARA`, `IDS` or `Sigma`), filtered to the technique.
    Detection(String, String),
    /// Syscall Trace at the first call behind the technique.
    Calls(String),
}

/// A behaviour rule that cited a technique.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleCause {
    pub rule: String,
    /// `high`, `medium`, `low` or `info`.
    pub tier: String,
    pub count: u64,
}

/// A detection rule that cited a technique.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectionCause {
    /// `YARA`, `IDS` or `Sigma`.
    pub engine: String,
    pub title: String,
    pub severity: String,
    pub count: u64,
}

/// What produced one technique of the list, for its expanded row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detail {
    pub id: String,
    /// The tactic the list files it under: the tactic of the first behaviour
    /// rule that cited it, else its first tactic in ATT&CK; `None` when the
    /// bundled table does not know the id.
    pub primary: Option<Tactic>,
    /// Every tactic ATT&CK files it under, in kill-chain order.
    pub tactics: Vec<Tactic>,
    pub rules: Vec<RuleCause>,
    pub detections: Vec<DetectionCause>,
}

/// For each technique of `list`, in its order, the rules and detections that
/// cited it and the tactic it is filed under.
pub fn details(
    list: &[Technique],
    behaviour: &Behaviour,
    detections: &[DetectionHit],
) -> Vec<Detail> {
    list.iter()
        .map(|technique| {
            let mut rules: Vec<RuleCause> = Vec::new();
            let mut primary = None;
            for hit in behaviour
                .rules
                .iter()
                .filter(|hit| hit.attack.contains(&technique.id))
            {
                primary = primary.or_else(|| Tactic::from_label(tactic_of(&hit.category)));
                rules.push(RuleCause {
                    rule: hit.rule.clone(),
                    tier: hit.tier.clone(),
                    count: hit.count.max(1),
                });
            }
            let detections = detections
                .iter()
                .filter(|hit| hit.attack_ids().any(|id| *id == technique.id))
                .map(|hit| DetectionCause {
                    engine: hit.engine.clone(),
                    title: if hit.title.is_empty() {
                        hit.rule_id.clone()
                    } else {
                        hit.title.clone()
                    },
                    severity: hit.severity.clone(),
                    count: hit.count.max(1),
                })
                .collect();
            let tactics = mitre::tactics(&technique.id);
            Detail {
                id: technique.id.clone(),
                primary: primary.or_else(|| tactics.first().copied()),
                tactics,
                rules,
                detections,
            }
        })
        .collect()
}

pub fn technique_id(id: &str) -> bool {
    let rest = id.strip_prefix('T').unwrap_or("");
    let (main, sub) = rest
        .split_once('.')
        .map_or((rest, None), |(a, b)| (a, Some(b)));
    main.len() == 4
        && main.bytes().all(|b| b.is_ascii_digit())
        && sub.is_none_or(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
}

/// The union of the techniques the behaviour rules and the detection hits cite,
/// in id order, each with the rules that cite it (`rule` for behaviour,
/// `Engine: title` for a detection) and how many times they matched.
pub fn techniques(behaviour: &Behaviour, detections: &[DetectionHit]) -> Vec<Technique> {
    let mut found: BTreeMap<String, (BTreeSet<String>, u64)> = BTreeMap::new();
    for hit in &behaviour.rules {
        for id in hit.attack.iter().filter(|id| technique_id(id)) {
            let entry = found.entry(id.clone()).or_default();
            entry.0.insert(hit.rule.clone());
            entry.1 += hit.count.max(1);
        }
    }
    for hit in detections {
        let name = if hit.title.is_empty() {
            &hit.rule_id
        } else {
            &hit.title
        };
        for id in hit.attack_ids().filter(|id| technique_id(id)) {
            let entry = found.entry(id.clone()).or_default();
            entry.0.insert(format!("{}: {name}", hit.engine));
            entry.1 += hit.count.max(1);
        }
    }
    found
        .into_iter()
        .map(|(id, (rules, count))| Technique {
            name: mitre::technique_name(&id).unwrap_or_default(),
            id,
            rules: rules.into_iter().collect(),
            count,
            rule_refs: Vec::new(),
        })
        .collect()
}
