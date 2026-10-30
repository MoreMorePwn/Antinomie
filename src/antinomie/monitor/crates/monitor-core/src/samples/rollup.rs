// SPDX-License-Identifier: GPL-3.0-only
//! What the sample window's Summary adds up over a sample's runs from the
//! runs' Triage digests: the highest suspicion, the detection rules that
//! matched, the ATT&CK techniques by tactic, the evasion checks and the
//! indicators. Pure: it only reads digests, so it is the same wherever it is
//! drawn and can be tested without a window.
use crate::run_digest::{self, RunDigest};
use std::collections::{BTreeMap, BTreeSet};

/// One run as the roll-up reads it: its number in start order and its digest
/// (`None` when Triage never read the run).
pub struct RunInput<'a> {
    pub number: usize,
    pub digest: Option<&'a RunDigest>,
}

/// A detection rule that matched in some of the runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleRow {
    pub engine: String,
    /// The rule's own id, as Triage lists it.
    pub rule_id: String,
    pub rule: String,
    /// The family a YARA rule names; empty when it names none.
    pub family: String,
    pub severity: String,
    /// Run numbers, ascending.
    pub runs: Vec<usize>,
    /// The newest run it matched in.
    pub latest: usize,
}

/// A technique and the runs whose findings mapped to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TechniqueRow {
    pub id: String,
    pub runs: Vec<usize>,
}

/// The techniques of one tactic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TacticRow {
    pub tactic: String,
    pub techniques: Vec<TechniqueRow>,
}

/// One check, in the runs it was made in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckRow {
    pub rule: String,
    pub object: String,
    pub runs: Vec<usize>,
    /// What the sample saw, per run.
    pub lines: Vec<(usize, String)>,
}

/// One evasion category, empty when nothing of it was seen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvasionRow {
    pub category: String,
    pub checks: Vec<CheckRow>,
}

/// The indicators over the runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndicatorRow {
    pub total: usize,
    /// Per type label, in the fixed order, only types that have some.
    pub per_type: Vec<(String, usize)>,
    /// Present in every run that has an indicator list.
    pub in_every_run: usize,
    /// Matched by a stored dataset.
    pub matched: usize,
    /// Runs the indicators were read from.
    pub runs: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rollup {
    pub runs: usize,
    /// Runs Triage read (they have behaviour findings, maybe none).
    pub triaged: usize,
    /// Runs a detection engine's report was read for.
    pub detected: usize,
    /// The highest tier and the runs that reached it.
    pub highest: Option<(String, Vec<usize>)>,
    pub rules: Vec<RuleRow>,
    pub tactics: Vec<TacticRow>,
    pub evasion: Vec<EvasionRow>,
    pub indicators: Option<IndicatorRow>,
}

/// Tiers from the highest down.
const TIERS: [&str; 4] = ["high", "medium", "low", "info"];

/// ATT&CK tactics in matrix order, then the techniques only a detection rule
/// named (their rules say no tactic).
const TACTICS: [&str; 13] = [
    "Execution",
    "Persistence",
    "Privilege escalation",
    "Defense evasion",
    "Credential access",
    "Discovery",
    "Lateral movement",
    "Collection",
    "Command and control",
    "Exfiltration",
    "Impact",
    "Other",
    "Detection rules",
];

/// The tactic of a behaviour finding category. Injection and rootkit
/// behaviours are listed under Defense evasion, as ATT&CK files them.
pub fn tactic_of(category: &str) -> &'static str {
    match category {
        "execution" => "Execution",
        "persistence" => "Persistence",
        "privilege" => "Privilege escalation",
        "evasion" | "injection" | "rootkit" => "Defense evasion",
        "credential" => "Credential access",
        "discovery" => "Discovery",
        "lateral" => "Lateral movement",
        "collection" => "Collection",
        "c2" => "Command and control",
        "exfiltration" => "Exfiltration",
        "impact" => "Impact",
        _ => "Other",
    }
}

/// A technique id (`T1059`, `T1059.004`); detection-strategy ids (`DET0168`)
/// are not techniques.
fn technique(id: &str) -> bool {
    id.strip_prefix('T').is_some_and(|rest| {
        !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    })
}

fn push_run(runs: &mut Vec<usize>, number: usize) {
    if !runs.contains(&number) {
        runs.push(number);
    }
}

/// Add up `runs`.
pub fn rollup(runs: &[RunInput<'_>]) -> Rollup {
    let mut out = Rollup {
        runs: runs.len(),
        ..Rollup::default()
    };
    let mut top: Option<(usize, Vec<usize>)> = None;
    let mut rules: BTreeMap<(String, String), RuleRow> = BTreeMap::new();
    let mut tactics: BTreeMap<&'static str, BTreeMap<String, Vec<usize>>> = BTreeMap::new();
    let mut checks: BTreeMap<(&'static str, String, String), CheckRow> = BTreeMap::new();
    for run in runs {
        let Some(digest) = run.digest else { continue };
        if let Some(behaviour) = &digest.behaviour {
            out.triaged += 1;
            if let Some(rank) = TIERS.iter().position(|tier| *tier == behaviour.highest) {
                match &mut top {
                    Some((best, at)) if *best == rank => push_run(at, run.number),
                    Some((best, _)) if *best < rank => {}
                    _ => top = Some((rank, vec![run.number])),
                }
            }
            for hit in &behaviour.rules {
                for id in hit.attack.iter().filter(|id| technique(id)) {
                    push_run(
                        tactics
                            .entry(tactic_of(&hit.category))
                            .or_default()
                            .entry(id.clone())
                            .or_default(),
                        run.number,
                    );
                }
            }
            for check in &behaviour.evasion {
                let Some(category) = run_digest::EVASION_CATEGORIES
                    .iter()
                    .find(|name| **name == check.category)
                else {
                    continue;
                };
                let row = checks
                    .entry((category, check.rule.clone(), check.object.clone()))
                    .or_insert_with(|| CheckRow {
                        rule: check.rule.clone(),
                        object: check.object.clone(),
                        runs: Vec::new(),
                        lines: Vec::new(),
                    });
                if !row.runs.contains(&run.number) {
                    row.runs.push(run.number);
                    row.lines.push((run.number, check.summary.clone()));
                }
            }
        }
        if digest.detections.is_some() {
            out.detected += 1;
        }
        for hit in digest.detections.iter().flatten() {
            let row = rules
                .entry((hit.engine.clone(), hit.rule_id.clone()))
                .or_insert_with(|| RuleRow {
                    engine: hit.engine.clone(),
                    rule_id: hit.rule_id.clone(),
                    family: hit.family.clone(),
                    rule: if hit.title.is_empty() {
                        hit.rule_id.clone()
                    } else {
                        hit.title.clone()
                    },
                    severity: hit.severity.clone(),
                    runs: Vec::new(),
                    latest: run.number,
                });
            push_run(&mut row.runs, run.number);
            row.latest = row.latest.max(run.number);
            for id in hit.mitre.iter().filter(|id| technique(id)) {
                push_run(
                    tactics
                        .entry("Detection rules")
                        .or_default()
                        .entry(id.clone())
                        .or_default(),
                    run.number,
                );
            }
        }
    }
    out.highest = top.map(|(rank, mut at)| {
        at.sort_unstable();
        (TIERS[rank].to_owned(), at)
    });
    out.rules = rules.into_values().collect();
    for row in &mut out.rules {
        row.runs.sort_unstable();
    }
    // Most runs first, then by name.
    out.rules.sort_by(|a, b| {
        b.runs
            .len()
            .cmp(&a.runs.len())
            .then_with(|| a.rule.cmp(&b.rule))
    });
    for tactic in TACTICS {
        if let Some(found) = tactics.remove(tactic) {
            let mut techniques: Vec<TechniqueRow> = found
                .into_iter()
                .map(|(id, mut runs)| {
                    runs.sort_unstable();
                    TechniqueRow { id, runs }
                })
                .collect();
            techniques.sort_by(|a, b| a.id.cmp(&b.id));
            out.tactics.push(TacticRow {
                tactic: tactic.to_owned(),
                techniques,
            });
        }
    }
    for category in run_digest::EVASION_CATEGORIES {
        let mut rows: Vec<CheckRow> = checks
            .iter()
            .filter(|((name, _, _), _)| *name == category)
            .map(|(_, row)| row.clone())
            .collect();
        for row in &mut rows {
            row.runs.sort_unstable();
            row.lines.sort_by_key(|(number, _)| *number);
        }
        out.evasion.push(EvasionRow {
            category: category.to_owned(),
            checks: rows,
        });
    }
    out.indicators = indicators(runs);
    out
}

fn indicators(runs: &[RunInput<'_>]) -> Option<IndicatorRow> {
    let listed: Vec<BTreeSet<(&str, &str)>> = runs
        .iter()
        .filter_map(|run| run.digest?.indicators.as_ref())
        .map(|list| {
            list.iter()
                .map(|entry| (entry.ty.as_str(), entry.value.as_str()))
                .collect()
        })
        .collect();
    if listed.is_empty() {
        return None;
    }
    let all: BTreeSet<(&str, &str)> = listed.iter().flatten().copied().collect();
    let matched: BTreeSet<(&str, &str)> = runs
        .iter()
        .filter_map(|run| run.digest?.indicators.as_ref())
        .flatten()
        .filter(|entry| entry.matched)
        .map(|entry| (entry.ty.as_str(), entry.value.as_str()))
        .collect();
    let in_every_run = all
        .iter()
        .filter(|value| listed.iter().all(|list| list.contains(*value)))
        .count();
    let mut per_type = Vec::new();
    for (id, label) in [
        ("endpoint", "Endpoints"),
        ("domain", "Domains"),
        ("url", "URLs"),
        ("tls", "TLS"),
        ("file", "Files"),
    ] {
        let count = all.iter().filter(|(ty, _)| *ty == id).count();
        if count > 0 {
            per_type.push((label.to_owned(), count));
        }
    }
    Some(IndicatorRow {
        total: all.len(),
        per_type,
        in_every_run,
        matched: matched.len(),
        runs: listed.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_digest::{Behaviour, BehaviourHit, DetectionHit, EvasionCheck, IndicatorEntry};

    fn behaviour(highest: &str, rules: Vec<BehaviourHit>, evasion: Vec<EvasionCheck>) -> RunDigest {
        RunDigest {
            version: run_digest::VERSION,
            behaviour: Some(Behaviour {
                highest: highest.into(),
                rules,
                evasion,
            }),
            ..RunDigest::default()
        }
    }

    fn hit(rule: &str, category: &str, attack: &[&str]) -> BehaviourHit {
        BehaviourHit {
            rule: rule.into(),
            tier: "high".into(),
            category: category.into(),
            attack: attack.iter().map(|id| (*id).to_owned()).collect(),
            count: 1,
            first_ns: 0,
        }
    }

    fn check(rule: &str, object: &str, summary: &str) -> EvasionCheck {
        EvasionCheck {
            category: run_digest::evasion_category(rule).unwrap().into(),
            rule: rule.into(),
            object: object.into(),
            summary: summary.into(),
            process: "sh".into(),
            count: 1,
        }
    }

    #[test]
    fn the_highest_tier_names_the_runs_that_reached_it() {
        let a = behaviour("medium", vec![], vec![]);
        let b = behaviour("high", vec![], vec![]);
        let c = behaviour("high", vec![], vec![]);
        let rolled = rollup(&[
            RunInput {
                number: 1,
                digest: Some(&a),
            },
            RunInput {
                number: 2,
                digest: Some(&b),
            },
            RunInput {
                number: 3,
                digest: Some(&c),
            },
            RunInput {
                number: 4,
                digest: None,
            },
        ]);
        assert_eq!(rolled.highest, Some(("high".into(), vec![2, 3])));
        assert_eq!((rolled.runs, rolled.triaged), (4, 3));
        assert_eq!(
            rollup(&[RunInput {
                number: 1,
                digest: None
            }])
            .highest,
            None
        );
    }

    #[test]
    fn techniques_group_by_tactic_in_matrix_order_and_skip_detection_strategies() {
        let a = behaviour(
            "high",
            vec![
                hit("impact.encrypt", "impact", &["T1486"]),
                hit("persistence.cron", "persistence", &["T1053.003", "DET0001"]),
            ],
            vec![],
        );
        let b = behaviour(
            "high",
            vec![hit("persistence.cron", "persistence", &["T1053.003"])],
            vec![],
        );
        let rolled = rollup(&[
            RunInput {
                number: 1,
                digest: Some(&a),
            },
            RunInput {
                number: 2,
                digest: Some(&b),
            },
        ]);
        let tactics: Vec<&str> = rolled
            .tactics
            .iter()
            .map(|row| row.tactic.as_str())
            .collect();
        assert_eq!(tactics, ["Persistence", "Impact"]);
        assert_eq!(rolled.tactics[0].techniques.len(), 1);
        assert_eq!(rolled.tactics[0].techniques[0].runs, [1, 2]);
    }

    #[test]
    fn detection_rules_list_the_runs_and_the_latest() {
        let hit = |id: &str| DetectionHit {
            engine: "YARA".into(),
            rule_id: id.into(),
            title: format!("title {id}"),
            severity: "high".into(),
            mitre: vec!["T1496".into()],
            count: 1,
            family: if id == "xmrig" {
                "XMRig".into()
            } else {
                String::new()
            },
        };
        let a = RunDigest {
            detections: Some(vec![hit("xmrig")]),
            ..RunDigest::default()
        };
        let b = RunDigest {
            detections: Some(vec![hit("xmrig"), hit("other")]),
            ..RunDigest::default()
        };
        let rolled = rollup(&[
            RunInput {
                number: 1,
                digest: Some(&a),
            },
            RunInput {
                number: 3,
                digest: Some(&b),
            },
        ]);
        assert_eq!(rolled.rules[0].rule, "title xmrig");
        assert_eq!(rolled.rules[0].runs, [1, 3]);
        assert_eq!(rolled.rules[0].latest, 3);
        assert_eq!(rolled.rules[0].rule_id, "xmrig");
        assert_eq!(rolled.rules[0].family, "XMRig");
        assert_eq!(rolled.rules[1].family, "");
        assert_eq!(rolled.rules[1].runs, [3]);
        // Rule-supplied techniques have no tactic of their own.
        assert_eq!(rolled.tactics[0].tactic, "Detection rules");
    }

    #[test]
    fn evasion_checks_fold_by_category_then_check_and_empty_categories_stay() {
        let a = behaviour(
            "medium",
            vec![],
            vec![check(
                "evasion.sandbox_probe",
                "/sys/class/dmi/id/product_name",
                "read: QEMU",
            )],
        );
        let b = behaviour(
            "medium",
            vec![],
            vec![check(
                "evasion.sandbox_probe",
                "/sys/class/dmi/id/product_name",
                "read: QEMU",
            )],
        );
        let rolled = rollup(&[
            RunInput {
                number: 1,
                digest: Some(&a),
            },
            RunInput {
                number: 2,
                digest: Some(&b),
            },
        ]);
        assert_eq!(rolled.evasion.len(), 4);
        assert_eq!(rolled.evasion[0].category, "Virtual machine");
        assert_eq!(rolled.evasion[0].checks.len(), 1);
        assert_eq!(rolled.evasion[0].checks[0].runs, [1, 2]);
        assert!(rolled.evasion[1].checks.is_empty());
    }

    #[test]
    fn indicators_count_unique_values_and_those_in_every_run() {
        let entry = |ty: &str, value: &str, matched: bool| IndicatorEntry {
            ty: ty.into(),
            value: value.into(),
            matched,
        };
        let a = RunDigest {
            indicators: Some(vec![
                entry("domain", "bad.example", true),
                entry("endpoint", "1.2.3.4:80", false),
            ]),
            ..RunDigest::default()
        };
        let b = RunDigest {
            indicators: Some(vec![entry("domain", "bad.example", true)]),
            ..RunDigest::default()
        };
        let rolled = rollup(&[
            RunInput {
                number: 1,
                digest: Some(&a),
            },
            RunInput {
                number: 2,
                digest: Some(&b),
            },
            RunInput {
                number: 3,
                digest: None,
            },
        ])
        .indicators
        .unwrap();
        assert_eq!(
            (
                rolled.total,
                rolled.in_every_run,
                rolled.matched,
                rolled.runs
            ),
            (2, 1, 1, 2)
        );
        assert_eq!(
            rolled.per_type,
            [("Endpoints".to_owned(), 1), ("Domains".to_owned(), 1)]
        );
    }
}
