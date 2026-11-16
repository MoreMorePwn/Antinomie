// SPDX-License-Identifier: GPL-3.0-only
//! The expression grammar, the default mapping of 4.9.2 and the policy rules
//! (card P3-5). No engine, no recording: the facts are written by hand.
use super::*;
use crate::{
    api::{
        assessment::{AssessmentKind, Counts, DetectionHit, Label, Tier},
        run::EndReason,
    },
    config::preset::{VerdictMapping, VerdictRule, VerdictSettings},
};

fn facts() -> Facts {
    Facts {
        assessment: AssessmentKind::NoFindings,
        highest_tier: Tier::None,
        counts: Counts::default(),
        detections: Vec::new(),
        families: Vec::new(),
        family_evidence: Vec::new(),
        techniques: Vec::new(),
        end_reason: Some(EndReason::Exited),
        triage_ran: true,
        ioc_datasets: 3,
        statement: "These are observations from a recorded run.".into(),
        key_behaviours: Vec::new(),
    }
}

fn hit(engine: &str, severity: &str) -> DetectionHit {
    DetectionHit {
        engine: engine.into(),
        rule_id: "rule_1".into(),
        title: "Rule one".into(),
        severity: severity.into(),
        count: 1,
    }
}

fn eval(text: &str, facts: &Facts) -> bool {
    Expr::parse(text)
        .unwrap_or_else(|e| panic!("{text}: {e}"))
        .eval(facts)
}

fn label(facts: &Facts) -> Label {
    default_label(facts).label
}

// ---- the grammar -------------------------------------------------------

#[test]
fn equality_comparison_and_or_in_and_parentheses_evaluate() {
    let mut f = facts();
    f.assessment = AssessmentKind::SuspiciousBehaviour;
    f.highest_tier = Tier::High;
    f.counts.findings = 7;
    f.families = vec!["Mirai".into(), "Gafgyt".into()];
    f.techniques = vec!["T1059".into()];
    f.detections = vec![hit("YARA", "high"), hit("IDS", "low")];
    assert!(eval("highest_tier == 'high'", &f));
    assert!(eval("highest_tier == \"HIGH\"", &f), "strings ignore case");
    assert!(eval("highest_tier != 'low'", &f));
    assert!(eval("counts.findings >= 7 and counts.findings < 8", &f));
    assert!(!eval("counts.findings > 7", &f));
    assert!(eval("counts.findings == 7", &f));
    assert!(eval(
        "assessment in ['matched_indicators', 'suspicious_behaviour']",
        &f
    ));
    assert!(eval("'Mirai' in families", &f), "a value in a list field");
    assert!(
        eval("families == 'gafgyt'", &f),
        "a list field compares as any"
    );
    assert!(eval(
        "detections.engine == 'yara' and detections.severity in ['critical', 'high']",
        &f
    ));
    assert!(eval("techniques != 'T1486'", &f));
    assert!(!eval("techniques != 'T1059'", &f));
    assert!(eval(
        "(counts.findings == 1 or counts.findings == 7) and highest_tier == 'high'",
        &f
    ));
    assert!(!eval("counts.findings == 1 or highest_tier == 'low'", &f));
    assert!(eval("run.end_reason == 'exited'", &f));
    f.end_reason = None;
    assert!(
        !eval("run.end_reason == 'exited'", &f),
        "no end reason matches nothing"
    );
}

#[test]
fn and_binds_tighter_than_or() {
    let mut f = facts();
    f.counts.findings = 1;
    // true or (false and false) is true; (true or false) and false is false.
    assert!(eval(
        "counts.findings == 1 or counts.processes == 5 and counts.domains == 5",
        &f
    ));
    assert!(!eval(
        "(counts.findings == 1 or counts.processes == 5) and counts.domains == 5",
        &f
    ));
}

#[test]
fn bad_expressions_are_refused_with_where() {
    for (text, why) in [
        ("", "empty"),
        ("   ", "empty"),
        ("highest_tier", "must be compared"),
        ("nonsense == 'x'", "unknown field"),
        ("counts.findings == 'x'", "same kind"),
        ("highest_tier < 'high'", "only numbers are ordered"),
        ("highest_tier == 'high' and", "ends where a value"),
        ("highest_tier == 'high' junk", "after the expression"),
        ("(highest_tier == 'high'", "parenthesis"),
        ("highest_tier == 'high", "not closed"),
        ("highest_tier == ['a']", "compared with `in`"),
        ("assessment in ['a', 1]", "one kind"),
        ("assessment in [['a']]", "do not nest"),
        ("assessment in ['a' 'b']", "expected `,` or `]`"),
        ("counts.findings == 99999999999999999999", "too large"),
        ("highest_tier = 'high'", "unexpected character"),
        ("highest_tier == 'a'; drop", "unexpected character"),
        ("os.system('x') == 1", "unknown field"),
    ] {
        let error = Expr::parse(text).expect_err(text);
        assert!(error.to_string().contains(why), "{text:?}: {error}");
    }
    let error = Expr::parse("highest_tier == 'high' and bogus == 1").unwrap_err();
    assert_eq!(error.at, 27, "the offset points at the bad word");
}

/// Found by the `label_expr` fuzz target (ANT-T0387): thousands of nested
/// parentheses or chained terms overflowed the stack.
#[test]
fn a_hostile_expression_is_refused_before_it_can_overflow_the_stack() {
    let nest = format!(
        "{}highest_tier == 'high'{}",
        "(".repeat(100),
        ")".repeat(100)
    );
    let error = Expr::parse(&nest).unwrap_err();
    assert!(error.to_string().contains("nest deeper"), "{error}");
    let huge = "(".repeat(5000);
    assert!(Expr::parse(&huge).is_err());
    let open_only = "(".repeat(100_000);
    assert!(Expr::parse(&open_only).is_err());
    let chain = vec!["highest_tier == 'high'"; 200_000].join(" and ");
    let error = Expr::parse(&chain).unwrap_err();
    assert!(error.to_string().contains("longer than"), "{error}");
    // Within the limits both still work.
    let ok = format!("{}counts.findings >= 1{}", "(".repeat(32), ")".repeat(32));
    assert!(Expr::parse(&ok).is_ok());
    let chain = vec!["highest_tier == 'high'"; 60].join(" or ");
    let _ = Expr::parse(&chain).unwrap().eval(&facts());
}

// ---- the default mapping ----------------------------------------------

#[test]
fn the_default_mapping_follows_the_table_in_order() {
    // Not completed, or Triage did not run: inconclusive, whatever else holds.
    let mut f = facts();
    f.assessment = AssessmentKind::MatchedIndicators;
    f.end_reason = Some(EndReason::GuestLost);
    assert_eq!(label(&f), Label::Inconclusive);
    assert!(default_label(&f).basis.contains("did not complete"));
    f.end_reason = Some(EndReason::Stopped);
    assert_eq!(label(&f), Label::Inconclusive, "a stop for a safety rule");
    let mut none = Facts::without_triage(Some(EndReason::Exited), 3);
    none.assessment = AssessmentKind::MatchedIndicators;
    assert_eq!(label(&none), Label::Inconclusive);
    assert!(default_label(&none).basis.contains("Triage did not run"));

    // Matched indicators with a named family.
    let mut f = facts();
    f.assessment = AssessmentKind::MatchedIndicators;
    f.counts.indicators_matched = 2;
    f.families = vec!["Mirai".into()];
    let v = default_label(&f);
    assert_eq!(v.label, Label::Malicious);
    assert!(
        v.basis.contains("Mirai") && v.basis.contains('2'),
        "{}",
        v.basis
    );

    // A high or critical YARA hit is suspicious, never malicious on its own
    // (A50: one rule's own severity made a low-tier run malicious).
    for severity in ["high", "critical", "HIGH"] {
        let mut f = facts();
        f.assessment = AssessmentKind::ObservedOnly;
        f.detections = vec![hit("YARA", severity)];
        let v = default_label(&f);
        assert_eq!(v.label, Label::Suspicious, "{severity}");
        assert!(v.basis.contains("rule_1"));
    }
    // From another engine, or a lower severity, a hit is not enough on its own.
    let mut f = facts();
    f.assessment = AssessmentKind::ObservedOnly;
    f.detections = vec![hit("IDS", "high"), hit("YARA", "medium")];
    assert_eq!(label(&f), Label::CleanObserved);

    // Matched indicators without a family are malicious by the next row.
    let mut f = facts();
    f.assessment = AssessmentKind::MatchedIndicators;
    f.counts.indicators_matched = 1;
    assert_eq!(label(&f), Label::Malicious);

    // The highest tier or the behaviour assessment: suspicious.
    let mut f = facts();
    f.highest_tier = Tier::High;
    f.assessment = AssessmentKind::ObservedOnly;
    assert_eq!(label(&f), Label::Suspicious);
    let mut f = facts();
    f.assessment = AssessmentKind::SuspiciousBehaviour;
    f.highest_tier = Tier::Medium;
    let v = default_label(&f);
    assert_eq!(v.label, Label::Suspicious);
    assert!(v.basis.contains(&f.statement));

    // Observed only, and nothing: clean_observed, never "clean".
    let mut f = facts();
    f.assessment = AssessmentKind::ObservedOnly;
    assert_eq!(label(&f), Label::CleanObserved);
    f.assessment = AssessmentKind::NoFindings;
    let v = default_label(&f);
    assert_eq!(v.label, Label::CleanObserved);
    assert!(v.basis.contains("not a statement that the sample is clean"));
    // A time limit is a completed run.
    f.end_reason = Some(EndReason::TimeLimit);
    assert_eq!(label(&f), Label::CleanObserved);
    f.end_reason = Some(EndReason::Signaled);
    assert_eq!(label(&f), Label::CleanObserved);
}

#[test]
fn the_default_mapping_sets_no_score_and_says_when_no_datasets_were_loaded() {
    let mapping = Mapping::compile(&VerdictSettings::default()).unwrap();
    assert!(mapping.is_default());
    let mut f = facts();
    f.assessment = AssessmentKind::ObservedOnly;
    let v = mapping.judge(&f);
    assert_eq!((v.label, v.score), (Label::CleanObserved, None));
    assert!(!v.basis.contains("datasets"));
    f.ioc_datasets = 0;
    let v = mapping.judge(&f);
    assert!(
        v.basis.contains("No indicator datasets were loaded"),
        "{}",
        v.basis
    );
    // Not said when Triage did not run: there was nothing to check.
    let mut none = Facts::without_triage(Some(EndReason::Exited), 0);
    none.ioc_datasets = 0;
    assert!(!mapping.judge(&none).basis.contains("datasets"));
}

// ---- preset rules ------------------------------------------------------

fn rules(list: &[(&str, Label, Option<u8>)]) -> VerdictSettings {
    VerdictSettings {
        mapping: VerdictMapping::Name("default".into()),
        rule: list
            .iter()
            .map(|(when, label, score)| VerdictRule {
                when: (*when).into(),
                label: *label,
                score: *score,
            })
            .collect(),
        tag_library: false,
    }
}

#[test]
fn policy_rules_give_the_first_label_and_the_largest_score() {
    let mapping = Mapping::compile(&rules(&[
        ("highest_tier == 'high'", Label::Suspicious, Some(70)),
        ("counts.findings > 5", Label::Malicious, Some(90)),
        ("counts.findings > 1", Label::CleanObserved, Some(10)),
    ]))
    .unwrap();
    assert!(!mapping.is_default());
    let mut f = facts();
    f.highest_tier = Tier::High;
    f.counts.findings = 9;
    let v = mapping.judge(&f);
    assert_eq!(
        v.label,
        Label::Suspicious,
        "the first rule that holds names it"
    );
    assert_eq!(
        v.score,
        Some(90),
        "the largest score of the rules that hold"
    );
    assert!(v.basis.contains("highest_tier == 'high'"));
    f.highest_tier = Tier::Low;
    f.counts.findings = 2;
    let v = mapping.judge(&f);
    assert_eq!((v.label, v.score), (Label::CleanObserved, Some(10)));
    // Nothing holds: inconclusive, null score.
    f.counts.findings = 0;
    let v = mapping.judge(&f);
    assert_eq!((v.label, v.score), (Label::Inconclusive, None));
    assert!(v.basis.contains("No rule"));
    // Without Triage no rule is applied.
    let v = mapping.judge(&Facts::without_triage(Some(EndReason::Exited), 1));
    assert_eq!(v.label, Label::Inconclusive);
    assert!(v.basis.contains("Triage did not run"));
}

#[test]
fn a_rule_without_a_score_leaves_the_score_null() {
    let mapping = Mapping::compile(&rules(&[(
        "assessment == 'no_findings'",
        Label::CleanObserved,
        None,
    )]))
    .unwrap();
    let v = mapping.judge(&facts());
    assert_eq!((v.label, v.score), (Label::CleanObserved, None));
}

#[test]
fn a_mapping_that_cannot_be_used_says_which_key() {
    let table = VerdictSettings {
        mapping: VerdictMapping::Table(Default::default()),
        rule: Vec::new(),
        tag_library: false,
    };
    let error = Mapping::compile(&table).unwrap_err();
    assert_eq!(error.key(), "verdict.mapping");
    let named = VerdictSettings {
        mapping: VerdictMapping::Name("strict".into()),
        rule: Vec::new(),
        tag_library: false,
    };
    assert!(
        Mapping::compile(&named)
            .unwrap_err()
            .to_string()
            .contains("strict")
    );
    let bad = rules(&[("fine == 1", Label::Malicious, None)]);
    let error = Mapping::compile(&bad).unwrap_err();
    assert_eq!(error.key(), "verdict.rule.0.when");
    let late = rules(&[
        ("counts.findings > 1", Label::Malicious, None),
        ("counts.findings > 2", Label::Malicious, Some(101)),
    ]);
    assert_eq!(
        Mapping::compile(&late).unwrap_err().key(),
        "verdict.rule.1.score"
    );
}

#[test]
fn rules_parse_from_a_policy_file_and_config_validate_checks_them() {
    let text = r#"
[verdict]
mapping = "default"

[[verdict.rule]]
when = "highest_tier == 'high' or counts.findings > 20"
label = "suspicious"
score = 70

[[verdict.rule]]
when = "detections.engine == 'YARA'"
label = "malicious"
score = 95
"#;
    let policy: crate::config::Preset = toml::from_str(text).unwrap();
    assert_eq!(policy.verdict.rule.len(), 2);
    assert_eq!(policy.verdict.rule[1].label, Label::Malicious);
    assert!(Mapping::compile(&policy.verdict).is_ok());
    let wrong: Result<crate::config::Preset, _> =
        toml::from_str("[[verdict.rule]]\nwhen = \"x == 1\"\nlabel = \"clean\"\n");
    assert!(wrong.is_err(), "`clean` is not a label");
    let unknown: Result<crate::config::Preset, _> =
        toml::from_str("[[verdict.rule]]\nwhen = \"x\"\nlabel = \"malicious\"\nextra = 1\n");
    assert!(unknown.is_err(), "unknown keys are errors");
}

#[test]
fn the_assessment_object_carries_the_facts_the_label_and_the_basis() {
    let mut f = facts();
    f.assessment = AssessmentKind::SuspiciousBehaviour;
    f.highest_tier = Tier::High;
    f.families = vec!["Mirai".into()];
    f.counts.findings = 3;
    f.ioc_datasets = 2;
    let verdict = Mapping::compile(&VerdictSettings::default())
        .unwrap()
        .judge(&f);
    let a = assessment_of(&f, &verdict);
    assert_eq!(a.assessment, AssessmentKind::SuspiciousBehaviour);
    assert_eq!(a.label, Some(Label::Suspicious));
    assert_eq!((a.ioc_dataset_count, a.counts.findings), (2, 3));
    assert_eq!(a.families, ["Mirai"]);
    assert!(!a.basis.is_empty());
    // It round-trips as JSON, the form the store keeps.
    let json = serde_json::to_string(&a).unwrap();
    assert_eq!(
        serde_json::from_str::<crate::api::assessment::Assessment>(&json).unwrap(),
        a
    );
}

// ---- labels from tiers and family evidence (ANT-T0556, A50, A11) --------

/// One row of the label table: the run's behaviour, its YARA hits (as the
/// 2026-11-16 evaluation recorded them, trimmed), what it did that names a
/// family, and the label the default mapping must give.
struct Row {
    run: &'static str,
    assessment: AssessmentKind,
    tier: Tier,
    /// `(rule, family meta, pack, severity)`.
    hits: &'static [(&'static str, &'static str, &'static str, &'static str)],
    observed: &'static [&'static str],
    label: Label,
    families: &'static [&'static str],
}

const HUB: &str = "selection/pack/abuse-ch-yarahub/x.yar";
const FORGE: &str = "selection/pack/yara-forge-core/x.yar";
const MASS: (&str, &str, &str, &str) = (
    "s1072::TH_Generic_MassHunt_Linux_Malware_2026_CYFARE",
    "",
    HUB,
    "indicator",
);
const OHSHIT: (&str, &str, &str, &str) =
    ("s1::MIRAI_OHSHIT_payload", "MIRAI_OHSHIT", HUB, "indicator");
const TORII: (&str, &str, &str, &str) = ("s2::ELF_Toriilike_persist", "Torii", HUB, "indicator");

fn label_table() -> Vec<Row> {
    use AssessmentKind::SuspiciousBehaviour as Behaviour;
    use AssessmentKind::{Inconclusive as NoBehaviour, NoFindings, ObservedOnly};
    vec![
        // A strong family rule and medium or high behaviour: malicious.
        Row {
            run: "1bcae1cc-r2",
            assessment: Behaviour,
            tier: Tier::High,
            hits: &[
                OHSHIT,
                (
                    "s3::MIRAI_TELNETCURL_payload",
                    "MIRAI_TELNETCURL",
                    HUB,
                    "indicator",
                ),
                MASS,
            ],
            observed: &[],
            label: Label::Malicious,
            families: &["Mirai"],
        },
        Row {
            run: "28b1b1ad",
            assessment: Behaviour,
            tier: Tier::Medium,
            hits: &[OHSHIT, MASS],
            observed: &[],
            label: Label::Malicious,
            families: &["Mirai"],
        },
        // The behaviour names Prometei; the Mirai rule is "also named".
        Row {
            run: "21011aed",
            assessment: Behaviour,
            tier: Tier::High,
            hits: &[OHSHIT, ("s885::RANSOMWARE", "", HUB, "indicator"), MASS],
            observed: &[
                "/usr/sbin/uplugplay",
                "GET 177.221.180.26/cgi-bin/p.cgi?r=59&i=4J8",
            ],
            label: Label::Malicious,
            families: &["Prometei", "Mirai"],
        },
        // A strong family rule and low behaviour: suspicious, never clean.
        Row {
            run: "d0d25b1a",
            assessment: ObservedOnly,
            tier: Tier::Low,
            hits: &[OHSHIT, MASS],
            observed: &[],
            label: Label::Suspicious,
            families: &["Mirai"],
        },
        Row {
            run: "f99021c2",
            assessment: NoFindings,
            tier: Tier::None,
            hits: &[
                OHSHIT,
                MASS,
                ("SEKOIA_Miner_Lin_Xmrig_Strings", "", FORGE, "indicator"),
                (
                    "SIGNATURE_BASE_PUA_Crypto_Mining_Commandline_Indicators_Oct21",
                    "",
                    FORGE,
                    "indicator",
                ),
            ],
            observed: &[],
            label: Label::Suspicious,
            families: &["Mirai", "XMRig"],
        },
        // A "high severity" rule beside a family rule on a low-tier run:
        // suspicious, no longer malicious.
        Row {
            run: "e898ef63",
            assessment: ObservedOnly,
            tier: Tier::Low,
            hits: &[
                OHSHIT,
                MASS,
                ("s1597::focusbot_ddos_botnet", "focusbot", HUB, "high"),
            ],
            observed: &[],
            label: Label::Suspicious,
            families: &["Mirai", "Focusbot"],
        },
        // Family rules of Gafgyt (meta, a known name, a Malpedia alias).
        Row {
            run: "14de1483",
            assessment: ObservedOnly,
            tier: Tier::Low,
            hits: &[
                TORII,
                MASS,
                ("botnet_Yakuza", "", HUB, "indicator"),
                ("botnet_mortem_qbot_gafgyt", "Gafgyt", HUB, "indicator"),
                ("gafgyt_ansi_beacon", "Gafgyt", HUB, "indicator"),
            ],
            observed: &[],
            label: Label::Suspicious,
            families: &["Gafgyt"],
        },
        Row {
            run: "938b3bf6",
            assessment: ObservedOnly,
            tier: Tier::Low,
            hits: &[
                ("ELF_DDoS_Gafgyt_Variant", "", HUB, "indicator"),
                TORII,
                MASS,
                ("botnet_dayzddos", "", HUB, "indicator"),
            ],
            observed: &[],
            label: Label::Suspicious,
            families: &["Gafgyt"],
        },
        Row {
            run: "d4c93991",
            assessment: ObservedOnly,
            tier: Tier::Low,
            hits: &[
                ("ELF_IoT_Persistence_Hunt", "", HUB, "indicator"),
                TORII,
                (
                    "LIN_Downloader_Unknown_WgetChmodExecute",
                    "",
                    HUB,
                    "indicator",
                ),
                MASS,
                ("MALPEDIA_Elf_Bashlite_Auto", "", FORGE, "indicator"),
            ],
            observed: &[],
            label: Label::Suspicious,
            families: &["Gafgyt"],
        },
        // A family rule and no recorded behaviour: suspicious, and says so.
        Row {
            run: "83ff6b2e-r2",
            assessment: NoBehaviour,
            tier: Tier::Low,
            hits: &[OHSHIT, MASS],
            observed: &[],
            label: Label::Suspicious,
            families: &["Mirai"],
        },
        // Technique and generic rules only: no family, the behaviour decides.
        Row {
            run: "624cf70d",
            assessment: ObservedOnly,
            tier: Tier::Low,
            hits: &[TORII, MASS],
            observed: &[],
            label: Label::CleanObserved,
            families: &[],
        },
        Row {
            run: "3dc4d1b1-r2",
            assessment: ObservedOnly,
            tier: Tier::Low,
            hits: &[
                ("DetectEncryptedVariants", "", HUB, "indicator"),
                ("DetectGoMethodSignatures", "", HUB, "indicator"),
                ("RANSOMWARE", "", HUB, "indicator"),
                ("Suspicious_Golang_Binary", "", HUB, "indicator"),
                MASS,
            ],
            observed: &[],
            label: Label::CleanObserved,
            families: &[],
        },
        Row {
            run: "791b8d17-r2",
            assessment: ObservedOnly,
            tier: Tier::Low,
            hits: &[
                ("botnet_Yakuza", "", HUB, "indicator"),
                ("Sus_CMD_Powershell_Usage", "", HUB, "indicator"),
                MASS,
            ],
            observed: &[],
            label: Label::CleanObserved,
            families: &[],
        },
        Row {
            run: "8632f4bb-r2",
            assessment: NoFindings,
            tier: Tier::None,
            hits: &[
                ("ELF_Packer_Dropper_Fileless_Armhf", "", HUB, "indicator"),
                MASS,
            ],
            observed: &[],
            label: Label::CleanObserved,
            families: &[],
        },
        Row {
            run: "56dffc63",
            assessment: Behaviour,
            tier: Tier::High,
            hits: &[
                ("ELF_IoT_Persistence_Hunt", "", HUB, "indicator"),
                ("NSVPS_Mirai_Busybox_Staging", "", HUB, "indicator"),
                MASS,
            ],
            observed: &[],
            label: Label::Suspicious,
            families: &[],
        },
        Row {
            run: "5bf67d64",
            assessment: Behaviour,
            tier: Tier::High,
            hits: &[("Suspicious_Golang_Binary", "", HUB, "indicator"), MASS],
            observed: &[],
            label: Label::Suspicious,
            families: &[],
        },
        // Nothing recorded and no family: inconclusive, not clean.
        Row {
            run: "032d50ab-r2",
            assessment: NoBehaviour,
            tier: Tier::Low,
            hits: &[MASS],
            observed: &[],
            label: Label::Inconclusive,
            families: &[],
        },
    ]
}

#[test]
fn the_label_follows_the_tier_and_the_family_evidence_in_every_evaluation_run() {
    use antinomie_monitor_core::family::{self, Bazaar};
    for row in label_table() {
        let hits: Vec<antinomie_monitor_core::run_digest::DetectionHit> = row
            .hits
            .iter()
            .map(|(rule, meta, source, severity)| {
                antinomie_monitor_core::run_digest::DetectionHit {
                    engine: "YARA".into(),
                    rule_id: (*rule).into(),
                    title: (*rule).into(),
                    severity: (*severity).into(),
                    family: (*meta).into(),
                    source: (*source).into(),
                    count: 1,
                    ..Default::default()
                }
            })
            .collect();
        let candidates = family::family_candidates_seen(&hits, Bazaar::default(), row.observed);
        let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, row.families, "{}: {candidates:?}", row.run);
        let mut f = facts();
        f.assessment = row.assessment;
        f.highest_tier = row.tier;
        f.families = names.iter().map(|n| (*n).to_owned()).collect();
        f.family_evidence = family::observed_families(&candidates);
        f.detections = hits
            .iter()
            .map(|h| DetectionHit {
                engine: h.engine.clone(),
                rule_id: h.rule_id.clone(),
                title: h.title.clone(),
                severity: h.severity.clone(),
                count: 1,
            })
            .collect();
        let v = default_label(&f);
        assert_eq!(v.label, row.label, "{}: {}", row.run, v.basis);
        if !row.families.is_empty() {
            assert!(
                v.basis.contains(row.families[0]),
                "{}: {}",
                row.run,
                v.basis
            );
        }
    }
}

#[test]
fn a_run_with_no_recorded_behaviour_is_inconclusive_and_says_why() {
    // A11: a crash before the first call, or a program stopped at the time
    // limit before its first call, is no "clean" run.
    let mut f = facts();
    f.assessment = AssessmentKind::Inconclusive;
    f.highest_tier = Tier::Low;
    f.end_reason = Some(EndReason::TimeLimit);
    f.statement = "Triage observed: no behaviour was recorded: the program made no system call before it was stopped (SIGTERM).".into();
    let v = default_label(&f);
    assert_eq!(v.label, Label::Inconclusive);
    assert!(v.basis.contains("No behaviour was recorded"), "{}", v.basis);
    assert!(v.basis.contains("SIGTERM"), "{}", v.basis);
    f.end_reason = Some(EndReason::Signaled);
    f.statement = "Triage observed: no behaviour was recorded: the program crashed before its first system call: SIGBUS (bus error).".into();
    let v = default_label(&f);
    assert_eq!(v.label, Label::Inconclusive);
    assert!(v.basis.contains("SIGBUS"), "{}", v.basis);
}
