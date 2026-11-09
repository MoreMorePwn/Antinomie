// SPDX-License-Identifier: GPL-3.0-only
//! The run's Triage digest: what the scan of a finished run found, written
//! beside the run so the sample window can add up many runs without reading
//! their recordings. See `antinomie_monitor_core::run_digest`. The GUI writes
//! it when it shows a finished run; the command line when it saves detections.
use super::*;
use crate::{detection, ioc_scan, lineage_index};
use antinomie_monitor_core::{
    analysis::detection::State,
    ioc::verdict::{OnlineResults, Outcome},
    run_digest::{
        self, Behaviour, BehaviourHit, DetectionHit, EvasionCheck, IndicatorEntry, IndicatorHit,
        RunDigest,
    },
};

fn text<'a>(values: &'a [(&'static str, RowValue)], key: &str) -> &'a str {
    values
        .iter()
        .find_map(|(name, value)| match value {
            RowValue::Text(text) if *name == key => Some(text.as_str()),
            _ => None,
        })
        .unwrap_or("")
}

fn number(values: &[(&'static str, RowValue)], key: &str) -> u64 {
    values
        .iter()
        .find_map(|(name, value)| match value {
            RowValue::Number(number) if *name == key => Some(*number),
            _ => None,
        })
        .map_or(0, |number| number.clamp(0, i128::from(u64::MAX)) as u64)
}

fn list(values: &[(&'static str, RowValue)], key: &str) -> Vec<String> {
    values
        .iter()
        .find_map(|(name, value)| match value {
            RowValue::List(list) if *name == key => Some(list.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// What the behaviour findings of the scan add up to.
pub fn behaviour(findings: &[Finding]) -> Behaviour {
    let mut out = Behaviour::default();
    let mut best = usize::MAX;
    for finding in findings {
        let values = &finding.values;
        let tier = text(values, "finding.tier");
        if let Some(rank) = rules::Tier::ALL.iter().position(|t| t.tag() == tier) {
            best = best.min(rank);
        }
        let rule = text(values, "finding.rule");
        out.rules.push(BehaviourHit {
            rule: rule.to_owned(),
            tier: tier.to_owned(),
            category: text(values, "finding.category").to_owned(),
            attack: list(values, "finding.technique"),
            count: number(values, "finding.count"),
            first_ns: number(values, "finding.first_ns"),
        });
        if let Some(category) = run_digest::evasion_category(rule) {
            out.evasion.push(EvasionCheck {
                category: category.to_owned(),
                rule: rule.to_owned(),
                object: text(values, "finding.object").to_owned(),
                summary: text(values, "finding.summary").to_owned(),
                process: text(values, "process.exe").to_owned(),
                count: number(values, "finding.count"),
                cookie: number(values, "process.cookie"),
                calls: evidence_calls(values),
            });
        }
    }
    if let Some(tier) = rules::Tier::ALL.get(best) {
        out.highest = tier.tag().to_owned();
    }
    out
}

/// The calls a finding names as its evidence: its first call, the calls its
/// detail lines cite ("(call 12)", "Occurrences: calls 12, 40, 41"), first
/// first and without repeats, at most [`run_digest::EVIDENCE_CALLS`].
pub fn evidence_calls(values: &[(&'static str, RowValue)]) -> Vec<u64> {
    let mut calls = Vec::new();
    let mut add = |call: u64| {
        if call != 0 && !calls.contains(&call) && calls.len() < run_digest::EVIDENCE_CALLS {
            calls.push(call);
        }
    };
    add(number(values, "event.id"));
    for line in list(values, "finding.detail") {
        for (marker, many) in [("(call ", false), ("calls ", true)] {
            let mut rest = line.as_str();
            while let Some(at) = rest.find(marker) {
                rest = &rest[at + marker.len()..];
                for part in rest.split(", ") {
                    let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
                    match digits.parse() {
                        Ok(call) => add(call),
                        Err(_) => break,
                    }
                    if !many || digits.len() != part.len() {
                        break;
                    }
                }
            }
        }
    }
    calls
}

/// The indicators with the stored datasets' answer, no false-positive list
/// and no online answers (those are the person's, per run).
pub fn indicators(ioc: &ioc_scan::IocScan) -> Vec<IndicatorEntry> {
    let verdicts = ioc_scan::verdicts(ioc, &[], &OnlineResults::default());
    ioc.indicators
        .iter()
        .zip(verdicts)
        .map(|(indicator, verdict)| IndicatorEntry {
            ty: indicator.ty.id().to_owned(),
            value: indicator.value.clone(),
            matched: verdict.outcome == Outcome::Matched,
            sub: indicator.sub.clone(),
            sources: indicator
                .sources
                .iter()
                .map(|source| source.label().to_owned())
                .collect(),
            first_us: indicator.first_us,
            last_us: indicator.last_us,
            count: indicator.count.clone(),
            process: indicator
                .process
                .as_ref()
                .map(|process| process.label())
                .unwrap_or_default(),
            path: indicator.path.clone(),
            roles: indicator.roles.clone(),
            not_checked: indicator.not_checked.clone().unwrap_or_default(),
            noise: indicator.noise.clone().unwrap_or_default(),
            hits: verdict
                .matches
                .iter()
                .map(|found| IndicatorHit {
                    dataset: found.record.feed.clone(),
                    family: found.record.family.clone(),
                    record_id: found.record.record_id.clone(),
                    reference: found.record.reference.clone(),
                })
                .collect(),
        })
        .collect()
}

/// The family a YARA rule names in its `meta` (`family`, `malware_family` or
/// `malware`); empty for the other engines and for a rule that names none.
pub fn yara_family(
    engine: antinomie_monitor_core::analysis::detection::Engine,
    rule: &str,
) -> String {
    if engine != antinomie_monitor_core::analysis::detection::Engine::Yara {
        return String::new();
    }
    rule.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            matches!(key.trim(), "family" | "malware_family" | "malware")
                .then(|| value.trim().trim_matches('"').trim().to_owned())
        })
        .find(|family| !family.is_empty())
        .unwrap_or_default()
}

/// Whether a match was found only in layers static analysis unpacked from the
/// sample: its evidence is bytes of an unpacked layer and nothing else.
fn only_in_layers(evidence: &[antinomie_monitor_core::analysis::detection::Evidence]) -> bool {
    use antinomie_monitor_core::analysis::detection::{Evidence, InputKind};
    !evidence.is_empty()
        && evidence.iter().all(|item| {
            matches!(
                item,
                Evidence::Bytes {
                    input: Some(InputKind::UnpackedLayer),
                    ..
                }
            )
        })
}

/// The matches of the engines whose reports are complete.
pub fn detections(
    results: &[Option<Result<antinomie_monitor_core::analysis::detection::Report, String>>; 3],
) -> Option<Vec<DetectionHit>> {
    let mut out = Vec::new();
    let mut any = false;
    for result in results {
        let Some(Ok(report)) = result else { continue };
        if !matches!(report.state, State::Complete | State::Partial) {
            continue;
        }
        any = true;
        for finding in &report.findings {
            out.push(DetectionHit {
                engine: detection::name(report.engine).to_owned(),
                rule_id: finding.rule_id.clone(),
                title: finding.title.clone(),
                severity: finding.severity.clone(),
                mitre: finding.mitre.clone(),
                count: finding.count,
                family: yara_family(report.engine, &finding.rule_text),
                author: finding.author.clone(),
                license: finding.license.clone(),
                source: detection::pack_name(report, finding),
                reference: finding.reference(report.engine),
                layer: only_in_layers(&finding.evidence),
            });
        }
    }
    any.then_some(out)
}

/// What the scan of a finished run adds to its digest: the behaviour
/// findings, the process lineage, the files it wrote and, when the scan read
/// the capture, the indicators. `detections` is the engines' matches, when one
/// of them has a result ([`detections`]); `None` keeps what the digest holds.
pub struct Update {
    pub behaviour: Behaviour,
    pub lineage: run_digest::Lineage,
    pub indicators: Option<Vec<IndicatorEntry>>,
    pub files: Vec<run_digest::WrittenFile>,
    pub detections: Option<Vec<DetectionHit>>,
    /// The run's file activity, for the programs it wrote (see
    /// [`crate::written_export`]); kept beside the run with the digest.
    activity: Arc<crate::file_activity::Activity>,
    /// The scan read the whole finished run.
    finished: bool,
    partial: bool,
}

impl Update {
    /// The digest parts of `scan`, with `detections`.
    pub fn of(scan: &ArchiveScan, detections: Option<Vec<DetectionHit>>) -> Self {
        Self {
            behaviour: behaviour(&scan.findings),
            lineage: lineage_index::index(&scan.process, scan.ioc.as_deref()),
            indicators: scan.ioc.as_deref().map(indicators),
            files: scan.written_files.clone(),
            detections,
            activity: scan.file_activity.clone(),
            finished: scan.whole_run,
            partial: scan.partial,
        }
    }

    /// Write them into the digest of the run in `directory` (a synced file).
    pub fn write(self, directory: &Path) -> Result<(), String> {
        // The programs and libraries the run wrote go beside the run for the
        // YARA scan, best effort: without them the scan says it had none.
        if self.finished {
            let _ = crate::written_export::export(directory, &self.activity, self.partial);
        }
        RunDigest::update(directory, |digest| {
            digest.behaviour = Some(self.behaviour);
            digest.lineage = Some(self.lineage);
            digest.files = Some(self.files);
            if self.indicators.is_some() {
                digest.indicators = self.indicators;
            }
            if self.detections.is_some() {
                digest.detections = self.detections;
            }
        })
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, tier: &str, category: &str, attack: &[&str], object: &str) -> Finding {
        Finding {
            key: Default::default(),
            cells: Vec::new(),
            call_id: 1,
            values: vec![
                ("finding.rule", RowValue::Text(rule.into())),
                ("finding.tier", RowValue::Text(tier.into())),
                ("finding.category", RowValue::Text(category.into())),
                (
                    "finding.technique",
                    RowValue::List(attack.iter().map(|id| (*id).to_owned()).collect()),
                ),
                ("finding.count", RowValue::Number(3)),
                ("finding.first_ns", RowValue::Number(9)),
                ("finding.object", RowValue::Text(object.into())),
                ("finding.summary", RowValue::Text(format!("read {object}"))),
                ("process.exe", RowValue::Text("/bin/sh".into())),
            ],
        }
    }

    #[test]
    fn the_behaviour_part_has_the_highest_tier_the_rules_and_the_evasion_checks() {
        let findings = vec![
            finding(
                "persistence.cron",
                "medium",
                "persistence",
                &["T1053.003"],
                "/etc/cron.d/x",
            ),
            finding(
                "evasion.sandbox_probe",
                "high",
                "evasion",
                &["T1497.001"],
                "/sys/class/dmi/id/product_name",
            ),
            finding(
                "evasion.log_clear",
                "low",
                "evasion",
                &["T1070.002"],
                "/var/log/syslog",
            ),
        ];
        let digest = behaviour(&findings);
        assert_eq!(digest.highest, "high");
        assert_eq!(digest.rules.len(), 3);
        assert_eq!(digest.rules[0].attack, ["T1053.003"]);
        assert_eq!(digest.rules[0].count, 3);
        // Only the check is an evasion attempt, not clearing a log.
        assert_eq!(digest.evasion.len(), 1);
        assert_eq!(digest.evasion[0].category, "Virtual machine");
        assert_eq!(digest.evasion[0].object, "/sys/class/dmi/id/product_name");
        assert_eq!(behaviour(&[]).highest, "");
    }

    #[test]
    fn a_yara_rule_names_its_family_in_its_meta() {
        use antinomie_monitor_core::analysis::detection::Engine;
        let rule = "rule miner {\n  meta:\n    description = \"x\"\n    family = \"XMRig\"\n  strings:\n    $a = \"x\"\n  condition: $a\n}";
        assert_eq!(yara_family(Engine::Yara, rule), "XMRig");
        assert_eq!(yara_family(Engine::Ids, rule), "");
        assert_eq!(yara_family(Engine::Yara, "rule a { condition: true }"), "");
    }

    #[test]
    fn a_match_only_in_an_unpacked_layer_is_marked_as_the_payload() {
        use antinomie_monitor_core::analysis::detection::{Evidence, InputKind};
        let bytes = |input| Evidence::Bytes {
            path: "layer-1.bin".into(),
            offset: Some(0),
            address: None,
            report_id: None,
            block: None,
            input,
        };
        assert!(only_in_layers(&[bytes(Some(InputKind::UnpackedLayer))]));
        assert!(!only_in_layers(&[]));
        assert!(!only_in_layers(&[bytes(Some(InputKind::Executable))]));
        assert!(!only_in_layers(&[bytes(None)]));
        assert!(!only_in_layers(&[
            bytes(Some(InputKind::UnpackedLayer)),
            bytes(Some(InputKind::Executable))
        ]));
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;

    #[test]
    fn a_finding_names_its_first_call_and_the_calls_its_detail_cites() {
        let values = vec![
            ("event.id", RowValue::Number(12)),
            (
                "finding.detail",
                RowValue::List(vec![
                    "DMI: product_name [read] → \"Q35\"  (gives it away)  (call 12)".into(),
                    "MAC: address [read] → \"52:54\"  (call 40)".into(),
                    "Occurrences: calls 12, 41, 43, … (9 in all)".into(),
                ]),
            ),
        ];
        assert_eq!(evidence_calls(&values), [12, 40, 41, 43]);
        assert!(evidence_calls(&[]).is_empty());
    }
}
