// SPDX-License-Identifier: GPL-3.0-only
//! The run's Triage digest: what the scan of a finished run found, written
//! beside the run so the sample window can add up many runs without reading
//! their recordings. See `antinomie_monitor_core::run_digest`.
use super::*;
use antinomie_monitor_core::{
    analysis::detection::State,
    ioc::verdict::{OnlineResults, Outcome},
    run_digest::{
        self, Behaviour, BehaviourHit, DetectionHit, EvasionCheck, IndicatorEntry, RunDigest,
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
pub(super) fn behaviour(findings: &[Finding]) -> Behaviour {
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
            });
        }
    }
    if let Some(tier) = rules::Tier::ALL.get(best) {
        out.highest = tier.tag().to_owned();
    }
    out
}

/// The indicators with the stored datasets' answer, no false-positive list
/// and no online answers (those are the person's, per run).
fn indicators(ioc: &ioc_scan::IocScan) -> Vec<IndicatorEntry> {
    let verdicts = ioc_scan::verdicts(ioc, &[], &OnlineResults::default());
    ioc.indicators
        .iter()
        .zip(verdicts)
        .map(|(indicator, verdict)| IndicatorEntry {
            ty: indicator.ty.id().to_owned(),
            value: indicator.value.clone(),
            matched: verdict.outcome == Outcome::Matched,
        })
        .collect()
}

/// The family a YARA rule names in its `meta` (`family`, `malware_family` or
/// `malware`); empty for the other engines and for a rule that names none.
fn yara_family(engine: antinomie_monitor_core::analysis::detection::Engine, rule: &str) -> String {
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

/// The matches of the engines whose reports are complete.
fn detections(
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
            });
        }
    }
    any.then_some(out)
}

impl TriageView {
    /// Write the digest of the run on screen when its scan of a finished run
    /// changed. Cheap while nothing changed: one fingerprint comparison.
    pub(super) fn digest_tick(&mut self) {
        if !self.scan_began_finished || self.scan_rx.is_some() {
            return;
        }
        let (Some(directory), Some(scan)) = (self.details_directory.clone(), self.scan.as_ref())
        else {
            return;
        };
        let fingerprint = format!(
            "{}|{}|{}|{:?}",
            directory.display(),
            scan.stamp,
            scan.findings.len(),
            self.detection
                .results
                .iter()
                .map(|result| match result {
                    Some(Ok(report)) => (report.findings.len(), format!("{:?}", report.state)),
                    _ => (0, String::new()),
                })
                .collect::<Vec<_>>()
        );
        if self.digested.as_deref() == Some(fingerprint.as_str()) {
            return;
        }
        self.digested = Some(fingerprint);
        let behaviour = behaviour(&scan.findings);
        let lineage = lineage_index::index(&scan.process, scan.ioc.as_deref());
        let indicators = scan.ioc.as_deref().map(indicators);
        let detections = detections(&self.detection.results);
        // Off the UI thread: the write is a synced file.
        let _ = std::thread::Builder::new()
            .name("triage-digest".into())
            .spawn(move || {
                let _ = RunDigest::update(&directory, |digest| {
                    digest.behaviour = Some(behaviour);
                    digest.lineage = Some(lineage);
                    if indicators.is_some() {
                        digest.indicators = indicators;
                    }
                    if detections.is_some() {
                        digest.detections = detections;
                    }
                });
            });
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
}
