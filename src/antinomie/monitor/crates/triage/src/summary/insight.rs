// SPDX-License-Identifier: GPL-3.0-only
//! What the Summary's header says about the run from data the app already has:
//! family candidates from the detection matches, behaviour tags from the rules
//! that fired, and the Key findings. Observations with their source, no
//! verdict and no score.
use super::super::{rules, Finding, RowValue};
use std::collections::BTreeSet;

/// Words in a detection name that say a botnet.
const BOTNET_WORDS: &[&str] = &[
    "botnet", "mirai", "gafgyt", "bashlite", "tsunami", "kaiten", "xorddos", "mozi", "hajime",
    "ddos", "satori", "okiru", "masuta",
];

/// Words in a detection name that say a coin miner.
const MINER_WORDS: &[&str] = &["miner", "xmrig", "coinminer", "cryptominer", "kinsing"];

/// What the tags are made from.
#[derive(Default)]
pub struct TagInput<'a> {
    /// `finding.category` and `finding.rule` of each finding of LOW and above.
    pub findings: Vec<(&'a str, &'a str)>,
    /// Titles and families of the detection matches.
    pub names: Vec<String>,
    /// Static analysis found a packer.
    pub packed: bool,
}

/// Rules of the evasion category that are checks for an analyst.
const ANTI_ANALYSIS: &[&str] = &[
    "evasion.sandbox_probe",
    "evasion.probe_then_exit",
    "evasion.traceme",
    "evasion.debugger_check",
    "evasion.container_check",
    "evasion.long_sleep",
    "evasion.dumpable_off",
];

/// Every tag in the order the header shows it.
const TAG_ORDER: &[&str] = &[
    "botnet",
    "miner",
    "downloader",
    "persistence",
    "injection",
    "network-c2",
    "anti-analysis",
    "defense-evasion",
    "privilege-escalation",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "exfiltration",
    "rootkit",
    "impact",
    "packed",
];

/// The behaviour tags the rule categories and tactics that fired, and the
/// names of the detections, give.
pub fn behaviour_tags(input: &TagInput<'_>) -> Vec<&'static str> {
    let mut on: BTreeSet<&'static str> = BTreeSet::new();
    for (category, rule) in &input.findings {
        match *category {
            "persistence" => on.insert("persistence"),
            "injection" => on.insert("injection"),
            "c2" => on.insert("network-c2"),
            "discovery" => on.insert("discovery"),
            "privilege" => on.insert("privilege-escalation"),
            "credential" => on.insert("credential-access"),
            "lateral" => on.insert("lateral-movement"),
            "collection" => on.insert("collection"),
            "exfiltration" => on.insert("exfiltration"),
            "rootkit" => on.insert("rootkit"),
            "impact" => on.insert("impact"),
            "evasion" if ANTI_ANALYSIS.contains(rule) => on.insert("anti-analysis"),
            "evasion" => on.insert("defense-evasion"),
            _ => false,
        };
        match *rule {
            "execution.download_cradle" | "c2.elf_download" => on.insert("downloader"),
            "impact.miner" | "impact.miner_tuning" => on.insert("miner"),
            "evasion.packed_image" => on.insert("packed"),
            _ => false,
        };
    }
    if input.packed {
        on.insert("packed");
    }
    for name in &input.names {
        let lower = name.to_ascii_lowercase();
        if BOTNET_WORDS.iter().any(|word| lower.contains(word)) {
            on.insert("botnet");
        }
        if MINER_WORDS.iter().any(|word| lower.contains(word)) {
            on.insert("miner");
        }
        if lower.contains("downloader") {
            on.insert("downloader");
        }
    }
    TAG_ORDER
        .iter()
        .copied()
        .filter(|tag| on.contains(tag))
        .collect()
}

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

/// A finding's tier, when it names one.
pub fn tier_of(finding: &Finding) -> Option<rules::Tier> {
    rules::Tier::from_tag(text(&finding.values, "finding.tier"))
}

fn hidden(finding: &Finding) -> bool {
    finding
        .values
        .iter()
        .any(|(name, value)| *name == "finding.hidden" && matches!(value, RowValue::Bool(true)))
}

/// What the tags are made from, for the findings of LOW and above.
pub fn tag_findings(findings: &[Finding]) -> Vec<(&str, &str)> {
    findings
        .iter()
        .filter(|finding| {
            !hidden(finding) && tier_of(finding).is_some_and(|t| t != rules::Tier::Info)
        })
        .map(|finding| {
            (
                text(&finding.values, "finding.category"),
                text(&finding.values, "finding.rule"),
            )
        })
        .collect()
}

/// One row of Key findings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    /// Place in the scan's findings.
    pub index: usize,
    pub tier: rules::Tier,
    pub rule: String,
    pub title: String,
    pub target: String,
    pub pid: u32,
    pub cookie: u64,
    pub exe: String,
    pub count: u64,
    pub first_ns: u64,
    /// The description, cut to its first sentence; ends in "\u{2026}" when cut.
    pub why: String,
    /// The whole description when `why` is cut, else empty.
    pub full: String,
}

/// How many findings the Summary lists.
pub const KEY_ROWS: usize = 6;

/// The first words of `text`, cut at a sentence end or `max` characters.
fn short(text: &str, max: usize) -> String {
    let first = text
        .split(". ")
        .next()
        .unwrap_or(text)
        .trim_end_matches('.');
    if first.chars().count() <= max {
        return first.to_owned();
    }
    let cut: String = first.chars().take(max.saturating_sub(1)).collect();
    format!("{}\u{2026}", cut.trim_end())
}

/// The findings of LOW and above that are not hidden, by tier and then by
/// first time: how many there are, and the top `limit`.
pub fn key_findings(findings: &[Finding], limit: usize) -> (usize, Vec<Key>) {
    let mut keys: Vec<Key> = findings
        .iter()
        .enumerate()
        .filter(|(_, finding)| !hidden(finding))
        .filter_map(|(index, finding)| {
            let tier = tier_of(finding).filter(|tier| *tier != rules::Tier::Info)?;
            let values = &finding.values;
            let rule = text(values, "finding.rule").to_owned();
            let description = super::rule_text::rule_description(&rule);
            let whole = if description.is_empty() {
                text(values, "finding.summary").trim().to_owned()
            } else {
                description.trim().to_owned()
            };
            let mut why = short(&whole, 140);
            let cut =
                !why.is_empty() && why.trim_end_matches('\u{2026}') != whole.trim_end_matches('.');
            if cut && !why.ends_with('\u{2026}') {
                why.push('\u{2026}');
            }
            let full = if cut { whole } else { String::new() };
            Some(Key {
                index,
                tier,
                title: super::rule_text::rule_title(&rule),
                rule,
                target: text(values, "finding.object").to_owned(),
                pid: number(values, "process.pid") as u32,
                cookie: number(values, "process.cookie"),
                exe: text(values, "process.exe").to_owned(),
                count: number(values, "finding.count").max(1),
                first_ns: number(values, "finding.first_ns"),
                why,
                full,
            })
        })
        .collect();
    let total = keys.len();
    keys.sort_by_key(|key| (key.tier.index(), key.first_ns, key.index));
    keys.truncate(limit);
    (total, keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_come_from_categories_rules_and_names() {
        let tags = behaviour_tags(&TagInput {
            findings: vec![
                ("persistence", "persistence.cron"),
                ("evasion", "evasion.debugger_check"),
                ("evasion", "evasion.log_clear"),
                ("c2", "c2.elf_download"),
                ("execution", "process.exec"),
            ],
            names: vec!["ET MALWARE Mirai Botnet".into()],
            packed: true,
        });
        assert_eq!(
            tags,
            [
                "botnet",
                "downloader",
                "persistence",
                "network-c2",
                "anti-analysis",
                "defense-evasion",
                "packed"
            ]
        );
        assert!(behaviour_tags(&TagInput::default()).is_empty());
        let miner = behaviour_tags(&TagInput {
            findings: vec![("impact", "impact.miner")],
            ..TagInput::default()
        });
        assert_eq!(miner, ["miner", "impact"]);
    }

    fn finding(rule: &str, tier: &str, ns: u64, hidden: bool) -> Finding {
        Finding {
            key: Default::default(),
            cells: Vec::new(),
            call_id: 0,
            values: vec![
                ("finding.rule", RowValue::Text(rule.into())),
                ("finding.tier", RowValue::Text(tier.into())),
                ("finding.first_ns", RowValue::Number(ns.into())),
                ("finding.hidden", RowValue::Bool(hidden)),
                ("finding.object", RowValue::Text("/tmp/x".into())),
                (
                    "finding.summary",
                    RowValue::Text("Opens /tmp/x. More.".into()),
                ),
                ("process.pid", RowValue::Number(7)),
            ],
        }
    }

    #[test]
    fn key_findings_are_the_top_six_by_tier_then_first_time() {
        let mut all = vec![
            finding("a.low", "low", 1, false),
            finding("b.high_late", "high", 90, false),
            finding("c.info", "info", 0, false),
            finding("d.hidden", "high", 0, true),
            finding("e.med", "medium", 5, false),
            finding("f.high_early", "high", 10, false),
        ];
        for at in 0..6 {
            all.push(finding(&format!("m{at}.med"), "medium", 100 + at, false));
        }
        let (total, keys) = key_findings(&all, KEY_ROWS);
        assert_eq!(total, 10, "info and hidden rows are not counted");
        let order: Vec<_> = keys.iter().map(|k| k.rule.as_str()).collect();
        assert_eq!(
            order,
            [
                "f.high_early",
                "b.high_late",
                "e.med",
                "m0.med",
                "m1.med",
                "m2.med"
            ]
        );
        assert_eq!(
            keys[0].why, "Opens /tmp/x\u{2026}",
            "the summary stands in for a description, cut at its first sentence"
        );
        assert_eq!(
            keys[0].full, "Opens /tmp/x. More.",
            "the whole text for a click"
        );
        assert_eq!(keys[0].target, "/tmp/x");
        assert_eq!(keys[0].count, 1);
    }
}
