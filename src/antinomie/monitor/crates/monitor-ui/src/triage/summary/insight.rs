// SPDX-License-Identifier: GPL-3.0-only
//! What the Summary's header says about the run from data the app already has:
//! family candidates from the detection matches, behaviour tags from the rules
//! that fired, and the Key findings. Observations with their source, no
//! verdict and no score.
use super::super::{rules, Finding, RowValue};
use antinomie_monitor_core::run_digest::DetectionHit;
use std::collections::BTreeSet;

/// A malware family a detection names, with where it said so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Candidate {
    pub name: String,
    pub source: String,
}

/// Words that name a kind of rule, a platform or a date, not a family.
const NOT_FAMILY: &[&str] = &[
    "mal",
    "malware",
    "elf",
    "linux",
    "lin",
    "unix",
    "win",
    "windows",
    "apt",
    "hktl",
    "susp",
    "suspicious",
    "trojan",
    "backdoor",
    "rat",
    "botnet",
    "exploit",
    "webshell",
    "loader",
    "dropper",
    "generic",
    "crime",
    "crimeware",
    "ransom",
    "ransomware",
    "miner",
    "cryptominer",
    "coinminer",
    "tool",
    "pua",
    "x64",
    "x86",
    "arm",
    "arm64",
    "mips",
    "packer",
    "upx",
    "shell",
    "script",
    "file",
    "ioc",
    "ttp",
    "cve",
    "rule",
    "hacktool",
    "stealer",
    "worm",
    "virus",
    "agent",
    "family",
    "bot",
    "downloader",
    "implant",
    "strings",
    "string",
    "payload",
    "obfuscated",
    "encoded",
    "code",
    "command",
    "config",
    "sample",
    "general",
    "common",
    "possible",
    "potential",
    "detect",
    "detection",
    "indicator",
    "indicators",
    "keyword",
    "keywords",
    "hash",
    "hashes",
    "anomaly",
    "behavior",
    "behaviour",
    "encrypted",
    "golang",
    "go",
    "rust",
    "python",
    "java",
    "php",
    "pe",
    "dll",
    "exe",
    "base64",
    "heur",
    "hunt",
    "hunting",
    "test",
];

/// Families that Linux IDS signature names carry as a word.
const IDS_FAMILIES: &[&str] = &[
    "mirai",
    "gafgyt",
    "bashlite",
    "tsunami",
    "kaiten",
    "xorddos",
    "mozi",
    "hajime",
    "qbot",
    "kinsing",
    "xmrig",
    "rekoobe",
    "dofloo",
    "lightaidra",
    "vpnfilter",
    "satori",
    "okiru",
    "masuta",
    "hide and seek",
    "ebury",
    "bpfdoor",
    "tsunami",
];

/// Words in a detection name that say a botnet.
const BOTNET_WORDS: &[&str] = &[
    "botnet", "mirai", "gafgyt", "bashlite", "tsunami", "kaiten", "xorddos", "mozi", "hajime",
    "ddos", "satori", "okiru", "masuta",
];

/// Words in a detection name that say a coin miner.
const MINER_WORDS: &[&str] = &["miner", "xmrig", "coinminer", "cryptominer", "kinsing"];

fn pretty(word: &str) -> String {
    if word.chars().any(char::is_uppercase) {
        return word.to_owned();
    }
    let mut chars = word.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// The family a Malpedia-style value names: `elf.mirai` is Mirai.
fn meta_family(value: &str) -> String {
    pretty(value.rsplit('.').next().unwrap_or(value).trim())
}

/// The family a rule name of a curated pack carries: `MAL_ELF_Mirai_Jan2020`,
/// `elf_mirai` and `Linux_Trojan_Gafgyt_ba2c1b10` all name one, a rule called
/// `Suspicious_Strings` names none.
fn family_in_rule_name(rule: &str) -> Option<String> {
    for token in rule.split(['_', '-', ' ', '.']) {
        let lower = token.to_ascii_lowercase();
        if lower.is_empty()
            || NOT_FAMILY.contains(&lower.as_str())
            || lower.chars().any(|c| c.is_ascii_digit())
        {
            continue;
        }
        return (lower.len() >= 3).then(|| pretty(token));
    }
    None
}

fn curated_pack(source: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    ["malpedia", "forge", "yarahub"]
        .iter()
        .any(|pack| lower.contains(pack))
}

/// The families the run's detection matches name, each with its source: the
/// YARA `family` metadata (Malpedia's included) first, then the rule names of
/// the Malpedia, YARA-Forge and YARAhub packs, then IDS signature names.
pub(super) fn family_candidates(hits: &[DetectionHit]) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut add = |name: String, source: String| {
        if !name.is_empty() && seen.insert(name.to_ascii_lowercase()) {
            out.push(Candidate { name, source });
        }
    };
    let yara = |hit: &&DetectionHit| hit.engine.eq_ignore_ascii_case("yara");
    for hit in hits.iter().filter(yara) {
        if !hit.family.is_empty() {
            add(
                meta_family(&hit.family),
                format!("YARA · {} meta {}", hit.source, hit.family),
            );
        }
    }
    for hit in hits.iter().filter(yara) {
        if curated_pack(&hit.source) {
            if let Some(name) = family_in_rule_name(&hit.rule_id) {
                add(name, format!("YARA · {} rule {}", hit.source, hit.rule_id));
            }
        }
    }
    for hit in hits
        .iter()
        .filter(|hit| hit.engine.eq_ignore_ascii_case("ids"))
    {
        let title = hit.title.to_ascii_lowercase();
        if let Some(word) = IDS_FAMILIES.iter().find(|family| title.contains(**family)) {
            add(pretty(word), format!("IDS · {}", hit.title));
        }
    }
    out
}

/// What the tags are made from.
#[derive(Default)]
pub(super) struct TagInput<'a> {
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
pub(super) fn behaviour_tags(input: &TagInput<'_>) -> Vec<&'static str> {
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
pub(super) fn tier_of(finding: &Finding) -> Option<rules::Tier> {
    rules::Tier::from_tag(text(&finding.values, "finding.tier"))
}

fn hidden(finding: &Finding) -> bool {
    finding
        .values
        .iter()
        .any(|(name, value)| *name == "finding.hidden" && matches!(value, RowValue::Bool(true)))
}

/// What the tags are made from, for the findings of LOW and above.
pub(super) fn tag_findings(findings: &[Finding]) -> Vec<(&str, &str)> {
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
pub(super) struct Key {
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
    pub why: String,
}

/// How many findings the Summary lists.
pub(super) const KEY_ROWS: usize = 6;

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
pub(super) fn key_findings(findings: &[Finding], limit: usize) -> (usize, Vec<Key>) {
    let mut keys: Vec<Key> = findings
        .iter()
        .enumerate()
        .filter(|(_, finding)| !hidden(finding))
        .filter_map(|(index, finding)| {
            let tier = tier_of(finding).filter(|tier| *tier != rules::Tier::Info)?;
            let values = &finding.values;
            let rule = text(values, "finding.rule").to_owned();
            let description = super::rule_text::rule_description(&rule);
            let why = if description.is_empty() {
                short(text(values, "finding.summary"), 90)
            } else {
                short(&description, 90)
            };
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

    fn hit(engine: &str, rule: &str, title: &str, family: &str, source: &str) -> DetectionHit {
        DetectionHit {
            engine: engine.into(),
            rule_id: rule.into(),
            title: title.into(),
            family: family.into(),
            source: source.into(),
            ..DetectionHit::default()
        }
    }

    #[test]
    fn yara_meta_names_a_family_with_its_source() {
        let found = family_candidates(&[hit("YARA", "r1", "r1", "elf.mirai", "Malpedia")]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "Mirai");
        assert!(found[0].source.contains("YARA") && found[0].source.contains("elf.mirai"));
    }

    #[test]
    fn curated_pack_rule_names_give_candidates_and_others_do_not() {
        let found = family_candidates(&[
            hit("YARA", "MAL_ELF_Mirai_Jan2020", "", "", "YARA-Forge core"),
            hit("YARA", "elf_gafgyt", "", "", "Malpedia"),
            hit("YARA", "Suspicious_Strings", "", "", "YARAhub"),
            hit("YARA", "Linux_Trojan_Xyzzy_ba2c1b10", "", "", "Elastic"),
        ]);
        let names: Vec<_> = found.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["Mirai", "Gafgyt"], "{found:?}");
    }

    #[test]
    fn ids_names_give_a_family_once_whatever_the_case() {
        let found = family_candidates(&[
            hit("IDS", "1", "ET MALWARE Gafgyt Botnet CnC Checkin", "", ""),
            hit("YARA", "r", "", "gafgyt", "x"),
            hit("IDS", "2", "ET INFO Something else", "", ""),
        ]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "Gafgyt");
        assert!(found[0].source.starts_with("YARA"), "meta wins: {found:?}");
        assert!(family_candidates(&[]).is_empty());
    }

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
            keys[0].why, "Opens /tmp/x",
            "the summary stands in for a description"
        );
        assert_eq!(keys[0].target, "/tmp/x");
        assert_eq!(keys[0].count, 1);
    }
}
