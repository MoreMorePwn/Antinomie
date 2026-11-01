// SPDX-License-Identifier: GPL-3.0-only
//! The malware families a run's detections name: a YARA rule's `family`
//! metadata and the family in an IDS signature's message ("ET MALWARE Kaiji
//! Variant Activity"). Each family is listed with its source, so the summary
//! says who named it. A family is a name someone's rule gave, not a verdict.
use antinomie_monitor_core::run_digest::DetectionHit;
use std::collections::BTreeMap;

/// Words that open a signature message and name no family.
const GENERIC: &[&str] = &[
    "possible",
    "suspicious",
    "generic",
    "malicious",
    "observed",
    "inbound",
    "outbound",
    "known",
    "potential",
    "likely",
    "unknown",
    "malware",
    "trojan",
    "backdoor",
    "botnet",
    "cnc",
    "c2",
    "ddos",
    "linux",
    "win32",
    "win64",
    "win",
    "elf",
    "http",
    "dns",
    "tls",
    "ssl",
    "tcp",
    "udp",
    "ssh",
    "user-agent",
    "request",
    "response",
    "executable",
    "download",
    "domain",
    "ip",
    "dropper",
    "loader",
    "stealer",
    "ransomware",
    "miner",
    "coinminer",
    "exploit",
    "scan",
    "attempted",
    "command",
    "multiple",
    "tor",
    "bot",
    "trojan.linux",
];

/// Names a rule pack spells in several ways.
const ALIASES: &[(&str, &str)] = &[
    ("xor", "XorDDoS"),
    ("xorddos", "XorDDoS"),
    ("gafgyt", "Gafgyt"),
    ("bashlite", "Gafgyt"),
    ("mirai", "Mirai"),
    ("kaiji", "Kaiji"),
    ("bpfdoor", "BPFDoor"),
    ("redtail", "RedTail"),
    ("p2pinfect", "P2PInfect"),
];

/// The family an IDS message names, when it names one.
pub(super) fn ids_family(message: &str) -> Option<String> {
    let mut rest = message.trim();
    // The ruleset's class: "ET MALWARE", "ETPRO TROJAN", "ET CNC".
    for prefix in ["ETPRO ", "ET "] {
        if let Some(after) = rest.strip_prefix(prefix) {
            rest = after;
            break;
        }
    }
    let after_class = ["MALWARE ", "TROJAN ", "CNC ", "BOTCC ", "EXPLOIT_KIT "]
        .iter()
        .find_map(|class| rest.strip_prefix(class))?;
    rest = after_class.trim_start();
    // "Linux/Kaiji ..." and "Win32/Foo ..." name the platform first.
    if let Some((platform, tail)) = rest.split_once('/') {
        if !platform.contains(' ') {
            rest = tail;
        }
    }
    let word = rest.split_whitespace().next()?;
    let word = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    // "Xorddos.F" is the family Xorddos, variant F; "DDoS.XOR" is a DDoS family XOR.
    let mut parts = word.split('.');
    let first = parts.next()?;
    let name = if GENERIC.contains(&first.to_ascii_lowercase().as_str()) {
        parts.next().filter(|second| second.len() >= 3)?
    } else {
        first
    };
    let lower = name.to_ascii_lowercase();
    if name.len() < 3 || GENERIC.contains(&lower.as_str()) {
        return None;
    }
    if let Some((_, alias)) = ALIASES.iter().find(|(key, _)| *key == lower) {
        return Some((*alias).to_owned());
    }
    let mut chars = name.chars();
    let first = chars.next()?;
    Some(first.to_uppercase().chain(chars).collect())
}

/// Every family the detections name with where each came from, by family.
/// A source reads "IDS: ET MALWARE Kaiji Variant Activity (15)" or "YARA: rule_id".
pub(super) fn from_detections(hits: &[DetectionHit]) -> Vec<(String, Vec<String>)> {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for hit in hits {
        let (family, source) = match hit.engine.as_str() {
            "YARA" if !hit.family.trim().is_empty() => (
                hit.family.trim().to_owned(),
                format!("YARA: {}", hit.rule_id),
            ),
            "IDS" => {
                let Some(family) = ids_family(&hit.title) else {
                    continue;
                };
                (family, format!("IDS: {} ({})", hit.title, hit.count))
            }
            _ => continue,
        };
        let sources = found.entry(family).or_default();
        if sources.len() < 5 && !sources.contains(&source) {
            sources.push(source);
        }
    }
    found.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(engine: &str, rule_id: &str, title: &str, family: &str, count: u64) -> DetectionHit {
        DetectionHit {
            engine: engine.into(),
            rule_id: rule_id.into(),
            title: title.into(),
            family: family.into(),
            count,
            ..DetectionHit::default()
        }
    }

    #[test]
    fn signature_messages_name_their_family() {
        for (message, family) in [
            ("ET MALWARE Kaiji Variant Activity", Some("Kaiji")),
            ("ET MALWARE Xorddos.F Checkin", Some("XorDDoS")),
            ("ET MALWARE DDoS.XOR Checkin", Some("XorDDoS")),
            ("ET MALWARE Linux/Mirai Variant CnC Activity", Some("Mirai")),
            ("ETPRO TROJAN Gafgyt Checkin", Some("Gafgyt")),
            ("ET MALWARE Possible Linux Backdoor Beacon", None),
            ("ET INFO Observed DNS Query", None),
            ("ET POLICY Outbound NTP", None),
            ("", None),
        ] {
            assert_eq!(ids_family(message).as_deref(), family, "{message}");
        }
    }

    #[test]
    fn families_come_with_their_sources_and_other_engines_name_none() {
        let hits = [
            hit(
                "IDS",
                "2038000",
                "ET MALWARE Kaiji Variant Activity",
                "",
                15,
            ),
            hit(
                "IDS",
                "2038001",
                "ET MALWARE Kaiji Variant Activity",
                "",
                15,
            ),
            hit("YARA", "Linux_Trojan_Mirai", "Mirai", "Mirai", 1),
            hit("YARA", "generic_elf", "ELF", "", 1),
            hit("Sigma", "s1", "ET MALWARE Foo Bar", "Foo", 1),
        ];
        let families = from_detections(&hits);
        let names: Vec<_> = families.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["Kaiji", "Mirai"]);
        assert_eq!(
            families[0].1,
            ["IDS: ET MALWARE Kaiji Variant Activity (15)"]
        );
        assert_eq!(families[1].1, ["YARA: Linux_Trojan_Mirai"]);
    }
}
