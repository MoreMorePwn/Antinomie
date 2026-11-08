// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The anchor ids of a report's entries. The same id names a row in the HTML
//! (`<td id>`), the PDF (a named destination), the Markdown (`<a id>`) and the
//! JSON (`id` and the `*_ref` fields), and is stable across exports of one
//! run: it is made from what the row is about, not from its position (except
//! for findings and indicators, which are numbered in the report's order).
use super::page::slug;

/// A process: `proc-<pid>`, `proc-<pid>-<n>` for the n-th process that had
/// the same pid (pid reuse).
pub fn process(pid: u32, nth: usize) -> String {
    if nth <= 1 {
        format!("proc-{pid}")
    } else {
        format!("proc-{pid}-{nth}")
    }
}

/// A file by its guest path: `file-<12 hex digits of FNV-1a 64>`. By path, not
/// by content: one hash can sit at 44 paths, and an id names one row.
pub fn file(path: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in path.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("file-{:012x}", hash >> 16)
}

/// An endpoint `address:port`: `ep-198.18.0.1-20`, `ep-2001-db8--1-443`.
pub fn endpoint(text: &str) -> String {
    format!("ep-{}", slug(text))
}

/// A domain name: `dom-mircd.xiao.my.id`.
pub fn domain(name: &str) -> String {
    format!("dom-{}", slug(&name.to_ascii_lowercase()))
}

/// A behaviour rule (on its first finding): `rule-c2.bpf_backdoor`.
pub fn rule(id: &str) -> String {
    format!("rule-{}", slug(id))
}

/// The n-th finding (from 1) of the Suspicious activity table.
pub fn finding(n: usize) -> String {
    format!("finding-{n}")
}

/// A detection engine's rule: `det-yara-Linux_Trojan_BPFDoor_f690fe3b`.
pub fn detection(engine: &str, rule: &str) -> String {
    format!(
        "det-{}-{}",
        slug(&engine.to_ascii_lowercase()),
        slug(super::layout::plain_rule(rule))
    )
}

/// An ATT&CK technique: `attack-T1205.002`.
pub fn attack(technique: &str) -> String {
    format!("attack-{}", slug(technique))
}

/// The n-th indicator (from 1) of the Indicators table.
pub fn indicator(n: usize) -> String {
    format!("ioc-{n}")
}

/// The finding number of `finding-<n>`.
pub fn finding_number(id: &str) -> Option<usize> {
    id.strip_prefix("finding-")?.parse().ok()
}

/// The ATT&CK ids at the start of a cell's items: `T1095 Non-Application
/// Layer Protocol +1` and `T1205.002, T1059` both name techniques.
pub fn techniques_in(text: &str) -> Vec<String> {
    text.split([',', ' ', ';'])
        .map(|word| word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.'))
        .filter(|word| {
            let digits = word.strip_prefix('T').unwrap_or("");
            let (main, sub) = digits.split_once('.').unwrap_or((digits, ""));
            main.len() == 4
                && main.bytes().all(|b| b.is_ascii_digit())
                && sub.bytes().all(|b| b.is_ascii_digit())
                && (sub.is_empty() || sub.len() == 3)
        })
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_follow_the_scheme() {
        assert_eq!(process(1352, 1), "proc-1352");
        assert_eq!(process(1352, 2), "proc-1352-2");
        assert_eq!(endpoint("198.18.0.1:20"), "ep-198.18.0.1-20");
        assert_eq!(domain("Mircd.Xiao.my.id"), "dom-mircd.xiao.my.id");
        assert_eq!(rule("c2.bpf_backdoor"), "rule-c2.bpf_backdoor");
        assert_eq!(
            detection("YARA", "s1919::Linux_Trojan_Tsunami_30c039e2"),
            "det-yara-Linux_Trojan_Tsunami_30c039e2"
        );
        assert_eq!(attack("T1205.002"), "attack-T1205.002");
        assert_eq!(finding(3), "finding-3");
        assert_eq!(finding_number("finding-12"), Some(12));
        let a = file("/etc/shadow");
        assert!(a.starts_with("file-") && a.len() == 17, "{a}");
        assert_ne!(a, file("/etc/passwd"));
        assert_eq!(a, file("/etc/shadow"), "stable");
    }

    #[test]
    fn technique_ids_are_read_from_a_cell() {
        assert_eq!(
            techniques_in("T1095 Non-Application Layer Protocol +1"),
            ["T1095"]
        );
        assert_eq!(techniques_in("T1205.002, T1059"), ["T1205.002", "T1059"]);
        assert!(techniques_in("Tor T12 T12345").is_empty());
    }
}
