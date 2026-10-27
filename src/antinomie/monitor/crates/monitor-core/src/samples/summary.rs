// SPDX-License-Identifier: GPL-3.0-only
//! What the sample window's Summary draws from a static report's regex scan:
//! the interesting strings and the regex matches, each longest first.
//!
//! The scan itself is `strings_regex`; this only chooses and orders rows, so
//! the choice is the same wherever the Summary is drawn and is testable
//! without a window.
use crate::strings_regex::{Category, Match, Scan};

/// One row of Interesting strings or Regex matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringRow {
    pub category: Category,
    /// The type indicator ("URL (https)", "IPv4").
    pub kind: String,
    /// The text as found.
    pub text: String,
    /// The text as shown: an IPv4 address has its last dot bracketed.
    pub shown: String,
    /// Strings, FLOSS or a layer, with the offset: "Strings · 0x1f00".
    pub found_in: String,
    /// How many times the same match was found.
    pub seen: u64,
}

/// A match is interesting when it is a URL, domain, address, key or path:
/// the network and key categories, and any attribution or behaviour match
/// whose type says it is a path.
fn interesting(found: &Match) -> bool {
    matches!(found.category, Category::Network | Category::Keys)
        || found.kind.to_ascii_lowercase().contains("path")
}

/// `text` with the last dot of an IPv4 address in brackets, so a copy of it
/// is not a live address. Anything else is as found.
pub fn defang(kind: &str, text: &str) -> String {
    if kind.starts_with("IPv4")
        && !text.contains("[.]")
        && let Some(at) = text.rfind('.')
    {
        return format!("{}[.]{}", &text[..at], &text[at + 1..]);
    }
    text.to_owned()
}

fn row(found: &Match) -> StringRow {
    let at = match found.position {
        Some(position) => format!("{} · 0x{position:04x}", found.origin),
        None => found.origin.clone(),
    };
    StringRow {
        category: found.category,
        kind: found.kind.clone(),
        text: found.text.clone(),
        shown: defang(&found.kind, &found.text),
        found_in: at,
        seen: found.repeats + 1,
    }
}

/// Longest text first, then alphabetical, so the order never depends on how
/// the scan happened to find them.
fn longest_first(rows: &mut [StringRow]) {
    rows.sort_by(|a, b| {
        b.text
            .chars()
            .count()
            .cmp(&a.text.chars().count())
            .then_with(|| a.text.cmp(&b.text))
    });
}

/// Every interesting string of the scan, longest first.
pub fn interesting_strings(scan: &Scan) -> Vec<StringRow> {
    let mut rows: Vec<StringRow> = scan
        .matches
        .iter()
        .filter(|found| interesting(found))
        .map(row)
        .collect();
    longest_first(&mut rows);
    rows
}

/// Every regex match of the scan, longest first.
pub fn regex_matches(scan: &Scan) -> Vec<StringRow> {
    let mut rows: Vec<StringRow> = scan.matches.iter().map(row).collect();
    longest_first(&mut rows);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(category: Category, kind: &str, text: &str, position: Option<u64>) -> Match {
        Match {
            rule: String::new(),
            category,
            kind: kind.into(),
            text: text.into(),
            origin: "Strings".into(),
            position,
            space: "offset",
            via: Vec::new(),
            note: String::new(),
            repeats: 0,
        }
    }

    #[allow(clippy::field_reassign_with_default)]
    fn scan() -> Scan {
        let mut scan = Scan::default();
        scan.matches = vec![
            found(Category::Network, "IPv4", "10.0.0.7", Some(0x40)),
            found(
                Category::Network,
                "URL (http)",
                "http://example.test/a/long/path",
                Some(0x10),
            ),
            found(
                Category::Behaviour,
                "Persistence path",
                "/etc/cron.d/x",
                None,
            ),
            found(
                Category::Behaviour,
                "Reverse shell",
                "bash -i >& /dev/tcp",
                None,
            ),
            found(
                Category::Crypto,
                "Bitcoin address",
                "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
                None,
            ),
        ];
        scan
    }

    #[test]
    fn interesting_strings_are_urls_addresses_keys_and_paths_longest_first() {
        let rows = interesting_strings(&scan());
        let texts: Vec<&str> = rows.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "http://example.test/a/long/path",
                "/etc/cron.d/x",
                "10.0.0.7"
            ]
        );
    }

    #[test]
    fn regex_matches_keep_every_category_longest_first() {
        let rows = regex_matches(&scan());
        assert_eq!(rows.len(), 5);
        assert!(
            rows.windows(2)
                .all(|pair| { pair[0].text.chars().count() >= pair[1].text.chars().count() })
        );
    }

    #[test]
    fn an_ip_is_defanged_and_the_offset_is_shown() {
        let rows = interesting_strings(&scan());
        let ip = rows.iter().find(|row| row.kind == "IPv4").unwrap();
        assert_eq!(ip.shown, "10.0.0[.]7");
        assert_eq!(ip.text, "10.0.0.7");
        assert_eq!(ip.found_in, "Strings · 0x0040");
        assert_eq!(ip.seen, 1);
        assert_eq!(defang("IPv4", "10.0.0[.]7"), "10.0.0[.]7");
        assert_eq!(defang("URL (http)", "http://a.b/c"), "http://a.b/c");
    }
}
