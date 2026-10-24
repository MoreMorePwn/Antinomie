// SPDX-License-Identifier: GPL-3.0-only
//! Regex matches in strings: the network, crypto, key, Linux behaviour,
//! attribution and encoded-data patterns that the Strings windows of Static
//! analysis and Core dumps list, each match with its category and type.
//!
//! The patterns are built in (`catalog`) and can be switched off or added to
//! from the rule manager (`config`). A match passes a validator before it is
//! kept (`checks`: a domain must end in a public suffix, an IPv4 address must
//! not be a version number, a Bitcoin address must have its checksum), and
//! base64 and hex text is decoded and scanned again (`encoded`). Everything
//! is bounded: input text, matches kept and decoding depth.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

mod catalog;
mod checks;
mod config;
mod encoded;
mod sources;

pub use config::{
    CUSTOM_MAX_COUNT, Config, CustomPattern, PATTERN_MAX_LEN, builtin_patterns, config_path,
};
pub use sources::{SockAddr, scan_core, scan_report, sockaddrs};

/// Matches kept; the counts keep growing past it.
pub const MATCH_MAX_COUNT: usize = 50_000;
/// Longest string scanned, in characters. Longer text is cut.
pub const TEXT_MAX_LEN: usize = 8192;
/// Longest match kept, in characters.
const MATCH_MAX_LEN: usize = 512;
/// How many encodings deep a decoded text is scanned again.
const DEPTH_MAX: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Network,
    Crypto,
    Keys,
    Behaviour,
    Attribution,
    Encoded,
    /// A pattern added in the rule manager under no built-in category.
    Custom,
}

impl Category {
    pub const ALL: [Self; 7] = [
        Self::Network,
        Self::Crypto,
        Self::Keys,
        Self::Behaviour,
        Self::Attribution,
        Self::Encoded,
        Self::Custom,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Network => "Network",
            Self::Crypto => "Crypto",
            Self::Keys => "Keys",
            Self::Behaviour => "Linux behaviour",
            Self::Attribution => "Attribution",
            Self::Encoded => "Encoded",
            Self::Custom => "Custom",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Crypto => "crypto",
            Self::Keys => "keys",
            Self::Behaviour => "behaviour",
            Self::Attribution => "attribution",
            Self::Encoded => "encoded",
            Self::Custom => "custom",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|category| category.key() == key)
    }
}

/// One regex of the active set.
pub struct Rule {
    pub id: String,
    pub category: Category,
    /// The type shown for its matches ("IPv4", "Bitcoin address").
    pub name: String,
    pub builtin: bool,
    regex: regex::Regex,
    check: checks::Check,
    /// Dropped when a stronger rule matched the same text (a domain inside a
    /// URL is part of the URL).
    weak: bool,
}

/// The patterns a scan uses.
pub struct RuleSet {
    rules: Vec<Rule>,
    /// One pass over a text names the rules worth running.
    prefilter: Option<regex::RegexSet>,
    /// Custom patterns that did not compile, with the reason.
    pub rejected: Vec<(String, String)>,
}

/// Where a scanned text came from.
#[derive(Clone, Debug, Default)]
pub struct Origin {
    /// "Strings", "FLOSS stack", "Core strings".
    pub label: String,
    /// Position of the text's first character: a file offset, or a virtual
    /// address in a core.
    pub position: Option<u64>,
    /// Octets a character takes there (1 for ASCII, 2 for UTF-16LE).
    pub unit: u64,
    /// Where the position is counted: "offset" or "address".
    pub space: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub rule: String,
    pub category: Category,
    /// The type indicator: the rule's name, with what the validator found
    /// ("IPv4 (private)", "URL (https)").
    pub kind: String,
    pub text: String,
    pub origin: String,
    pub position: Option<u64>,
    pub space: &'static str,
    /// The encodings the text was found inside, outermost first.
    pub via: Vec<&'static str>,
    /// What the validator established, when it said anything.
    pub note: String,
    /// The same match found again in other strings.
    pub repeats: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Scan {
    pub matches: Vec<Match>,
    /// Matches per category, kept or not, repeats included.
    pub counts: BTreeMap<Category, u64>,
    /// Matches per type indicator.
    pub kinds: BTreeMap<String, u64>,
    pub strings: u64,
    /// More matches than `MATCH_MAX_COUNT` were found.
    pub truncated: bool,
    /// The scan was stopped before it read every string.
    pub cancelled: bool,
    /// Unique matches by (rule, text, encodings), for the repeats.
    index: HashMap<(String, String, String), usize>,
}

impl Scan {
    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }

    fn add(&mut self, found: Match) {
        *self.counts.entry(found.category).or_default() += 1;
        *self.kinds.entry(found.kind.clone()).or_default() += 1;
        let key = (found.rule.clone(), found.text.clone(), found.via.join(">"));
        if let Some(&slot) = self.index.get(&key) {
            self.matches[slot].repeats += 1;
        } else if self.matches.len() < MATCH_MAX_COUNT {
            self.index.insert(key, self.matches.len());
            self.matches.push(found);
        } else {
            self.truncated = true;
        }
    }
}

impl RuleSet {
    /// The built-in patterns that are not switched off, and the custom ones.
    pub fn build(config: &Config) -> Self {
        let mut rules = Vec::new();
        let mut rejected = Vec::new();
        for pattern in catalog::BUILTIN {
            if config.disabled.iter().any(|id| id == pattern.id) {
                continue;
            }
            match compile(pattern.regex) {
                Ok(regex) => rules.push(Rule {
                    id: pattern.id.into(),
                    category: pattern.category,
                    name: pattern.name.into(),
                    builtin: true,
                    regex,
                    check: pattern.check,
                    weak: pattern.weak,
                }),
                Err(error) => rejected.push((pattern.id.into(), error)),
            }
        }
        for custom in &config.custom {
            if !custom.enabled || config.disabled.contains(&custom.id) {
                continue;
            }
            match compile(&custom.pattern) {
                Ok(regex) => rules.push(Rule {
                    id: custom.id.clone(),
                    category: custom.category,
                    name: custom.name.clone(),
                    builtin: false,
                    regex,
                    check: checks::Check::None,
                    weak: false,
                }),
                Err(error) => rejected.push((custom.id.clone(), error)),
            }
        }
        let prefilter = regex::RegexSetBuilder::new(rules.iter().map(|rule| rule.regex.as_str()))
            .size_limit(64 << 20)
            .build()
            .ok();
        Self {
            rules,
            prefilter,
            rejected,
        }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Scan `text`, found at `origin`, and add what matches to `scan`.
    pub fn scan_text(&self, text: &str, origin: &Origin, scan: &mut Scan) {
        scan.strings += 1;
        self.scan_depth(text, origin, &mut Vec::new(), scan);
    }

    fn scan_depth(
        &self,
        text: &str,
        origin: &Origin,
        via: &mut Vec<&'static str>,
        scan: &mut Scan,
    ) {
        let text = clip(text, TEXT_MAX_LEN);
        let wanted: Vec<usize> = match &self.prefilter {
            Some(prefilter) => prefilter.matches(text).into_iter().collect(),
            None => (0..self.rules.len()).collect(),
        };
        // (start, end) of what strong rules matched in this text.
        let mut covered: Vec<(usize, usize)> = Vec::new();
        let mut weak: Vec<(usize, usize, usize, checks::Verdict)> = Vec::new();
        for index in wanted {
            let rule = &self.rules[index];
            for found in rule.regex.find_iter(text) {
                if matches!(rule.check, checks::Check::Base64 | checks::Check::Hex) {
                    self.decode(rule, found.as_str(), origin, via, scan);
                    continue;
                }
                let Some(verdict) = checks::run(rule.check, text, found.range()) else {
                    continue;
                };
                let (start, end) = (
                    found.start() + verdict.trim_start,
                    found.end() - verdict.trim_end,
                );
                if start >= end {
                    continue;
                }
                if rule.weak {
                    weak.push((index, start, end, verdict));
                } else {
                    covered.push((start, end));
                    self.record(rule, text, (start, end), &verdict, origin, via, scan);
                }
            }
        }
        for (index, start, end, verdict) in weak {
            if covered.iter().any(|(a, b)| *a <= start && end <= *b) {
                continue;
            }
            self.record(
                &self.rules[index],
                text,
                (start, end),
                &verdict,
                origin,
                via,
                scan,
            );
        }
    }

    /// A base64 or hex run: keep it when it decodes to something, and scan
    /// the decoded text again.
    fn decode(
        &self,
        rule: &Rule,
        run: &str,
        origin: &Origin,
        via: &mut Vec<&'static str>,
        scan: &mut Scan,
    ) {
        if via.len() >= DEPTH_MAX {
            return;
        }
        let Some(decoded) = encoded::decode(rule.check, run) else {
            return;
        };
        scan.add(Match {
            rule: rule.id.clone(),
            category: rule.category,
            kind: format!("{} ({})", rule.name, decoded.what),
            text: clip(run, MATCH_MAX_LEN).to_owned(),
            origin: origin.label.clone(),
            position: origin.position,
            space: origin.space,
            via: via.clone(),
            note: decoded.preview.clone(),
            repeats: 0,
        });
        if let Some(inner) = &decoded.text {
            via.push(decoded.how);
            self.scan_depth(inner, origin, via, scan);
            via.pop();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        rule: &Rule,
        text: &str,
        (start, end): (usize, usize),
        verdict: &checks::Verdict,
        origin: &Origin,
        via: &[&'static str],
        scan: &mut Scan,
    ) {
        let position = origin.position.map(|base| {
            let unit = origin.unit.max(1);
            base + text[..start].chars().count() as u64 * unit
        });
        let kind = match &verdict.detail {
            Some(detail) => format!("{} ({detail})", rule.name),
            None => rule.name.clone(),
        };
        scan.add(Match {
            rule: rule.id.clone(),
            category: rule.category,
            kind,
            text: clip(&text[start..end], MATCH_MAX_LEN).to_owned(),
            origin: origin.label.clone(),
            position,
            space: origin.space,
            via: via.to_vec(),
            note: verdict.note.clone(),
            repeats: 0,
        });
    }
}

fn compile(pattern: &str) -> Result<regex::Regex, String> {
    regex::RegexBuilder::new(pattern)
        .size_limit(8 << 20)
        .dfa_size_limit(16 << 20)
        .nest_limit(64)
        .build()
        .map_err(|error| {
            let text = error.to_string();
            text.lines().last().unwrap_or("invalid pattern").to_owned()
        })
}

/// The first `max` characters of `text`.
fn clip(text: &str, max: usize) -> &str {
    match text.char_indices().nth(max) {
        Some((end, _)) => &text[..end],
        None => text,
    }
}

#[cfg(test)]
mod tests;
