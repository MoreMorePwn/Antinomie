// SPDX-License-Identifier: MIT
//! Rule matching with the built-in YARA-X engine and the bundled rule sets.
use super::*;
use std::time::Duration;

const ANTINOMIE: &str = include_str!("../../assets/rules/antinomie.yar");
const COMMUNITY: &str = include_str!("../../assets/rules/yara-forge-core.yar");
pub(super) const COMMUNITY_RELEASE: &str = "YARA-Forge core 20261004";
const ENGINE: &str = "YARA-X 1.21";

fn count_rules(source: &str) -> usize {
    source
        .lines()
        .filter(|line| {
            let line = line
                .trim_start_matches("private ")
                .trim_start_matches("global ");
            line.starts_with("rule ")
        })
        .count()
}

/// Compile the bundled rule sets; each lives in its own namespace.
pub(super) fn compile() -> Result<yara_x::Rules, String> {
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    compiler.new_namespace("antinomie");
    compiler
        .add_source(ANTINOMIE)
        .map_err(|e| format!("Antinomie rules: {e}"))?;
    compiler.new_namespace("community");
    compiler
        .add_source(COMMUNITY)
        .map_err(|e| format!("community rules: {e}"))?;
    Ok(compiler.build())
}

fn meta_text(value: &yara_x::MetaValue) -> Option<String> {
    match value {
        yara_x::MetaValue::String(text) => Some((*text).to_owned()),
        yara_x::MetaValue::Integer(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Printable form of matched bytes: text when printable, hex otherwise.
fn matched_text(data: &[u8]) -> String {
    let data = &data[..data.len().min(48)];
    if data.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        format!("\"{}\"", String::from_utf8_lossy(data))
    } else {
        data.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub(super) fn scan(section: &mut AnalysisSection, specimen: &[u8]) {
    let rules = match compile() {
        Ok(rules) => rules,
        Err(error) => {
            section.state = AnalysisSectionState::Unavailable;
            section.summary = format!("bundled rules failed to compile: {error}");
            return;
        }
    };
    let (own, community) = (count_rules(ANTINOMIE), count_rules(COMMUNITY));
    section.tools = vec![
        ENGINE.into(),
        format!("Antinomie rules ({own})"),
        format!("{COMMUNITY_RELEASE} ({community} redistributable rules)"),
    ];
    let mut scanner = yara_x::Scanner::new(&rules);
    scanner.set_timeout(Duration::from_secs(60));
    let results = match scanner.scan(specimen) {
        Ok(results) => results,
        Err(error) => {
            section.state = AnalysisSectionState::Unavailable;
            section.summary = format!("rule scan failed: {error}");
            return;
        }
    };
    let mut matched = 0usize;
    for rule in results.matching_rules() {
        matched += 1;
        let metadata: Vec<(String, String)> = rule
            .metadata()
            .filter_map(|(name, value)| meta_text(&value).map(|v| (name.to_owned(), v)))
            .collect();
        let meta = |key: &str| {
            metadata
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
        };
        let mut first = None;
        let mut evidence = Vec::new();
        for pattern in rule.patterns() {
            for found in pattern.matches().take(3) {
                let range = found.range();
                first.get_or_insert(range.clone());
                if evidence.len() < 8 {
                    evidence.push(format!(
                        "{} at 0x{:x}: {}",
                        pattern.identifier(),
                        range.start,
                        matched_text(found.data())
                    ));
                }
            }
        }
        let description = meta("description").unwrap_or_default();
        let value = if evidence.is_empty() {
            description.clone()
        } else if description.is_empty() {
            evidence.join("; ")
        } else {
            format!("{description} — {}", evidence.join("; "))
        };
        let namespace = rule.namespace().to_owned();
        let ruleset = if namespace == "antinomie" {
            "Antinomie".to_owned()
        } else {
            let author = meta("author").unwrap_or_else(|| "unknown author".into());
            let license = meta("license")
                .or_else(|| meta("malpedia_license"))
                .unwrap_or_default();
            format!("{COMMUNITY_RELEASE}; {author}; {license}")
        };
        let mut tags: Vec<String> = rule.tags().map(|t| t.identifier().to_owned()).collect();
        if let Some(category) = meta("category") {
            tags.insert(0, category);
        }
        super::worker::structured_entry(
            section,
            rule.identifier(),
            value,
            first.map(|range| AnalysisLocation {
                kind: AnalysisAddressKind::FileOffset,
                value: range.start as u64,
                file_range: Some(AnalysisRange {
                    offset: range.start as u64,
                    len: (range.end - range.start) as u64,
                }),
            }),
            AnalysisData::RuleMatch {
                rule: rule.identifier().to_owned(),
                namespace,
                tags,
                ruleset,
            },
        );
    }
    section.state = AnalysisSectionState::Complete;
    section.summary = format!(
        "{matched} of {} rules matched; a match is an indicator, not a verdict",
        own + community
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn bundled_rule_sets_compile_with_yara_x() {
        super::compile().unwrap();
    }
}
