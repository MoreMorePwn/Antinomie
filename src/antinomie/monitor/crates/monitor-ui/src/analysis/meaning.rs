// SPDX-License-Identifier: GPL-3.0-only
//! Meaning colors for static-analysis lists.
//! Rule names follow severity, string encodings follow the string type,
//! structure names follow the structure kind, and hardening values follow
//! pass or fail. Entropy stays on its chart. Decompiled source keeps the
//! highlighting in the listing view.
use super::records::Column;
use crate::theme;
use antinomie_monitor_core::{AnalysisData, AnalysisEntry, AnalysisKind};
use eframe::egui::{self, Color32};

mod metadata;

/// The list cell that carries the row's meaning, when this list has one.
pub(super) fn cell_color(
    kind: AnalysisKind,
    column: Column,
    entry: &AnalysisEntry,
) -> Option<Color32> {
    match kind {
        AnalysisKind::Rules => {
            if column == Column::Name {
                Some(rule_color(entry))
            } else {
                None
            }
        }
        AnalysisKind::Strings => {
            if column == Column::Encoding {
                string_encoding(entry).and_then(string_type_color)
            } else {
                None
            }
        }
        AnalysisKind::Structures => {
            if column == Column::Name {
                structure_color(entry)
            } else {
                None
            }
        }
        AnalysisKind::Hardening => {
            if column == Column::Value {
                hardening_color(entry)
            } else {
                None
            }
        }
        AnalysisKind::Metadata => metadata::cell_color(column, entry),
        _ => None,
    }
}

/// The text a cell shows. Metadata sizes read as bytes with a KB/MB/GB
/// figure and timestamps in local time; every other list shows `text`.
pub(super) fn shown_text(
    kind: AnalysisKind,
    column: Column,
    entry: &AnalysisEntry,
    text: &str,
) -> String {
    if kind == AnalysisKind::Metadata {
        metadata::shown_text(column, entry, text)
    } else {
        text.to_owned()
    }
}

pub(super) fn meaning_text(
    kind: AnalysisKind,
    column: Column,
    entry: &AnalysisEntry,
    text: String,
) -> egui::RichText {
    let mut text = egui::RichText::new(text);
    if kind == AnalysisKind::Metadata && metadata::monospace(column, entry) {
        text = text.monospace();
    }
    match cell_color(kind, column, entry) {
        Some(color) => text.color(color),
        None => text,
    }
}

/// A match with no severity metadata is an indicator.
fn rule_color(entry: &AnalysisEntry) -> Color32 {
    severity_color(rule_severity(entry))
}

fn rule_severity(entry: &AnalysisEntry) -> &'static str {
    let tags = match entry.record.as_ref().map(|record| &record.data) {
        Some(AnalysisData::RuleMatch { tags, .. }) => tags.as_slice(),
        _ => &[],
    };
    for tag in tags {
        if let Some(token) = severity_word(tag) {
            return token;
        }
    }
    if let Some(token) = keyed_severity(&entry.value) {
        return token;
    }
    if let Some(token) = keyed_severity(&entry.label) {
        return token;
    }
    for tag in tags {
        if let Some(token) = score_word(tag) {
            return token;
        }
    }
    "indicator"
}

fn severity_word(text: &str) -> Option<&'static str> {
    let text = text.trim().to_ascii_lowercase();
    let text = text
        .strip_prefix("severity")
        .or_else(|| text.strip_prefix("level"))
        .unwrap_or(&text);
    let text = text.trim_start_matches(|c: char| {
        c == '_' || c == '-' || c == '=' || c == ':' || c.is_whitespace()
    });
    match text {
        "1" | "critical" => Some("critical"),
        "high" => Some("high"),
        "2" | "medium" => Some("medium"),
        "indicator" => Some("indicator"),
        "3" | "4" | "low" => Some("low"),
        "informational" | "info" => Some("info"),
        _ => None,
    }
}

fn severity_color(token: &str) -> Color32 {
    match token {
        "critical" | "high" => theme::error(),
        "medium" | "indicator" => theme::warn(),
        "low" | "info" => theme::blue(),
        _ => theme::muted(),
    }
}

fn keyed_severity(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    for key in ["severity", "level"] {
        let mut rest = lower.as_str();
        while let Some(at) = rest.find(key) {
            let after = rest[at + key.len()..].trim_start_matches(|c: char| {
                c == '=' || c == ':' || c == '"' || c == '\'' || c.is_whitespace()
            });
            let end = after
                .find(|c: char| !c.is_ascii_alphanumeric())
                .unwrap_or(after.len());
            if let Some(token) = severity_word(&after[..end]) {
                return Some(token);
            }
            let next = at + key.len();
            if next >= rest.len() {
                break;
            }
            rest = &rest[next..];
        }
    }
    None
}

/// A numeric tag outside the 1–4 priority scale, read as a 0–100 score.
fn score_word(text: &str) -> Option<&'static str> {
    let text = text.trim();
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let score = match text.parse::<u32>() {
        Ok(score) => score,
        Err(_) => return None,
    };
    if score > 100 {
        return None;
    }
    Some(if score >= 75 {
        "high"
    } else if score >= 40 {
        "medium"
    } else {
        "low"
    })
}

fn string_encoding(entry: &AnalysisEntry) -> Option<&str> {
    match entry.record.as_ref().map(|record| &record.data) {
        Some(AnalysisData::String { encoding, .. }) => Some(encoding.as_str()),
        _ => None,
    }
}

fn string_type_color(encoding: &str) -> Option<Color32> {
    let encoding = encoding.trim();
    if encoding.is_empty() || encoding == "-" {
        return None;
    }
    let upper = encoding.to_ascii_uppercase();
    Some(if upper.contains("UTF-16") || upper.contains("UTF16") {
        theme::info()
    } else if upper.contains("UTF-32") || upper.contains("UTF32") {
        theme::palette().pointer
    } else if upper == "UTF-8" || upper == "UTF8" {
        theme::good()
    } else if upper == "ASCII" {
        theme::palette().string
    } else if upper.starts_with("UTF") {
        theme::blue()
    } else {
        theme::warn()
    })
}

fn structure_color(entry: &AnalysisEntry) -> Option<Color32> {
    if entry.label == "Segment" {
        return Some(theme::info());
    }
    match entry.record.as_ref().map(|record| &record.data) {
        Some(AnalysisData::Section { .. }) => Some(theme::blue()),
        Some(AnalysisData::Import { .. }) => Some(theme::warn()),
        Some(AnalysisData::Export { .. }) => Some(theme::good()),
        Some(AnalysisData::Symbol { .. }) => Some(theme::palette().name),
        Some(AnalysisData::Field { .. }) => Some(theme::muted()),
        None => match entry.label.as_str() {
            "Import" => Some(theme::warn()),
            "Export" => Some(theme::good()),
            "Section" => Some(theme::blue()),
            _ => None,
        },
        Some(_) => None,
    }
}

enum Outcome {
    Pass,
    Fail,
}

fn hardening_color(entry: &AnalysisEntry) -> Option<Color32> {
    let (label, value) = hardening_parts(entry);
    match hardening_outcome(label, value) {
        Some(Outcome::Pass) => Some(theme::good()),
        Some(Outcome::Fail) => Some(theme::error()),
        None => None,
    }
}

fn hardening_parts(entry: &AnalysisEntry) -> (&str, &str) {
    if let Some(record) = entry.record.as_ref() {
        if let AnalysisData::Property {
            observed, evidence, ..
        } = &record.data
        {
            return (evidence.as_str(), observed.as_str());
        }
    }
    (entry.label.as_str(), entry.value.as_str())
}

fn hardening_outcome(label: &str, value: &str) -> Option<Outcome> {
    let label_l = label.to_ascii_lowercase();
    let value_l = value.trim().to_ascii_lowercase();
    if label_l.contains("executable stack") {
        if value_l.contains("allowed") {
            return Some(Outcome::Fail);
        }
        if value_l.contains("not requested") {
            return Some(Outcome::Pass);
        }
    }
    if value_l.starts_with("not declared") || value_l.starts_with("not observed") {
        return Some(Outcome::Fail);
    }
    if value_l == "declared" || value_l == "observed" {
        return Some(Outcome::Pass);
    }
    elf_line(value)
}

fn elf_line(value: &str) -> Option<Outcome> {
    let upper = value.to_ascii_uppercase();
    if upper.contains("TEXTREL") {
        return Some(Outcome::Fail);
    }
    if upper.contains("GNU_STACK") {
        return Some(if executable_stack(value) {
            Outcome::Fail
        } else {
            Outcome::Pass
        });
    }
    if upper.contains("GNU_RELRO") || upper.contains("BIND_NOW") {
        return Some(Outcome::Pass);
    }
    None
}

fn executable_stack(line: &str) -> bool {
    line.split_whitespace()
        .any(|token| token.contains('E') && token.chars().all(|c| c == 'R' || c == 'W' || c == 'E'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{AnalysisRange, AnalysisRecord};

    fn entry(label: &str, value: &str, data: AnalysisData) -> AnalysisEntry {
        AnalysisEntry {
            label: label.into(),
            value: value.into(),
            offset: None,
            record: Some(AnalysisRecord {
                revision: 1,
                id: 1,
                location: None,
                data,
            }),
        }
    }

    fn rule(tags: &[&str], value: &str) -> AnalysisEntry {
        entry(
            "RuleName",
            value,
            AnalysisData::RuleMatch {
                rule: "RuleName".into(),
                namespace: "ns".into(),
                tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
                ruleset: "set".into(),
            },
        )
    }

    fn string_row(encoding: &str) -> AnalysisEntry {
        entry(
            encoding,
            "text",
            AnalysisData::String {
                encoding: encoding.into(),
                byte_len: 4,
                retained_len: 4,
            },
        )
    }

    fn property(label: &str, value: &str) -> AnalysisEntry {
        entry(
            label,
            value,
            AnalysisData::Property {
                scope: "Static file metadata".into(),
                observed: value.into(),
                evidence: label.into(),
            },
        )
    }

    #[test]
    fn rule_names_follow_severity_and_other_columns_stay_plain() {
        let high = rule(&["high"], "Detects a dropper");
        assert_eq!(
            cell_color(AnalysisKind::Rules, Column::Name, &high),
            Some(theme::error())
        );
        assert_eq!(cell_color(AnalysisKind::Rules, Column::Tags, &high), None);
        assert_eq!(cell_color(AnalysisKind::Rules, Column::Value, &high), None);
        assert_eq!(cell_color(AnalysisKind::Rules, Column::Source, &high), None);
        assert_eq!(
            cell_color(
                AnalysisKind::Rules,
                Column::Name,
                &rule(&["severity_critical"], "")
            ),
            Some(theme::error())
        );
        assert_eq!(
            cell_color(AnalysisKind::Rules, Column::Name, &rule(&["2"], "")),
            Some(theme::warn())
        );
        assert_eq!(
            cell_color(AnalysisKind::Rules, Column::Name, &rule(&["low"], "")),
            Some(theme::blue())
        );
        assert_eq!(
            cell_color(
                AnalysisKind::Rules,
                Column::Name,
                &rule(&[], "severity: informational")
            ),
            Some(theme::blue())
        );
        assert_eq!(
            cell_color(
                AnalysisKind::Rules,
                Column::Name,
                &rule(&["FILE"], "Detects high entropy blobs")
            ),
            Some(theme::warn())
        );
        assert_eq!(
            cell_color(AnalysisKind::Rules, Column::Name, &rule(&["90"], "")),
            Some(theme::error())
        );
        assert_eq!(
            cell_color(AnalysisKind::Rules, Column::Name, &rule(&["10"], "")),
            Some(theme::blue())
        );
        assert_eq!(
            cell_color(AnalysisKind::Rules, Column::Name, &rule(&["2024"], "")),
            Some(theme::warn())
        );
    }

    #[test]
    fn string_encodings_use_distinct_type_colors() {
        let ascii = string_row("ASCII");
        let utf8 = string_row("UTF-8");
        let utf16 = string_row("UTF-16LE");
        let utf32 = string_row("UTF-32BE");
        let other = string_row("EBCDIC");
        let colors = [
            cell_color(AnalysisKind::Strings, Column::Encoding, &ascii),
            cell_color(AnalysisKind::Strings, Column::Encoding, &utf8),
            cell_color(AnalysisKind::Strings, Column::Encoding, &utf16),
            cell_color(AnalysisKind::Strings, Column::Encoding, &utf32),
            cell_color(AnalysisKind::Strings, Column::Encoding, &other),
        ];
        assert_eq!(colors[0], Some(theme::palette().string));
        assert_eq!(colors[1], Some(theme::good()));
        assert_eq!(colors[2], Some(theme::info()));
        assert_eq!(colors[3], Some(theme::palette().pointer));
        assert_eq!(colors[4], Some(theme::warn()));
        for left in 0..colors.len() {
            for right in (left + 1)..colors.len() {
                assert_ne!(colors[left], colors[right]);
            }
        }
        assert_eq!(
            cell_color(
                AnalysisKind::Strings,
                Column::Encoding,
                &string_row("utf-16le")
            ),
            Some(theme::info())
        );
        assert_eq!(
            cell_color(AnalysisKind::Strings, Column::Value, &ascii),
            None
        );
        assert_eq!(
            cell_color(AnalysisKind::Strings, Column::Offset, &ascii),
            None
        );
        assert_eq!(
            cell_color(AnalysisKind::Strings, Column::Size, &ascii),
            None
        );
    }

    #[test]
    fn structure_names_follow_the_record_kind() {
        let section = entry(
            "Section",
            ".text",
            AnalysisData::Section {
                name: ".text".into(),
                address: 0x1000,
                virtual_size: 32,
                file_size: Some(32),
                raw_flags: "0x6".into(),
                flags: vec!["EXECINSTR".into()],
            },
        );
        let mut segment = section.clone();
        segment.label = "Segment".into();
        let import = entry(
            "Import",
            "puts",
            AnalysisData::Import {
                name: Some("puts".into()),
                library: Some("libc".into()),
                ordinal: None,
            },
        );
        let export = entry(
            "Export",
            "main",
            AnalysisData::Export {
                name: Some("main".into()),
                ordinal: None,
                address: Some(0x1000),
            },
        );
        let symbol = entry(
            "start",
            "Text",
            AnalysisData::Symbol {
                name: "start".into(),
                kind: "Text".into(),
                scope: "Linkage".into(),
                undefined: false,
                address: Some(0x1000),
                size: 16,
            },
        );
        let field = entry(
            "EI_CLASS",
            "ELF64",
            AnalysisData::Field {
                group: "Headers".into(),
            },
        );
        let colors = [
            cell_color(AnalysisKind::Structures, Column::Name, &field),
            cell_color(AnalysisKind::Structures, Column::Name, &section),
            cell_color(AnalysisKind::Structures, Column::Name, &segment),
            cell_color(AnalysisKind::Structures, Column::Name, &import),
            cell_color(AnalysisKind::Structures, Column::Name, &export),
            cell_color(AnalysisKind::Structures, Column::Name, &symbol),
        ];
        assert_eq!(colors[0], Some(theme::muted()));
        assert_eq!(colors[1], Some(theme::blue()));
        assert_eq!(colors[2], Some(theme::info()));
        assert_eq!(colors[3], Some(theme::warn()));
        assert_eq!(colors[4], Some(theme::good()));
        assert_eq!(colors[5], Some(theme::palette().name));
        for left in 0..colors.len() {
            for right in (left + 1)..colors.len() {
                assert_ne!(colors[left], colors[right]);
            }
        }
        assert_eq!(
            cell_color(AnalysisKind::Structures, Column::Flags, &section),
            None
        );
        assert_eq!(
            cell_color(AnalysisKind::Structures, Column::Kind, &symbol),
            None
        );
        let legacy = AnalysisEntry {
            label: "Import".into(),
            value: "puts".into(),
            offset: None,
            record: None,
        };
        assert_eq!(
            cell_color(AnalysisKind::Structures, Column::Name, &legacy),
            Some(theme::warn())
        );
    }

    #[test]
    fn hardening_values_follow_pass_and_fail() {
        let pass = |label, value| {
            assert_eq!(
                cell_color(
                    AnalysisKind::Hardening,
                    Column::Value,
                    &property(label, value)
                ),
                Some(theme::good()),
                "{label} / {value}"
            );
        };
        let fail = |label, value| {
            assert_eq!(
                cell_color(
                    AnalysisKind::Hardening,
                    Column::Value,
                    &property(label, value)
                ),
                Some(theme::error()),
                "{label} / {value}"
            );
        };
        let plain = |label, value| {
            assert_eq!(
                cell_color(
                    AnalysisKind::Hardening,
                    Column::Value,
                    &property(label, value)
                ),
                None,
                "{label} / {value}"
            );
        };
        pass("NX compatible", "declared");
        pass("Stack protector symbol", "observed");
        pass("Executable stack", "not requested by header");
        pass(
            "ELF hardening metadata",
            "GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10",
        );
        pass(
            "ELF hardening metadata",
            "GNU_RELRO      0x000000 0x00000000003ff000 0x00000000003ff000 0x000000 0x001000 R   0x1",
        );
        pass(
            "ELF hardening metadata",
            "0x000000000000001e (FLAGS)              BIND_NOW",
        );
        fail("NX compatible", "not declared");
        fail(
            "Stack protector symbol",
            "not observed; absence does not prove no protection",
        );
        fail("Executable stack", "allowed by header");
        fail(
            "ELF hardening metadata",
            "GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWE 0x10",
        );
        fail(
            "ELF hardening metadata",
            "0x0000000000000016 (TEXTREL)            0x0",
        );
        plain(
            "ELF hardening metadata",
            "0x000000006ffffffb (FLAGS_1)            Flags: ORIGIN",
        );
        plain(
            "Object kind",
            "Dynamic; a dynamic kind alone is not proof of PIE",
        );
        assert_eq!(
            cell_color(
                AnalysisKind::Hardening,
                Column::Name,
                &property("NX compatible", "declared")
            ),
            None
        );
    }

    #[test]
    fn metadata_cells_use_theme_colors_and_shown_text() {
        let size = AnalysisEntry {
            label: "File size".into(),
            value: "4096".into(),
            offset: None,
            record: None,
        };
        assert_eq!(
            cell_color(AnalysisKind::Metadata, Column::Name, &size),
            Some(theme::muted())
        );
        assert_eq!(
            shown_text(AnalysisKind::Metadata, Column::Value, &size, "4096"),
            "4096 bytes (4.0 KB)"
        );
        // Other lists show their text unchanged.
        assert_eq!(
            shown_text(AnalysisKind::Strings, Column::Value, &size, "4096"),
            "4096"
        );
    }

    #[test]
    fn entropy_and_decompiled_rows_are_not_meaning_colored() {
        let entropy = entry(
            "region",
            "4.000",
            AnalysisData::Entropy {
                range: AnalysisRange { offset: 0, len: 16 },
                milli_bits: 4000,
            },
        );
        assert_eq!(
            cell_color(AnalysisKind::Entropy, Column::Entropy, &entropy),
            None
        );
        assert_eq!(
            cell_color(AnalysisKind::Entropy, Column::Name, &entropy),
            None
        );
        let line = AnalysisEntry {
            label: "12".into(),
            value: "return 1;".into(),
            offset: None,
            record: None,
        };
        assert_eq!(
            cell_color(AnalysisKind::Decompilation, Column::Value, &line),
            None
        );
        assert_eq!(
            cell_color(AnalysisKind::Disassembly, Column::Name, &line),
            None
        );
    }
}
