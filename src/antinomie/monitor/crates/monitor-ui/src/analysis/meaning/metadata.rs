// SPDX-License-Identifier: GPL-3.0-only
//! Metadata rows: muted labels, hashes and hex values in monospace, sizes as
//! bytes with a KB/MB/GB figure, yes/no style values by outcome and
//! timestamps in local time.
use super::super::records::Column;
use crate::theme;
use antinomie_monitor_core::AnalysisEntry;
use eframe::egui::Color32;

/// How a Metadata value reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Style {
    Plain,
    /// A hash, address or other hex value.
    Hex,
    Good,
    Warn,
}

pub(super) fn style(entry: &AnalysisEntry) -> Style {
    let label = entry.label.to_ascii_lowercase();
    let value = entry.value.trim();
    match flag(value) {
        Some(true) => return Style::Good,
        Some(false) => return Style::Warn,
        None => {}
    }
    if hash_label(&label) || is_hex(value) {
        return Style::Hex;
    }
    Style::Plain
}

pub(super) fn cell_color(column: Column, entry: &AnalysisEntry) -> Option<Color32> {
    match column {
        Column::Name => Some(theme::muted()),
        Column::Offset => Some(theme::muted()),
        Column::Value => match style(entry) {
            Style::Good => Some(theme::good()),
            Style::Warn => Some(theme::warn()),
            Style::Plain | Style::Hex => None,
        },
        _ => None,
    }
}

/// Whether the cell is drawn in the monospace font.
pub(super) fn monospace(column: Column, entry: &AnalysisEntry) -> bool {
    match column {
        Column::Value => style(entry) == Style::Hex,
        Column::Offset => true,
        _ => false,
    }
}

/// The text a Metadata cell shows. Older reports stored the length as a bare
/// number under "Length (octets)".
pub(super) fn shown_text(column: Column, entry: &AnalysisEntry, text: &str) -> String {
    let label = entry.label.to_ascii_lowercase();
    match column {
        Column::Name if label == "length (octets)" => "File size".into(),
        Column::Value => {
            let value = text.trim();
            match value.parse::<u64>() {
                Ok(number) if size_label(&label) => crate::values::file_size(number),
                Ok(number) if timestamp_label(&label) => unix_seconds(number),
                _ if timestamp_label(&label) => rfc3339(value).unwrap_or_else(|| text.into()),
                _ => text.into(),
            }
        }
        _ => text.into(),
    }
}

fn size_label(label: &str) -> bool {
    label == "length (octets)"
        || label == "length"
        || label.ends_with("size")
        || label.ends_with("length")
}

fn timestamp_label(label: &str) -> bool {
    label.contains("timestamp")
        || label.contains("date")
        || label.ends_with("time")
        || label.contains("compiled")
        || label.contains("created")
        || label.contains("modified")
}

/// MD5, SHA-1, SHA-256, ssdeep, TLSH, import hashes, digests and checksums.
fn hash_label(label: &str) -> bool {
    label
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| {
            matches!(
                word,
                "md5" | "ssdeep" | "tlsh" | "hash" | "imphash" | "digest" | "checksum"
            ) || word
                .strip_prefix("sha")
                .is_some_and(|rest| rest.bytes().all(|byte| byte.is_ascii_digit()))
        })
}

/// `0x` followed by hex digits, or at least eight bare hex digits with a
/// letter among them (a plain number is not a hash).
fn is_hex(value: &str) -> bool {
    if let Some(rest) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_hexdigit());
    }
    value.len() >= 8
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte.is_ascii_alphabetic())
}

/// Some for a yes/no style value: true when it reads as present or yes.
fn flag(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" | "present" | "enabled" | "declared" | "observed" | "found" => Some(true),
        "no" | "false" | "absent" | "disabled" | "not declared" | "not observed" | "not found"
        | "missing" => Some(false),
        _ => None,
    }
}

fn unix_seconds(seconds: u64) -> String {
    if seconds == 0 {
        return "not set".into();
    }
    seconds
        .checked_mul(1_000_000)
        .map(crate::time_format::unix_us)
        .unwrap_or_else(|| seconds.to_string())
}

fn rfc3339(value: &str) -> Option<String> {
    let time = chrono::DateTime::parse_from_rfc3339(value).ok()?;
    u64::try_from(time.timestamp_micros())
        .ok()
        .map(crate::time_format::unix_us)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(label: &str, value: &str) -> AnalysisEntry {
        AnalysisEntry {
            label: label.into(),
            value: value.into(),
            offset: None,
            record: None,
        }
    }

    #[test]
    fn labels_are_muted_and_hashes_and_hex_are_monospace() {
        let sha = row("SHA-256", &"ab".repeat(32));
        assert_eq!(cell_color(Column::Name, &sha), Some(theme::muted()));
        assert_eq!(cell_color(Column::Value, &sha), None);
        assert!(monospace(Column::Value, &sha));
        assert!(!monospace(Column::Name, &sha));
        assert!(monospace(Column::Value, &row("Entry point", "0x401000")));
        assert!(monospace(Column::Value, &row("ssdeep", "3:abc:def")));
        assert!(monospace(Column::Value, &row("MD5", &"1".repeat(32))));
        assert!(!monospace(Column::Value, &row("Format", "Elf")));
        assert!(!monospace(Column::Value, &row("Shared", "Dynamic")));
        assert!(!monospace(Column::Value, &row("Class", "64-bit")));
    }

    #[test]
    fn yes_no_values_are_good_or_warn() {
        for value in ["yes", "Present", "true", "declared"] {
            assert_eq!(
                cell_color(Column::Value, &row("Signed", value)),
                Some(theme::good()),
                "{value}"
            );
        }
        for value in ["no", "Absent", "false", "not declared"] {
            assert_eq!(
                cell_color(Column::Value, &row("Signed", value)),
                Some(theme::warn()),
                "{value}"
            );
        }
        assert_eq!(cell_color(Column::Value, &row("Format", "Elf")), None);
    }

    #[test]
    fn sizes_read_as_bytes_and_old_reports_are_converted() {
        let shown =
            |label: &str, value: &str, column| shown_text(column, &row(label, value), value);
        assert_eq!(
            shown("File size", "4096", Column::Value),
            "4096 bytes (4.0 KB)"
        );
        assert_eq!(
            shown("Length (octets)", "16080", Column::Value),
            "16080 bytes (15.7 KB)"
        );
        assert_eq!(
            shown_text(
                Column::Name,
                &row("Length (octets)", "1"),
                "Length (octets)"
            ),
            "File size"
        );
        // Already formatted text and other values stay as they are.
        assert_eq!(
            shown("File size", "4096 bytes (4.0 KB)", Column::Value),
            "4096 bytes (4.0 KB)"
        );
        assert_eq!(shown("Class", "64-bit", Column::Value), "64-bit");
        assert_eq!(shown("Section count", "12", Column::Value), "12");
    }

    #[test]
    fn timestamps_are_readable() {
        let shown = |label: &str, value: &str| shown_text(Column::Value, &row(label, value), value);
        let time = shown("Compile timestamp", "1700000000");
        assert!(time.starts_with("2023-11-1"), "{time}");
        assert!(time.contains("UTC"), "{time}");
        assert_eq!(shown("Compile timestamp", "0"), "not set");
        let iso = shown("Created", "2023-11-14T22:13:20Z");
        assert!(iso.starts_with("2023-11-1") && iso.contains("UTC"), "{iso}");
        assert_eq!(shown("Created", "unknown"), "unknown");
        assert_eq!(shown("Endianness", "Little"), "Little");
    }
}
