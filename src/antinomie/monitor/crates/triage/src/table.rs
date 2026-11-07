// SPDX-License-Identifier: GPL-3.0-only
//! The cells of Triage tables.
use super::*;

pub fn cell(text: impl Into<String>, tone: Tone, mono: bool) -> Cell {
    Cell {
        text: text.into(),
        tone,
        mono,
        values: Vec::new(),
        badges: Vec::new(),
        note: None,
    }
}

/// Characters a table cell shows. A cut cell's hover text is its shown text,
/// so this also bounds the hover box; Details keeps the whole value.
pub const CELL_TEXT_MAX: usize = 240;

/// Keep the unresolved directory reason in Details while shortening table text.
pub fn display_text(text: &str) -> String {
    text.replace("(relative, cwd not recorded)", "(relative)")
        .replace("(relative, dirfd not recorded)", "(relative)")
}

pub fn display_cell(text: &str) -> String {
    bounded_cell(&display_text(text))
}

pub fn bounded_cell(text: &str) -> String {
    match text.char_indices().nth(CELL_TEXT_MAX) {
        Some((end, _)) => format!("{}… (full value in Details)", &text[..end]),
        None => text.to_owned(),
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn push_limited(limited: &mut LimitedRows, row: Vec<Cell>) -> bool {
    limited.rows.push(row);
    true
}

pub fn evidence_key(row: &[Cell]) -> String {
    let identity = evidence_values_key(
        row.first()
            .map(|cell| cell.values.as_slice())
            .unwrap_or_default(),
    );
    if identity.is_empty() {
        row.iter()
            .map(|cell| cell.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        identity
    }
}

pub fn evidence_values_key(values: &[(&str, RowValue)]) -> String {
    values
        .iter()
        .filter(|(name, _)| {
            matches!(
                *name,
                "event.id"
                    | "stream.id"
                    | "frame.number"
                    | "dns.name"
                    | "http.uri"
                    | "process.cookie"
                    | "finding.rule"
                    | "finding.engine"
                    | "capture.path"
            )
        })
        .map(|(name, value)| format!("{name}:{value:?}"))
        .collect::<Vec<_>>()
        .join("/")
}
