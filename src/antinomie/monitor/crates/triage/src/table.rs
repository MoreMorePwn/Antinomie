// SPDX-License-Identifier: GPL-3.0-only
//! The cells of Triage tables.
use super::*;

pub(super) fn cell(text: impl Into<String>, tone: Tone, mono: bool) -> Cell {
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
const CELL_TEXT_MAX: usize = 240;

/// Keep the unresolved directory reason in Details while shortening table text.
pub(super) fn display_text(text: &str) -> String {
    text.replace("(relative, cwd not recorded)", "(relative)")
        .replace("(relative, dirfd not recorded)", "(relative)")
}

fn display_cell(text: &str) -> String {
    bounded_cell(&display_text(text))
}

fn bounded_cell(text: &str) -> String {
    match text.char_indices().nth(CELL_TEXT_MAX) {
        Some((end, _)) => format!("{}… (full value in Details)", &text[..end]),
        None => text.to_owned(),
    }
}

#[cfg(test)]
pub(super) fn push_limited(limited: &mut LimitedRows, row: Vec<Cell>) -> bool {
    limited.rows.push(row);
    true
}

