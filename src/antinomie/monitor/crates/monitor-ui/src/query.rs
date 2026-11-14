// SPDX-License-Identifier: GPL-3.0-only
//! Display filter for syscall rows: the filter bar, the guide and the row
//! menus. The language itself (lexer, parser, evaluator, table fields) is in
//! `antinomie_triage::query`.
use eframe::egui;

pub(crate) use antinomie_triage::query::*;

mod editor;
mod guide;
mod row_menu;
mod tables;

pub(crate) use self::{
    editor::*,
    guide::*,
    row_menu::{note_cell, note_head, Extras as RowMenuExtras, NoteRun},
    tables::*,
};

/// The filter syntax ([`HELP`]) as a help icon's text: each field and
/// example line as code, the sentences after them as a paragraph.
pub(crate) fn filter_help() -> String {
    let mut lines = String::from("Filter syntax\n\n");
    let mut prose = Vec::new();
    for line in HELP.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line.ends_with('.') {
            prose.push(line);
        } else {
            lines.push_str(&format!("- `{line}`\n"));
        }
    }
    lines.push('\n');
    lines.push_str(&prose.join(" "));
    lines
}

#[cfg(test)]
mod tests;
