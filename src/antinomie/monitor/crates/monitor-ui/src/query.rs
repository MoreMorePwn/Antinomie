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
