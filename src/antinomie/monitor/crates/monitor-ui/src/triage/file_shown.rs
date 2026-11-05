// SPDX-License-Identifier: GPL-3.0-only
//! What the Files tables draw of the rows they keep. A stored row has every
//! column its filters, sorts and Details know it by; the table draws fewer: the
//! time from the start of the run (the absolute time on hover), the location,
//! other names and a finding that involves the path as small badges on the
//! Path cell, and no Evidence column (Details opens the original syscall).
use super::file_location::Location;
use super::*;
use crate::widgets::Tone;
use std::collections::BTreeSet;

/// What a table needs besides its rows.
pub(super) struct Notes<'a> {
    /// The start of the run, in the guest's nanoseconds.
    pub start: Option<u64>,
    /// Paths a Suspicious activity finding names as its object.
    pub flagged: &'a BTreeSet<String>,
}

/// The stored column a table's Path is in.
fn path_column(slot: usize) -> usize {
    match slot {
        1 | 8..=15 => 3,
        _ => 1,
    }
}

pub(super) fn text_of<'a>(values: &'a [(&'static str, RowValue)], key: &str) -> Option<&'a str> {
    values.iter().find_map(|(name, value)| match value {
        RowValue::Text(text) if *name == key => Some(text.as_str()),
        _ => None,
    })
}

fn list_of<'a>(values: &'a [(&'static str, RowValue)], key: &str) -> &'a [String] {
    values
        .iter()
        .find_map(|(name, value)| match value {
            RowValue::List(list) if *name == key => Some(list.as_slice()),
            _ => None,
        })
        .unwrap_or_default()
}

/// The badge of a path a finding involves.
pub(super) fn finding_badge() -> Badge {
    Badge {
        text: "\u{26a0}".into(),
        tone: Tone::Warn,
        hover: "A Suspicious activity finding involves this file".into(),
    }
}

/// The badges of a path: where it lives, its other names, and a finding.
pub(super) fn path_badges(locations: &[String], names: &[String], flagged: bool) -> Vec<Badge> {
    let mut badges: Vec<Badge> = locations
        .iter()
        .map(|tag| Badge {
            text: Location::badge(tag).to_owned(),
            tone: if matches!(tag.as_str(), "hidden" | "persistence" | "credentials") {
                Tone::Warn
            } else {
                Tone::Neutral
            },
            hover: format!("Location: {tag}"),
        })
        .collect();
    if names.len() > 1 {
        badges.push(Badge {
            text: format!("+{} names", names.len() - 1),
            tone: Tone::Info,
            hover: format!("Also seen as {}", names[1..].join(", ")),
        });
    }
    if flagged {
        badges.push(finding_badge());
    }
    badges
}

/// A SHA-256 as the table shows it: the first twelve digits.
pub(super) fn short_hash(hash: &str) -> String {
    match hash.char_indices().nth(12) {
        Some((end, _)) => format!("{}\u{2026}", &hash[..end]),
        None => hash.to_owned(),
    }
}

/// Swap the text of `cell` for its time from the start of the run; the
/// absolute time it showed moves to the hover.
fn relative_time(cell: &mut Cell, notes: &Notes<'_>) {
    let Some(ns) = files::number(&cell.values, "event.time_ns") else {
        return;
    };
    if notes.start.is_none() {
        return;
    }
    let absolute = std::mem::take(&mut cell.text);
    cell.text = process_cells::relative(Some(ns), notes.start);
    cell.note = Some(absolute);
}

/// The rows of a Files table as drawn: the columns of `slot` (see
/// [`file_tabs::shown_columns`]) with the decoration above.
pub(super) fn shown(slot: usize, rows: &[Vec<Cell>], notes: &Notes<'_>) -> Vec<Vec<Cell>> {
    let keep = file_tabs::shown_columns(slot);
    let path_at = path_column(slot);
    rows.iter()
        .map(|row| {
            let values = row.first().map(|cell| cell.values.as_slice());
            let values = values.unwrap_or_default();
            keep.iter()
                .filter_map(|&index| {
                    let mut cell = row.get(index)?.clone();
                    match index {
                        0 => relative_time(&mut cell, notes),
                        _ if index == path_at => {
                            let path = text_of(values, "file.path").unwrap_or(&cell.text);
                            cell.badges = path_badges(
                                list_of(values, "file.location"),
                                list_of(values, "file.names"),
                                notes.flagged.contains(path),
                            );
                        }
                        _ => {}
                    }
                    if slot == 2 && index == 8 {
                        // Changed files: the digest cut, the whole one on hover.
                        let full = std::mem::take(&mut cell.text);
                        cell.text = short_hash(&full);
                        cell.note = (!full.is_empty()).then_some(full);
                    }
                    Some(cell)
                })
                .collect()
        })
        .collect()
}

/// The run's SHA-256 note in a row's menu: copy the whole digest.
pub(super) fn copy_hash_menu(ui: &mut egui::Ui, values: &[(&str, RowValue)]) {
    let hash = values.iter().find_map(|(name, value)| match value {
        RowValue::Text(hash) if *name == "file.sha256" && !hash.is_empty() => Some(hash),
        _ => None,
    });
    if let Some(hash) = hash {
        if ui
            .button("Copy SHA-256")
            .on_hover_text(hash.as_str())
            .clicked()
        {
            ui.ctx().copy_text(hash.clone());
            ui.close();
        }
    }
}

/// A size as the table writes it: "812 B", "4.1 KiB".
pub(super) fn size_text(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        antinomie_monitor_core::byte_size::short_size(bytes).replace(".0 ", " ")
    }
}
