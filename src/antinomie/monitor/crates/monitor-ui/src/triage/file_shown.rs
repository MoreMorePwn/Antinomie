// SPDX-License-Identifier: GPL-3.0-only
//! What the Files tables draw of the rows they keep. A stored row has every
//! column its filters, sorts and Details know it by; the table draws fewer: the
//! time from the start of the run (the absolute time on hover), the location,
//! other names and a finding that involves the path as tags in a Tags
//! column after the Path, and no Evidence column (Details opens the original syscall).
use super::file_location::Location;
use super::*;
use crate::widgets::Tone;

/// What a table needs besides its rows.
pub(super) struct Notes<'a> {
    /// The start of the run, in the guest's nanoseconds.
    pub start: Option<u64>,
    /// Paths a Suspicious activity finding names as its object.
    pub flagged: &'a Flags,
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

/// What the findings above Info say of one path: how many name it as their
/// object, and the worst of them.
#[derive(Clone)]
pub(super) struct PathFlag {
    pub count: u64,
    pub worst: rules::Tier,
    /// The rule of the worst finding, whose title the tag shows.
    pub rule: String,
}

/// The paths that findings above Info name, with what they say of each.
pub(super) type Flags = std::collections::BTreeMap<String, PathFlag>;

/// Count one finding of `rule` and `tier` against `path`.
pub(super) fn flag(flags: &mut Flags, path: &str, tier: rules::Tier, rule: &str) {
    let entry = flags.entry(path.to_owned()).or_insert_with(|| PathFlag {
        count: 0,
        worst: tier,
        rule: rule.to_owned(),
    });
    entry.count += 1;
    if tier > entry.worst {
        entry.worst = tier;
        entry.rule = rule.to_owned();
    }
}

/// The tag of a path a finding involves: the worst tier with the behaviour's
/// title, or the number of findings when there are several.
pub(super) fn finding_tag(flag: &PathFlag) -> Badge {
    let title = rules::rule_title(&flag.rule);
    let (text, hover) = if flag.count == 1 {
        (
            format!("{} \u{b7} {title}", flag.worst.label()),
            format!(
                "Suspicious activity: {title} ({}). Open Suspicious activity for the evidence.",
                flag.worst.label()
            ),
        )
    } else {
        (
            format!("{} findings \u{b7} {}", flag.count, flag.worst.label()),
            format!(
                "{} Suspicious activity findings name this file; the worst is {title} ({}).",
                flag.count,
                flag.worst.label()
            ),
        )
    };
    Badge {
        text,
        tone: flag.worst.tone(),
        hover,
    }
}

/// The tags of a path: where it lives, its other names, and a finding.
pub(super) fn path_tags(
    locations: &[String],
    names: &[String],
    flagged: Option<&PathFlag>,
) -> Vec<Badge> {
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
    if let Some(flag) = flagged {
        badges.push(finding_tag(flag));
    }
    badges
}

/// The Tags cell: the tags of a path as pills, and no text of its own.
pub(super) fn tags_cell(badges: Vec<Badge>) -> Cell {
    let mut cell = table::cell("", theme::text(), false);
    cell.badges = badges;
    cell
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

/// The headers a Files table draws: those of the columns it shows (see
/// [`file_tabs::shown_columns`]), with Tags after the Path.
pub(super) fn headers<'a>(slot: usize, stored: &[&'a str]) -> Vec<&'a str> {
    let mut shown: Vec<&str> = file_tabs::shown_columns(slot)
        .iter()
        .map(|&index| stored[index])
        .collect();
    let at = shown.iter().position(|title| *title == "Path");
    shown.insert(at.map_or(shown.len(), |at| at + 1), "Tags");
    shown
}

/// The rows of a Files table as drawn: the columns of `slot` (see
/// [`file_tabs::shown_columns`]) with the decoration above.
pub(super) fn shown(slot: usize, rows: &[Vec<Cell>], notes: &Notes<'_>) -> Vec<Vec<Cell>> {
    let keep = file_tabs::shown_columns(slot);
    let path_at = path_column(slot);
    let path_shown = keep.iter().position(|&index| index == path_at).unwrap_or(0);
    rows.iter()
        .map(|row| {
            keep.iter()
                .filter_map(|&index| {
                    let mut cell = row.get(index)?.clone();
                    if index == 0 {
                        relative_time(&mut cell, notes);
                    }
                    if slot == 2 && index == 8 {
                        // Changed files: the digest cut, the whole one on hover.
                        let full = std::mem::take(&mut cell.text);
                        cell.text = short_hash(&full);
                        cell.note = (!full.is_empty()).then_some(full);
                    }
                    Some(cell)
                })
                .collect::<Vec<_>>()
        })
        .map(|mut cells| {
            // The tags of the path, in a column after it.
            let tags = {
                let values = cells.first().map_or(&[][..], |cell| cell.values.as_slice());
                let path = text_of(values, "file.path")
                    .or_else(|| cells.get(path_shown).map(|cell| cell.text.as_str()))
                    .unwrap_or_default();
                tags_cell(path_tags(
                    list_of(values, "file.location"),
                    list_of(values, "file.names"),
                    notes.flagged.get(path),
                ))
            };
            cells.insert((path_shown + 1).min(cells.len()), tags);
            cells
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
