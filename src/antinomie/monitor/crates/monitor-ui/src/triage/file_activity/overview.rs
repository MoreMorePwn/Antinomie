// SPDX-License-Identifier: GPL-3.0-only
//! The Per-file view of Triage > Files: one row for each file the run touched,
//! with what happened to it, who did it, when, how its size changed, what it
//! is and its SHA-256. The calls behind a row (offset, length, content) are in
//! the Per-file history and the row's Details.
use super::window::Window;
use super::{Activity, FileActivity, Kind};
use crate::theme;
use crate::triage::file_shown::{self, Notes};
use crate::triage::{details, file_location, file_type, process_cells, table, Cell, RowValue};
use crate::widgets;
use eframe::egui;

/// The id of the table, which Details and the row menu know it by.
pub(in crate::triage) const TABLE: &str = "triage-files";

pub(in crate::triage) const HEADERS: &[&str] = &[
    "Path",
    "Tags",
    "What happened",
    "By",
    "First \u{2192} last",
    "Size",
    "Type",
    "SHA-256",
];

/// Steps of the chain written out before it ends in an ellipsis.
const CHAIN_STEPS: usize = 8;

/// The first octets of the file the run captured, from offset 0.
pub(in crate::triage) fn head(file: &FileActivity) -> Vec<u8> {
    let transfer = file
        .events
        .iter()
        .filter(|event| matches!(event.kind, Kind::Write | Kind::Read))
        .filter(|event| event.success != Some(false) && event.offset == Some(0))
        .find(|event| !event.content.is_empty());
    if let Some(event) = transfer {
        return event
            .content
            .iter()
            .take(file_type::HEAD)
            .copied()
            .collect();
    }
    file.contents
        .runs
        .iter()
        .find(|run| run.offset == 0)
        .map(|run| {
            run.after
                .iter()
                .map_while(|byte| *byte)
                .take(file_type::HEAD)
                .collect()
        })
        .unwrap_or_default()
}

/// What the file is, from the bytes captured of it.
pub(in crate::triage) fn type_of(file: &FileActivity) -> &'static str {
    file_type::of(&head(file), &file.path)
}

/// "created → written 812 KiB → chmod +x → executed → deleted": what the
/// calls that succeeded did to the file, in order, a run of the same thing
/// once.
pub(in crate::triage) fn chain(file: &FileActivity) -> String {
    // (what was done, octets moved, calls)
    let mut steps: Vec<(String, u64, u32)> = Vec::new();
    for event in &file.events {
        if event.success == Some(false) {
            continue;
        }
        let word = match event.kind {
            Kind::Open => "opened".to_owned(),
            Kind::Create => "created".to_owned(),
            Kind::Read => "read".to_owned(),
            Kind::Write => "written".to_owned(),
            Kind::Resize => "resized".to_owned(),
            Kind::Rename => "renamed".to_owned(),
            Kind::Link => "linked".to_owned(),
            Kind::Delete => "deleted".to_owned(),
            Kind::Exec => "executed".to_owned(),
            Kind::Map => "mapped".to_owned(),
            Kind::Attributes if !event.note.is_empty() => format!("chmod {}", event.note),
            Kind::Attributes if event.operation.contains("chmod") => "chmod".to_owned(),
            Kind::Attributes => "attributes changed".to_owned(),
            Kind::Probe | Kind::Other => continue,
        };
        let moved = if matches!(event.kind, Kind::Read | Kind::Write) {
            event.len.unwrap_or(0)
        } else {
            0
        };
        match steps.last_mut() {
            Some((last, bytes, count)) if *last == word => {
                *bytes += moved;
                *count += 1;
            }
            _ => steps.push((word, moved, 1)),
        }
    }
    // An open that led to something else is not worth a step of its own.
    if steps.iter().any(|(word, _, _)| word != "opened") {
        steps.retain(|(word, _, _)| word != "opened");
    }
    if steps.is_empty() {
        return if file.failed_only {
            "every call refused".to_owned()
        } else if file.events.is_empty() {
            "calls not listed".to_owned()
        } else {
            "only looked at".to_owned()
        };
    }
    let more = steps.len() > CHAIN_STEPS;
    let mut text = steps
        .into_iter()
        .take(CHAIN_STEPS)
        .map(|(word, bytes, count)| {
            if bytes > 0 {
                format!("{word} {}", file_shown::size_text(bytes))
            } else if count > 1 {
                format!("{word} {count}\u{d7}")
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" \u{2192} ");
    if more {
        text.push_str(" \u{2192} \u{2026}");
    }
    text
}

/// The size column: "0 B → 812 KiB", or the one size when it did not change.
pub(in crate::triage) fn size_change(file: &FileActivity) -> String {
    let before = file
        .contents
        .original_size
        .or_else(|| file.created.then_some(0));
    match (before, file.contents.final_size) {
        (Some(before), Some(after)) if before == after => file_shown::size_text(after),
        (Some(before), Some(after)) => format!(
            "{} \u{2192} {}",
            file_shown::size_text(before),
            file_shown::size_text(after)
        ),
        (Some(before), None) => format!("{} \u{2192} unknown", file_shown::size_text(before)),
        (None, Some(after)) => format!("unknown \u{2192} {}", file_shown::size_text(after)),
        (None, None) => "unknown".to_owned(),
    }
}

/// The processes that made the calls: the first, and how many more.
fn by(activity: &Activity, file: &FileActivity) -> String {
    let mut seen: Vec<u32> = Vec::new();
    for event in &file.events {
        if !seen.contains(&event.process) {
            seen.push(event.process);
        }
    }
    match seen.split_first() {
        None => String::new(),
        Some((first, [])) => activity.process_label(*first),
        Some((first, rest)) => format!("{} +{}", activity.process_label(*first), rest.len()),
    }
}

/// One file as a row of the table.
pub(in crate::triage) fn cells(
    activity: &Activity,
    file: &FileActivity,
    notes: &Notes<'_>,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) -> Vec<Cell> {
    let locations: Vec<String> = file_location::classify(&file.path, &[])
        .into_iter()
        .map(|location| location.tag().to_owned())
        .collect();
    let names: Vec<String> = std::iter::once(file.path.clone())
        .chain(file.names.iter().cloned())
        .collect();
    let hash = file.sha256();
    let kind = type_of(file);
    let mut path = table::cell(&file.path, theme::text(), true);
    let tags = file_shown::tags_cell(file_shown::path_tags(
        &locations,
        &names,
        notes.flagged.get(&file.path),
    ));
    // The first call of the file: what Details opens in Trace.
    let mut values = vec![
        ("file.path", RowValue::Text(file.path.clone())),
        ("file.names", RowValue::List(names)),
        ("file.location", RowValue::List(locations)),
        ("event.time_ns", RowValue::Number(i128::from(file.first_ns))),
    ];
    if let Some(first) = file.events.first() {
        let (stream, task, call) = first.key;
        values.push(("stream.id", RowValue::Number(i128::from(stream))));
        values.push(("process.cookie", RowValue::Number(i128::from(task))));
        values.push(("event.id", RowValue::Number(i128::from(call))));
    }
    if let Some(hash) = &hash {
        values.push(("file.sha256", RowValue::Text(hash.clone())));
    }
    path.values = values;
    let mut span = table::cell(
        if file.first_ns == file.last_ns {
            process_cells::relative(Some(file.first_ns), notes.start)
        } else {
            format!(
                "{} \u{2192} {}",
                process_cells::relative(Some(file.first_ns), notes.start),
                process_cells::relative(Some(file.last_ns), notes.start)
            )
        },
        theme::text(),
        true,
    );
    span.note = Some(format!(
        "{} \u{2192} {}",
        crate::time_format::guest_ns(clock, Some(file.first_ns)),
        crate::time_format::guest_ns(clock, Some(file.last_ns))
    ));
    let mut digest = table::cell(
        hash.as_deref()
            .map(file_shown::short_hash)
            .unwrap_or_default(),
        theme::text(),
        true,
    );
    digest.note = hash;
    vec![
        path,
        tags,
        table::cell(chain(file), theme::text(), false),
        table::cell(by(activity, file), theme::text(), false),
        span,
        table::cell(size_change(file), theme::text(), true),
        table::cell(kind, theme::text(), false),
        digest,
    ]
}

impl Window {
    /// The table of every file the run touched, under its filters.
    pub(in crate::triage) fn overview(
        &mut self,
        ui: &mut egui::Ui,
        activity: Option<&Activity>,
        notes: &Notes<'_>,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        let Some(activity) = activity else {
            theme::loading_weak(ui, "Indexing this run\u{2019}s files\u{2026}");
            return;
        };
        let mut shown = Vec::new();
        ui.horizontal_wrapped(|ui| {
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text(theme::placeholder(ui, "Filter by path"))
                    .margin(crate::widgets::clear_margin(egui::Margin::symmetric(4, 2)))
                    .desired_width(260.0),
            );
            crate::widgets::clear_button(ui, &edit, &mut self.filter);
            for (label, flag, hover) in [
                (
                    "Hide stdio",
                    &mut self.hide_standard_io,
                    "Hide stdin, stdout, stderr",
                ),
                (
                    "Hide library",
                    &mut self.hide_libraries,
                    "Hide shared libraries and the loader cache",
                ),
                (
                    "Changed only",
                    &mut self.changed_only,
                    "Only files a call created, wrote, resized, renamed, linked, deleted or changed the attributes of",
                ),
            ] {
                if widgets::toggle_chip(ui, label, *flag, None)
                    .on_hover_text(hover)
                    .clicked()
                {
                    *flag = !*flag;
                }
            }
            // Shown / total, as the other tables' filter bars say it.
            shown = self.shown(activity);
            let group = antinomie_monitor_core::analysis::detection::group_digits;
            ui.colored_label(
                theme::muted(),
                format!(
                    "{} / {} rows",
                    group(shown.len() as u64),
                    group(activity.files.len() as u64 + activity.omitted_files)
                ),
            )
            .on_hover_text("Files listed with the filter and the Hide chips, out of all the run touched");
        });
        if activity.omitted_files > 0 || activity.omitted_events > 0 {
            crate::activity::info(
                ui,
                format!(
                    "Kept the first {} files and {} calls per file; {} files and {} calls are not listed. Trace has every call.",
                    super::FILES_MAX,
                    super::EVENTS_PER_FILE,
                    activity.omitted_files,
                    activity.omitted_events
                ),
            );
        }
        if shown.is_empty() {
            theme::empty_state(
                ui,
                if activity.files.is_empty() {
                    "The run touched no files"
                } else {
                    "No file matches the filter"
                },
            );
            return;
        }
        let rows: Vec<Vec<Cell>> = shown
            .iter()
            .map(|&index| cells(activity, &activity.files[index], notes, clock))
            .collect();
        table::table_rows(ui, TABLE, HEADERS, &rows);
        // Details shows the whole file, not the columns the table draws.
        let full: Vec<Vec<Cell>> = shown
            .iter()
            .zip(&rows)
            .map(|(&index, row)| {
                let mut full = super::window::file_cells(&activity.files[index], clock);
                if let (Some(first), Some(shown)) = (full.first_mut(), row.first()) {
                    first.values.clone_from(&shown.values);
                }
                full
            })
            .collect();
        details::refresh(ui.ctx(), TABLE, super::window::FILE_HEADERS, &full);
    }
}
