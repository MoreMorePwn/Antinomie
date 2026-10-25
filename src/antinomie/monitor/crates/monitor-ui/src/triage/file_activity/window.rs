// SPDX-License-Identifier: GPL-3.0-only
//! The Per-file history tab of Triage > Files: every file the run touched on the left, and for
//! the chosen one its history as a graph, the calls behind a chosen node and
//! what is known of the bytes the run changed.
use super::graph::{self, Layout};
use super::{Activity, ByteRun, Event, FileActivity};
use crate::theme;
use crate::triage::{details, Cell, RowValue};
use crate::widgets::{self, Tone};
use eframe::egui;

/// How the list of files is ordered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Order {
    #[default]
    First,
    Last,
    Calls,
    Path,
}

impl Order {
    const ALL: [Self; 4] = [Self::First, Self::Last, Self::Calls, Self::Path];

    fn label(self) -> &'static str {
        match self {
            Self::First => "First touched",
            Self::Last => "Last touched",
            Self::Calls => "Most calls",
            Self::Path => "Path",
        }
    }
}

pub(in crate::triage) struct Window {
    pub(super) filter: String,
    pub(super) hide_standard_io: bool,
    pub(super) hide_libraries: bool,
    pub(super) changed_only: bool,
    pub(super) order: Order,
    /// The chosen file: its path and first call, which survive a new index.
    selected: Option<(String, u64)>,
    node: Option<usize>,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            filter: String::new(),
            hide_standard_io: true,
            hide_libraries: true,
            changed_only: false,
            order: Order::First,
            selected: None,
            node: None,
        }
    }
}

impl Window {
    /// Show the file at `path` (the caller switches to the tab).
    pub(in crate::triage) fn open_on(&mut self, path: &str) {
        self.filter.clear();
        self.selected = Some((path.to_owned(), 0));
        self.node = None;
    }

    /// The path of the chosen file and the chosen node, for the tests.
    #[cfg(test)]
    pub(super) fn chosen(&self) -> (Option<&str>, Option<usize>) {
        (
            self.selected.as_ref().map(|(path, _)| path.as_str()),
            self.node,
        )
    }

    /// The files the filter, toggles and order keep, as indices into the
    /// activity.
    pub(super) fn shown(&self, activity: &Activity) -> Vec<usize> {
        let needle = self.filter.trim().to_lowercase();
        let mut kept: Vec<usize> = activity
            .files
            .iter()
            .enumerate()
            .filter(|(_, file)| {
                !(self.hide_standard_io && file.standard_io)
                    && !(self.hide_libraries && file.library())
                    && (!self.changed_only || file.changed())
                    && (needle.is_empty()
                        || file.path.to_lowercase().contains(&needle)
                        || file
                            .names
                            .iter()
                            .any(|name| name.to_lowercase().contains(&needle)))
            })
            .map(|(index, _)| index)
            .collect();
        let files = &activity.files;
        match self.order {
            Order::First => {}
            Order::Last => kept.sort_by_key(|&i| std::cmp::Reverse(files[i].last_ns)),
            Order::Calls => kept.sort_by_key(|&i| {
                std::cmp::Reverse(files[i].events.len() as u64 + files[i].omitted)
            }),
            Order::Path => kept.sort_by(|&a, &b| files[a].path.cmp(&files[b].path)),
        }
        kept
    }

    fn selected_file<'a>(&self, activity: &'a Activity) -> Option<&'a FileActivity> {
        let (path, first) = self.selected.as_ref()?;
        activity
            .files
            .iter()
            .find(|file| file.path == *path && file.first_ns == *first)
            .or_else(|| {
                activity
                    .files
                    .iter()
                    .find(|file| file.path == *path || file.names.contains(path))
            })
    }

    /// The tab's content: the file list on the left, the chosen file's
    /// history on the right.
    pub(in crate::triage) fn show(
        &mut self,
        ui: &mut egui::Ui,
        activity: Option<&Activity>,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        match activity {
            Some(activity) => self.body(ui, activity, clock),
            None => {
                theme::loading_weak(ui, "Indexing this run’s files…");
            }
        }
    }

    fn body(
        &mut self,
        ui: &mut egui::Ui,
        activity: &Activity,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        if activity.omitted_files > 0 || activity.omitted_events > 0 {
            crate::activity::warning(
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
        let shown = self.shown(activity);
        // Beside each other when there is room, else the list above the history.
        if ui.available_width() >= STACK_BELOW {
            egui::SidePanel::left("file-activity-list")
                .resizable(true)
                .default_width(310.0)
                .show_inside(ui, |ui| self.list(ui, activity, &shown, clock));
        } else {
            egui::TopBottomPanel::top("file-activity-list")
                .resizable(true)
                .default_height(230.0)
                .show_inside(ui, |ui| self.list(ui, activity, &shown, clock));
        }
        egui::CentralPanel::default().show_inside(ui, |ui| {
            match self.selected_file(activity) {
                Some(file) => self.history(ui, activity, file, clock),
                None => {
                    ui.weak("Select a file.");
                }
            };
        });
    }

    fn list(
        &mut self,
        ui: &mut egui::Ui,
        activity: &Activity,
        shown: &[usize],
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        ui.add(
            egui::TextEdit::singleline(&mut self.filter)
                .hint_text(theme::hint_text("Filter by path"))
                .desired_width(f32::INFINITY),
        );
        ui.horizontal_wrapped(|ui| {
            for (label, flag, hover) in [
                ("Hide stdio", &mut self.hide_standard_io, "Hide stdin, stdout, stderr"),
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
        });
        egui::ComboBox::from_id_salt("file-activity-order")
            .selected_text(self.order.label())
            .show_ui(ui, |ui| {
                for order in Order::ALL {
                    ui.selectable_value(&mut self.order, order, order.label());
                }
            });
        ui.weak(format!(
            "{} of {} files",
            shown.len(),
            activity.files.len() as u64 + activity.omitted_files
        ));
        if shown.is_empty() {
            theme::empty_state(
                ui,
                if activity.files.is_empty() {
                    "The run touched no files"
                } else {
                    "No file matches the filter"
                },
            );
        }
        let row = ui.text_style_height(&egui::TextStyle::Body) * 2.0 + 10.0;
        let selected = self
            .selected_file(activity)
            .map(|file| file as *const FileActivity);
        let mut chosen = None;
        egui::ScrollArea::vertical()
            .id_salt("file-activity-files")
            .auto_shrink([false, false])
            .show_rows(ui, row, shown.len(), |ui, range| {
                for &index in &shown[range] {
                    let file = &activity.files[index];
                    let is_selected = selected == Some(file as *const FileActivity);
                    let response = ui
                        .scope(|ui| {
                            ui.set_min_width(ui.available_width());
                            ui.vertical(|ui| {
                                ui.add(
                                    egui::Label::new(egui::RichText::new(&file.path).monospace())
                                        .truncate()
                                        .selectable(false),
                                );
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(file.summary())
                                            .small()
                                            .color(theme::muted()),
                                    )
                                    .truncate()
                                    .selectable(false),
                                );
                            });
                        })
                        .response
                        .interact(egui::Sense::click());
                    if is_selected {
                        ui.painter().rect_filled(
                            response.rect,
                            3.0,
                            theme::primary().gamma_multiply(0.18),
                        );
                    } else if response.hovered() {
                        ui.painter().rect_filled(
                            response.rect,
                            3.0,
                            theme::primary().gamma_multiply(0.08),
                        );
                    }
                    if response.clicked() {
                        chosen = Some((file.path.clone(), file.first_ns));
                    }
                }
            });
        if chosen.is_some() {
            self.selected = chosen;
            self.node = None;
            // A click shows the file in Details, as a click on a row of any
            // other Triage table does.
            if let Some(file) = self.selected_file(activity) {
                let ctx = ui.ctx();
                details::select(ctx, FILE_TABLE, FILE_HEADERS, &file_cells(file, clock));
                details::clicked(ctx, FILE_TABLE);
            }
        }
    }

    fn history(
        &mut self,
        ui: &mut egui::Ui,
        activity: &Activity,
        file: &FileActivity,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        egui::ScrollArea::vertical()
            .id_salt("file-activity-history")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add(
                    egui::Label::new(egui::RichText::new(&file.path).strong().monospace()).wrap(),
                );
                ui.horizontal_wrapped(|ui| {
                    if file.created {
                        widgets::chip(ui, "created by the run", Tone::Good);
                    }
                    if file.deleted {
                        widgets::chip(ui, "deleted", Tone::Error);
                    }
                    if !file.path_known {
                        widgets::chip(ui, "path unknown", Tone::Warn);
                    }
                    if file.failed_only {
                        widgets::chip(ui, "every call refused", Tone::Neutral);
                    }
                    ui.weak(file.summary());
                });
                for name in &file.names {
                    ui.weak(format!("also seen as {name}"));
                }
                let layout = graph::layout(file);
                ui.add_space(6.0);
                if let Some(clicked) = graph::show(ui, activity, file, &layout, self.node) {
                    self.node = Some(clicked);
                }
                if file.omitted > 0 {
                    crate::activity::warning(
                        ui,
                        format!(
                            "{} more calls are not listed; Trace has them.",
                            file.omitted
                        ),
                    );
                }
                self.calls(ui, activity, file, &layout, clock);
                contents(ui, file, clock);
            });
    }

    /// The calls behind the chosen node, or all of them.
    fn calls(
        &mut self,
        ui: &mut egui::Ui,
        activity: &Activity,
        file: &FileActivity,
        layout: &Layout,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        let range = self
            .node
            .and_then(|node| layout.nodes.get(node))
            .map_or(0..file.events.len(), |node| node.events.clone());
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(if self.node.is_some() {
                    "Calls in the chosen step"
                } else {
                    "All calls"
                })
                .strong()
                .color(theme::heading()),
            );
            if self.node.is_some() && ui.small_button("Show all").clicked() {
                self.node = None;
            }
        });
        let rows: Vec<Vec<Cell>> = file.events[range]
            .iter()
            .take(CALLS_SHOWN)
            .map(|event| call_cells(activity, event, clock))
            .collect();
        // The shared Triage table: it takes the panel's width however short
        // its content, a click shows the call in Details and a double-click
        // opens the original syscall, as in every other Triage table.
        // Room for exactly its rows, so the table's ground does not fill the
        // rest of the pane; wide content scrolls sideways.
        let row = ui.text_style_height(&egui::TextStyle::Body).max(14.0) + 8.0;
        let height = (row + ui.spacing().item_spacing.y) * (rows.len() as f32 + 1.0) + 48.0;
        egui::ScrollArea::horizontal()
            .id_salt("file-activity-calls-columns")
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.allocate_ui(egui::vec2(ui.available_width(), height), |ui| {
                    crate::triage::table::table_rows(ui, CALLS_TABLE, CALL_HEADERS, &rows);
                });
            });
        if file.events.len() > CALLS_SHOWN && self.node.is_none() {
            ui.weak(format!("First {CALLS_SHOWN} calls."));
        }
    }
}

/// Narrower than this, the file list sits above the history.
const STACK_BELOW: f32 = 700.0;

/// Calls drawn in the table at once.
const CALLS_SHOWN: usize = 200;

/// The id of the calls table, which Details knows it by.
pub(in crate::triage) const CALLS_TABLE: &str = "triage-file-calls";
/// The id the chosen file is known by in Details.
pub(in crate::triage) const FILE_TABLE: &str = "triage-file-history";
const CALL_HEADERS: &[&str] = &[
    "Time", "Process", "Call", "Result", "Offset", "Length", "Content",
];
const FILE_HEADERS: &[&str] = &[
    "Path",
    "Also seen as",
    "First touched",
    "Last touched",
    "Calls",
    "Steps",
    "State",
    "Size before",
    "Size at the end",
    "SHA-256",
];

/// One call as a row of the calls table. The first cell carries what the
/// original syscall is found by, so Details offers it and a double-click opens it.
pub(super) fn call_cells(
    activity: &Activity,
    event: &Event,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) -> Vec<Cell> {
    use crate::triage::table::cell;
    let mut result = event.result.clone();
    if event.via.is_some() {
        result.push_str(" · async");
    }
    if !event.note.is_empty() {
        result.push_str(&format!(" · {}", event.note));
    }
    if let Some(other) = &event.other_path {
        result.push_str(&format!(" → {other}"));
    }
    let offset = match event.offset {
        Some(offset) => format!("0x{offset:x}"),
        None if event.len.is_some() => "unknown".to_owned(),
        None => String::new(),
    };
    let (stream, task, call) = event.key;
    let mut time = cell(
        crate::time_format::guest_ns(clock, Some(event.time)),
        theme::text(),
        true,
    );
    time.values = vec![
        ("stream.id", RowValue::Number(i128::from(stream))),
        ("process.cookie", RowValue::Number(i128::from(task))),
        ("event.id", RowValue::Number(i128::from(call))),
    ];
    vec![
        time,
        cell(activity.process_label(event.process), theme::text(), false),
        cell(&event.operation, graph::tint(event.kind), false),
        cell(result, theme::text(), false),
        cell(offset, theme::text(), true),
        cell(
            event.len.map(|len| len.to_string()).unwrap_or_default(),
            theme::text(),
            true,
        ),
        cell(content_text(event), theme::text(), true),
    ]
}

/// The chosen file as Details shows it.
pub(super) fn file_cells(
    file: &FileActivity,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) -> Vec<Cell> {
    use crate::triage::table::cell;
    let size = |size: Option<u64>| size.map_or("unknown".to_owned(), |size| format!("{size} B"));
    let mut state = Vec::new();
    if file.created {
        state.push("created by the run");
    }
    if file.deleted {
        state.push("deleted");
    }
    if !file.path_known {
        state.push("path unknown");
    }
    if file.failed_only {
        state.push("every call refused");
    }
    let calls = file.events.len() as u64 + file.omitted;
    let hash = file
        .contents
        .hash
        .as_ref()
        .and_then(|hash| hash.sha256_hex())
        .unwrap_or_default();
    vec![
        cell(&file.path, theme::text(), true),
        cell(file.names.join(", "), theme::text(), true),
        cell(
            crate::time_format::guest_ns(clock, Some(file.first_ns)),
            theme::text(),
            true,
        ),
        cell(
            crate::time_format::guest_ns(clock, Some(file.last_ns)),
            theme::text(),
            true,
        ),
        cell(calls.to_string(), theme::text(), true),
        cell(file.summary(), theme::text(), false),
        cell(state.join(", "), theme::text(), false),
        cell(size(file.contents.original_size), theme::text(), true),
        cell(size(file.contents.final_size), theme::text(), true),
        cell(hash, theme::text(), true),
    ]
}

/// What a transfer carried, as far as the kernel captured it.
pub(super) fn content_text(event: &Event) -> String {
    let Some(len) = event.len else {
        return String::new();
    };
    if event.content.is_empty() {
        return if len == 0 || event.success != Some(true) {
            String::new()
        } else {
            "not captured".into()
        };
    }
    let mut text: String = event.content.iter().map(|byte| printable(*byte)).collect();
    if event.content_gap || (event.content.len() as u64) < len {
        text.push_str(" …");
    }
    if event.extends {
        text.push_str("  [extends the file]");
    }
    text
}

fn printable(byte: u8) -> String {
    match byte {
        b'\n' => "\\n".into(),
        b'\r' => "\\r".into(),
        b'\t' => "\\t".into(),
        32..=126 => char::from(byte).to_string(),
        _ => format!("\\x{byte:02x}"),
    }
}

/// The bytes the run changed, where the run captured what they were and what
/// they became.
fn contents(
    ui: &mut egui::Ui,
    file: &FileActivity,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) {
    let known = &file.contents;
    if known.runs.is_empty()
        && known.gaps.is_empty()
        && known.hash.is_none()
        && file.hashes.is_empty()
    {
        return;
    }
    ui.add_space(8.0);
    ui.label(
        egui::RichText::new("Content changes")
            .strong()
            .color(theme::heading()),
    );
    let size = |size: Option<u64>| size.map_or("unknown".to_owned(), |size| format!("{size} B"));
    ui.weak(format!(
        "Size {} → {}",
        size(known.original_size),
        size(known.final_size)
    ));
    if let Some(hash) = &known.hash {
        match hash.sha256_hex() {
            Some(hex) => {
                ui.label("SHA-256 the guest took of the file");
                ui.monospace(hex);
            }
            None => {
                ui.weak(format!(
                    "The guest took no hash: {}.",
                    hash.skipped().unwrap_or_else(|| "no digest".into())
                ));
            }
        }
    }
    hashes(ui, file, clock);
    if known.differing > 0 {
        ui.weak(format!(
            "{} byte{} differ",
            known.differing,
            if known.differing == 1 { "" } else { "s" }
        ))
        .on_hover_text(
            "Between what the run saw first and last. ?? = not captured, ∅ = beyond the known size.",
        );
    }
    for run in &known.runs {
        ui.add(
            egui::Label::new(egui::RichText::new(run_text(run, known.original_size)).monospace())
                .wrap(),
        );
    }
    if known.differing > known.runs.iter().map(|run| run.after.len()).sum::<usize>() {
        ui.weak("More differences exist than are listed; Trace has the calls.");
    }
    for gap in &known.gaps {
        crate::activity::warning(ui, *gap);
    }
}

/// The guest's hashes in order. Two different digests prove the bytes changed
/// between them, whether or not a write payload was captured (a shared mapping
/// leaves none).
fn hashes(
    ui: &mut egui::Ui,
    file: &FileActivity,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) {
    for (index, note) in file.hashes.iter().enumerate() {
        let digest = note
            .sha256
            .as_deref()
            .map_or("no digest".to_owned(), |hex| format!("SHA-256 {hex}"));
        let mut text = format!(
            "{} · {} · {digest}",
            crate::time_format::guest_ns(clock, Some(note.time)),
            note.moment
        );
        if note.changed {
            text.push_str(" · changed while read, may not match");
        }
        if let Some(why) = &note.skipped {
            text.push_str(&format!(" · {why}"));
        }
        ui.add(egui::Label::new(egui::RichText::new(text).monospace()).wrap());
        let earlier = file.hashes[..index]
            .iter()
            .rev()
            .find_map(|earlier| earlier.sha256.as_ref());
        if let (Some(before), Some(after)) = (earlier, &note.sha256) {
            if before != after {
                ui.weak("The bytes differ from the earlier hash: the file changed in between.");
            }
        }
    }
}

/// `0x0010  ?? ?? → 68 65  (he)`, `added` when the bytes lie past the end the
/// run first saw.
pub(super) fn run_text(run: &ByteRun, original_size: Option<u64>) -> String {
    let hex = |bytes: &[Option<u8>], beyond: bool| {
        bytes
            .iter()
            .map(|byte| match byte {
                Some(byte) => format!("{byte:02x}"),
                None if beyond => "∅".to_owned(),
                None => "??".to_owned(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let added = original_size.is_some_and(|size| run.offset >= size);
    let ascii: String = run
        .after
        .iter()
        .map(|byte| match byte {
            Some(byte @ 32..=126) => char::from(*byte),
            Some(_) => '.',
            None => '?',
        })
        .collect();
    format!(
        "{}0x{:08x}  {} → {}  |{ascii}|",
        if added { "added " } else { "" },
        run.offset,
        hex(&run.before, added),
        hex(&run.after, false)
    )
}
