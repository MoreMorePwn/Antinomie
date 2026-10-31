// SPDX-License-Identifier: GPL-3.0-only
//! Notes on a sample: the editor window, the reference picker and the chips
//! that show a note's references.
//!
//! A menu anywhere in the app adds a note with one call: [`menu_item`] draws
//! "Add note…" and, when it is clicked, leaves a request that the
//! Samples page picks up on its next frame and opens the editor with. The
//! editor lets the analyst pick references from the open sample's runs,
//! processes, trace entries, indicators, artifacts, custody entries and
//! lineage nodes.
use super::detail::Data;
use super::*;
use crate::widgets::{self, Tone};
use antinomie_monitor_core::samples::{
    build_lineage, Known, LineageOptions, Note, NoteRef, RefKind, RunLineage, MAX_NOTE,
};
use std::{collections::HashMap, path::PathBuf};

/// The most rows the picker lists at once.
const ROWS: usize = 200;

fn request_id() -> egui::Id {
    egui::Id::new("sample_note_request")
}

/// What a menu asked a note for: the reference, and the sample it belongs to
/// when the menu knows it (a run's sample); `None` is the sample that is open.
#[derive(Clone)]
pub(in crate::app) struct Request {
    pub reference: NoteRef,
    pub sample: Option<String>,
}

/// "Add note…" for a menu: on a click it asks the Samples page to open the
/// note editor with `reference` already attached, and closes the menu.
/// Returns whether it was clicked. The note goes to the open sample.
pub(in crate::app) fn menu_item(ui: &mut egui::Ui, reference: impl FnOnce() -> NoteRef) -> bool {
    menu_item_for(ui, None, reference)
}

/// [`menu_item`] for an entry of a run: `sample` is the SHA-256 of the
/// sample the run started, which the Samples window opens when another one
/// (or none) is open.
pub(in crate::app) fn menu_item_for(
    ui: &mut egui::Ui,
    sample: Option<&str>,
    reference: impl FnOnce() -> NoteRef,
) -> bool {
    let clicked = ui.button("Add note…").clicked();
    if clicked {
        let request = Request {
            reference: reference(),
            sample: sample.map(str::to_owned),
        };
        ui.ctx()
            .data_mut(|data| data.insert_temp(request_id(), request));
        ui.close_menu();
    }
    clicked
}

/// A menu's request, left where it is until it is carried out.
fn peek_request(ctx: &egui::Context) -> Option<Request> {
    ctx.data(|data| data.get_temp::<Request>(request_id()))
}

fn clear_request(ctx: &egui::Context) {
    ctx.data_mut(|data| data.remove::<Request>(request_id()));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Category {
    Runs,
    Processes,
    Trace,
    Ioc,
    Files,
    Custody,
    Lineage,
}

impl Category {
    const ALL: [Category; 7] = [
        Self::Runs,
        Self::Processes,
        Self::Trace,
        Self::Ioc,
        Self::Files,
        Self::Custody,
        Self::Lineage,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Runs => "Runs",
            Self::Processes => "Processes",
            Self::Trace => "Trace entries",
            Self::Ioc => "IoC",
            Self::Files => "Files / artifacts",
            Self::Custody => "Custody entries",
            Self::Lineage => "Lineage nodes",
        }
    }

    /// What the category is, one line, for its hover.
    fn about(self) -> &'static str {
        match self {
            Self::Runs => "A whole run of the sample",
            Self::Processes => "A process of one run, opened in its Syscall Trace",
            Self::Trace => "One entry of a run's Syscall Trace: the note jumps to that record",
            Self::Ioc => "An indicator the runs produced: address, domain, file hash",
            Self::Files => "A file or capture a run kept",
            Self::Custody => "An entry of this sample's custody log",
            Self::Lineage => "A file in the lineage graph",
        }
    }

    /// The group the picker lists the category under.
    fn group(self) -> &'static str {
        match self {
            Self::Runs | Self::Processes | Self::Trace => "In a run",
            Self::Ioc | Self::Files => "What a run produced",
            Self::Custody | Self::Lineage => "In this sample's record",
        }
    }

    fn icon(self) -> &'static str {
        use egui_phosphor::regular as icon;
        match self {
            Self::Runs => icon::PLAY_CIRCLE,
            Self::Processes => icon::TREE_STRUCTURE,
            Self::Trace => icon::LIST_BULLETS,
            Self::Ioc => icon::CROSSHAIR,
            Self::Files => icon::FILE,
            Self::Custody => icon::SCROLL,
            Self::Lineage => icon::GRAPH,
        }
    }

    /// Whether the category has a second level between it and its entries.
    fn has_subtypes(self) -> bool {
        matches!(
            self,
            Self::Processes | Self::Trace | Self::Ioc | Self::Files
        )
    }

    /// Whether the entries are read from a run's recording, on a thread.
    fn from_recording(self) -> bool {
        matches!(self, Self::Processes | Self::Trace)
    }
}

/// One thing a note can refer to.
struct Candidate {
    category: Category,
    /// The second level: a run, an indicator type or an artifact kind.
    sub: String,
    reference: NoteRef,
    /// What a typed search is matched against, lower case.
    haystack: String,
}

/// A run whose processes the picker can read.
struct RunInfo {
    label: String,
    key: String,
    vm_id: String,
    run_id: String,
    directory: PathBuf,
    pid: u32,
    path: String,
    folder: bool,
}

/// What the picker offers, read from the open sample's data.
pub(super) struct Candidates {
    list: Vec<Candidate>,
    runs: Vec<RunInfo>,
}

fn candidate(category: Category, sub: &str, reference: NoteRef) -> Candidate {
    let haystack = format!("{} {}", reference.label, sub).to_lowercase();
    Candidate {
        category,
        sub: sub.to_owned(),
        reference,
        haystack,
    }
}

impl Candidates {
    pub(super) fn of(data: &Data) -> Self {
        let mut list = Vec::new();
        let mut runs = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for entry in &data.runs {
            let label = format!("Run {}", entry.number);
            let key = format!("{}/{}", entry.run.vm_id, entry.run.id);
            list.push(candidate(
                Category::Runs,
                "",
                NoteRef::new(RefKind::Run, key.clone(), label.clone()),
            ));
            runs.push(RunInfo {
                label,
                key,
                vm_id: entry.run.vm_id.clone(),
                run_id: entry.run.id.clone(),
                directory: entry.run.directory.clone(),
                pid: entry.run.pid,
                path: entry.run.request.path.clone(),
                folder: entry.folder,
            });
            for found in entry
                .digest
                .iter()
                .flat_map(|digest| digest.indicators.iter().flatten())
            {
                if seen.insert((found.ty.clone(), found.value.clone())) {
                    list.push(candidate(
                        Category::Ioc,
                        &found.ty,
                        NoteRef::new(
                            RefKind::Indicator,
                            format!("{}:{}", found.ty, found.value),
                            format!("{} ({})", found.value, found.ty),
                        ),
                    ));
                }
            }
        }
        for output in data.outputs() {
            let reference = output.reference();
            list.push(candidate(Category::Files, output.kind_label(), reference));
        }
        for event in &data.events {
            list.push(candidate(
                Category::Custody,
                "",
                NoteRef::new(
                    RefKind::Custody,
                    event.seq.to_string(),
                    format!("Custody entry {} · {}", event.seq, event.event.label()),
                ),
            ));
        }
        for node in lineage_nodes(data) {
            list.push(candidate(Category::Lineage, "", node));
        }
        Self { list, runs }
    }

    fn count(&self, category: Category) -> usize {
        if category.from_recording() {
            return self.runs.iter().filter(|run| run.folder).count();
        }
        self.list
            .iter()
            .filter(|found| found.category == category)
            .count()
    }

    fn subtypes(&self, category: Category) -> Vec<(String, usize)> {
        if category.from_recording() {
            return self
                .runs
                .iter()
                .filter(|run| run.folder)
                .map(|run| (run.label.clone(), 0))
                .collect();
        }
        let mut counts: Vec<(String, usize)> = Vec::new();
        for found in self.list.iter().filter(|found| found.category == category) {
            match counts.iter_mut().find(|(sub, _)| *sub == found.sub) {
                Some((_, count)) => *count += 1,
                None => counts.push((found.sub.clone(), 1)),
            }
        }
        counts
    }
}

/// The lineage graph's nodes as references (the graph at its default levels).
fn lineage_nodes(data: &Data) -> Vec<NoteRef> {
    let runs: Vec<RunLineage<'_>> = data
        .runs
        .iter()
        .map(|entry| RunLineage {
            number: entry.number,
            sample: entry
                .run
                .request
                .sample
                .as_ref()
                .map_or("", |sample| sample.sha256.as_str()),
            sample_path: entry.run.request.path.as_str(),
            lineage: entry
                .digest
                .as_ref()
                .and_then(|digest| digest.lineage.as_ref()),
        })
        .collect();
    let known = |sha: &str| {
        data.known.get(sha).map(|(name, verdict)| Known {
            name: name.clone(),
            verdict: verdict.clone(),
        })
    };
    let options = LineageOptions {
        hide_system: false,
        ..LineageOptions::default()
    };
    build_lineage(&data.record.sha256, &runs, &data.links, &known, &options)
        .nodes
        .into_iter()
        .filter(|node| node.id != data.record.sha256)
        .map(|node| NoteRef::new(RefKind::Lineage, node.id, node.label))
        .collect()
}

/// What a thread read from a run's recording: the candidates it found.
type Read = Result<Vec<(NoteRef, String)>, String>;

enum Reading {
    Working(Receiver<Read>),
    Ready(Vec<Candidate>),
    Failed(String),
}

/// Calls of a run the picker lists: four pages of the Syscall Trace.
const TRACE_PAGES: usize = 4;
/// Calls per page the recording gives.
const TRACE_PAGE: usize = 256;

/// The first calls of a run's Syscall Trace, as `(event sequence, what the
/// call was)`; [`TRACE_PAGES`] pages at most.
fn read_trace(
    recording: &antinomie_monitor_core::recording::Recording,
    cancel: &std::sync::atomic::AtomicBool,
) -> Read {
    let mut found = Vec::new();
    let mut offset = 0;
    for _ in 0..TRACE_PAGES {
        let page = recording
            .invocation_page_cancellable(offset, TRACE_PAGE, cancel)
            .map_err(|error| error.to_string())?;
        for invocation in &page.invocations {
            let Some(event) = crate::trace::representative(invocation) else {
                continue;
            };
            let info = crate::trace::info(invocation);
            let what = if info.is_empty() {
                event.syscall_name.clone()
            } else {
                format!(
                    "{} {}",
                    event.syscall_name,
                    info.chars().take(90).collect::<String>()
                )
            };
            found.push((
                NoteRef::new(RefKind::Trace, event.event_seq.to_string(), ""),
                what,
            ));
        }
        match page.next_offset {
            Some(next) => offset = next,
            None => break,
        }
    }
    Ok(found)
}

/// The key a run's reading of `category` is kept under.
fn reading_key(category: Category, run: &RunInfo) -> String {
    format!("{}|{}", category.label(), run.key)
}

/// How a row of the picker is drawn.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RowState {
    Normal,
    /// The row the arrow keys are on.
    Cursor,
    /// Already one of the note's references.
    Taken,
    /// Nothing to pick in it.
    Empty,
}

/// One row of the picker: an icon, the text cut to one line, a count or the
/// run it belongs to at the right and, for a group of entries, a chevron.
/// The row lights up under the pointer, and the row the keys are on has the
/// accent bar the tables use for a selected row.
fn pick_row(
    ui: &mut egui::Ui,
    icon: &str,
    text: &str,
    right: &str,
    chevron: bool,
    state: RowState,
) -> egui::Response {
    let palette = theme::palette();
    let height = ui.spacing().interact_size.y + 6.0;
    let sense = if matches!(state, RowState::Taken | RowState::Empty) {
        egui::Sense::hover()
    } else {
        egui::Sense::click()
    };
    let (rect, response) = ui.allocate_exact_size(egui::vec2(ui.available_width(), height), sense);
    if ui.is_rect_visible(rect) {
        let lit = response.hovered() && sense != egui::Sense::hover();
        if lit || state == RowState::Cursor {
            ui.painter().rect_filled(rect, 4.0, palette.selection_soft);
        }
        if state == RowState::Cursor {
            let bar = egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height()));
            ui.painter().rect_filled(bar, 2.0, palette.accent);
        }
        if lit {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        let body = egui::TextStyle::Body.resolve(ui.style());
        let dim = matches!(state, RowState::Taken | RowState::Empty);
        let ink = if dim { palette.muted } else { palette.text };
        let centre = rect.left_center();
        ui.painter().text(
            centre + egui::vec2(12.0, 0.0),
            egui::Align2::LEFT_CENTER,
            icon,
            body.clone(),
            if dim { palette.muted } else { palette.accent },
        );
        let mut right_edge = rect.right() - 10.0;
        if chevron {
            ui.painter().text(
                egui::pos2(right_edge, centre.y),
                egui::Align2::RIGHT_CENTER,
                egui_phosphor::regular::CARET_RIGHT,
                body.clone(),
                palette.muted,
            );
            right_edge -= body.size + 6.0;
        }
        if state == RowState::Taken {
            let done = ui.painter().text(
                egui::pos2(right_edge, centre.y),
                egui::Align2::RIGHT_CENTER,
                format!("{} added", egui_phosphor::regular::CHECK),
                body.clone(),
                palette.good,
            );
            right_edge = done.left() - 8.0;
        } else if !right.is_empty() {
            let shown = ui.painter().text(
                egui::pos2(right_edge, centre.y),
                egui::Align2::RIGHT_CENTER,
                right,
                body.clone(),
                palette.muted,
            );
            right_edge = shown.left() - 8.0;
        }
        let left = rect.left() + 12.0 + body.size + 10.0;
        let mut job = egui::text::LayoutJob::simple_singleline(text.to_owned(), body, ink);
        job.wrap = egui::text::TextWrapping {
            max_width: (right_edge - left).max(40.0),
            max_rows: 1,
            break_anywhere: true,
            overflow_character: Some('…'),
        };
        let galley = ui.fonts(|fonts| fonts.layout_job(job));
        ui.painter().galley(
            egui::pos2(left, centre.y - galley.size().y / 2.0),
            galley,
            ink,
        );
    }
    response
}

/// The small muted title of a group of rows.
fn group_title(ui: &mut egui::Ui, text: &str) {
    ui.add_space(4.0);
    ui.label(
        RichText::new(text.to_uppercase())
            .small()
            .strong()
            .color(theme::muted()),
    );
}

/// The picker inside the editor: a search field and a cascade.
struct Picker {
    search: String,
    category: Option<Category>,
    sub: Option<String>,
    cursor: usize,
    focus: bool,
    /// What the recording-backed categories read, by [`reading_key`].
    processes: HashMap<String, Reading>,
}

impl Picker {
    fn new() -> Self {
        Self {
            search: String::new(),
            category: None,
            sub: None,
            cursor: 0,
            focus: true,
            processes: HashMap::new(),
        }
    }

    /// Read the process tree, or the first calls of the Syscall Trace, of a
    /// run on a thread.
    fn read_run(&mut self, ctx: &egui::Context, category: Category, run: &RunInfo) {
        let key = reading_key(category, run);
        if self.processes.contains_key(&key) {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let (directory, pid, path) = (run.directory.clone(), run.pid, run.path.clone());
        let wake = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("note-run-read".into())
            .spawn(move || {
                let cancel = std::sync::atomic::AtomicBool::new(false);
                let recording = antinomie_monitor_core::recording::Recording {
                    directory,
                    manifest: serde_json::Value::Null,
                    events: Vec::new(),
                };
                let result = if category == Category::Trace {
                    read_trace(&recording, &cancel)
                } else {
                    recording
                        .process_tree_cancellable(pid, &path, &cancel)
                        .map(|(processes, _)| {
                            processes
                                .into_iter()
                                .map(|process| {
                                    let exe = process.exe.unwrap_or_default();
                                    let name = if exe.is_empty() { process.name } else { exe };
                                    (
                                        NoteRef::new(RefKind::Process, process.pid.to_string(), ""),
                                        name,
                                    )
                                })
                                .collect()
                        })
                        .map_err(|error| error.to_string())
                };
                let _ = sender.send(result);
                wake.request_repaint();
            });
        self.processes.insert(
            key,
            match spawned {
                Ok(_) => Reading::Working(receiver),
                Err(error) => Reading::Failed(error.to_string()),
            },
        );
    }

    fn poll(&mut self, candidates: &Candidates) {
        for (key, reading) in &mut self.processes {
            let Reading::Working(receiver) = reading else {
                continue;
            };
            let Ok(result) = receiver.try_recv() else {
                continue;
            };
            let Some((tag, run_key)) = key.split_once('|') else {
                continue;
            };
            let Some(run) = candidates.runs.iter().find(|run| run.key == run_key) else {
                continue;
            };
            let trace = tag == Category::Trace.label();
            let category = if trace {
                Category::Trace
            } else {
                Category::Processes
            };
            let label = run.label.clone();
            *reading = match result {
                Ok(found) => Reading::Ready(
                    found
                        .into_iter()
                        .map(|(reference, name)| {
                            let number = reference.target.clone();
                            let reference = if trace {
                                // The recording named the call by its event sequence.
                                NoteRef::new(
                                    RefKind::Trace,
                                    antinomie_monitor_core::samples::trace_target(
                                        &run.vm_id,
                                        &run.run_id,
                                        number.parse().unwrap_or(0),
                                    ),
                                    format!("{label} · {name} · record {number}"),
                                )
                            } else {
                                NoteRef::new(
                                    RefKind::Process,
                                    format!("{run_key}/{number}"),
                                    format!(
                                        "{} {number} · {}",
                                        short_name(&name),
                                        label.to_lowercase()
                                    ),
                                )
                            };
                            candidate(category, &label, reference)
                        })
                        .collect(),
                ),
                Err(error) => Reading::Failed(error),
            };
        }
    }

    /// The entries to list now (at most [`ROWS`]) and how many there are.
    fn entries(&self, candidates: &Candidates) -> (Vec<(Category, NoteRef)>, usize) {
        let needle = self.search.trim().to_lowercase();
        let loaded = || {
            self.processes.values().filter_map(|reading| match reading {
                Reading::Ready(list) => Some(list.iter()),
                _ => None,
            })
        };
        let wanted: Box<dyn Iterator<Item = &Candidate> + '_> = if !needle.is_empty() {
            Box::new(
                candidates
                    .list
                    .iter()
                    .chain(loaded().flatten())
                    .filter(|found| found.haystack.contains(&needle))
                    .filter(|found| {
                        self.category
                            .is_none_or(|category| found.category == category)
                            && self.sub.as_ref().is_none_or(|sub| found.sub == *sub)
                    }),
            )
        } else if let Some(category) = self.category {
            if category.from_recording() {
                let run = candidates
                    .runs
                    .iter()
                    .find(|run| Some(&run.label) == self.sub.as_ref());
                match run.and_then(|run| self.processes.get(&reading_key(category, run))) {
                    Some(Reading::Ready(list)) => Box::new(list.iter()),
                    _ => Box::new(std::iter::empty()),
                }
            } else {
                Box::new(
                    candidates
                        .list
                        .iter()
                        .filter(move |found| found.category == category)
                        .filter(|found| self.sub.as_ref().is_none_or(|sub| found.sub == *sub)),
                )
            }
        } else {
            Box::new(std::iter::empty())
        };
        let mut shown = Vec::new();
        let mut total = 0;
        for found in wanted {
            total += 1;
            if shown.len() < ROWS {
                shown.push((found.category, found.reference.clone()));
            }
        }
        (shown, total)
    }

    /// One frame of the picker; returns the reference picked, and whether it
    /// should close.
    fn show(
        &mut self,
        ui: &mut egui::Ui,
        candidates: &Candidates,
        taken: &[NoteRef],
    ) -> (Option<NoteRef>, bool) {
        self.poll(candidates);
        let mut picked = None;
        let mut close = false;
        let searching = !self.search.trim().is_empty();
        let hint = match self.category {
            Some(category) => format!("Search {}", category.label().to_lowercase()),
            None => "Search what this note refers to".into(),
        };
        let frame = egui::Frame::new()
            .fill(ui.visuals().extreme_bg_color)
            .stroke(egui::Stroke::new(1.0_f32, theme::palette().line))
            .corner_radius(4)
            .inner_margin(egui::Margin::symmetric(6, 3));
        let search = frame
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(egui_phosphor::regular::MAGNIFYING_GLASS)
                            .color(theme::muted()),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text(theme::hint_text(hint))
                            .frame(false)
                            .desired_width(f32::INFINITY),
                    )
                })
                .inner
            })
            .inner;
        if self.focus {
            search.request_focus();
            self.focus = false;
        }
        let (entries, total) = self.entries(candidates);
        let shown = entries.len();
        let (down, up, enter, escape) = ui.input(|input| {
            (
                input.key_pressed(egui::Key::ArrowDown),
                input.key_pressed(egui::Key::ArrowUp),
                input.key_pressed(egui::Key::Enter),
                input.key_pressed(egui::Key::Escape),
            )
        });
        if search.has_focus() || search.lost_focus() {
            if down && shown > 0 {
                self.cursor = (self.cursor + 1).min(shown - 1);
            }
            if up {
                self.cursor = self.cursor.saturating_sub(1);
            }
        }
        if search.changed() {
            self.cursor = 0;
        }
        let mut back = escape && (search.has_focus() || search.lost_focus());
        let mut step = None;
        if back && searching {
            self.search.clear();
            self.cursor = 0;
            back = false;
        }
        if enter && search.lost_focus() && searching {
            picked = entries.get(self.cursor).map(|found| found.1.clone());
        }
        ui.add_space(4.0);
        if self.category.is_some() && !searching {
            // Where the list is: "‹ Back" and the path to the rows below.
            ui.horizontal(|ui| {
                if widgets::link(ui, "‹ Back").clicked() {
                    back = true;
                }
                if let Some(category) = self.category {
                    let mut place = category.label().to_owned();
                    if let Some(sub) = &self.sub {
                        place = format!("{place} › {sub}");
                    }
                    ui.label(RichText::new(place).color(theme::muted()))
                        .on_hover_text(category.about());
                }
            });
        }
        let height = 240.0_f32.min(ui.ctx().screen_rect().height() * 0.4);
        egui::ScrollArea::vertical()
            .id_salt("note_picker_rows")
            .max_height(height)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                if !searching && self.category.is_none() {
                    let mut group = "";
                    for category in Category::ALL {
                        if category.group() != group {
                            group = category.group();
                            group_title(ui, group);
                        }
                        let count = candidates.count(category);
                        let response = pick_row(
                            ui,
                            category.icon(),
                            category.label(),
                            &count.to_string(),
                            count > 0,
                            if count == 0 {
                                RowState::Empty
                            } else {
                                RowState::Normal
                            },
                        )
                        .on_hover_text(category.about());
                        if response.clicked() {
                            step = Some((Some(category), None));
                        }
                    }
                    return;
                }
                if !searching
                    && self.sub.is_none()
                    && self.category.is_some_and(Category::has_subtypes)
                {
                    let category = self.category.unwrap_or(Category::Runs);
                    for (sub, count) in candidates.subtypes(category) {
                        let right = if count > 0 {
                            count.to_string()
                        } else {
                            String::new()
                        };
                        if pick_row(ui, category.icon(), &sub, &right, true, RowState::Normal)
                            .clicked()
                        {
                            step = Some((Some(category), Some(sub)));
                        }
                    }
                    return;
                }
                if let (Some(sub), Some(category)) = (&self.sub, self.category) {
                    if category.from_recording() {
                        match candidates
                            .runs
                            .iter()
                            .find(|run| &run.label == sub)
                            .and_then(|run| self.processes.get(&reading_key(category, run)))
                        {
                            Some(Reading::Working(_)) => {
                                ui.horizontal(|ui| {
                                    theme::spinner(ui);
                                    ui.label(if category == Category::Trace {
                                        "Reading the Syscall Trace…"
                                    } else {
                                        "Reading the process tree…"
                                    });
                                });
                            }
                            Some(Reading::Failed(error)) => {
                                ui.colored_label(theme::error(), error);
                            }
                            _ => {}
                        }
                    }
                }
                if entries.is_empty() && !self.category.is_some_and(Category::from_recording) {
                    parts_line(ui, "Nothing matches.");
                }
                for (index, (category, reference)) in entries.iter().enumerate() {
                    let taken = taken.iter().any(|known| {
                        known.kind == reference.kind && known.target == reference.target
                    });
                    let text = if searching && self.category.is_none() {
                        format!("{}  ·  {}", category_word(*category), reference.label)
                    } else {
                        reference.label.clone()
                    };
                    let state = if taken {
                        RowState::Taken
                    } else if index == self.cursor {
                        RowState::Cursor
                    } else {
                        RowState::Normal
                    };
                    let response = pick_row(ui, category.icon(), &text, "", false, state)
                        .on_hover_text(&text);
                    if response.clicked() {
                        picked = Some(reference.clone());
                    }
                }
                if total > shown {
                    parts_line(ui, &format!("Showing {shown} of {total}"));
                }
                if self.category == Some(Category::Trace) && self.sub.is_some() {
                    parts_line(
                        ui,
                        &format!(
                            "The first {} calls of the run. Right-click any entry in the Syscall Trace to note one beyond them.",
                            TRACE_PAGES * TRACE_PAGE
                        ),
                    );
                }
            });
        if let Some((category, sub)) = step {
            self.category = category;
            self.sub = sub;
            self.cursor = 0;
            self.focus = true;
            if let (Some(category), Some(sub)) = (self.category, &self.sub) {
                if category.from_recording() {
                    if let Some(run) = candidates.runs.iter().find(|run| &run.label == sub) {
                        self.read_run(ui.ctx(), category, run);
                    }
                }
            }
        }
        if back {
            if self.sub.is_some() {
                self.sub = None;
            } else if self.category.is_some() {
                self.category = None;
            } else {
                close = true;
            }
            self.cursor = 0;
            self.focus = true;
        }
        (picked, close)
    }
}

fn parts_line(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::muted()));
}

fn category_word(category: Category) -> &'static str {
    match category {
        Category::Runs => "Run",
        Category::Processes => "Process",
        Category::Trace => "Trace entry",
        Category::Ioc => "IoC",
        Category::Files => "Artifact",
        Category::Custody => "Custody entry",
        Category::Lineage => "Lineage node",
    }
}

/// The last part of a path, for a process's label.
fn short_name(path: &str) -> &str {
    path.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
}

/// The icon and tone a reference chip of `kind` wears, so a note about a whole
/// run and a note about one trace entry of it read differently at a glance.
fn kind_style(kind: RefKind) -> (&'static str, Tone) {
    use egui_phosphor::regular as icon;
    match kind {
        RefKind::Run => (icon::PLAY_CIRCLE, Tone::Accent),
        RefKind::Process => (icon::TREE_STRUCTURE, Tone::Accent),
        RefKind::Call | RefKind::Trace => (icon::LIST_BULLETS, Tone::Info),
        RefKind::Indicator => (icon::CROSSHAIR, Tone::Warn),
        RefKind::Artifact => (icon::FILE, Tone::Good),
        RefKind::Custody => (icon::SCROLL, Tone::Neutral),
        RefKind::Lineage => (icon::GRAPH, Tone::Neutral),
    }
}

/// How a reference chip is drawn and what clicking it does.
pub(super) enum ChipOut {
    None,
    /// The chip itself: go to what it names.
    Open,
    /// The arrow of an artifact chip: open the file in its window.
    OpenFile,
    /// The chip's remove button (editor only).
    Remove,
}

/// Draw a reference as a chip. `exists` is false when what it names is gone.
pub(super) fn chip(
    ui: &mut egui::Ui,
    reference: &NoteRef,
    exists: bool,
    removable: bool,
) -> ChipOut {
    let mut out = ChipOut::None;
    let (icon, kind_tone) = kind_style(reference.kind);
    let tone = if exists { kind_tone } else { Tone::Neutral };
    let mut label = RichText::new(format!("{icon} {}", reference.label))
        .small()
        .color(tone.fg());
    if !exists {
        label = label.strikethrough();
    }
    ui.spacing_mut().item_spacing.x = 2.0;
    let main = ui
        .add(
            egui::Button::new(label)
                .fill(tone.bg())
                .corner_radius(10)
                .stroke(egui::Stroke::NONE),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(if exists {
            format!("{} · open it", reference.kind.label())
        } else {
            format!(
                "{} · it is no longer there (it was deleted or removed)",
                reference.kind.label()
            )
        });
    if main.clicked() {
        out = ChipOut::Open;
    }
    if reference.kind == RefKind::Artifact
        && exists
        && ui
            .add(egui::Button::new(RichText::new("↗").small().color(tone.fg())).fill(tone.bg()))
            .on_hover_text("Open the file in its window")
            .clicked()
    {
        out = ChipOut::OpenFile;
    }
    if removable
        && ui
            .add(egui::Button::new(RichText::new("✕").small().color(theme::muted())).frame(false))
            .on_hover_text("Remove the reference")
            .clicked()
    {
        out = ChipOut::Remove;
    }
    out
}

/// What the editor asks of the page.
pub(super) enum Outcome {
    None,
    Save {
        id: Option<i64>,
        sha256: String,
        text: String,
        refs: Vec<NoteRef>,
    },
    Cancel,
}

/// The Add note / Edit note window.
pub(super) struct Editor {
    sha256: String,
    sample: String,
    id: Option<i64>,
    text: String,
    refs: Vec<NoteRef>,
    candidates: Candidates,
    picker: Option<Picker>,
    error: Option<String>,
}

impl Editor {
    /// A new note on a sample, with `refs` attached.
    pub(super) fn new(data: &Data, refs: Vec<NoteRef>) -> Self {
        Self {
            sha256: data.record.sha256.clone(),
            sample: data.record.name.clone(),
            id: None,
            text: String::new(),
            refs,
            candidates: Candidates::of(data),
            picker: None,
            error: None,
        }
    }

    /// An existing note.
    pub(super) fn edit(data: &Data, note: &Note) -> Self {
        Self {
            id: Some(note.id),
            text: note.text.clone(),
            refs: note.refs.clone(),
            ..Self::new(data, Vec::new())
        }
    }

    pub(super) fn fail(&mut self, error: String) {
        self.error = Some(error);
    }

    pub(super) fn show(&mut self, ctx: &egui::Context, data: &Data) -> Outcome {
        let mut open = true;
        let mut outcome = Outcome::None;
        let title = if self.id.is_some() {
            "Edit note"
        } else {
            "Add note"
        };
        widgets::window(title)
            .id(egui::Id::new("sample_note_editor"))
            .open(&mut open)
            .default_width(520.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Sample").color(theme::muted()));
                    ui.label(&self.sample);
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Refers to").color(theme::muted()));
                    if self.refs.is_empty() {
                        ui.label(RichText::new("Nothing yet").color(theme::muted()));
                    }
                });
                let mut remove = None;
                ui.horizontal_wrapped(|ui| {
                    for (index, reference) in self.refs.iter().enumerate() {
                        if let ChipOut::Remove =
                            chip(ui, reference, reference_exists(reference, data), true)
                        {
                            remove = Some(index);
                        }
                    }
                    if self.picker.is_none() && widgets::link(ui, "Add reference").clicked() {
                        self.picker = Some(Picker::new());
                    }
                });
                if let Some(index) = remove {
                    self.refs.remove(index);
                }
                if let Some(picker) = &mut self.picker {
                    ui.add_space(4.0);
                    let (picked, close) = picker.show(ui, &self.candidates, &self.refs);
                    if let Some(reference) = picked {
                        self.refs.push(reference);
                        self.picker = None;
                    } else if close {
                        self.picker = None;
                    }
                }
                ui.add_space(6.0);
                ui.add(
                    egui::TextEdit::multiline(&mut self.text)
                        .hint_text(theme::hint_text("What this shows"))
                        .desired_rows(5)
                        .desired_width(f32::INFINITY)
                        .char_limit(MAX_NOTE),
                );
                if let Some(error) = &self.error {
                    ui.colored_label(theme::error(), error);
                }
                widgets::footer(ui, |ui| {
                    let ready = !self.text.trim().is_empty();
                    if ui
                        .add_enabled(
                            ready,
                            egui::Button::new(if self.id.is_some() {
                                "Save note"
                            } else {
                                "Add note"
                            }),
                        )
                        .clicked()
                    {
                        outcome = Outcome::Save {
                            id: self.id,
                            sha256: self.sha256.clone(),
                            text: self.text.clone(),
                            refs: self.refs.clone(),
                        };
                    }
                    if ui.button("Cancel").clicked() {
                        outcome = Outcome::Cancel;
                    }
                });
            });
        if !open {
            return Outcome::Cancel;
        }
        outcome
    }
}

/// Whether what a reference names is still in the sample's data.
pub(super) fn reference_exists(reference: &NoteRef, data: &Data) -> bool {
    let run = |vm: &str, id: &str| {
        data.runs
            .iter()
            .find(|entry| entry.run.vm_id == vm && entry.run.id == id)
    };
    match reference.kind {
        RefKind::Run => reference
            .run()
            .is_some_and(|(vm, id)| run(vm, id).is_some_and(|entry| entry.folder)),
        RefKind::Process | RefKind::Call | RefKind::Trace => reference
            .run()
            .is_some_and(|(vm, id)| run(vm, id).is_some_and(|entry| entry.folder)),
        RefKind::Indicator => data.runs.iter().any(|entry| {
            entry
                .digest
                .iter()
                .flat_map(|digest| digest.indicators.iter().flatten())
                .any(|found| format!("{}:{}", found.ty, found.value) == reference.target)
        }),
        RefKind::Artifact => data
            .outputs()
            .iter()
            .any(|output| output.reference().target == reference.target && output.is_present()),
        RefKind::Custody => reference
            .target
            .parse::<u64>()
            .is_ok_and(|seq| data.events.iter().any(|event| event.seq == seq)),
        RefKind::Lineage => {
            reference.target == data.record.sha256
                || lineage_nodes(data)
                    .iter()
                    .any(|node| node.target == reference.target)
        }
    }
}

impl SamplesPage {
    /// Open the editor for a new note on the open sample.
    pub(super) fn start_note(&mut self, refs: Vec<NoteRef>) {
        let Some(data) = self.detail.as_ref().and_then(|detail| detail.data.clone()) else {
            return;
        };
        self.note_editor = Some(Editor::new(&data, refs));
    }

    pub(in crate::app) fn edit_note(&mut self, note: &Note) {
        let Some(data) = self.detail.as_ref().and_then(|detail| detail.data.clone()) else {
            return;
        };
        self.note_editor = Some(Editor::edit(&data, note));
    }
}

impl MonitorApp {
    /// The note editor, and the requests menus made this frame.
    pub(super) fn note_windows(&mut self, ctx: &egui::Context) {
        // A request waits until the sample's data is read; one that names a
        // sample opens it first.
        if let Some(request) = peek_request(ctx) {
            let open = self.samples_page.detail.as_ref().map(|detail| {
                (
                    detail.sha256.clone(),
                    detail.data.is_some(),
                    detail.error.clone(),
                )
            });
            match (&request.sample, open) {
                (Some(sample), Some((open, _, _))) if *sample != open => {
                    self.samples_page.open_detail(sample);
                    self.open_library(crate::workspace::LibraryPage::Samples);
                }
                (Some(sample), None) => {
                    self.samples_page.open_detail(sample);
                    self.open_library(crate::workspace::LibraryPage::Samples);
                }
                (_, Some((_, _, Some(error)))) => {
                    clear_request(ctx);
                    self.samples_page.notice =
                        Some((format!("Cannot add the note: {error}"), true));
                }
                (_, Some((_, true, None))) => {
                    clear_request(ctx);
                    self.samples_page.start_note(vec![request.reference]);
                }
                (None, None) => {
                    clear_request(ctx);
                    self.samples_page.notice =
                        Some(("Open a sample first, then add the note.".into(), true));
                }
                _ => {}
            }
        }
        let Some(editor) = &mut self.samples_page.note_editor else {
            return;
        };
        let Some(data) = self
            .samples_page
            .detail
            .as_ref()
            .and_then(|detail| detail.data.clone())
        else {
            self.samples_page.note_editor = None;
            return;
        };
        match editor.show(ctx, &data) {
            Outcome::None => {}
            Outcome::Cancel => self.samples_page.note_editor = None,
            Outcome::Save {
                id,
                sha256,
                text,
                refs,
            } => self.save_note(id, &sha256, &text, &refs),
        }
    }

    /// Store the note the editor holds and close it; on a failure the editor
    /// stays open and says why.
    fn save_note(&mut self, id: Option<i64>, sha256: &str, text: &str, refs: &[NoteRef]) {
        let result = Library::open(&self.options.data_dir).and_then(|mut library| match id {
            Some(id) => library.edit_note(id, text, refs),
            None => library.add_note(sha256, text, refs).map(|_| ()),
        });
        match result {
            Ok(()) => {
                self.samples_page.note_editor = None;
                self.samples_page.notice = Some((
                    if id.is_some() {
                        "Note saved".into()
                    } else {
                        "Note added".into()
                    },
                    false,
                ));
                self.samples_page.refresh();
            }
            Err(error) => {
                if let Some(editor) = &mut self.samples_page.note_editor {
                    editor.fail(error);
                }
            }
        }
    }
}

#[cfg(test)]
impl MonitorApp {
    /// Type `text` into the open editor and press Add note.
    pub(in crate::app) fn save_open_note(&mut self, text: &str) {
        let Some(editor) = &mut self.samples_page.note_editor else {
            return;
        };
        editor.text = text.to_owned();
        let (id, sha256, refs) = (editor.id, editor.sha256.clone(), editor.refs.clone());
        self.save_note(id, &sha256, text, &refs);
    }
}

#[cfg(test)]
impl SamplesPage {
    /// Ask for a note the way a menu does.
    pub(in crate::app) fn ask_note(ctx: &egui::Context, reference: NoteRef) {
        ctx.data_mut(|data| {
            data.insert_temp(
                request_id(),
                Request {
                    reference,
                    sample: None,
                },
            )
        });
    }

    /// The labels of the open editor's references, and whether it edits.
    pub(in crate::app) fn note_editor_refs(&self) -> Option<(Vec<String>, bool)> {
        self.note_editor.as_ref().map(|editor| {
            (
                editor.refs.iter().map(|r| r.label.clone()).collect(),
                editor.id.is_some(),
            )
        })
    }

    /// The notes the window read: text and reference labels.
    pub(in crate::app) fn detail_notes(&self) -> Vec<(i64, String, Vec<String>)> {
        self.detail
            .as_ref()
            .and_then(|detail| detail.data.as_ref())
            .map(|data| {
                data.notes
                    .iter()
                    .map(|note| {
                        (
                            note.id,
                            note.text.clone(),
                            note.refs.iter().map(|r| r.label.clone()).collect(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How many entries each category of the picker offers.
    pub(in crate::app) fn picker_counts(&self) -> Vec<(&'static str, usize)> {
        let Some(editor) = &self.note_editor else {
            return Vec::new();
        };
        Category::ALL
            .into_iter()
            .map(|category| (category.label(), editor.candidates.count(category)))
            .collect()
    }

    /// What typing `text` into the picker's search field finds, by label.
    pub(in crate::app) fn picker_search(&self, text: &str) -> Vec<String> {
        let Some(editor) = &self.note_editor else {
            return Vec::new();
        };
        let mut picker = Picker::new();
        picker.search = text.to_owned();
        picker
            .entries(&editor.candidates)
            .0
            .iter()
            .map(|(category, reference)| {
                format!("{} · {}", category_word(*category), reference.label)
            })
            .collect()
    }

    /// Open the editor with several references, and no picker.
    pub(in crate::app) fn start_note_with_for_test(&mut self, refs: Vec<NoteRef>) {
        self.start_note(refs);
    }

    /// Open the editor on a reference, with the picker open when asked.
    pub(in crate::app) fn start_note_for_test(&mut self, reference: NoteRef, picker: bool) {
        self.start_note(vec![reference]);
        if let (true, Some(editor)) = (picker, &mut self.note_editor) {
            editor.picker = Some(Picker::new());
        }
    }

    pub(in crate::app) fn show_notes_tab(&mut self) {
        if let Some(detail) = &mut self.detail {
            detail.tab = super::detail::Tab::Notes;
        }
    }
}
