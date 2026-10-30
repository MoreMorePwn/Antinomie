// SPDX-License-Identifier: GPL-3.0-only
//! Notes on a sample: the editor window, the reference picker and the chips
//! that show a note's references.
//!
//! A menu anywhere in the app adds a note with one call: [`menu_item`] draws
//! "Add note to sample…" and, when it is clicked, leaves a request that the
//! Samples page picks up on its next frame and opens the editor with. The
//! editor lets the analyst pick references from the open sample's runs,
//! processes, indicators, artifacts, custody entries and lineage nodes.
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

/// "Add note to sample…" for a menu: on a click it asks the Samples page to
/// open the note editor with `reference` already attached, and closes the
/// menu. Returns whether it was clicked. The note goes to the open sample.
pub(in crate::app) fn menu_item(ui: &mut egui::Ui, reference: impl FnOnce() -> NoteRef) -> bool {
    let clicked = ui.button("Add note to sample…").clicked();
    if clicked {
        let reference = reference();
        ui.ctx()
            .data_mut(|data| data.insert_temp(request_id(), reference));
        ui.close_menu();
    }
    clicked
}

/// The reference a menu asked a note for, once.
fn take_request(ctx: &egui::Context) -> Option<NoteRef> {
    ctx.data_mut(|data| {
        let found = data.get_temp::<NoteRef>(request_id());
        data.remove::<NoteRef>(request_id());
        found
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Category {
    Runs,
    Processes,
    Ioc,
    Files,
    Custody,
    Lineage,
}

impl Category {
    const ALL: [Category; 6] = [
        Self::Runs,
        Self::Processes,
        Self::Ioc,
        Self::Files,
        Self::Custody,
        Self::Lineage,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Runs => "Runs",
            Self::Processes => "Processes",
            Self::Ioc => "IoC",
            Self::Files => "Files / artifacts",
            Self::Custody => "Custody entries",
            Self::Lineage => "Lineage nodes",
        }
    }

    /// Whether the category has a second level between it and its entries.
    fn has_subtypes(self) -> bool {
        matches!(self, Self::Processes | Self::Ioc | Self::Files)
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
        if category == Category::Processes {
            return self.runs.iter().filter(|run| run.folder).count();
        }
        self.list
            .iter()
            .filter(|found| found.category == category)
            .count()
    }

    fn subtypes(&self, category: Category) -> Vec<(String, usize)> {
        if category == Category::Processes {
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

type Processes = Result<Vec<(u32, String)>, String>;

enum Reading {
    Working(Receiver<Processes>),
    Ready(Vec<Candidate>),
    Failed(String),
}

/// The picker inside the editor: a search field and a cascade.
struct Picker {
    search: String,
    category: Option<Category>,
    sub: Option<String>,
    cursor: usize,
    focus: bool,
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

    /// Read the process tree of a run on a thread.
    fn read_processes(&mut self, ctx: &egui::Context, run: &RunInfo) {
        if self.processes.contains_key(&run.key) {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let (directory, pid, path) = (run.directory.clone(), run.pid, run.path.clone());
        let wake = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("note-processes".into())
            .spawn(move || {
                let cancel = std::sync::atomic::AtomicBool::new(false);
                let result = antinomie_monitor_core::recording::Recording {
                    directory,
                    manifest: serde_json::Value::Null,
                    events: Vec::new(),
                }
                .process_tree_cancellable(pid, &path, &cancel)
                .map(|(processes, _)| {
                    processes
                        .into_iter()
                        .map(|process| {
                            let exe = process.exe.unwrap_or_default();
                            let name = if exe.is_empty() { process.name } else { exe };
                            (process.pid, name)
                        })
                        .collect()
                })
                .map_err(|error| error.to_string());
                let _ = sender.send(result);
                wake.request_repaint();
            });
        self.processes.insert(
            run.key.clone(),
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
            let label = candidates
                .runs
                .iter()
                .find(|run| run.key == *key)
                .map(|run| run.label.clone())
                .unwrap_or_default();
            *reading = match result {
                Ok(found) => Reading::Ready(
                    found
                        .into_iter()
                        .map(|(pid, name)| {
                            candidate(
                                Category::Processes,
                                &label,
                                NoteRef::new(
                                    RefKind::Process,
                                    format!("{key}/{pid}"),
                                    format!(
                                        "{} {pid} · {}",
                                        short_name(&name),
                                        label.to_lowercase()
                                    ),
                                ),
                            )
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
            if category == Category::Processes {
                let run = candidates
                    .runs
                    .iter()
                    .find(|run| Some(&run.label) == self.sub.as_ref());
                match run.and_then(|run| self.processes.get(&run.key)) {
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
            None => "Search runs, processes, IoCs, files, custody entries and lineage nodes".into(),
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
                            .hint_text(hint)
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
        if self.category.is_some() && !searching && widgets::link(ui, "‹ Back").clicked() {
            back = true;
        }
        egui::ScrollArea::vertical()
            .id_salt("note_picker_rows")
            .max_height(180.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                if !searching && self.category.is_none() {
                    for category in Category::ALL {
                        let count = candidates.count(category);
                        let text = format!("{}  {count}", category.label());
                        if ui
                            .add_enabled(count > 0, egui::Button::new(text).frame(false))
                            .clicked()
                        {
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
                        let text = if count > 0 {
                            format!("{sub}  {count}")
                        } else {
                            sub.clone()
                        };
                        if ui.add(egui::Button::new(text).frame(false)).clicked() {
                            step = Some((Some(category), Some(sub)));
                        }
                    }
                    return;
                }
                if let (Some(sub), Some(Category::Processes)) = (&self.sub, self.category) {
                    match self.processes.get(
                        &candidates
                            .runs
                            .iter()
                            .find(|run| &run.label == sub)
                            .map_or_else(String::new, |run| run.key.clone()),
                    ) {
                        Some(Reading::Working(_)) => {
                            ui.horizontal(|ui| {
                                theme::spinner(ui);
                                ui.label("Reading the process tree…");
                            });
                        }
                        Some(Reading::Failed(error)) => {
                            ui.colored_label(theme::error(), error);
                        }
                        _ => {}
                    }
                }
                if entries.is_empty() && !matches!(self.category, Some(Category::Processes)) {
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
                    let response = ui.add_enabled(
                        !taken,
                        egui::Button::new(text)
                            .frame(false)
                            .selected(index == self.cursor),
                    );
                    if response.clicked() {
                        picked = Some(reference.clone());
                    }
                }
                if total > shown {
                    parts_line(ui, &format!("Showing {shown} of {total}"));
                }
            });
        if let Some((category, sub)) = step {
            self.category = category;
            self.sub = sub;
            self.cursor = 0;
            self.focus = true;
            if let (Some(Category::Processes), Some(sub)) = (self.category, &self.sub) {
                if let Some(run) = candidates.runs.iter().find(|run| &run.label == sub) {
                    self.read_processes(ui.ctx(), run);
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
    let tone = if exists { Tone::Accent } else { Tone::Neutral };
    let mut label = RichText::new(&reference.label).small().color(tone.fg());
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
            format!("{} · it is no longer there", reference.kind.label())
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
                        .hint_text("What this shows")
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
        RefKind::Process | RefKind::Call => reference
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
        // A request waits until the sample's data is read.
        let ready = self
            .samples_page
            .detail
            .as_ref()
            .is_some_and(|detail| detail.data.is_some());
        if let Some(reference) = ready.then(|| take_request(ctx)).flatten() {
            self.samples_page.start_note(vec![reference]);
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
        ctx.data_mut(|data| data.insert_temp(request_id(), reference));
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
