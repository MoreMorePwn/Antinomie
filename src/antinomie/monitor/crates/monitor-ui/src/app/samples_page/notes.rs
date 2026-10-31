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
use super::note_picker::{category_word, lineage_nodes, Candidates, Category, Picker};
use super::*;
use crate::widgets::{self, Tone};
use antinomie_monitor_core::samples::{Note, NoteRef, RefKind, MAX_NOTE};

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
        // The runs every view may file a note under.
        crate::query::NoteRun::publish(ctx, &self.snapshot.runs, &self.history);
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
