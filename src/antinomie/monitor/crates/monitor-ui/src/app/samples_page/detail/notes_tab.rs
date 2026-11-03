// SPDX-License-Identifier: GPL-3.0-only
//! The Notes tab (the sample's notes with their references) and the
//! Summary's Latest note line.
use super::{parts, *};
use crate::app::samples_page::notes::{self, ChipOut};
use antinomie_monitor_core::samples::{Note, NoteRef, RefKind};

/// What a click in the tab, or on the Summary's Latest note, asks for.
pub(super) enum Act {
    /// Go to the Notes tab.
    Tab,
    Add,
    Edit(i64),
    Delete(i64),
    Open(NoteRef),
    OpenFile(NoteRef),
}

/// The newest note, with its date, Edit and Delete, and a link to the tab.
/// Absent without notes.
pub(super) fn latest(ui: &mut egui::Ui, data: &Data) -> Option<Act> {
    let note = data.notes.first()?;
    let mut act = None;
    parts::section(ui, "Latest note", None, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(parts::second(note.created_ms)).color(theme::muted()));
            edited_label(ui, note);
            if parts::more(ui, &format!("Notes ({}) ›", data.notes.len())).clicked() {
                act = Some(Act::Tab);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                actions(ui, note, &mut act);
            });
        });
        let text = ui.add(egui::Label::new(first_lines(&note.text, 3)).sense(egui::Sense::click()));
        note_menu(&text, note, &mut act);
    });
    act
}

/// "edited <time>" after an edit.
fn edited_label(ui: &mut egui::Ui, note: &Note) {
    if let Some(ms) = note.edited_ms {
        ui.label(
            RichText::new(format!("edited {}", parts::second(ms)))
                .small()
                .color(theme::muted()),
        );
    }
}

fn confirm_id(note: &Note) -> egui::Id {
    egui::Id::new(("sample_note_delete", note.id))
}

/// Edit and Delete as icon buttons; Delete asks first.
fn actions(ui: &mut egui::Ui, note: &Note, act: &mut Option<Act>) {
    let confirm = confirm_id(note);
    let asking = ui.data(|d| d.get_temp::<bool>(confirm)).unwrap_or(false);
    if asking {
        if ui.button("Keep").clicked() {
            ui.data_mut(|d| d.insert_temp(confirm, false));
        }
        if ui.button("Delete note").clicked() {
            ui.data_mut(|d| d.insert_temp(confirm, false));
            *act = Some(Act::Delete(note.id));
        }
    } else {
        if ui
            .add(egui::Button::new(egui_phosphor::regular::TRASH).frame(false))
            .on_hover_text("Delete note")
            .clicked()
        {
            ui.data_mut(|d| d.insert_temp(confirm, true));
        }
        if ui
            .add(egui::Button::new(egui_phosphor::regular::PENCIL_SIMPLE).frame(false))
            .on_hover_text("Edit note")
            .clicked()
        {
            *act = Some(Act::Edit(note.id));
        }
    }
}

/// Right-click on a note: Edit, Delete (asks first) and Copy text.
fn note_menu(response: &egui::Response, note: &Note, act: &mut Option<Act>) {
    response.context_menu(|ui| {
        if ui.button("Edit").clicked() {
            *act = Some(Act::Edit(note.id));
            ui.close();
        }
        if ui.button("Delete…").clicked() {
            ui.data_mut(|d| d.insert_temp(confirm_id(note), true));
            ui.close();
        }
        if ui.button("Copy text").clicked() {
            ui.ctx().copy_text(note.text.clone());
            ui.close();
        }
    });
}

/// The first `lines` lines of a text, with an ellipsis when there is more.
fn first_lines(text: &str, lines: usize) -> String {
    let mut shown: Vec<&str> = text.lines().take(lines).collect();
    let more = text.lines().count() > lines;
    if more {
        shown.push("…");
    }
    shown.join("\n")
}

fn note_card(ui: &mut egui::Ui, note: &Note, data: &Data, act: &mut Option<Act>) {
    let palette = theme::palette();
    let frame = egui::Frame::new()
        .fill(palette.panel)
        .stroke(egui::Stroke::new(1.0_f32, palette.line_soft))
        .corner_radius(6)
        .inner_margin(10);
    // The card's own click (the right-click menu) is registered before its
    // content, from the rect of the last frame: one added after the content
    // would lie over the Edit and Delete buttons and take their clicks.
    let card_id = ui.id().with(("note-card", note.id));
    let last = ui.data(|d| d.get_temp::<egui::Rect>(card_id));
    let card = last.map(|rect| ui.interact(rect, card_id.with("menu"), egui::Sense::click()));
    let shown = frame.show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(parts::second(note.created_ms))
                    .small()
                    .color(theme::muted()),
            );
            edited_label(ui, note);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                actions(ui, note, act);
            });
        });
        ui.add(egui::Label::new(&note.text).selectable(true));
        if !note.refs.is_empty() {
            ui.add_space(2.0);
            ui.horizontal_wrapped(|ui| {
                for reference in &note.refs {
                    let exists = notes::reference_exists(reference, data);
                    match notes::chip(ui, reference, exists, false) {
                        ChipOut::Open => *act = Some(Act::Open(reference.clone())),
                        ChipOut::OpenFile => *act = Some(Act::OpenFile(reference.clone())),
                        ChipOut::None | ChipOut::Remove => {}
                    }
                }
            });
        }
    });
    ui.data_mut(|d| d.insert_temp(card_id, shown.response.rect));
    if let Some(card) = card {
        note_menu(&card, note, act);
    }
}

fn show(ui: &mut egui::Ui, data: &Data) -> Option<Act> {
    let mut act = None;
    ui.horizontal(|ui| {
        if ui.button("Add note…").clicked() {
            act = Some(Act::Add);
        }
        ui.label(RichText::new(format!("{} notes", data.notes.len())).color(theme::muted()));
    });
    ui.add_space(4.0);
    if data.notes.is_empty() {
        theme::empty_state(ui, "No notes yet.");
        return act;
    }
    egui::ScrollArea::vertical()
        .id_salt("sample_notes")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for note in &data.notes {
                note_card(ui, note, data, &mut act);
                ui.add_space(6.0);
            }
        });
    act
}

impl MonitorApp {
    pub(super) fn notes_tab(&mut self, ui: &mut egui::Ui, data: &Arc<Data>) {
        match show(ui, data) {
            Some(Act::Add) => self.samples_page.start_note(Vec::new()),
            Some(act @ (Act::Edit(_) | Act::Delete(_))) => self.apply_note_act(data, act),
            Some(Act::Tab) => {}
            Some(Act::Open(reference)) => self.open_reference(data, &reference),
            Some(Act::OpenFile(reference)) => {
                if let Some(output) = data
                    .outputs()
                    .iter()
                    .find(|output| output.reference().target == reference.target)
                {
                    let (number, kind) = (output.number, output.kind);
                    self.open_output(data, number, kind);
                }
            }
            None => {}
        }
    }

    /// Edit or delete a note (from the Notes tab or the Summary).
    pub(super) fn apply_note_act(&mut self, data: &Arc<Data>, act: Act) {
        match act {
            Act::Edit(id) => {
                if let Some(note) = data.notes.iter().find(|note| note.id == id) {
                    self.samples_page.edit_note(note);
                }
            }
            Act::Delete(id) => {
                let result = Library::open(&self.options.data_dir)
                    .and_then(|mut library| library.delete_note(id));
                self.samples_page.notice = Some(match result {
                    Ok(()) => ("Note deleted".into(), false),
                    Err(error) => (error, true),
                });
                self.samples_page.refresh();
            }
            _ => {}
        }
    }

    /// Go to what a note's reference names.
    fn open_reference(&mut self, data: &Arc<Data>, reference: &NoteRef) {
        let run = reference.run().and_then(|(vm, id)| {
            data.runs
                .iter()
                .find(|entry| entry.run.vm_id == vm && entry.run.id == id && entry.folder)
        });
        let tab = match reference.kind {
            RefKind::Run => {
                if let Some(entry) = run {
                    self.open_sample_run(&entry.run, crate::workspace::Panel::Triage, None);
                }
                None
            }
            RefKind::Process => {
                if let (Some(entry), Some(pid)) = (run, reference.number()) {
                    self.open_sample_run(
                        &entry.run,
                        crate::workspace::Panel::Trace,
                        Some(format!("process.pid == {pid}")),
                    );
                }
                None
            }
            RefKind::Call => {
                if let Some(entry) = run {
                    // The call by its id, when the note kept one.
                    let filter = reference.number().map(|call| format!("call.id == {call}"));
                    self.open_sample_run(&entry.run, crate::workspace::Panel::Trace, filter);
                }
                None
            }
            RefKind::Trace => {
                // The Syscall Trace of the run, filtered to the one record.
                if let (Some(entry), Some(seq)) = (run, reference.number()) {
                    self.open_sample_run(
                        &entry.run,
                        crate::workspace::Panel::Trace,
                        Some(format!("event.sequence == {seq}")),
                    );
                }
                None
            }
            RefKind::Packet
            | RefKind::Capture
            | RefKind::MemoryDump
            | RefKind::DiskDump
            | RefKind::ProcessCore => {
                self.open_note_surface(reference);
                None
            }
            RefKind::StaticRow => {
                self.open_static_row(data, reference);
                None
            }
            RefKind::Custody => Some(Tab::Custody),
            RefKind::Indicator | RefKind::Artifact | RefKind::Lineage => Some(Tab::Summary),
        };
        if let (Some(tab), Some(detail)) = (tab, self.samples_page.detail.as_mut()) {
            detail.tab = tab;
            // The tab centres on what the chip names.
            detail.focus = Some(reference.clone());
        }
    }
}
