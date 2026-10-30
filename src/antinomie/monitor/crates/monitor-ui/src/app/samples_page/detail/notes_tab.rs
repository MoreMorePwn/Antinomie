// SPDX-License-Identifier: GPL-3.0-only
//! The Notes tab (the sample's notes with their references) and the
//! Summary's Latest note line.
use super::{parts, *};
use crate::app::samples_page::notes::{self, ChipOut};
use antinomie_monitor_core::samples::{Note, NoteRef, RefKind};

/// What a click in the tab asks for.
enum Act {
    Add,
    Edit(i64),
    Delete(i64),
    Open(NoteRef),
    OpenFile(NoteRef),
}

/// The newest note, with its date and a link to the tab. Absent without
/// notes. Returns whether the link was clicked.
pub(super) fn latest(ui: &mut egui::Ui, data: &Data) -> bool {
    let Some(note) = data.notes.first() else {
        return false;
    };
    let mut open = false;
    parts::section(ui, "Latest note", None, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(parts::second(note.created_ms)).color(theme::muted()));
            if parts::more(ui, &format!("Notes ({}) ›", data.notes.len())).clicked() {
                open = true;
            }
        });
        ui.add(egui::Label::new(first_lines(&note.text, 3)).selectable(true));
    });
    open
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
    frame.show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(parts::second(note.created_ms))
                    .small()
                    .color(theme::muted()),
            );
            if note.edited_ms.is_some() {
                ui.label(RichText::new("edited").small().color(theme::muted()));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let confirm = egui::Id::new(("sample_note_delete", note.id));
                let asking = ui.data(|d| d.get_temp::<bool>(confirm)).unwrap_or(false);
                if asking {
                    if ui.button("Keep").clicked() {
                        ui.data_mut(|d| d.insert_temp(confirm, false));
                    }
                    if ui.button("Delete note").clicked() {
                        *act = Some(Act::Delete(note.id));
                    }
                } else {
                    if widgets::link(ui, "Delete").clicked() {
                        ui.data_mut(|d| d.insert_temp(confirm, true));
                    }
                    if widgets::link(ui, "Edit").clicked() {
                        *act = Some(Act::Edit(note.id));
                    }
                }
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
            Some(Act::Edit(id)) => {
                if let Some(note) = data.notes.iter().find(|note| note.id == id) {
                    self.samples_page.edit_note(note);
                }
            }
            Some(Act::Delete(id)) => {
                let result = Library::open(&self.options.data_dir)
                    .and_then(|mut library| library.delete_note(id));
                self.samples_page.notice = Some(match result {
                    Ok(()) => ("Note deleted".into(), false),
                    Err(error) => (error, true),
                });
                self.samples_page.refresh();
            }
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
                    self.open_sample_run(&entry.run, crate::workspace::Panel::Trace, None);
                }
                None
            }
            RefKind::Custody => Some(Tab::Custody),
            RefKind::Indicator | RefKind::Artifact | RefKind::Lineage => Some(Tab::Summary),
        };
        if let (Some(tab), Some(detail)) = (tab, self.samples_page.detail.as_mut()) {
            detail.tab = tab;
        }
    }
}
