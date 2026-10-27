// SPDX-License-Identifier: GPL-3.0-only
//! The Add file… dialog: the file is read and hashed, never run or unpacked;
//! a hash the library already has adds an origin to the existing sample
//! instead of a second row.
use super::picker::TagPicker;
use crate::{sample_tags, theme, widgets};
use antinomie_monitor_core::samples::{
    Added, FileProbe, Library, NewOrigin, NewSample, OriginKind, Tag,
};
use eframe::egui::{self, RichText};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
};

enum Probe {
    Idle,
    Reading(Receiver<Result<FileProbe, String>>),
    Ready(FileProbe),
    Failed(String),
}

pub(super) struct AddDialog {
    pub(super) path: String,
    probe: Probe,
    name: String,
    name_edited: bool,
    description: String,
    tags: TagPicker,
    tags_open: bool,
    delete_original: bool,
    adding: Option<Receiver<Result<Added, String>>>,
    error: Option<String>,
    /// The last path that was probed, so a path is read once however often
    /// the field is redrawn.
    probed: String,
}

/// What the dialog asks of the page after a frame.
pub(super) enum Outcome {
    None,
    Close,
    ChooseFile,
    Added(Added),
}

impl AddDialog {
    pub(super) fn new(path: Option<&Path>, delete_original: bool) -> Self {
        Self {
            path: path
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            probe: Probe::Idle,
            name: String::new(),
            name_edited: false,
            description: String::new(),
            tags: TagPicker::default(),
            tags_open: false,
            delete_original,
            adding: None,
            error: None,
            probed: String::new(),
        }
    }

    pub(super) fn set_path(&mut self, path: &Path) {
        self.path = path.display().to_string();
        self.probed.clear();
    }

    pub(super) fn delete_original(&self) -> bool {
        self.delete_original
    }

    #[cfg(test)]
    pub(super) fn ready(&self) -> bool {
        matches!(self.probe, Probe::Ready(_))
    }

    #[cfg(test)]
    pub(super) fn tick_delete_original(&mut self) {
        self.delete_original = true;
    }

    fn start_probe(&mut self, ctx: &egui::Context, data_dir: &Path) {
        let path = self.path.trim().to_owned();
        self.probed.clone_from(&path);
        self.error = None;
        if path.is_empty() {
            self.probe = Probe::Idle;
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let data_dir = data_dir.to_path_buf();
        let wake = ctx.clone();
        let probing = PathBuf::from(&path);
        let started = std::thread::Builder::new()
            .name("sample-probe".into())
            .spawn(move || {
                let result =
                    Library::open(&data_dir).and_then(|library| library.probe_file(&probing));
                let _ = sender.send(result);
                wake.request_repaint();
            });
        self.probe = match started {
            Ok(_) => Probe::Reading(receiver),
            Err(error) => Probe::Failed(error.to_string()),
        };
    }

    fn poll(&mut self) {
        if let Probe::Reading(receiver) = &self.probe {
            if let Ok(result) = receiver.try_recv() {
                self.probe = match result {
                    Ok(probe) => {
                        if !self.name_edited {
                            self.name.clone_from(&probe.name);
                        }
                        Probe::Ready(probe)
                    }
                    Err(error) => Probe::Failed(error),
                };
            }
        }
    }

    fn add(&mut self, ctx: &egui::Context, data_dir: &Path) {
        let (sender, receiver) = mpsc::channel();
        let data_dir = data_dir.to_path_buf();
        let path = PathBuf::from(self.path.trim());
        let new = NewSample {
            name: self.name.trim().to_owned(),
            description: self.description.trim().to_owned(),
            tags: self.tags.tags(),
            origin: NewOrigin {
                kind: OriginKind::Added,
                source: "Add file".into(),
                path: path.display().to_string(),
                ..NewOrigin::default()
            },
            ..NewSample::default()
        };
        let delete = self.delete_original;
        let wake = ctx.clone();
        match std::thread::Builder::new()
            .name("sample-add".into())
            .spawn(move || {
                let result = Library::open(&data_dir)
                    .and_then(|mut library| library.add_file(&path, new, delete));
                let _ = sender.send(result);
                wake.request_repaint();
            }) {
            Ok(_) => self.adding = Some(receiver),
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    pub(super) fn show(
        &mut self,
        ctx: &egui::Context,
        data_dir: &Path,
        can_choose: bool,
        known_custom: &[Tag],
    ) -> Outcome {
        if self.probed != self.path.trim() && self.adding.is_none() && self.path.trim().is_empty() {
            self.probe = Probe::Idle;
            self.probed.clear();
        }
        self.poll();
        if let Some(receiver) = &self.adding {
            if let Ok(result) = receiver.try_recv() {
                self.adding = None;
                match result {
                    Ok(added) => return Outcome::Added(added),
                    Err(error) => self.error = Some(error),
                }
            }
        }
        let mut outcome = Outcome::None;
        let mut open = true;
        widgets::window("Add file")
            .id(egui::Id::new("samples_add_file"))
            .open(&mut open)
            .default_width(520.0)
            .resizable(false)
            .show(ctx, |ui| {
                let busy = self.adding.is_some();
                egui::Grid::new("samples_add_grid")
                    .num_columns(2)
                    .spacing([10.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("File").color(theme::muted()));
                        ui.horizontal(|ui| {
                            let edit = ui.add_enabled(
                                !busy,
                                egui::TextEdit::singleline(&mut self.path)
                                    .hint_text(theme::hint_text("Path on this computer"))
                                    .desired_width(300.0),
                            );
                            if (edit.lost_focus() && self.probed != self.path.trim())
                                || (self.probed.is_empty() && !self.path.trim().is_empty())
                            {
                                self.start_probe(ctx, data_dir);
                            }
                            if ui
                                .add_enabled(can_choose && !busy, egui::Button::new("Choose file…"))
                                .clicked()
                            {
                                outcome = Outcome::ChooseFile;
                            }
                        });
                        ui.end_row();
                        match &self.probe {
                            Probe::Idle => {}
                            Probe::Reading(_) => {
                                ui.label("");
                                theme::loading(ui, "Reading and hashing…");
                                ui.end_row();
                            }
                            Probe::Failed(error) => {
                                ui.label("");
                                ui.colored_label(theme::error(), error);
                                ui.end_row();
                            }
                            Probe::Ready(probe) => {
                                ui.label(RichText::new("Size").color(theme::muted()));
                                ui.label(
                                    RichText::new(antinomie_monitor_core::byte_size::file_size(
                                        probe.size,
                                    ))
                                    .monospace(),
                                );
                                ui.end_row();
                                ui.label(RichText::new("SHA-256").color(theme::muted()));
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&probe.sha256).monospace().small(),
                                    )
                                    .wrap(),
                                );
                                ui.end_row();
                                ui.label(RichText::new("Type").color(theme::muted()));
                                ui.label(if probe.arch.is_empty() {
                                    probe.file_type.clone()
                                } else {
                                    format!("{} · {}", probe.file_type, probe.arch)
                                });
                                ui.end_row();
                                ui.label(RichText::new("In Samples").color(theme::muted()));
                                if probe.known {
                                    widgets::chip(
                                        ui,
                                        "Yes: this adds an origin",
                                        widgets::Tone::Info,
                                    );
                                } else {
                                    ui.label("No");
                                }
                                ui.end_row();
                            }
                        }
                        ui.label(RichText::new("Name").color(theme::muted()));
                        if ui
                            .add_enabled(
                                !busy,
                                egui::TextEdit::singleline(&mut self.name).desired_width(300.0),
                            )
                            .changed()
                        {
                            self.name_edited = true;
                        }
                        ui.end_row();
                        ui.label(RichText::new("Description").color(theme::muted()));
                        ui.add_enabled(
                            !busy,
                            egui::TextEdit::multiline(&mut self.description)
                                .desired_rows(2)
                                .desired_width(300.0),
                        );
                        ui.end_row();
                        ui.label(RichText::new("Tags").color(theme::muted()));
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 4.0;
                            for tag in self.tags.tags() {
                                sample_tags::tag(ui, &tag);
                            }
                            if ui
                                .button(if self.tags_open { "Done" } else { "Tags…" })
                                .clicked()
                            {
                                self.tags_open = !self.tags_open;
                            }
                        });
                        ui.end_row();
                    });
                if self.tags_open {
                    ui.add_space(4.0);
                    egui::Frame::new()
                        .fill(theme::palette().panel)
                        .inner_margin(8)
                        .corner_radius(6)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            self.tags.show(ui, &[], known_custom);
                        });
                }
                ui.add_space(6.0);
                ui.add_enabled(
                    !busy,
                    egui::Checkbox::new(
                        &mut self.delete_original,
                        "Delete the original after it is archived",
                    ),
                )
                .on_hover_text(
                    "The archive is read back and its hash checked first. The file is deleted \
                     with a plain delete and its path is logged.",
                );
                if let Some(error) = &self.error {
                    ui.colored_label(theme::error(), error);
                }
                let ready = matches!(self.probe, Probe::Ready(..));
                widgets::footer(ui, |ui| {
                    if ui
                        .add_enabled(ready && !busy, egui::Button::new("Add"))
                        .clicked()
                    {
                        self.add(ctx, data_dir);
                    }
                    if ui.button("Cancel").clicked() {
                        outcome = Outcome::Close;
                    }
                    if busy {
                        theme::loading(ui, "Archiving…");
                    }
                });
            });
        if !open {
            return Outcome::Close;
        }
        outcome
    }
}
