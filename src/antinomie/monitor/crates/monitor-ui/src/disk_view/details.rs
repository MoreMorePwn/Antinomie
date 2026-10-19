// SPDX-License-Identifier: MIT
//! The shared Details dock for the Disks tab: the open view, or the selected
//! file, directory or link, with Extract, Save, Open with and Static Analysis.
use super::{extraction::Intent, *};
use crate::theme;
use antinomie_monitor_core::disks::reader::DiskEntry;

const GUEST_NOTE: &str = "Guest file; never executed on the host.";

fn row(ui: &mut egui::Ui, label: &str, value: impl Into<String>) {
    ui.label(egui::RichText::new(label).color(theme::muted()));
    ui.add(egui::Label::new(egui::RichText::new(value.into()).monospace()).wrap());
    ui.end_row();
}

fn time(value: i64) -> String {
    u64::try_from(value)
        .ok()
        .map(crate::time_format::local_seconds)
        .unwrap_or_else(|| "Unavailable".into())
}

impl DiskView {
    /// The Details of the tab; the action it asks for goes to `out`.
    pub(crate) fn details(&mut self, ui: &mut egui::Ui) -> Option<DiskAction> {
        self.poll_save(ui.ctx());
        self.action = None;
        let Some(view) = self.bound.clone() else {
            ui.add_space(8.0);
            ui.colored_label(
                theme::muted(),
                "Open the current disk of a stopped VM in the Disks tab, then select a file or \
                 folder to see its details.",
            );
            return None;
        };
        egui::ScrollArea::vertical()
            .id_salt("disk_details")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                match self
                    .selection
                    .as_ref()
                    .map(|selection| selection.path.clone())
                {
                    Some(path) => self.entry_details(ui, &path),
                    None => self.view_details(ui, &view),
                }
                self.extracted_files(ui, &view);
            });
        self.action.take()
    }

    fn view_details(&mut self, ui: &mut egui::Ui, view: &CurrentDiskView) {
        theme::section(ui, "Current disk (VM off)");
        egui::Grid::new("disk_view_details")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                row(ui, "VM", view.vm_id.clone());
                row(ui, "Source layer", view.source.active_layer.clone());
                if let Some(parent) = &view.source.active_parent_id {
                    row(ui, "After checkpoint", parent.clone());
                }
                row(
                    ui,
                    "Read at",
                    crate::time_format::local_seconds(view.taken_ms / 1000),
                );
                row(ui, "Filesystem state", view.fs_state.label());
                row(ui, "Logical size", format_size(view.logical_size));
                row(ui, "Allocated", format_size(view.allocated_size));
                match &self.probe {
                    Some(Ok(probe)) => {
                        row(ui, "Label", display_name(&probe.label));
                        row(ui, "UUID", probe.uuid.clone());
                    }
                    Some(Err(error)) => row(ui, "Filesystem", error.clone()),
                    None => {}
                }
                for (index, layer) in view.source.layers.iter().enumerate() {
                    row(
                        ui,
                        if index == 0 { "Layers" } else { "" },
                        format!("{} · {}", layer.filename, format_size(layer.size)),
                    );
                }
            });
        ui.add_space(4.0);
        ui.add(
            egui::Label::new(
                egui::RichText::new(view.fs_state.explanation()).color(theme::muted()),
            )
            .wrap(),
        );
        ui.add_space(4.0);
        if ui.button("Close").clicked() {
            self.action = Some(DiskAction::Close);
        }
    }

    fn entry_details(&mut self, ui: &mut egui::Ui, path: &str) {
        theme::section(ui, "Entry");
        let Some(selection) = &self.selection else {
            return;
        };
        let info = match &selection.info {
            None => {
                ui.horizontal(|ui| {
                    theme::spinner(ui);
                    ui.colored_label(theme::muted(), "Reading…");
                });
                return;
            }
            Some(Err(error)) => {
                crate::activity::error(ui, error);
                return;
            }
            Some(Ok(info)) => info.clone(),
        };
        let hashed = selection.hashed;
        let entry = &info.entry;
        let numeric = self.settings.numeric_modes;
        egui::Grid::new("disk_entry_details")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                row(ui, "Path", display_name(&info.path));
                row(ui, "Name", display_name(&entry.name));
                row(ui, "Type", entry.kind.label());
                if matches!(entry.kind, DiskEntryKind::File | DiskEntryKind::Symlink) {
                    row(
                        ui,
                        "Size",
                        format!("{} bytes ({})", entry.size, format_size(entry.size)),
                    );
                }
                if let Some(target) = &entry.link_target {
                    row(ui, "Points to", display_name(target));
                }
                row(
                    ui,
                    "Mode",
                    format!(
                        "{}  {}",
                        mode_numeric(entry.mode),
                        mode_rwx(entry.kind, entry.mode)
                    ),
                );
                let _ = numeric;
                row(ui, "Owner", format!("{}:{}", entry.uid, entry.gid));
                row(ui, "Modified", time(entry.mtime));
                row(ui, "Accessed", time(entry.atime));
                row(ui, "Changed", time(entry.ctime));
                if let Some(sha) = &info.sha256 {
                    row(ui, "SHA-256", sha.clone());
                }
                if let Some(md5) = &info.md5 {
                    row(ui, "MD5", md5.clone());
                }
                if hashed && info.sha256.is_none() {
                    row(
                        ui,
                        "Hashes",
                        info.hash_note
                            .clone()
                            .unwrap_or_else(|| "not computed".into()),
                    );
                }
            });
        if entry.kind == DiskEntryKind::Dir {
            let loaded = self
                .tree
                .listings
                .get(path)
                .and_then(|listing| listing.result.as_ref())
                .and_then(|result| result.as_ref().ok())
                .map(|listing| listing.entries.len());
            ui.colored_label(
                theme::muted(),
                match loaded {
                    Some(count) => format!("{count} entries loaded in the current page"),
                    None => "Expand the folder to load its entries".to_string(),
                },
            );
            return;
        }
        ui.add_space(6.0);
        self.entry_buttons(
            ui,
            path,
            &info.entry,
            info.elf,
            info.sha256.is_none() && !hashed,
        );
        ui.add_space(2.0);
        ui.colored_label(theme::muted(), GUEST_NOTE);
    }

    fn entry_buttons(
        &mut self,
        ui: &mut egui::Ui,
        path: &str,
        entry: &DiskEntry,
        elf: bool,
        can_hash: bool,
    ) {
        let extractable = matches!(entry.kind, DiskEntryKind::File | DiskEntryKind::Symlink);
        let busy = self.extraction.running.contains(path);
        let size = entry.size;
        ui.horizontal_wrapped(|ui| {
            let viewable =
                extractable && (size <= VIEW_CAP || entry.kind == DiskEntryKind::Symlink);
            if ui
                .add_enabled(viewable && !busy, egui::Button::new("Extract to view"))
                .on_hover_text(
                    "Copy the file to the host and show its bytes (UTF-8, hex, hexdump…)",
                )
                .on_disabled_hover_text(if extractable {
                    "Files over 16 MiB are Save-to-host only"
                } else {
                    "Only files and link targets can be extracted"
                })
                .clicked()
            {
                self.request_extract(path.to_owned(), size, Intent::View);
            }
            if ui
                .add_enabled(extractable && !busy, egui::Button::new("Save to host…"))
                .on_hover_text("Extract the file and save a copy where you choose")
                .clicked()
            {
                self.request_extract(path.to_owned(), size, Intent::Save);
            }
            if ui
                .add_enabled(extractable && !busy, egui::Button::new("Open with…"))
                .on_hover_text("Extract the file and open it with the desktop's application")
                .clicked()
            {
                self.request_extract(path.to_owned(), size, Intent::OpenWith);
            }
            if ui
                .add_enabled(
                    elf && !busy && entry.kind == DiskEntryKind::File,
                    egui::Button::new("Hand to Static Analysis"),
                )
                .on_hover_text("Extract the file and analyze it offline, in the isolated worker")
                .on_disabled_hover_text("Only ELF files are handed over")
                .clicked()
            {
                self.request_extract(path.to_owned(), size, Intent::Analyze);
            }
            let hash = ui
                .add_enabled(
                    can_hash
                        && entry.kind == DiskEntryKind::File
                        && size <= self.settings.hash_cap(),
                    egui::Button::new("Compute hashes"),
                )
                .on_disabled_hover_text(format!(
                    "Files over {} are not hashed",
                    format_size(self.settings.hash_cap())
                ))
                .clicked();
            if hash {
                if let Some(selection) = self.selection.as_mut() {
                    selection.hashed = true;
                }
                let hash_cap = self.settings.hash_cap();
                let path = path.to_owned();
                self.queue_browse(
                    Purpose::Info { path: path.clone() },
                    DiskRequest::Info { path, hash_cap },
                    None,
                );
            }
            if busy {
                theme::spinner(ui);
            }
        });
        self.confirmations(ui);
    }

    /// Bars for what needs a second click: a file over the limit, a copy
    /// that another application would open.
    fn confirmations(&mut self, ui: &mut egui::Ui) {
        if let Some((path, size, intent)) = self.extraction.large.clone() {
            ui.horizontal_wrapped(|ui| {
                crate::activity::warning(
                    ui,
                    format!(
                        "{} is {}, over the {} extraction limit.",
                        display_name(&path),
                        format_size(size),
                        format_size(self.settings.extract_cap())
                    ),
                );
                if ui.button("Extract anyway").clicked() {
                    self.extraction.allow_large.insert(path.clone());
                    self.extraction.large = None;
                    self.request_extract(path, size, intent);
                }
                if ui.button("Cancel").clicked() {
                    self.extraction.large = None;
                }
            });
        }
        if let Some(host) = self.extraction.confirm_open.clone() {
            ui.horizontal_wrapped(|ui| {
                crate::activity::warning(
                    ui,
                    "This file came from the guest and may be hostile: the other application \
                     may render or run it.",
                );
                if ui.button("Open anyway").clicked() {
                    self.extraction.confirm_open = None;
                    self.action = Some(DiskAction::OpenWith(host));
                }
                if ui.button("Cancel").clicked() {
                    self.extraction.confirm_open = None;
                }
            });
        }
        if let Some((message, failed)) = &self.status {
            if *failed {
                crate::activity::error(ui, message);
            } else {
                ui.colored_label(theme::good(), message);
            }
        }
    }

    fn extracted_files(&mut self, ui: &mut egui::Ui, view: &CurrentDiskView) {
        if self.extracted.is_empty() {
            return;
        }
        ui.add_space(8.0);
        egui::CollapsingHeader::new(format!("Extracted files ({})", self.extracted.len()))
            .id_salt("disk_extracted")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("disk_extracted_files")
                    .num_columns(3)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        for file in &self.extracted {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(display_name(&file.guest_path)).monospace(),
                                )
                                .truncate(),
                            );
                            ui.colored_label(theme::muted(), format_size(file.size));
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(file.host_path.display().to_string())
                                        .monospace()
                                        .color(theme::muted()),
                                )
                                .truncate(),
                            )
                            .on_hover_text(format!("SHA-256 {}", file.sha256));
                            ui.end_row();
                        }
                    });
                if ui.button("Open directory").clicked() {
                    self.action = Some(DiskAction::OpenWith(view.extract_dir.clone()));
                }
            });
    }
}
