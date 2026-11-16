// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Sidebar host-file explorer; sends through the existing upload workflow.
use super::*;

impl MonitorApp {
    pub(super) fn explorer_sidebar(&mut self, ui: &mut egui::Ui) {
        let choose = section_header(
            ui,
            SectionHeader {
                title: "Explorer",
                count: None,
                tooltip: "Host files: click to fold",
                glyph: egui_phosphor::regular::FOLDER_OPEN,
                action: "Open Folder",
                blocked: "Install Zenity first",
                enabled: self.folder_picker.available(),
                open: false,
            },
            &mut self.settings.explorer_collapsed,
        )
        .clicked();
        if !self.settings.explorer_collapsed {
            if let Some(root) = &self.explorer_browser.root {
                let label = root
                    .file_name()
                    .unwrap_or(root.as_os_str())
                    .to_string_lossy();
                let mut refresh = false;
                let mut open = false;
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        // The folder name, then its Refresh button on its
                        // right; a long name is cut short to leave room.
                        let button = ui.spacing().interact_size.y + ui.spacing().item_spacing.x;
                        let name_width = (ui.available_width() - button).max(0.0);
                        ui.scope(|ui| {
                            ui.set_max_width(name_width);
                            let response = ui
                                .add(
                                    egui::Label::new(RichText::new(label.as_ref()).strong())
                                        .truncate(),
                                )
                                .on_hover_text(root.display().to_string());
                            response.context_menu(|ui| {
                                if ui.button("Open Directory").clicked() {
                                    open = true;
                                    ui.close();
                                }
                            });
                        });
                        refresh = icon(
                            ui,
                            egui_phosphor::regular::ARROW_CLOCKWISE,
                            "Refresh Explorer",
                            true,
                        );
                    });
                });
                if open {
                    open_directory(root);
                }
                if refresh {
                    self.explorer_browser.invalidate();
                }
            } else {
                ui.add_space(8.0);
                ui.colored_label(theme::muted(), "Browse files on this computer.");
            }
            if self.folder_picker.checking() {
                theme::loading_weak(ui, "Checking file chooser…");
            } else if !self.folder_picker.installed() {
                ui.colored_label(theme::muted(), "Install Zenity to choose a folder.");
            }
            let can_send = self.running() && self.pending_upload.is_none() && !self.closing;
            let height = ui.available_height();
            let action = if self.explorer_browser.root.is_some() {
                self.explorer_browser.show_explorer(ui, height, can_send)
            } else {
                None
            };
            if let Some(action) = action {
                match action {
                    upload_browser::Action::Select(_) => {}
                    upload_browser::Action::OpenDirectory(path) => open_directory(&path),
                    upload_browser::Action::SendRun(path) => self.send_explorer_file(path),
                    upload_browser::Action::SendOnly(path) => self.send_explorer_file_only(path),
                    upload_browser::Action::AddToSamples(path) => self.add_explorer_file(path),
                }
            }
        }
        if choose {
            self.open_folder_dialog();
        }
    }

    /// Add to Samples…: the Samples page opens with the Add file dialog on
    /// the file. Nothing is read until the dialog is confirmed or its path
    /// field is left.
    pub(super) fn add_explorer_file(&mut self, path: PathBuf) {
        self.open_library(LibraryPage::Samples);
        self.samples_page.open_add(Some(&path));
    }

    /// Send to VM: the upload path of the Upload file window, started at once
    /// with the same default destination; the file is not run.
    pub(super) fn send_explorer_file_only(&mut self, path: PathBuf) {
        if !self.running() || self.pending_upload.is_some() || self.closing {
            self.report_info(
                "Start the selected VM and wait for any pending upload before Send to VM".into(),
            );
            return;
        }
        let Some(source) = path.to_str() else {
            self.report_error(
                "The selected file was not sent: its path is not valid UTF-8; rename it or choose another file"
                    .into(),
            );
            return;
        };
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return;
        };
        self.source = source.into();
        self.destination = format!("/tmp/{name}");
        self.upload_browser.selected = Some(path);
        self.request_upload(false);
    }

    /// Open Folder: a small window for the folder path, with the folder
    /// browser one click away.
    pub(super) fn open_folder_dialog(&mut self) {
        let current = self
            .explorer_browser
            .root
            .as_ref()
            .map(|root| root.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.folder_dialog = Some(current);
    }

    pub(super) fn folder_dialog(&mut self, ctx: &egui::Context) {
        let Some(path) = &mut self.folder_dialog else {
            return;
        };
        let mut open = true;
        let mut accept = false;
        let mut cancel = false;
        let mut browse = false;
        let can_browse = self.folder_picker.available();
        crate::widgets::window("Open Folder")
            .id(Dialog::Folder.window_id())
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label("Folder on this computer");
                ui.horizontal(|ui| {
                    let edit = ui.add(
                        text_field(path)
                            .font(egui::TextStyle::Monospace)
                            .hint_text(crate::theme::placeholder(ui, "Enter a folder path"))
                            .desired_width(crate::theme::edit_width(360.0)),
                    );
                    if edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                        accept = true;
                    }
                    if icon(
                        ui,
                        egui_phosphor::regular::FOLDER_OPEN,
                        if can_browse {
                            "Choose a folder with the filesystem explorer"
                        } else {
                            "Install Zenity first"
                        },
                        can_browse,
                    ) {
                        browse = true;
                    }
                });
                let valid = crate::folders::user_path(path).is_dir();
                if !path.trim().is_empty() && !valid {
                    ui.colored_label(theme::muted(), "This is not a folder that exists.");
                }
                dialog_footer(ui, |ui| {
                    accept =
                        ui.add_enabled(valid, primary_button("OK")).clicked() || (accept && valid);
                    cancel = ui.button("Cancel").clicked();
                });
            });
        if accept {
            if let Some(path) = self.folder_dialog.take() {
                self.accept_explorer_folder(crate::folders::user_path(&path));
            }
        } else if browse {
            self.folder_dialog = None;
            self.choose_explorer_folder();
        } else if !open || cancel {
            self.folder_dialog = None;
        }
    }

    /// The filesystem explorer's folder chooser, for the explorer root.
    pub(super) fn choose_explorer_folder(&mut self) {
        if let Err(error) = self.folder_picker.choose(FolderTarget {
            generation: self.explorer_browser.generation,
            kind: FolderKind::ExplorerRoot,
        }) {
            self.report_error(format!("Explorer folder: {error}"));
        }
    }

    /// The explorer shows `path` and keeps it for the next start.
    pub(super) fn accept_explorer_folder(&mut self, path: PathBuf) {
        self.settings.explorer_root = Some(path.clone());
        self.settings.explorer_collapsed = false;
        self.explorer_browser.reset(path);
    }

    pub(super) fn send_explorer_file(&mut self, path: PathBuf) {
        if !self.running() || self.pending_upload.is_some() || self.closing {
            self.report_info(
                "Start the selected VM and wait for any pending upload before Send and Run".into(),
            );
            return;
        }
        let Some(source) = path.to_str() else {
            self.report_error(
                "The selected file was not sent: its path is not valid UTF-8; rename it or choose another file"
                    .into(),
            );
            return;
        };
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return;
        };
        let destination = format!("/tmp/{name}");
        self.open_upload();
        self.source = source.into();
        self.destination = destination;
        self.upload_browser.selected = Some(path);
        self.status = "Review the upload destination, then press Upload and Run".into();
    }
}
