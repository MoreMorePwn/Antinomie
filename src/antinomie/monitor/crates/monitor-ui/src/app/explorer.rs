// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Sidebar host-file explorer; sends through the existing upload workflow.
use super::*;

impl MonitorApp {
    pub(super) fn explorer_sidebar(&mut self, ui: &mut egui::Ui) {
        let mut choose = section_header(
            ui,
            SectionHeader {
                title: "Explorer",
                count: usize::from(self.explorer_browser.root.is_some()),
                tooltip: "Host files: click to fold",
                action: "Choose Explorer folder",
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
                        refresh = icon(
                            ui,
                            egui_phosphor::regular::ARROW_CLOCKWISE,
                            "Refresh Explorer",
                            true,
                        );
                        let response = ui
                            .add(
                                egui::Label::new(RichText::new(label.as_ref()).strong()).truncate(),
                            )
                            .on_hover_text(root.display().to_string());
                        response.context_menu(|ui| {
                            if ui.button("Open Directory").clicked() {
                                open = true;
                                ui.close_menu();
                            }
                        });
                    });
                });
                if open {
                    open_directory(root);
                }
                if refresh {
                    self.explorer_browser.invalidate();
                }
            } else {
                choose |= ui
                    .add_enabled(
                        self.folder_picker.available(),
                        egui::Button::new("Choose folder…"),
                    )
                    .clicked();
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
                }
            }
        }
        if choose {
            if let Err(error) = self.folder_picker.choose(FolderTarget {
                generation: self.explorer_browser.generation,
                kind: FolderKind::ExplorerRoot,
            }) {
                self.report_error(format!("Explorer folder: {error}"));
            }
        }
    }

    pub(super) fn send_explorer_file(&mut self, path: PathBuf) {
        if !self.running() || self.pending_upload.is_some() || self.closing {
            self.report_warning(
                "Start the selected VM and wait for any pending upload before Send and Run".into(),
            );
            return;
        }
        let Some(source) = path.to_str() else {
            self.report_warning("The selected file path is not valid UTF-8".into());
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
