// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Upload controls and the correlated, non-executing Run program handoff.
use super::*;
use crate::analysis::LaunchSource;

#[derive(Clone)]
pub(super) struct Intent {
    source: PathBuf,
    destination: String,
    executable: bool,
    run_after: bool,
    vm_id: String,
    boot_id: Option<String>,
    capture_dir: Option<PathBuf>,
}

impl Intent {
    pub(super) fn same_session(&self, snapshot: &Snapshot) -> bool {
        snapshot.active_vm.as_ref() == Some(&self.vm_id)
            && snapshot.boot_id == self.boot_id
            && snapshot.capture_dir == self.capture_dir
    }
}

pub(super) struct Pending {
    pub(super) id: u64,
    pub(super) intent: Intent,
}

impl MonitorApp {
    pub(super) fn open_upload(&mut self) {
        self.upload_browser.invalidate();
        self.launch_open = false;
        self.upload_open = true;
    }

    pub(super) fn close_upload(&mut self) {
        self.upload_open = false;
        self.cancel_upload_handoff();
    }

    /// Closing a dialog hides it and cancels the handoff, not the guest write.
    pub(super) fn cancel_upload_handoff(&mut self) {
        if let Some(upload) = &mut self.pending_upload {
            upload.intent.run_after = false;
        }
    }

    pub(super) fn upload_form(&mut self, ui: &mut egui::Ui) {
        dialog_section(ui, "Host file");
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    self.folder_picker.available() && self.pending_upload.is_none(),
                    egui::Button::new("Choose file…"),
                )
                .on_hover_text("Choose a file with the filesystem explorer")
                .clicked()
            {
                if let Err(error) = self.folder_picker.choose(FolderTarget {
                    generation: self.upload_browser.generation,
                    kind: FolderKind::UploadFile,
                }) {
                    self.report_error(format!("Host file: {error}"));
                }
            }
            if self.folder_picker.checking() {
                theme::loading_weak(ui, "Checking file chooser…");
            } else if !self.folder_picker.installed() {
                ui.colored_label(
                    theme::muted(),
                    "File selection requires Zenity; you can type a file path below.",
                );
            }
        });
        dialog_section(ui, "Upload destination");
        ui.add_enabled_ui(self.pending_upload.is_none(), |ui| {
            form_grid("upload", ui).show(ui, |ui| {
                ui.label("Host file");
                if ui
                    .add(
                        text_field(&mut self.source)
                            .font(egui::TextStyle::Monospace)
                            .hint_text(crate::theme::hint_text("Choose a file or enter its path"))
                            .desired_width(400.0),
                    )
                    .changed()
                {
                    self.upload_browser.selected = None;
                }
                ui.end_row();
                ui.label("Guest path");
                ui.add(
                    text_field(&mut self.destination)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(400.0),
                );
                ui.end_row();
                ui.label("Options");
                ui.vertical(|ui| {
                    ui.checkbox(&mut self.executable, "Executable");
                    ui.checkbox(&mut self.overwrite, "Overwrite existing file");
                });
                ui.end_row();
            });
        });
        if self.pending_upload.is_some() {
            theme::loading(ui, "Uploading…");
        } else if !self.running() {
            ui.colored_label(theme::muted(), "Start the selected VM to upload.");
        }
        let ready = self.running()
            && self.pending_upload.is_none()
            && !self.source.trim().is_empty()
            && !self.destination.trim().is_empty();
        dialog_footer(ui, |ui| {
            if ui.add_enabled(ready, egui::Button::new("Upload")).clicked() {
                self.request_upload(false);
            }
            if ui
                .add_enabled(ready, primary_button("Upload and Run"))
                .on_hover_text(
                    "Upload as executable, then open Run program to review launch settings",
                )
                .clicked()
            {
                self.request_upload(true);
            }
            if ui
                .button(if self.pending_upload.is_some() {
                    "Close"
                } else {
                    "Cancel"
                })
                .clicked()
            {
                self.close_upload();
            }
        });
    }

    pub(super) fn accept_upload_file(&mut self, generation: u64, path: PathBuf) {
        if !(self.upload_open || self.launch_open && self.launch_source == LaunchSource::Upload)
            || self.pending_upload.is_some()
            || generation != self.upload_browser.generation
        {
            return;
        }
        let Some(source) = path.to_str() else {
            self.report_warning("The selected file path is not valid UTF-8".into());
            return;
        };
        if !path.is_file() {
            self.report_warning("Choose a regular file to upload".into());
            return;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return;
        };
        let parent = std::path::Path::new(&self.destination)
            .parent()
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| std::path::Path::new("/tmp"));
        self.destination = parent.join(name).to_string_lossy().into_owned();
        self.source = source.into();
        self.upload_browser.selected = Some(path);
    }

    pub(super) fn request_upload(&mut self, run_after: bool) {
        if !self.running() || self.pending_upload.is_some() {
            self.report_warning(
                "Upload requires the selected running VM and no pending upload".into(),
            );
            return;
        }
        let Some(vm_id) = self.snapshot.active_vm.clone() else {
            return;
        };
        let intent = Intent {
            source: self
                .upload_browser
                .selected
                .clone()
                .unwrap_or_else(|| crate::folders::user_path(&self.source)),
            destination: self.destination.clone(),
            executable: self.executable || run_after,
            run_after,
            vm_id,
            boot_id: self.snapshot.boot_id.clone(),
            capture_dir: self.snapshot.capture_dir.clone(),
        };
        if self.overwrite {
            self.confirm = Some(Confirm::Upload(intent));
        } else {
            self.submit_upload(intent, false);
        }
    }

    /// The host file that was uploaded to `guest_path` in this VM session, for
    /// the run of it: static analysis can then use the host's copy.
    pub(super) fn uploaded_host_file(&self, guest_path: &str) -> Option<PathBuf> {
        self.uploaded
            .as_ref()
            .filter(|upload| {
                upload.destination == guest_path && upload.same_session(&self.snapshot)
            })
            .map(|upload| upload.source.clone())
    }

    pub(super) fn submit_upload(&mut self, intent: Intent, overwrite: bool) {
        if !intent.same_session(&self.snapshot) || !self.running() || self.pending_upload.is_some()
        {
            self.report_warning(
                "Upload cancelled: the selected VM session changed or an upload is pending".into(),
            );
            return;
        }
        let command = Command::Upload {
            source: intent.source.clone(),
            destination: intent.destination.clone(),
            executable: intent.executable,
            overwrite,
        };
        if let Some(id) = self.send_request(command) {
            self.pending_upload = Some(Pending { id, intent });
        }
    }

    pub(super) fn complete_upload(&mut self, id: u64, success: bool) {
        if !self
            .pending_upload
            .as_ref()
            .is_some_and(|upload| upload.id == id)
        {
            return;
        }
        let Some(upload) = self.pending_upload.take() else {
            return;
        };
        if !success || !upload.intent.run_after {
            return;
        }
        if !upload.intent.same_session(&self.snapshot) || !self.running() || self.closing {
            self.report_warning("Upload completed; Run program was not opened because the selected VM session changed".into());
            return;
        }
        self.exec.path = upload.intent.destination.clone();
        self.uploaded = Some(upload.intent);
        self.upload_open = false;
        self.launch_open = true;
        // The file is in the guest now: the dialog continues from its path.
        self.launch_source = LaunchSource::Guest;
        self.status = "Uploaded: review program settings, then press Run".into();
    }
}
