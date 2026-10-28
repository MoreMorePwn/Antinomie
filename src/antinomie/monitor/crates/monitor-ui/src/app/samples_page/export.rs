// SPDX-License-Identifier: GPL-3.0-only
//! Export custody record…: the sample's log as JSON (with a verifier beside
//! it) or HTML, optionally signed with the analyst's own minisign or SSH key.
//! The app has no key of its own and never asks for a passphrase.
use super::custody_parts;
use crate::{theme, widgets};
use antinomie_monitor_core::samples::{
    ChainCheck, ExportFormat, Exported, Library, SampleRecord, SignWith, Signer,
};
use eframe::egui::{self, RichText};
use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sign {
    None,
    Minisign,
    Ssh,
}

pub(in crate::app) struct ExportDialog {
    sha256: String,
    name: String,
    check: ChainCheck,
    format: ExportFormat,
    sign: Sign,
    key: String,
    destination: String,
    /// The analyst typed the destination: the extension no longer follows
    /// the format.
    destination_edited: bool,
    working: Option<Receiver<Result<Exported, String>>>,
    result: Option<Result<Exported, String>>,
    /// The log changed (the export noted itself): the page reads it again.
    pub(super) wrote: bool,
    pub(super) open: bool,
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn default_key(sign: Sign) -> String {
    match sign {
        Sign::None => String::new(),
        Sign::Minisign => home().join(".minisign/minisign.key").display().to_string(),
        Sign::Ssh => home().join(".ssh/id_ed25519").display().to_string(),
    }
}

impl ExportDialog {
    pub(super) fn new(record: &SampleRecord, check: ChainCheck) -> Self {
        let mut dialog = Self {
            sha256: record.sha256.clone(),
            name: record.name.clone(),
            check,
            format: ExportFormat::Json,
            sign: Sign::None,
            key: String::new(),
            destination: String::new(),
            destination_edited: false,
            working: None,
            result: None,
            wrote: false,
            open: true,
        };
        dialog.follow_format();
        dialog
    }

    fn follow_format(&mut self) {
        if !self.destination_edited {
            let file: String = self
                .name
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                        c
                    } else {
                        '_'
                    }
                })
                .take(40)
                .collect();
            self.destination = home()
                .join(format!(
                    "custody-{file}-{}.{}",
                    &self.sha256[..8],
                    self.format.extension()
                ))
                .display()
                .to_string();
        }
    }

    fn start(&mut self, ctx: &egui::Context, data_dir: &std::path::Path) {
        let signer = match self.sign {
            Sign::None => None,
            Sign::Minisign => Some(SignWith {
                signer: Signer::Minisign,
                key: PathBuf::from(self.key.trim()),
            }),
            Sign::Ssh => Some(SignWith {
                signer: Signer::Ssh,
                key: PathBuf::from(self.key.trim()),
            }),
        };
        let (sender, receiver) = mpsc::channel();
        let (data_dir, sha256, format) = (data_dir.to_path_buf(), self.sha256.clone(), self.format);
        let destination = PathBuf::from(self.destination.trim());
        let wake = ctx.clone();
        match std::thread::Builder::new()
            .name("custody-export".into())
            .spawn(move || {
                let result = Library::open(&data_dir).and_then(|mut library| {
                    library.export_custody(&sha256, format, &destination, signer.as_ref())
                });
                let _ = sender.send(result);
                wake.request_repaint();
            }) {
            Ok(_) => self.working = Some(receiver),
            Err(error) => self.result = Some(Err(error.to_string())),
        }
    }

    pub(super) fn show(&mut self, ctx: &egui::Context, data_dir: &std::path::Path) {
        if let Some(receiver) = &self.working {
            if let Ok(result) = receiver.try_recv() {
                self.working = None;
                self.wrote |= result.is_ok();
                self.result = Some(result);
            }
        }
        let mut open = true;
        let mut start = false;
        let mut close = false;
        widgets::window(format!("Export custody record: {}", self.name))
            .id(egui::Id::new("samples_export_custody"))
            .open(&mut open)
            .default_width(560.0)
            .resizable(false)
            .show(ctx, |ui| {
                let busy = self.working.is_some();
                ui.horizontal_wrapped(|ui| {
                    if self.check.ok() {
                        ui.colored_label(theme::good(), "Chain verified.");
                        ui.label(format!("{} entries. Head", self.check.entries));
                        custody_parts::head(ui, &self.check.head);
                    } else {
                        ui.colored_label(
                            theme::error(),
                            format!(
                                "{}. The export marks that entry and everything after it as unverified.",
                                self.check.summary().trim_end_matches('.')
                            ),
                        );
                    }
                });
                ui.add_space(6.0);
                ui.add_enabled_ui(!busy && self.result.is_none(), |ui| {
                    ui.label(RichText::new("Format").color(theme::muted()));
                    ui.horizontal(|ui| {
                        let before = self.format;
                        ui.radio_value(&mut self.format, ExportFormat::Json, "JSON")
                            .on_hover_text(
                                "The entries and hashes, with verify-custody.py written beside it",
                            );
                        ui.radio_value(&mut self.format, ExportFormat::Html, "HTML")
                            .on_hover_text("A readable record with the JSON embedded");
                        if before != self.format {
                            self.follow_format();
                        }
                    });
                    ui.add_space(4.0);
                    ui.label(RichText::new("Signature").color(theme::muted()));
                    let before = self.sign;
                    ui.radio_value(&mut self.sign, Sign::None, "Do not sign");
                    ui.radio_value(&mut self.sign, Sign::Minisign, "Sign with your minisign key")
                        .on_hover_text("Runs minisign -S with the key file below");
                    ui.radio_value(&mut self.sign, Sign::Ssh, "Sign with an SSH key")
                        .on_hover_text(format!(
                            "Runs ssh-keygen -Y sign, namespace {}",
                            antinomie_monitor_core::samples::SSH_NAMESPACE
                        ));
                    if before != self.sign {
                        self.key = default_key(self.sign);
                    }
                    if self.sign != Sign::None {
                        ui.horizontal(|ui| {
                            ui.label("Key file");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.key)
                                    .hint_text(theme::hint_text("Your own key, not an app key"))
                                    .desired_width(380.0),
                            );
                        });
                        ui.label(
                            RichText::new(
                                "Antinomie never reads the key or asks for a passphrase. A key \
                                 that needs one must be loaded in your agent.",
                            )
                            .weak()
                            .small(),
                        );
                    }
                    ui.add_space(4.0);
                    ui.label(RichText::new("Save as").color(theme::muted()));
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut self.destination)
                                .desired_width(f32::INFINITY),
                        )
                        .changed()
                    {
                        self.destination_edited = true;
                    }
                });
                ui.add_space(4.0);
                custody_parts::note(ui);
                match &self.result {
                    Some(Ok(done)) => {
                        ui.colored_label(
                            theme::good(),
                            format!("Exported {} entries to {}", done.entries, done.path.display()),
                        );
                        if let Some(path) = &done.verifier {
                            ui.label(format!("Verifier: {}", path.display()));
                        }
                        if let Some(path) = &done.signature {
                            ui.label(format!("Signature: {}", path.display()));
                        }
                    }
                    Some(Err(error)) => {
                        ui.colored_label(theme::error(), error);
                    }
                    None => {}
                }
                widgets::footer(ui, |ui| {
                    if self.result.is_some() {
                        close = ui.button("Close").clicked();
                        if self.result.as_ref().is_some_and(Result::is_err)
                            && ui.button("Back").clicked()
                        {
                            self.result = None;
                        }
                    } else {
                        let ready = !self.destination.trim().is_empty()
                            && (self.sign == Sign::None || !self.key.trim().is_empty());
                        start = ui
                            .add_enabled(ready && !busy, egui::Button::new("Export"))
                            .clicked();
                        close = ui.button("Cancel").clicked();
                        if busy {
                            theme::spinner(ui);
                        }
                    }
                });
            });
        if start {
            self.start(ctx, data_dir);
        }
        if close || !open {
            self.open = false;
        }
    }
}

#[cfg(test)]
impl ExportDialog {
    pub(in crate::app) fn set_destination(&mut self, path: &std::path::Path) {
        self.destination = path.display().to_string();
        self.destination_edited = true;
    }
    pub(in crate::app) fn set_format(&mut self, format: ExportFormat) {
        self.format = format;
        self.follow_format();
    }
    pub(in crate::app) fn begin(&mut self, ctx: &egui::Context, data_dir: &std::path::Path) {
        self.start(ctx, data_dir);
    }
    pub(in crate::app) fn outcome(&self) -> Option<&Result<Exported, String>> {
        self.result.as_ref()
    }
}
