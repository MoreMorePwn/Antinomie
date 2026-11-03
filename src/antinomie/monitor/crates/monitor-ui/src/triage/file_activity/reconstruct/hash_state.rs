// SPDX-License-Identifier: GPL-3.0-only
//! The Hash check of the File Reconstruction window. A reconstruction with
//! every byte known is hashed (SHA-256, MD5, SHA-1) as a normal state, like a
//! file elsewhere in the app, and compared with the guest's hash. One with
//! unknown bytes or gaps cannot match the real file, so its hash control is
//! disabled and says why.
use super::{Hashed, Open, Pending};
use crate::theme;
use crate::widgets::{self, Tone};
use antinomie_monitor_core::file_reconstruct::Incomplete;
use eframe::egui::{self, RichText};

/// Largest reconstruction hashed without being asked: the hash of each step of
/// the slider would otherwise read a big file again and again.
const AUTO_HASH_LIMIT: u64 = 64 << 20;

fn plural(count: u64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

impl Open {
    /// Why this state cannot be hashed, or None when it can.
    fn hash_blocker(&self) -> Option<String> {
        if !self.map.size_known() {
            return Some(
                "The file's size is not known: a hash would not match the real file".into(),
            );
        }
        let counts = self.map.counts();
        if counts.missing() == 0 {
            return None;
        }
        let (gaps, unknown) = self.map.gaps();
        let mut parts = Vec::new();
        if gaps > 0 {
            parts.push(plural(gaps, "gap", "gaps"));
        }
        if unknown > 0 {
            parts.push(plural(unknown, "unknown byte", "unknown bytes"));
        }
        Some(format!(
            "{}: a hash would not match the real file",
            parts.join(", ")
        ))
    }

    fn start_hashing(&mut self, ctx: &egui::Context) {
        let map = self.map.clone();
        let position = map.position();
        self.hashing = Some(Pending::spawn(ctx, move || Hashed {
            position,
            result: map.digests(),
        }));
    }

    pub(super) fn hash(
        &mut self,
        ui: &mut egui::Ui,
        file: &super::FileActivity,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        let mut guest: Vec<(String, String)> = file
            .hashes
            .iter()
            .filter_map(|note| {
                Some((
                    note.sha256.clone()?,
                    format!(
                        "{} at {}",
                        note.moment,
                        crate::time_format::guest_ns(clock, Some(note.time))
                    ),
                ))
            })
            .collect();
        if let Some(hex) = file
            .contents
            .hash
            .as_ref()
            .and_then(|hash| hash.sha256_hex())
        {
            if !guest.iter().any(|(known, _)| *known == hex) {
                guest.push((hex, "the guest's hash".into()));
            }
        }
        if guest.is_empty() && file.changed() {
            ui.weak(
                "No guest hash: still open at run end (the guest hashes a file when its last writer closes it).",
            );
        }
        for (hex, moment) in &guest {
            ui.add(
                egui::Label::new(
                    RichText::new(format!("{moment}\n{hex}"))
                        .monospace()
                        .small(),
                )
                .wrap(),
            );
        }
        let blocker = self.hash_blocker();
        let position = self.map.position();
        let current = self.hashed.as_ref().is_some_and(|h| h.position == position);
        if blocker.is_none()
            && !current
            && self.hashing.is_none()
            && self.map.size() <= AUTO_HASH_LIMIT
        {
            self.start_hashing(&ui.ctx().clone());
        }
        ui.horizontal(|ui| {
            let busy = self.hashing.is_some();
            let button = ui.add_enabled(
                blocker.is_none() && !busy && !current,
                egui::Button::new("Hash this state"),
            );
            let button = match &blocker {
                Some(reason) => button.on_disabled_hover_text(reason),
                None => button.on_hover_text(
                    "SHA-256, MD5 and SHA-1 of the file as reconstructed at the chosen call",
                ),
            };
            if button.clicked() {
                self.start_hashing(&ui.ctx().clone());
            }
            if guest.is_empty() && !file.changed() {
                ui.add(
                    egui::Label::new(
                        RichText::new(egui_phosphor::regular::INFO).color(theme::muted()),
                    )
                    .sense(egui::Sense::hover()),
                )
                .on_hover_text(
                    "No guest hash: only read, and the guest hashes only programs, written files and deleted files.",
                );
            }
            let last = file.hashes.iter().rev().find(|note| note.sha256.is_some());
            if let Some(note) = last {
                if ui
                    .button("Go to the last hash")
                    .on_hover_text("Show the file as it stood when the guest took its last hash")
                    .clicked()
                {
                    let position = self.map.steps_until(note.time);
                    self.goto(position);
                }
            }
        });
        if let Some(reason) = &blocker {
            widgets::chip(ui, "no hash", Tone::Warn);
            ui.add(egui::Label::new(RichText::new(reason).small()).wrap());
            return;
        }
        if self.hashing.is_some() {
            ui.weak("Hashing…");
        }
        let Some(hashed) = self.hashed.as_ref().filter(|h| h.position == position) else {
            return;
        };
        match &hashed.result {
            Ok(digests) => {
                for (label, hex) in [
                    ("SHA-256", &digests.sha256),
                    ("MD5", &digests.md5),
                    ("SHA-1", &digests.sha1),
                ] {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(label).strong().small());
                        if ui
                            .small_button(egui_phosphor::regular::COPY)
                            .on_hover_text(format!("Copy the {label}"))
                            .clicked()
                        {
                            ui.ctx().copy_text(hex.clone());
                        }
                    });
                    ui.add(egui::Label::new(RichText::new(hex).monospace().small()).wrap());
                }
                match guest.iter().find(|(known, _)| *known == digests.sha256) {
                    Some((_, moment)) => {
                        widgets::chip(ui, "matches the guest's hash", Tone::Good);
                        ui.weak(format!(
                            "Same as the hash taken {moment}: the reconstruction is byte-exact."
                        ));
                    }
                    None if guest.is_empty() => {
                        ui.weak("There is no guest hash to compare with.");
                    }
                    None => {
                        widgets::chip(ui, "differs from the guest's hash", Tone::Warn);
                        ui.weak("Step to the call just before a hash was taken, or use Go to the last hash.");
                    }
                }
            }
            Err(Incomplete::SizeUnknown) => {
                ui.weak("No hash: the file's size is not known.");
            }
            Err(Incomplete::Missing(count)) => {
                ui.weak(format!("No hash: {count} bytes have no value (?? ## ~~)."));
            }
            Err(Incomplete::Unreadable) => {
                ui.weak("No hash: some bytes could not be read back (the starting disk is gone).");
            }
        }
    }
}
