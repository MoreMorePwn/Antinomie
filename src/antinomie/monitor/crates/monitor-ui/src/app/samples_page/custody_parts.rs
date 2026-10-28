// SPDX-License-Identifier: GPL-3.0-only
//! What the sample window's Custody log tab, the global custody view and the
//! export dialog share: the verify banner, the check mark, the head hash.
use crate::widgets::Tone;
use antinomie_monitor_core::samples::{short, ChainCheck, EntryState};
use eframe::egui::{self, RichText};

/// Said wherever the log is shown or exported.
pub(super) const NOT_PROOF: &str = "Tamper-evident, not tamper-proof: an edited, removed or \
reordered entry is detected, but someone who rewrites the whole log and the library index \
together is not. Keep the head hash somewhere else to rule that out.";

/// The banner over a sample's log: verified with the head (copyable), or
/// broken at an entry. Returns true when Verify was clicked.
pub(super) fn banner(ui: &mut egui::Ui, check: &ChainCheck, verifying: bool) -> bool {
    let (tone, icon) = if check.ok() {
        (Tone::Good, egui_phosphor::regular::CHECK_CIRCLE)
    } else {
        (Tone::Error, egui_phosphor::regular::X_CIRCLE)
    };
    let mut verify = false;
    egui::Frame::new()
        .fill(tone.bg())
        .corner_radius(4)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(icon).color(tone.fg()).size(16.0));
                match &check.problem {
                    None if check.entries == 0 => {
                        ui.label("No entries yet.");
                    }
                    None => {
                        ui.label(RichText::new("Log verified.").strong());
                        ui.label(format!(
                            "{} entries, every link matches. Head",
                            check.entries
                        ));
                        head(ui, &check.head);
                    }
                    Some(problem) => {
                        ui.label(
                            RichText::new(format!("Entry {} changed.", problem.at))
                                .strong()
                                .color(tone.fg()),
                        );
                        ui.label(format!(
                            "{}. Entries from {} on are unverified, and exports say so.",
                            check.summary().trim_end_matches('.'),
                            problem.at
                        ));
                    }
                }
                if ui
                    .add_enabled(!verifying, egui::Button::new("Verify"))
                    .on_hover_text("Recompute every hash and compare with the library index")
                    .clicked()
                {
                    verify = true;
                }
            });
        });
    note(ui);
    verify
}

/// The tamper-evident, not tamper-proof note, inset so glyph overshoot stays inside the clip.
pub(super) fn note(ui: &mut egui::Ui) {
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(2, 0))
        .show(ui, |ui| {
            ui.label(RichText::new(NOT_PROOF).weak().small());
        });
}

/// A short hash that copies the whole one when clicked.
pub(super) fn head(ui: &mut egui::Ui, hash: &str) {
    let response = ui
        .add(egui::Label::new(RichText::new(short(hash)).monospace()).sense(egui::Sense::click()))
        .on_hover_text(format!("{hash}\nClick to copy the head hash"));
    if response.clicked() {
        ui.ctx().copy_text(hash.to_owned());
    }
    if ui
        .small_button(egui_phosphor::regular::COPY)
        .on_hover_text("Copy the head hash, to keep it somewhere else")
        .clicked()
    {
        ui.ctx().copy_text(hash.to_owned());
    }
}

/// The check column: a mark, with the hash links in its tooltip.
pub(super) fn check_mark(
    ui: &mut egui::Ui,
    state: EntryState,
    prev: &str,
    hash: &str,
) -> egui::Response {
    let (text, tone) = match state {
        EntryState::Verified => ("✓", Tone::Good),
        EntryState::Changed => ("changed", Tone::Error),
        EntryState::Unverified => ("unverified", Tone::Warn),
    };
    let response = ui
        .add(egui::Label::new(RichText::new(text).color(tone.fg())).sense(egui::Sense::click()))
        .on_hover_text(format!(
            "previous {}\nthis {}\nRight-click to copy",
            short(prev),
            short(hash)
        ));
    response.context_menu(|ui| {
        if ui.button("Copy entry hash").clicked() {
            ui.ctx().copy_text(hash.to_owned());
            ui.close_menu();
        }
        if ui.button("Copy previous hash").clicked() {
            ui.ctx().copy_text(prev.to_owned());
            ui.close_menu();
        }
    });
    response
}
