// SPDX-License-Identifier: GPL-3.0-only
//! The panel a run-based window shows while it has nothing to show: what the
//! window is for and how to fill it. Every such window uses this one layout.
use crate::theme;
use eframe::egui::{self, RichText};

/// Text of an [`info_panel`].
pub struct InfoPanel<'a> {
    /// A phosphor icon, shown large and muted.
    pub icon: &'a str,
    /// What is missing, one line (for example "Select a run to view its triage").
    pub title: &'a str,
    /// What the window shows, one or two sentences.
    pub about: &'a str,
    /// The heading of the numbered steps.
    pub steps_title: &'a str,
    /// The numbered steps, short sentences.
    pub steps: &'a [&'a str],
}

/// Widest the text and the steps card grow, so a wide window keeps a readable line.
const WIDTH: f32 = 560.0;

/// Icon, title, description and a card with the numbered steps, centred.
pub fn info_panel(ui: &mut egui::Ui, panel: &InfoPanel<'_>) {
    ui.add_space(16.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(WIDTH);
        ui.label(RichText::new(panel.icon).size(32.0).color(theme::muted()));
        ui.label(RichText::new(panel.title).strong().color(theme::heading()));
        ui.add_space(4.0);
        ui.add(egui::Label::new(RichText::new(panel.about).color(theme::muted())).wrap());
    });
    ui.add_space(10.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(WIDTH);
        egui::Frame::new()
            .fill(theme::raised())
            .stroke(egui::Stroke::new(1.0_f32, theme::line()))
            .corner_radius(6)
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    theme::section(ui, panel.steps_title);
                    for (index, text) in panel.steps.iter().enumerate() {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new((index + 1).to_string())
                                    .monospace()
                                    .color(theme::value(theme::ValueKind::Number)),
                            );
                            ui.label(*text);
                        });
                    }
                });
            });
    });
}
