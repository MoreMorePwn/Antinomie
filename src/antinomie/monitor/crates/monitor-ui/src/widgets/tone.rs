// SPDX-License-Identifier: MIT
//! Semantic tones and the status chip.
use crate::theme;
use eframe::egui::{self, Color32, RichText};

/// What a status or badge means; picks its text and tinted background.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Error,
    Info,
    /// Recording / live.
    Live,
    Accent,
    Neutral,
    /// Body-colored text on the neutral tint: a count that is not a warning.
    Plain,
}

impl Tone {
    pub const ALL: [Tone; 8] = [
        Tone::Good,
        Tone::Warn,
        Tone::Error,
        Tone::Info,
        Tone::Live,
        Tone::Accent,
        Tone::Neutral,
        Tone::Plain,
    ];

    /// Text (and dot) color.
    pub fn fg(self) -> Color32 {
        let palette = theme::palette();
        match self {
            Tone::Good => palette.good,
            Tone::Warn => palette.warn,
            Tone::Error => palette.error,
            Tone::Info => palette.info,
            Tone::Live => palette.live,
            Tone::Accent => palette.accent,
            Tone::Neutral => palette.muted,
            Tone::Plain => palette.text,
        }
    }

    /// Translucent background that works over every surface.
    pub fn bg(self) -> Color32 {
        let palette = theme::palette();
        match self {
            Tone::Good => palette.good_bg,
            Tone::Warn => palette.warn_bg,
            Tone::Error => palette.error_bg,
            Tone::Info => palette.info_bg,
            Tone::Live => palette.error_bg,
            Tone::Accent => palette.selection_soft,
            Tone::Neutral | Tone::Plain => palette.neutral_bg,
        }
    }
}

/// A pill with `text` in `tone`.
pub fn chip(ui: &mut egui::Ui, text: impl Into<String>, tone: Tone) -> egui::Response {
    egui::Frame::new()
        .fill(tone.bg())
        .corner_radius(10)
        .inner_margin(egui::Margin::symmetric(8, 1))
        .show(ui, |ui| {
            ui.label(RichText::new(text).small().color(tone.fg()));
        })
        .response
}
