// SPDX-License-Identifier: GPL-3.0-only
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

/// A filter-bar toggle: a pill that is on (check mark) or off (dimmed, struck
/// through), with an optional muted count. Returns the click; the caller flips
/// the flag.
pub fn toggle_chip(ui: &mut egui::Ui, label: &str, on: bool, count: Option<u64>) -> egui::Response {
    toggle_chip_with(ui, egui_phosphor::regular::CHECK, label, on, count)
}

/// [`toggle_chip`] with `icon` where the check mark is, for a filter whose
/// values have an icon of their own (the finding categories). It shows only
/// while the chip is on; an off chip is dimmed and struck through as before.
pub fn toggle_chip_with(
    ui: &mut egui::Ui,
    icon: &str,
    label: &str,
    on: bool,
    count: Option<u64>,
) -> egui::Response {
    let palette = theme::palette();
    let color = if on { palette.text } else { palette.muted };
    let mut text = if on {
        format!("{icon} {label}")
    } else {
        label.to_owned()
    };
    if let Some(count) = count {
        text.push_str(&format!(" {count}"));
    }
    let mut rich = RichText::new(text).small().color(color);
    if !on {
        rich = rich.strikethrough();
    }
    ui.add(
        egui::Button::new(rich)
            .fill(palette.raised)
            .stroke(egui::Stroke::new(1.0_f32, palette.line))
            .corner_radius(10)
            .min_size(egui::vec2(0.0, 20.0)),
    )
}
