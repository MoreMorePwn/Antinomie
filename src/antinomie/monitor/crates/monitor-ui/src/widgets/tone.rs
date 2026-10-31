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
            Tone::Neutral => neutral_ink(palette),
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

/// The text of a neutral chip: between the muted and the body color, so a
/// source or process tag inside a line of text still reads in every theme
/// (the muted color alone is too faint on the chip's tint).
pub(crate) fn neutral_ink(palette: &theme::Palette) -> Color32 {
    palette.muted.lerp_to_gamma(palette.text, 0.6)
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

/// [`chip`] with its text centred in a pill `width` wide (see [`chip_width`]),
/// so a column of chips lines up.
pub fn chip_wide(
    ui: &mut egui::Ui,
    text: impl Into<String>,
    tone: Tone,
    width: f32,
) -> egui::Response {
    egui::Frame::new()
        .fill(tone.bg())
        .corner_radius(10)
        .inner_margin(egui::Margin::symmetric(8, 1))
        .show(ui, |ui| {
            ui.set_width((width - 16.0).max(0.0));
            ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                ui.label(RichText::new(text).small().color(tone.fg()));
            });
        })
        .response
}

/// The width of a [`chip_wide`] that fits the longest of `words`.
pub fn chip_width(ui: &egui::Ui, words: &[&str]) -> f32 {
    let font = egui::TextStyle::Small.resolve(ui.style());
    let widest = words
        .iter()
        .map(|word| {
            ui.fonts(|fonts| {
                fonts
                    .layout_no_wrap((*word).to_owned(), font.clone(), Color32::PLACEHOLDER)
                    .size()
                    .x
            })
        })
        .fold(0.0, f32::max);
    widest + 16.0
}

/// A filter-bar toggle: a pill that is on (check mark, filled) or off (a
/// plain muted label), with an optional muted count. Returns the click; the caller flips
/// the flag.
pub fn toggle_chip(ui: &mut egui::Ui, label: &str, on: bool, count: Option<u64>) -> egui::Response {
    toggle_chip_with(ui, egui_phosphor::regular::CHECK, label, on, count)
}

/// [`toggle_chip`] with `icon` where the check mark is, for a filter whose
/// values have an icon of their own (the finding categories). It shows only
/// while the chip is on; an off chip is a plain muted label.
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
    // Off is a plain muted label (a struck-through one reads as removed); on is
    // filled and checked. The size is the buttons' own.
    let rich = RichText::new(text).color(color);
    ui.add(
        egui::Button::new(rich)
            .fill(if on {
                palette.selection
            } else {
                palette.raised
            })
            .stroke(egui::Stroke::new(
                1.0_f32,
                if on { palette.accent } else { palette.line },
            ))
            .corner_radius(10)
            .min_size(egui::vec2(0.0, ui.spacing().interact_size.y - 4.0)),
    )
}
