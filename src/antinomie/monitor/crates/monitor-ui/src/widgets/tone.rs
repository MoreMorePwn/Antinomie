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
    #[cfg(test)]
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

/// The text colour of `tone`; `None` is the plain muted grey of a state with
/// nothing to say (stopped, skipped, unknown).
pub fn fg_or_muted(tone: Option<Tone>) -> Color32 {
    tone.map_or_else(theme::muted, Tone::fg)
}

/// The text of a neutral chip: between the muted and the body color, so a
/// source or process tag inside a line of text still reads in every theme
/// (the muted color alone is too faint on the chip's tint).
pub(crate) fn neutral_ink(palette: &theme::Palette) -> Color32 {
    palette.muted.lerp_to_gamma(palette.text, 0.6)
}

/// How a [`pill`] is drawn: its fill, outline, corner and side padding.
#[derive(Clone, Copy)]
pub struct PillLook {
    pub fill: Color32,
    pub stroke: egui::Stroke,
    pub corner: u8,
    /// Space left and right of the text.
    pub pad: f32,
}

impl PillLook {
    /// The look of a [`chip`] in `tone`.
    pub fn tone(tone: Tone) -> Self {
        Self {
            fill: tone.bg(),
            stroke: egui::Stroke::NONE,
            corner: 10,
            pad: 8.0,
        }
    }
}

/// Space above and below a pill's text.
const PILL_PAD_Y: f32 = 2.0;

/// The one way every chip, tag and status pill is drawn: one line of text,
/// never wrapped inside, centred in a box of a fixed height. In a wrapping
/// row a pill that does not fit what is left of the line starts the next one
/// whole; only a pill wider than a whole line is cut, with "…", and its
/// tooltip is the caller's to add. `min_width` lines up a column of pills.
pub fn pill(
    ui: &mut egui::Ui,
    look: PillLook,
    job: egui::text::LayoutJob,
    min_width: f32,
) -> egui::Response {
    let natural = ui.fonts(|fonts| fonts.layout_job(single_line(job.clone(), f32::INFINITY)));
    let width = |text: f32| (text + 2.0 * look.pad).max(min_width);
    let layout = *ui.layout();
    if layout.is_horizontal()
        && layout.main_wrap()
        && ui.cursor().min.x > ui.min_rect().left() + 1.0
        && width(natural.size().x) > ui.available_width()
    {
        ui.end_row();
    }
    let room = ui.available_width() - 2.0 * look.pad;
    let galley = if natural.size().x > room && room > 0.0 {
        ui.fonts(|fonts| fonts.layout_job(single_line(job, room)))
    } else {
        natural
    };
    let size = egui::vec2(width(galley.size().x), galley.size().y + 2.0 * PILL_PAD_Y);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::hover());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect(
            rect,
            look.corner,
            look.fill,
            look.stroke,
            egui::StrokeKind::Inside,
        );
        let at = rect.center() - galley.size() * 0.5;
        painter.galley(at, galley, Color32::PLACEHOLDER);
    }
    response
}

/// `job` on one line no wider than `width`, cut with "…".
fn single_line(mut job: egui::text::LayoutJob, width: f32) -> egui::text::LayoutJob {
    job.wrap = egui::text::TextWrapping {
        max_width: width,
        max_rows: 1,
        break_anywhere: true,
        overflow_character: Some('…'),
    };
    job
}

/// One run of pill text in `font` and `color`.
pub fn pill_text(job: &mut egui::text::LayoutJob, text: &str, font: egui::FontId, color: Color32) {
    job.append(
        text,
        0.0,
        egui::TextFormat {
            font_id: font,
            color,
            valign: egui::Align::Center,
            ..Default::default()
        },
    );
}

/// The small font every pill uses.
pub fn pill_font(ui: &egui::Ui) -> egui::FontId {
    egui::TextStyle::Small.resolve(ui.style())
}

/// A pill with `text` in `tone`.
pub fn chip(ui: &mut egui::Ui, text: impl Into<String>, tone: Tone) -> egui::Response {
    chip_wide(ui, text, tone, 0.0)
}

/// [`chip`] with its text centred in a pill `width` wide (see [`chip_width`]),
/// so a column of chips lines up.
pub fn chip_wide(
    ui: &mut egui::Ui,
    text: impl Into<String>,
    tone: Tone,
    width: f32,
) -> egui::Response {
    let mut job = egui::text::LayoutJob::default();
    pill_text(&mut job, &text.into(), pill_font(ui), tone.fg());
    pill(ui, PillLook::tone(tone), job, width)
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
