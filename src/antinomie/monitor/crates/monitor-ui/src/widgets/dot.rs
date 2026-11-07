// SPDX-License-Identifier: GPL-3.0-only
//! A state dot beside a label. The dot is drawn, not typed as a "●" glyph: the
//! glyph sits on the font's own box, a point or two below the middle of the
//! lowercase letters it stands beside. [`middle`] is the visual middle of a
//! laid-out text, from the baseline of its first row (the font's ascent) and
//! the em size, never from the row rectangle; every dot beside text takes its
//! height from it.
use crate::theme;
use eframe::egui::{self, Color32, FontId, Galley, Painter, Pos2, Response, Sense, Vec2};
use std::sync::Arc;

/// How far above the baseline the visual middle of mixed text sits, in ems:
/// halfway between the middle of the x-height (0.27) and of the capitals (0.36).
const MIDDLE: f32 = 0.31;

/// The diameter of the dot for text of `size` points.
pub(crate) fn diameter(size: f32) -> f32 {
    (size * 0.5).round().max(5.0)
}

/// The width the dot takes, with the gap to the text.
pub(crate) fn advance(size: f32) -> f32 {
    diameter(size) + (size * 0.4).round().max(4.0)
}

/// The height, from the top of `galley`, of the visual middle of its first row.
pub(crate) fn middle(galley: &Galley, size: f32) -> f32 {
    let Some(row) = galley.rows.first() else {
        return galley.size().y * 0.5;
    };
    match row.glyphs.first() {
        Some(glyph) => row.pos.y + glyph.pos.y - size * MIDDLE,
        None => row.pos.y + row.size.y * 0.5,
    }
}

/// Paint the dot in `color` centred at `x`, on the visual middle of the text
/// of `galley` placed with its top at `top`.
pub(crate) fn paint(
    painter: &Painter,
    x: f32,
    top: f32,
    galley: &Galley,
    size: f32,
    color: Color32,
) {
    painter.circle_filled(
        Pos2::new(x, top + middle(galley, size)),
        diameter(size) * 0.5,
        color,
    );
}

/// A dot after a label already drawn (`text` is its response, in `font`): the
/// dot's own slot, centred on the middle of the label's first line.
pub(crate) fn after(ui: &mut egui::Ui, text: &Response, font: &FontId, color: Color32) -> Response {
    let sample = ui.fonts_mut(|fonts| fonts.layout_no_wrap("x".into(), font.clone(), color));
    let width = advance(font.size);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(width, text.rect.height()), Sense::hover());
    if ui.is_rect_visible(rect) {
        paint(
            ui.painter(),
            rect.center().x,
            text.rect.top(),
            &sample,
            font.size,
            color,
        );
    }
    response
}

/// A dot and a label as one widget: the dot on the middle of the label's
/// first line, the label wrapping (or cut) in the room that is left.
pub(crate) struct DotLabel {
    dot: Color32,
    text: String,
    text_color: Color32,
    strong: bool,
    wrap: bool,
}

impl DotLabel {
    /// `text` in the text colour, beside a dot in `dot`.
    pub(crate) fn new(dot: Color32, text: impl Into<String>) -> Self {
        Self {
            dot,
            text: text.into(),
            text_color: theme::text(),
            strong: false,
            wrap: false,
        }
    }

    pub(crate) fn text_color(mut self, color: Color32) -> Self {
        self.text_color = color;
        self
    }

    pub(crate) fn strong(mut self) -> Self {
        self.strong = true;
        self
    }

    pub(crate) fn wrap(mut self) -> Self {
        self.wrap = true;
        self
    }

    fn galley(&self, ui: &egui::Ui, font: &FontId, width: f32) -> Arc<Galley> {
        let mut text = egui::RichText::new(&self.text).color(self.text_color);
        if self.strong {
            text = text.strong();
        }
        let mut job = egui::text::LayoutJob::default();
        text.append_to(
            &mut job,
            ui.style(),
            egui::FontSelection::FontId(font.clone()),
            egui::Align::LEFT,
        );
        job.wrap = if self.wrap {
            egui::text::TextWrapping::wrap_at_width(width.max(1.0))
        } else {
            egui::text::TextWrapping::truncate_at_width(width.max(1.0))
        };
        ui.fonts_mut(|fonts| fonts.layout_job(job))
    }
}

impl egui::Widget for DotLabel {
    fn ui(self, ui: &mut egui::Ui) -> Response {
        let font = egui::TextStyle::Body.resolve(ui.style());
        let lead = advance(font.size);
        let galley = self.galley(ui, &font, ui.available_width() - lead);
        let size = Vec2::new(lead + galley.size().x, galley.size().y);
        let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
        if ui.is_rect_visible(rect) {
            let top = rect.top();
            paint(
                ui.painter(),
                rect.left() + diameter(font.size) * 0.5,
                top,
                &galley,
                font.size,
                self.dot,
            );
            ui.painter()
                .galley(Pos2::new(rect.left() + lead, top), galley, self.text_color);
        }
        response
    }
}
