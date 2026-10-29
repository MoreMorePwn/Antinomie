// SPDX-License-Identifier: GPL-3.0-only
//! Official penguin symbol and outlined Comfortaa wordmark.
use eframe::egui::{self, Color32, ColorImage, Rect, TextureHandle, TextureOptions};

const SYMBOL: &[u8] = include_bytes!("../../../assets/antinomie-icon.png");
const COLOR_WORDMARK: &[u8] = include_bytes!("../../../assets/antinomie-logo-color.png");
const WHITE_WORDMARK: &[u8] = include_bytes!("../../../assets/antinomie-logo-white.png");

pub(crate) fn window_icon() -> Option<egui::IconData> {
    decode(SYMBOL)
}

pub(crate) fn paint_symbol(ui: &egui::Ui, rect: Rect) {
    if let Some(texture) = texture(ui.ctx(), "symbol", SYMBOL) {
        ui.painter_at(rect).image(
            texture.id(),
            rect,
            Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
            Color32::WHITE,
        );
    }
}

pub(crate) fn show_wordmark(ui: &mut egui::Ui, width: f32) {
    let (name, bytes) = if crate::theme::is_light() {
        ("wordmark-color", COLOR_WORDMARK)
    } else {
        ("wordmark-white", WHITE_WORDMARK)
    };
    if let Some(texture) = texture(ui.ctx(), name, bytes) {
        let size = texture.size_vec2();
        let width = width.min(ui.available_width());
        ui.add(
            egui::Image::new((texture.id(), egui::vec2(width, width * size.y / size.x)))
                .alt_text("Antinomie"),
        );
    }
}

fn decode(bytes: &[u8]) -> Option<egui::IconData> {
    match eframe::icon_data::from_png_bytes(bytes) {
        Ok(icon) => Some(icon),
        Err(error) => {
            eprintln!("antinomie: could not decode embedded brand artwork: {error}");
            None
        }
    }
}

fn texture(ctx: &egui::Context, name: &'static str, bytes: &[u8]) -> Option<TextureHandle> {
    let id = egui::Id::new(("antinomie-branding", name));
    if let Some(cached) = ctx.data(|data| data.get_temp::<Option<TextureHandle>>(id)) {
        return cached;
    }
    let texture = decode(bytes).map(|icon| {
        let image = ColorImage::from_rgba_unmultiplied(
            [icon.width as usize, icon.height as usize],
            &icon.rgba,
        );
        ctx.load_texture(name, image, TextureOptions::LINEAR)
    });
    // Cache the failure as well, so damaged artwork never causes per-frame decoding.
    ctx.data_mut(|data| data.insert_temp(id, texture.clone()));
    texture
}
