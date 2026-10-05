use eframe::egui::{self, Color32, FontId, Stroke, TextStyle};

pub const BG: Color32 = Color32::from_rgb(31, 31, 32);
pub const PANEL: Color32 = Color32::from_rgb(37, 37, 38);
pub const RAISED: Color32 = Color32::from_rgb(44, 44, 46);
pub const LINE: Color32 = Color32::from_rgb(62, 62, 65);
pub const TEXT: Color32 = Color32::from_rgb(210, 214, 220);
pub const MUTED: Color32 = Color32::from_rgb(147, 155, 166);
pub const BLUE: Color32 = Color32::from_rgb(148, 188, 235);
pub const PRIMARY: Color32 = Color32::from_rgb(49, 93, 139);
pub const GOOD: Color32 = Color32::from_rgb(128, 192, 153);
pub const WARN: Color32 = Color32::from_rgb(224, 182, 111);
pub const ERROR: Color32 = Color32::from_rgb(235, 139, 139);
pub const TERMINAL: Color32 = Color32::from_rgb(26, 26, 27);

pub fn install(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
    ctx.set_fonts(fonts);
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = PANEL;
    style.visuals.window_fill = RAISED;
    style.visuals.extreme_bg_color = BG;
    style.visuals.faint_bg_color = PANEL;
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.selection.bg_fill = Color32::from_rgb(45, 62, 82);
    style.visuals.selection.stroke = Stroke::new(1.0_f32, BLUE);
    style.visuals.window_stroke = Stroke::new(1.0_f32, LINE);
    style.visuals.window_corner_radius = 3.into();
    for widgets in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        widgets.corner_radius = 2.into();
        widgets.bg_stroke = Stroke::new(1.0_f32, LINE);
        widgets.fg_stroke = Stroke::new(1.0_f32, TEXT);
    }
    style.visuals.widgets.noninteractive.bg_fill = PANEL;
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, MUTED);
    style.visuals.widgets.inactive.bg_fill = RAISED;
    style.visuals.widgets.inactive.weak_bg_fill = RAISED;
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(54, 54, 57);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(54, 54, 57);
    style.visuals.widgets.active.bg_fill = PRIMARY;
    style.visuals.widgets.active.weak_bg_fill = PRIMARY;
    style.spacing.item_spacing = egui::vec2(8.0, 5.0);
    style.spacing.button_padding = egui::vec2(8.0, 4.0);
    style.spacing.interact_size.y = 28.0;
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(16.0));
    style
        .text_styles
        .insert(TextStyle::Button, FontId::proportional(16.0));
    style
        .text_styles
        .insert(TextStyle::Small, FontId::proportional(14.0));
    style
        .text_styles
        .insert(TextStyle::Heading, FontId::proportional(20.0));
    style
        .text_styles
        .insert(TextStyle::Monospace, FontId::monospace(16.0));
    ctx.set_style(style);
}

pub(crate) fn text_size(ctx: &egui::Context, size: f32) {
    let size = size.clamp(12.0, 24.0);
    ctx.style_mut(|style| {
        for text_style in [TextStyle::Body, TextStyle::Button] {
            style
                .text_styles
                .insert(text_style, FontId::proportional(size));
        }
        style.text_styles.insert(
            TextStyle::Small,
            FontId::proportional((size - 2.0).max(12.0)),
        );
        style
            .text_styles
            .insert(TextStyle::Heading, FontId::proportional(size + 4.0));
        style
            .text_styles
            .insert(TextStyle::Monospace, FontId::monospace(size));
        style.spacing.interact_size.y = size + 12.0;
    });
}

pub fn frame(fill: Color32) -> egui::Frame {
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0_f32, LINE))
        .inner_margin(egui::Margin::symmetric(12, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_native_theme_installs_readable_dark_controls() {
        let ctx = egui::Context::default();
        install(&ctx);
        let style = ctx.style();
        assert!(style.visuals.dark_mode);
        assert_eq!(style.visuals.panel_fill, PANEL);
        assert_eq!(style.visuals.window_fill, RAISED);
        assert_eq!(style.visuals.extreme_bg_color, BG);
        assert_eq!(style.visuals.override_text_color, Some(TEXT));
        assert_eq!(style.visuals.selection.stroke.color, BLUE);
        for (text_style, size) in [
            (TextStyle::Body, 16.0),
            (TextStyle::Button, 16.0),
            (TextStyle::Monospace, 16.0),
            (TextStyle::Small, 14.0),
            (TextStyle::Heading, 20.0),
        ] {
            assert_eq!(style.text_styles[&text_style].size, size);
        }
    }
}
