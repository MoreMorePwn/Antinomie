// SPDX-License-Identifier: MIT
//! The theme choice: Settings > Appearance, remembered across launches, and
//! the windows that follow the new window style.
use super::*;
use crate::theme::Theme;

const SIZE: egui::Vec2 = egui::vec2(1280.0, 900.0);

#[test]
fn the_theme_is_remembered_and_older_settings_still_load() {
    assert_eq!(Settings::default().active_theme(), Theme::Dark);
    for theme in Theme::ALL {
        let mut settings = Settings::default();
        settings.set_theme(theme);
        let saved = serde_json::to_string(&settings).unwrap();
        let loaded: Settings = serde_json::from_str(&saved).unwrap();
        assert_eq!(loaded.active_theme(), theme, "{saved}");
    }
    // Settings saved before themes existed only have the light flag.
    let light: Settings = serde_json::from_str(r#"{"light_theme": true}"#).unwrap();
    assert_eq!(light.active_theme(), Theme::Light);
    let dark: Settings = serde_json::from_str(r#"{"light_theme": false}"#).unwrap();
    assert_eq!(dark.active_theme(), Theme::Dark);
    // The chosen theme wins over the legacy flag; blue keeps the flag off so
    // an older build opens dark.
    let blue: Settings = serde_json::from_str(r#"{"theme": "blue", "light_theme": true}"#).unwrap();
    assert_eq!(blue.active_theme(), Theme::Blue);
    let mut settings = Settings::default();
    settings.set_theme(Theme::Blue);
    assert!(!settings.light_theme);
}

#[test]
fn choosing_a_theme_in_settings_restyles_the_app_and_is_kept() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.settings_open = true;
    for (label, expected) in [
        ("Blue", Theme::Blue),
        ("Light", Theme::Light),
        ("Dark", Theme::Dark),
    ] {
        click_label(&mut app, &ctx, SIZE, label);
        assert_eq!(app.settings.active_theme(), expected, "{label}");
        assert_eq!(theme::theme(), expected);
        assert_eq!(ctx.style().visuals.panel_fill, expected.palette().panel);
        let saved = serde_json::to_string(&app.settings).unwrap();
        let loaded: Settings = serde_json::from_str(&saved).unwrap();
        assert_eq!(loaded.active_theme(), expected);
    }
    theme::apply_theme(&ctx, Theme::Dark);
}
