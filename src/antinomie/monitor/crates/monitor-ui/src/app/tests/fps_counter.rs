// SPDX-License-Identifier: GPL-3.0-only
//! The debug FPS counter: off by default, drawn only when enabled, never a
//! reason to repaint.
use super::*;

const SIZE: egui::Vec2 = egui::vec2(1280.0, 900.0);

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

fn counter_text(output: &egui::FullOutput) -> Option<String> {
    texts(output)
        .into_iter()
        .map(|(text, _)| text)
        .find(|text| text.contains(" fps") || text.starts_with("idle"))
}

/// A steady 50 fps burst that ends now.
fn busy(app: &mut MonitorApp) {
    let now = Instant::now();
    for ago in [80_u64, 60, 40, 20, 0] {
        app.performance
            .record_at(now - Duration::from_millis(ago), Duration::from_micros(400));
    }
}

#[test]
fn the_counter_is_off_by_default_and_old_settings_still_load() {
    assert!(!Settings::default().show_fps);
    let old: Settings =
        serde_json::from_str(r#"{"bundle": "", "quota_gib": 4, "timeout": 10, "font_size": 16.0}"#)
            .unwrap();
    assert!(!old.show_fps);
    let on: Settings = serde_json::from_str(r#"{"show_fps": true}"#).unwrap();
    assert!(on.show_fps);
    let saved = serde_json::to_string(&on).unwrap();
    assert!(serde_json::from_str::<Settings>(&saved).unwrap().show_fps);
}

#[test]
fn nothing_is_drawn_while_the_setting_is_off() {
    let ctx = context();
    let mut app = app();
    busy(&mut app);
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    assert_eq!(counter_text(&render(&mut app, &ctx, SIZE)), None);
}

#[test]
fn the_counter_shows_the_repaint_rate_then_idle() {
    let ctx = context();
    let mut app = app();
    app.settings.show_fps = true;
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    assert_eq!(
        counter_text(&render(&mut app, &ctx, SIZE)).as_deref(),
        Some("idle")
    );
    busy(&mut app);
    let output = render(&mut app, &ctx, SIZE);
    let text = counter_text(&output).expect("counter drawn");
    assert!(text.contains(" fps") && text.contains("ms") && text.contains("UI"));
    let corner = texts(&output)
        .into_iter()
        .find(|(shown, _)| *shown == text)
        .unwrap()
        .1;
    // In the title bar, just left of the three window buttons.
    let buttons_left = SIZE.x - 3.0 * crate::title_bar::BUTTON_WIDTH;
    assert!(corner.max.x > buttons_left - 20.0 && corner.max.x < buttons_left);
    assert!(corner.min.y < 20.0);
    // Without new frames the reading ages out and says so, keeping the last value.
    app.performance = Default::default();
    app.performance.record_at(
        Instant::now() - Duration::from_secs(5),
        Duration::from_micros(400),
    );
    let _ = app
        .performance
        .fps_label(Instant::now() - Duration::from_secs(5));
    let idle = counter_text(&render(&mut app, &ctx, SIZE)).unwrap();
    assert!(idle.starts_with("idle"), "{idle}");
}

#[test]
fn drawing_the_counter_does_not_ask_for_more_repaints() {
    let delay = |show_fps: bool| {
        let ctx = context();
        let mut app = app();
        app.settings.show_fps = show_fps;
        busy(&mut app);
        for _ in 0..3 {
            render(&mut app, &ctx, SIZE);
        }
        render(&mut app, &ctx, SIZE)
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .map(|viewport| viewport.repaint_delay)
    };
    assert_eq!(delay(true), delay(false));
}

#[test]
fn settings_offers_the_option_under_debug() {
    let ctx = context();
    let mut app = app();
    app.settings_open = true;
    app.settings_page = super::super::settings_window::SettingsPage::Advanced;
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    let shown: Vec<_> = texts(&render(&mut app, &ctx, SIZE))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    assert!(
        shown.iter().any(|text| text == "Show FPS counter"),
        "{shown:?}"
    );
    assert!(shown.iter().any(|text| text == "Advanced"));
}
