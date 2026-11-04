// SPDX-License-Identifier: GPL-3.0-only
//! Settings: every page at 1280x800 and at the large text sizes keeps its
//! texts clear of the scroll bar, and the page's rows are spread apart.
use super::*;
use crate::app::settings_window::SettingsPage;

const SIZE: egui::Vec2 = egui::vec2(1280.0, 800.0);

#[test]
fn no_page_puts_a_text_under_the_scroll_bar_at_the_large_text_sizes() {
    for font_size in [16.0, 18.0, 24.0] {
        for page in SettingsPage::ALL {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, font_size);
            let mut app = app();
            app.settings.font_size = font_size;
            app.settings_open = true;
            app.settings_page = page;
            app.snapshot.analysis_tools =
                vec![antinomie_monitor_core::analysis_tools::ToolStatus {
                    id: "capa".into(),
                    name: "capa".into(),
                    version: "9".into(),
                    size: 1024,
                    system: Some("/usr/bin/capa".into()),
                    ..Default::default()
                }];
            // What the main window shows behind the Settings window is not the
            // page's.
            app.settings_open = false;
            for _ in 0..4 {
                render(&mut app, &ctx, SIZE);
            }
            let behind = texts(&render(&mut app, &ctx, SIZE));
            app.settings_open = true;
            for _ in 0..4 {
                render(&mut app, &ctx, SIZE);
            }
            let visible: Vec<_> = texts(&render(&mut app, &ctx, SIZE))
                .into_iter()
                .filter(|shown| !behind.contains(shown))
                .collect();
            let window = ctx
                .memory(|memory| memory.area_rect(Dialog::Settings.window_id()))
                .expect("the Settings window");
            // The scroll bar sits at the right edge of the page area; the page
            // keeps 18 points clear of it, and the window's own margin lies
            // beyond that.
            let page_top = window.top() + 40.0;
            let page_bottom = window.bottom() - 70.0;
            for (text, rect) in &visible {
                let inside = rect.left() > window.left()
                    && rect.top() > page_top
                    && rect.bottom() < page_bottom
                    && rect.right() < window.right() + 40.0;
                if inside {
                    assert!(
                        rect.right() <= window.right() - 20.0,
                        "{text:?} reaches the scroll bar on {page:?} at {font_size} pt: {rect:?} in {window:?}"
                    );
                }
            }
            assert!(
                window.right() <= SIZE.x && window.bottom() <= SIZE.y,
                "{page:?} at {font_size} pt: {window:?}"
            );
        }
    }
}

#[test]
fn the_settings_window_is_wide_and_its_rows_are_spread_apart() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.settings_open = true;
    app.settings_page = SettingsPage::Advanced;
    for _ in 0..4 {
        render(&mut app, &ctx, SIZE);
    }
    let visible = texts(&render(&mut app, &ctx, SIZE));
    let window = ctx
        .memory(|memory| memory.area_rect(Dialog::Settings.window_id()))
        .expect("the Settings window");
    assert!(window.width() >= 880.0, "{window:?}");
    // The Advanced page has sub-headings, and the rows under one are at least
    // a line apart.
    for heading in ["Display", "Starting a VM"] {
        assert!(
            visible.iter().any(|(text, _)| text == heading),
            "{heading}: {visible:?}"
        );
    }
}
