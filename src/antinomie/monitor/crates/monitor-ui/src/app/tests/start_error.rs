// SPDX-License-Identifier: GPL-3.0-only
//! The blocking screen for a backend that did not start, and the catalog
//! refresh feedback.
use super::*;
use std::fs;

fn unique_id() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

const SIZE: egui::Vec2 = egui::vec2(1280.0, 820.0);

fn frame(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    events: Vec<egui::Event>,
) -> (egui::FullOutput, bool) {
    let mut shown = false;
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            events,
            ..Default::default()
        },
        |root| {
            shown = app.start_error_screen(root);
            if !shown {
                app.draw(root);
            }
        },
    );
    (output, shown)
}

fn click_text(app: &mut MonitorApp, ctx: &egui::Context, label: &str) -> egui::FullOutput {
    let (output, _) = frame(app, ctx, vec![]);
    let pos = texts(&output)
        .into_iter()
        .find(|(text, _)| text == label)
        .unwrap_or_else(|| panic!("no {label} on screen"))
        .1
        .center();
    let mut last = output;
    for pressed in [true, false] {
        last = frame(
            app,
            ctx,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        )
        .0;
    }
    last
}

fn failing_app(blocker: &std::path::Path) -> MonitorApp {
    let mut app = app();
    fs::write(blocker, b"a file where the data folder should be").unwrap();
    app.options.data_dir = blocker.join("data");
    app.start_error = Some(
        crate::app::start_error::start_backend(&app.options, &egui::Context::default())
            .err()
            .expect("a data folder under a file cannot start"),
    );
    app
}

#[test]
fn a_backend_that_did_not_start_shows_only_the_error_screen_and_retry_recovers() {
    let scratch = std::env::temp_dir().join(format!("ant-start-error-{}", unique_id()));
    fs::create_dir_all(&scratch).unwrap();
    let blocker = scratch.join("blocker");
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = failing_app(&blocker);
    let reason = app.start_error.clone().unwrap();
    let (output, shown) = frame(&mut app, &ctx, vec![]);
    assert!(shown);
    let on_screen: Vec<String> = texts(&output).into_iter().map(|(text, _)| text).collect();
    for wanted in ["Antinomie could not start", "What to do", "Retry", "Quit"] {
        assert!(
            on_screen.iter().any(|t| t == wanted),
            "{wanted}: {on_screen:?}"
        );
    }
    assert!(
        on_screen.iter().any(|t| t.contains(&reason)),
        "{on_screen:?}"
    );
    assert!(!on_screen.iter().any(|t| t == "Refresh catalog"));
    // Retry while the cause is still there stays on the error screen.
    click_text(&mut app, &ctx, "Retry");
    assert!(app.start_error.is_some() && app.backend.is_none());
    // The cause is removed meanwhile: Retry reaches the normal UI.
    fs::remove_file(&blocker).unwrap();
    click_text(&mut app, &ctx, "Retry");
    assert!(app.start_error.is_none() && app.backend.is_some());
    assert!(!frame(&mut app, &ctx, vec![]).1);
    if let Some(backend) = app.backend.as_mut() {
        let _ = backend.shutdown();
    }
    let _ = fs::remove_dir_all(&scratch);
}

#[test]
fn quit_on_the_error_screen_closes_the_window() {
    let scratch = std::env::temp_dir().join(format!("ant-start-quit-{}", unique_id()));
    fs::create_dir_all(&scratch).unwrap();
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = failing_app(&scratch.join("blocker"));
    let output = click_text(&mut app, &ctx, "Quit");
    let closes = ctx_close_asked(&output);
    assert!(closes, "Quit asks the window to close");
    let _ = fs::remove_dir_all(&scratch);
}

fn ctx_close_asked(output: &egui::FullOutput) -> bool {
    output.viewport_output.values().any(|viewport| {
        viewport
            .commands
            .iter()
            .any(|command| matches!(command, egui::ViewportCommand::Close))
    })
}

#[test]
fn a_finished_catalog_refresh_replaces_the_refreshing_status() {
    let mut app = app();
    app.status = "refreshing base catalog".into();
    app.snapshot.remote_refreshing = true;
    app.track_catalog_refresh();
    assert!(
        app.catalog_feedback.busy(false),
        "the spinner outlasts a quick fetch"
    );
    app.snapshot.remote_refreshing = false;
    app.track_catalog_refresh();
    assert_eq!(app.status, "base catalog updated: 0 bases");
    assert!(app.catalog_feedback.updated.is_some());
    app.snapshot.remote_refreshing = true;
    app.track_catalog_refresh();
    app.snapshot.remote_refreshing = false;
    app.snapshot.remote_error = Some("offline".into());
    app.track_catalog_refresh();
    assert_eq!(app.status, "catalog refresh failed: offline");
}
