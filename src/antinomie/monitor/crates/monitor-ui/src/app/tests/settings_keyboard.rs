// SPDX-License-Identifier: GPL-3.0-only
//! Settings > Keyboard: every action has its own row; a click records the next
//! key, a taken key asks, and a row resets to its default. The choice is kept
//! and the menus, tooltips and palette show it.
use super::*;
use crate::app::settings_window::SettingsPage;

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

const SIZE: egui::Vec2 = egui::vec2(1280.0, 800.0);

fn shown(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<(String, egui::Rect)> {
    for _ in 0..3 {
        render(app, ctx, SIZE);
    }
    texts(&render(app, ctx, SIZE))
}

fn has(visible: &[(String, egui::Rect)], label: &str) -> bool {
    visible.iter().any(|(text, _)| text == label)
}

/// Press `key` with `modifiers` for one frame.
fn press(app: &mut MonitorApp, ctx: &egui::Context, key: egui::Key, modifiers: egui::Modifiers) {
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            events: vec![
                egui::Event::ModifiersChanged(modifiers),
                egui::Event::Key {
                    key,
                    physical_key: Some(key),
                    pressed: true,
                    repeat: false,
                    modifiers,
                },
            ],
            ..Default::default()
        },
        |root| app.draw(root),
    );
    let _ = output;
    // Let go of the modifiers.
    let _ = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            events: vec![egui::Event::ModifiersChanged(egui::Modifiers::NONE)],
            ..Default::default()
        },
        |root| app.draw(root),
    );
}

fn keyboard_page() -> (MonitorApp, egui::Context) {
    let ctx = context();
    let mut app = app();
    app.settings_open = true;
    app.settings_page = SettingsPage::Keyboard;
    shown(&mut app, &ctx);
    (app, ctx)
}

#[test]
fn every_action_has_its_own_row_and_the_new_defaults_are_listed() {
    let (mut app, ctx) = keyboard_page();
    // One row per action: the bottom pane and each view have their own, with
    // the default of each beside it.
    for (words, label, keys) in [
        ("start vm", "Start VM", "Ctrl+Shift+S"),
        ("stop vm", "Stop VM", "Ctrl+Shift+X"),
        ("details", "Details", "Ctrl+Shift+D"),
        (
            "details",
            "Fold or open Details, Activity and Jobs",
            "Ctrl+J",
        ),
        ("activity", "Activity", "Ctrl+Shift+A"),
        ("jobs", "Jobs", "Ctrl+Shift+J"),
    ] {
        app.shortcut_ui.filter = words.into();
        let visible = shown(&mut app, &ctx);
        assert!(has(&visible, label), "{label}: {visible:?}");
        assert!(has(&visible, keys), "{keys}: {visible:?}");
    }
}

#[test]
fn a_click_records_the_next_key_and_a_reset_brings_the_default_back() {
    let (mut app, ctx) = keyboard_page();
    // Recording starts at the click, and a press with Ctrl takes the row.
    app.shortcut_ui.recording = Some(Action::ToggleSidebar);
    press(&mut app, &ctx, egui::Key::M, egui::Modifiers::COMMAND);
    assert!(app.shortcut_ui.recording.is_none());
    let chosen = app.shortcut_of(&Action::ToggleSidebar).expect("a shortcut");
    assert_eq!(bindings::to_text(&chosen), "Ctrl+M");
    assert!(app.shortcut_changed(&Action::ToggleSidebar));
    // It is saved, by the action's name.
    assert_eq!(
        app.settings
            .shortcuts
            .get("ToggleSidebar")
            .map(String::as_str),
        Some("Ctrl+M")
    );
    // The menus and tooltips show it.
    assert_eq!(
        app.shortcut_text(&ctx, &Action::ToggleSidebar).as_deref(),
        Some("Ctrl+M")
    );
    // A press without Ctrl or Alt is refused with a reason, and recording goes on.
    app.shortcut_ui.recording = Some(Action::Quit);
    press(&mut app, &ctx, egui::Key::Q, egui::Modifiers::NONE);
    assert!(app.shortcut_ui.recording.is_some());
    assert!(app.shortcut_ui.notice.is_some());
    // Escape cancels.
    press(&mut app, &ctx, egui::Key::Escape, egui::Modifiers::NONE);
    assert!(app.shortcut_ui.recording.is_none());
    assert_eq!(
        app.shortcut_of(&Action::Quit),
        Action::Quit.default_shortcut()
    );
    // Reset through the row's button.
    app.shortcut_ui.filter = "sidebar".into();
    let visible = shown(&mut app, &ctx);
    assert!(has(&visible, "Ctrl+M"), "{visible:?}");
    click_label(&mut app, &ctx, SIZE, "Reset");
    assert!(!app.shortcut_changed(&Action::ToggleSidebar));
    assert_eq!(
        app.shortcut_of(&Action::ToggleSidebar),
        Action::ToggleSidebar.default_shortcut()
    );
}

#[test]
fn a_key_another_action_has_asks_before_it_moves() {
    let (mut app, ctx) = keyboard_page();
    app.shortcut_ui.recording = Some(Action::ToggleSidebar);
    // Ctrl+K is the command palette's.
    press(&mut app, &ctx, egui::Key::K, egui::Modifiers::COMMAND);
    assert_eq!(
        app.shortcut_of(&Action::ToggleSidebar),
        Action::ToggleSidebar.default_shortcut(),
        "nothing changed yet"
    );
    let (action, _, owner) = app.shortcut_ui.conflict.clone().expect("a conflict");
    assert_eq!((action, owner), (Action::ToggleSidebar, Action::Palette));
    let visible = shown(&mut app, &ctx);
    assert!(
        visible
            .iter()
            .any(|(text, _)| text.starts_with("Ctrl+K is already Command palette")),
        "{visible:?}"
    );
    // Keep it where it is: nothing moves.
    click_label(&mut app, &ctx, SIZE, "Keep it where it is");
    assert!(app.shortcut_ui.conflict.is_none());
    assert_eq!(
        app.shortcut_of(&Action::Palette),
        Action::Palette.default_shortcut()
    );
    // Move it: the palette is left without one.
    app.shortcut_ui.recording = Some(Action::ToggleSidebar);
    press(&mut app, &ctx, egui::Key::K, egui::Modifiers::COMMAND);
    click_label(&mut app, &ctx, SIZE, "Move it to Fold or open the sidebar");
    assert_eq!(app.shortcut_of(&Action::Palette), None);
    assert_eq!(
        bindings::to_text(&app.shortcut_of(&Action::ToggleSidebar).unwrap()),
        "Ctrl+K"
    );
}

#[test]
fn a_chosen_shortcut_runs_its_action_and_the_old_one_does_not() {
    let ctx = context();
    let mut app = app();
    let before = app.layout.bottom_folded();
    app.set_shortcut(
        &Action::ToggleBottomPane,
        Some(bindings::from_text("Alt+J").unwrap()),
    );
    // The default no longer folds the pane.
    press(&mut app, &ctx, egui::Key::J, egui::Modifiers::COMMAND);
    assert_eq!(app.layout.bottom_folded(), before);
    press(&mut app, &ctx, egui::Key::J, egui::Modifiers::ALT);
    assert_ne!(app.layout.bottom_folded(), before);
}

#[test]
fn the_new_defaults_run_their_actions() {
    let ctx = context();
    let mut app = app();
    let before = app.layout.bottom_folded();
    press(&mut app, &ctx, egui::Key::J, egui::Modifiers::COMMAND);
    assert_ne!(app.layout.bottom_folded(), before);
    assert_eq!(
        app.shortcut_text(&ctx, &Action::ToggleBottomPane)
            .as_deref(),
        Some("Ctrl+J")
    );
}
