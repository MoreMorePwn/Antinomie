// SPDX-License-Identifier: GPL-3.0-only
//! The Statistics window in the app: shortcut, menu, palette, the Trace button,
//! the settings and the click-through into the Trace (ANT-T0477, card B and C4).
//!
//! Run with `XDG_CACHE_HOME` set to a scratch folder: a walk builds the packet
//! index of its fixture in the cache folder.
use super::*;
use crate::statistics::Tab;
use antinomie_triage::statistics::fixture::{nr, Call, Fixture, ROOT};

const SIZE: egui::Vec2 = egui::vec2(1400.0, 900.0);

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

fn shown(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<(String, egui::Rect)> {
    for _ in 0..3 {
        render(app, ctx, SIZE);
    }
    texts(&render(app, ctx, SIZE))
}

fn has(visible: &[(String, egui::Rect)], label: &str) -> bool {
    visible.iter().any(|(text, _)| text == label)
}

fn calls() -> Vec<Call> {
    let mut calls = Vec::new();
    for i in 0..4_u64 {
        calls.push(
            Call::new(nr::OPENAT, 2)
                .at(10_000 + i * 1000, 40)
                .returns(3),
        );
    }
    calls.push(Call::new(nr::OPENAT, 2).at(20_000, 40).fails(2));
    calls.push(Call::new(nr::READ, 3).at(21_000, 40).returns(8));
    calls
}

/// An app with a finished run whose recording is `fixture`, selected.
fn app_with_run(fixture: &Fixture) -> MonitorApp {
    let mut app = app();
    observer_fixture(&mut app);
    let mut past = run("past");
    past.state = RunState::Finalized;
    past.root_task_cookie = ROOT;
    past.directory = fixture.directory.clone();
    app.history = vec![past];
    app.select_run(Some("past".into()));
    app
}

#[test]
fn ctrl_shift_t_opens_the_window_and_every_entry_point_is_listed() {
    let action = Action::Statistics(None);
    assert!(Action::bindable().contains(&action));
    for tab in Tab::ALL {
        assert!(Action::bindable().contains(&Action::Statistics(Some(tab))));
    }
    let shortcut = action.default_shortcut().expect("a default shortcut");
    assert_eq!(crate::app::bindings::to_text(&shortcut), "Ctrl+Shift+T");
    let ctx = context();
    let mut app = app();
    shown(&mut app, &ctx);
    assert!(!app.statistics.open);
    press(
        &mut app,
        &ctx,
        SIZE,
        egui::Key::T,
        egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
    );
    assert!(app.statistics.open, "the shortcut opens the window");
    // A second press keeps one window.
    press(
        &mut app,
        &ctx,
        SIZE,
        egui::Key::T,
        egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
    );
    assert!(app.statistics.open);
    let visible = shown(&mut app, &ctx);
    assert!(
        has(
            &visible,
            "Select a run in Run History or the sidebar to see its statistics."
        ),
        "{visible:?}"
    );
}

#[test]
fn the_statistics_menu_opens_the_window_on_a_tab() {
    let ctx = context();
    let mut app = app();
    click_label(&mut app, &ctx, SIZE, "Statistics");
    let visible = shown(&mut app, &ctx);
    for item in [
        "Statistics window",
        "Statistics: Properties",
        "Statistics: Hierarchy",
    ] {
        assert!(has(&visible, item), "{item}: {visible:?}");
    }
    click_label(&mut app, &ctx, SIZE, "Statistics: Hierarchy");
    assert!(app.statistics.open);
    assert_eq!(app.statistics.tab(), Tab::Hierarchy);
}

#[test]
fn the_menu_bar_still_fits_in_the_narrowest_window() {
    let ctx = context();
    let mut app = app();
    let narrow = egui::vec2(800.0, 600.0);
    for _ in 0..3 {
        render(&mut app, &ctx, narrow);
    }
    let visible = texts(&render(&mut app, &ctx, narrow));
    for menu in ["File", "VM", "Run", "View", "Statistics", "Tools", "Help"] {
        assert!(
            has(&visible, menu),
            "{menu} is clipped at 800 points: {visible:?}"
        );
    }
}

#[test]
fn the_trace_button_opens_the_window_on_the_traces_filter() {
    let ctx = context();
    let mut app = app();
    app.selected = Some("vm".into());
    let mut past = run("past");
    past.state = RunState::Finalized;
    app.history.push(past);
    app.select_run(Some("past".into()));
    app.filter = "syscall.name == openat".into();
    app.applied_filter = "syscall.name == openat".into();
    click_label(&mut app, &ctx, SIZE, "Statistics of these calls");
    assert!(app.statistics.open);
    assert_eq!(app.statistics.applied_filter(), "syscall.name == openat");
}

#[test]
fn the_size_and_pop_out_state_are_settings_that_older_files_lack() {
    let settings: Settings = serde_json::from_str("{}").expect("an empty settings file loads");
    assert_eq!(settings.statistics_window, crate::statistics::DEFAULT_SIZE);
    assert!(!settings.statistics_popped);
    let settings = Settings {
        statistics_window: [1000.0, 700.0],
        statistics_popped: true,
        ..Settings::default()
    };
    let text = serde_json::to_string(&settings).unwrap();
    let back: Settings = serde_json::from_str(&text).unwrap();
    assert_eq!(back.statistics_window, [1000.0, 700.0]);
    assert!(back.statistics_popped);
    // The window takes them and hands changes back.
    let ctx = context();
    let mut app = app();
    app.settings = back;
    app.statistics.request_open(None);
    shown(&mut app, &ctx);
    assert!(app.statistics.popped());
    assert_eq!(app.statistics.size(), [1000.0, 700.0]);
    app.statistics.set_popped(false);
    shown(&mut app, &ctx);
    assert!(
        !app.settings.statistics_popped,
        "Back into the main window is saved"
    );
}

#[test]
fn the_window_follows_the_selected_run_and_a_click_scopes_the_trace() {
    let fixture = Fixture::new(&calls());
    let ctx = context();
    let mut app = app_with_run(&fixture);
    let target = app.statistics_target().expect("the selected run");
    assert_eq!(target.id, "past");
    assert_eq!(target.directory, fixture.directory);
    assert!(!target.capture);
    assert!(!target.live);
    assert_eq!(target.root_cookie, ROOT);
    app.statistics.request_open(Some(Tab::Hierarchy));
    let begin = std::time::Instant::now();
    loop {
        let visible = shown(&mut app, &ctx);
        if has(&visible, "openat") {
            break;
        }
        assert!(
            begin.elapsed() < std::time::Duration::from_secs(60),
            "{visible:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    click_label(&mut app, &ctx, SIZE, "openat");
    assert_eq!(app.applied_filter, "syscall.name == openat");
    assert_eq!(app.filter, "syscall.name == openat");
    assert_eq!(app.focus_panel, Some(Panel::Trace));
    // A hidden category: Show and open removes it from the Trace's hidden list.
    let group = SyscallGroup::of("openat").unwrap();
    app.settings.hidden_trace_categories = vec![group];
    app.filter.clear();
    app.applied_filter.clear();
    // Two clicks in one place within 0.3 s are a double click.
    for _ in 0..24 {
        shown(&mut app, &ctx);
    }
    click_label(&mut app, &ctx, SIZE, "openat");
    assert!(
        app.applied_filter.is_empty() && app.filter.is_empty(),
        "asked first, nothing opened"
    );
    assert_eq!(app.settings.hidden_trace_categories, vec![group]);
    for _ in 0..24 {
        shown(&mut app, &ctx);
    }
    click_label(&mut app, &ctx, SIZE, "Show and open");
    assert!(app.settings.hidden_trace_categories.is_empty());
    assert_eq!(app.applied_filter, "syscall.name == openat");
}

#[test]
fn a_selected_capture_is_a_target_of_its_own() {
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot
        .captures
        .push(observer("cap-1234abcd", CaptureState::Stopped));
    app.selected_capture = Some("cap-1234abcd".into());
    let target = app.statistics_target().expect("the capture");
    assert!(target.capture);
    assert_eq!(target.root_cookie, 0);
    assert_eq!(target.label, "capture cap-1234");
    assert!(target.facts.capture);
}
