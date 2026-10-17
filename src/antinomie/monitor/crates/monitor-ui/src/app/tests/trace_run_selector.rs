// SPDX-License-Identifier: MIT
//! The program-run dropdown in the syscall trace.
use super::*;

const SIZE: egui::Vec2 = egui::vec2(1400.0, 900.0);

fn past_run(id: &str, path: &str, started_ms: u64) -> RunSummary {
    let mut run = run(id);
    run.state = RunState::Finalized;
    run.started_ms = Some(started_ms);
    run.request.path = path.into();
    run.directory = PathBuf::from(format!("/runs/{id}"));
    run
}

fn app_with_runs() -> (MonitorApp, egui::Context) {
    let mut app = app();
    observer_fixture(&mut app);
    app.history = vec![
        past_run("old", "/bin/old", 1_800_000_000_000),
        past_run("new", "/bin/new", 1_800_000_900_000),
    ];
    let ctx = egui::Context::default();
    theme::install(&ctx);
    (app, ctx)
}

fn settle(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<(String, egui::Rect)> {
    for _ in 0..3 {
        render(app, ctx, SIZE);
    }
    texts(&render(app, ctx, SIZE))
}

fn row_y(shown: &[(String, egui::Rect)], needle: &str) -> f32 {
    shown
        .iter()
        .find(|(text, _)| text.contains(needle))
        .unwrap_or_else(|| panic!("missing {needle}: {shown:?}"))
        .1
        .min
        .y
}

#[test]
fn trace_dropdown_lists_live_trace_then_runs_newest_first() {
    let (mut app, ctx) = app_with_runs();
    assert!(settle(&mut app, &ctx)
        .iter()
        .any(|(text, _)| text == "Live trace"));
    click_label(&mut app, &ctx, SIZE, "Live trace");
    let shown = settle(&mut app, &ctx);
    let live_entries = shown
        .iter()
        .filter(|(text, _)| text == "Live trace")
        .count();
    assert_eq!(live_entries, 2, "closed dropdown plus its first entry");
    let newest = row_y(&shown, "/bin/new");
    let oldest = row_y(&shown, "/bin/old");
    assert!(newest < oldest, "{shown:?}");
}

#[test]
fn choosing_a_run_selects_it_and_loads_its_archive_asynchronously() {
    let (mut app, ctx) = app_with_runs();
    settle(&mut app, &ctx);
    click_label(&mut app, &ctx, SIZE, "Live trace");
    settle(&mut app, &ctx);
    let label = run_selector_label_for(&app, "old");
    click_label(&mut app, &ctx, SIZE, &label);
    assert_eq!(app.selected_run.as_deref(), Some("old"));
    assert_eq!(
        app.trace_archive_directory(),
        Some(PathBuf::from("/runs/old"))
    );
    assert!(app.archive_pending);
    assert!(matches!(
        &app.pending_archive,
        Some(Request::Invocations { directory, offset: 0, .. }) if directory == &PathBuf::from("/runs/old")
    ));
    // Back to the live trace.
    let shown = settle(&mut app, &ctx);
    assert!(shown.iter().any(|(text, _)| text == &label));
    click_label(&mut app, &ctx, SIZE, &label);
    settle(&mut app, &ctx);
    click_label(&mut app, &ctx, SIZE, "Live trace");
    assert_eq!(app.selected_run, None);
    assert_eq!(app.trace_archive_directory(), None);
}

#[test]
fn run_chosen_in_triage_shows_in_the_trace_dropdown_and_back() {
    let (mut app, ctx) = app_with_runs();
    app.focus_panel = Some(Panel::Triage);
    settle(&mut app, &ctx);
    click_label(&mut app, &ctx, SIZE, "Select a program run");
    settle(&mut app, &ctx);
    let label = run_selector_label_for(&app, "old");
    click_label(&mut app, &ctx, SIZE, &label);
    assert_eq!(app.selected_run.as_deref(), Some("old"));
    app.focus_panel = Some(Panel::Trace);
    let shown = settle(&mut app, &ctx);
    assert!(shown.iter().any(|(text, _)| text == &label), "{shown:?}");
    assert!(!shown.iter().any(|(text, _)| text == "Live trace"));
    // The reverse direction: the trace choice is the Triage choice.
    click_label(&mut app, &ctx, SIZE, &label);
    settle(&mut app, &ctx);
    let newest = run_selector_label_for(&app, "new");
    click_label(&mut app, &ctx, SIZE, &newest);
    assert_eq!(app.selected_run.as_deref(), Some("new"));
    app.focus_panel = Some(Panel::Triage);
    let shown = settle(&mut app, &ctx);
    assert!(shown.iter().any(|(text, _)| text == &newest), "{shown:?}");
}

fn run_selector_label_for(app: &MonitorApp, id: &str) -> String {
    let runs = app.triage_runs();
    super::super::run_selector::run_selector_label(runs.iter().find(|run| run.id == id).unwrap())
}
