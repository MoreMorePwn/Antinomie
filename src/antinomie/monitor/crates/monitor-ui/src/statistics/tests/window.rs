// SPDX-License-Identifier: GPL-3.0-only
//! Card B: opening, closing, pop-out, following the run, the texts, copy and export.
use super::*;
use crate::statistics::worker::{Phase, Where};

fn rig_with_run() -> (Rig, Fixture) {
    let fixture = Fixture::new(&calls());
    let mut rig = Rig::new(Some(target(&fixture, "run-a")));
    rig.window.request_open(None);
    (rig, fixture)
}

#[test]
fn b1_a_second_request_opens_no_second_window_and_asks_for_focus() {
    let (mut rig, _fixture) = rig_with_run();
    assert!(rig.window.open);
    rig.window.focus = false;
    rig.window.request_open(Some(Tab::Hierarchy));
    assert!(rig.window.open);
    assert!(rig.window.focus, "the second request brings it forward");
    assert_eq!(rig.window.tab(), Tab::Hierarchy);
    rig.settle();
    assert!(!rig.window.focus, "the focus request is taken by a frame");
    assert!(rig.window.drawn > 0);
    let shown = rig.texts();
    let titles = shown
        .iter()
        .filter(|(text, _)| text.starts_with("Statistics ·"))
        .count();
    assert_eq!(titles, 1, "{shown:?}");
}

#[test]
fn b2_escape_closes_the_window_and_stops_the_walk() {
    let (mut rig, _fixture) = rig_with_run();
    rig.settle();
    assert!(rig.window.open);
    rig.key(egui::Key::Escape);
    assert!(!rig.window.open);
    assert!(!rig.window.worker.running());
    let before = rig.window.drawn;
    rig.frame(vec![]);
    assert_eq!(rig.window.drawn, before, "a closed window draws nothing");
}

#[test]
fn b3_pop_out_draws_a_viewport_and_back_returns_to_the_floating_window() {
    let (mut rig, _fixture) = rig_with_run();
    rig.settle();
    let floating = rig.window.drawn;
    // The viewport has an id of its own, the same every frame.
    let id = crate::statistics::window::viewport_id();
    assert_ne!(id, egui::ViewportId::ROOT);
    assert_eq!(id, crate::statistics::window::viewport_id());
    rig.window.set_popped(true);
    rig.frame(vec![]);
    rig.frame(vec![]);
    assert!(rig.window.popped());
    assert!(rig.window.drawn_popped > 0, "the viewport closure ran");
    assert_eq!(
        rig.window.drawn, floating,
        "the floating window is not drawn too"
    );
    // The embedded fallback (no separate windows in a test context) still shows the body.
    let shown = rig.texts();
    assert!(
        shown
            .iter()
            .any(|(text, _)| text == "Back into the main window"),
        "{shown:?}"
    );
    rig.click("Back into the main window");
    assert!(!rig.window.popped());
    let popped = rig.window.drawn_popped;
    rig.frame(vec![]);
    rig.frame(vec![]);
    // Floating again: no frame goes through the viewport.
    assert_eq!(rig.window.drawn_popped, popped);
    assert!(rig.window.drawn > floating);
    let shown = rig.texts();
    assert!(shown.iter().any(|(text, _)| text == "Pop out"), "{shown:?}");
}

#[test]
fn b4_size_and_pop_out_are_saved_and_restored() {
    let mut window = StatisticsWindow::default();
    assert_eq!(window.take_saved(), None);
    window.set_popped(true);
    assert_eq!(
        window.take_saved(),
        Some((crate::statistics::DEFAULT_SIZE, true))
    );
    window.remember([1000.4, 700.0]);
    assert_eq!(window.take_saved(), Some(([1000.0, 700.0], true)));
    // Too small a size is not kept.
    window.remember([100.0, 100.0]);
    assert_eq!(window.take_saved(), None);
    let mut restored = StatisticsWindow::default();
    restored.restore([1111.0, 777.0], true);
    assert_eq!(restored.size(), [1111.0, 777.0]);
    assert!(restored.popped());
    // Read once: a later restore does not undo what the person did since.
    restored.restore([700.0, 500.0], false);
    assert_eq!(restored.size(), [1111.0, 777.0]);
}

#[test]
fn b5_another_run_cancels_the_walk_and_reads_the_new_run() {
    let first = Fixture::new(&calls());
    let second = Fixture::new(&calls()[..6]);
    let mut rig = Rig::new(Some(target(&first, "run-a")));
    rig.window.request_open(None);
    rig.frame(vec![]);
    assert!(
        rig.window.worker.running(),
        "the walk started with the first frame"
    );
    assert_eq!(rig.window.worker.started, 1);
    rig.target = Some(target(&second, "run-b"));
    rig.frame(vec![]);
    assert_eq!(
        rig.window.worker.started, 2,
        "the new run starts its own walk"
    );
    rig.settle();
    let (key, stats) = rig.window.worker.shown().unwrap();
    assert_eq!(key.directory, second.directory);
    assert_eq!(stats.calls, 6);
    assert_eq!(rig.window.worker.phase, Phase::Done);
    // The same run asked again is served from memory, no new walk.
    rig.target = Some(target(&first, "run-a"));
    rig.settle();
    assert_eq!(rig.window.worker.started, 3);
    rig.target = Some(target(&second, "run-b"));
    rig.settle();
    assert_eq!(rig.window.worker.started, 3, "the result is kept in memory");
}

#[test]
fn b6_the_texts_of_progress_stopped_empty_no_telemetry_and_a_changed_recording() {
    use super::super::toolbar::status_line;
    let fixture = Fixture::new(&calls());
    let mut rig = Rig::new(Some(target(&fixture, "run-a")));
    rig.window.request_open(None);
    rig.settle();
    let (_, stats) = rig.window.worker.shown().unwrap();
    let stats = stats.clone();
    assert_eq!(
        status_line(
            &Phase::Running(Where::Indexing {
                done: 1 << 30,
                total: 6 << 30
            }),
            0,
            None,
            ""
        )
        .unwrap(),
        "Indexing the recording: 1.0 GiB of 6.0 GiB"
    );
    assert_eq!(
        status_line(
            &Phase::Running(Where::Reading {
                read: 2_100_000,
                total: 9_800_000
            }),
            0,
            None,
            ""
        )
        .unwrap(),
        "Reading calls: 2.1 M of 9.8 M (21 %)"
    );
    let mut partial = (*stats).clone();
    partial.read = 2_100_000;
    assert_eq!(
        status_line(&Phase::Stopped, 9_800_000, Some(&partial), "").unwrap(),
        "Stopped after 2.1 M of 9.8 M calls. The numbers cover those calls."
    );
    let mut none = (*stats).clone();
    none.calls = 0;
    assert_eq!(
        status_line(&Phase::Done, 0, Some(&none), "syscall.name == nosuch").unwrap(),
        "No call matches `syscall.name == nosuch`."
    );
    assert!(status_line(&Phase::Done, 0, Some(&stats), "").is_none());
    // The engine's own texts reach the window.
    let empty = Fixture::empty();
    let mut rig = Rig::new(Some(target(&empty, "run-empty")));
    rig.window.request_open(None);
    rig.settle();
    let shown = rig.texts();
    assert!(
        shown
            .iter()
            .any(|(text, _)| text
                .starts_with("This run saved no telemetry: it failed before recording")),
        "{shown:?}"
    );
    let changed = antinomie_triage::statistics::StatsError::Changed.to_string();
    assert_eq!(
        status_line(&Phase::Failed(changed.clone()), 0, None, "").unwrap(),
        changed
    );
    // No run selected.
    let mut rig = Rig::new(None);
    rig.window.request_open(None);
    let shown = rig.texts();
    assert!(
        shown
            .iter()
            .any(|(text, _)| text
                == "Select a run in Run History or the sidebar to see its statistics."),
        "{shown:?}"
    );
}

#[test]
fn b7_use_trace_filter_copies_it_and_an_invalid_filter_keeps_the_old_result_greyed() {
    let (mut rig, _fixture) = rig_with_run();
    rig.trace_filter = "syscall.name == openat".into();
    rig.settle();
    assert_eq!(rig.window.worker.shown().unwrap().1.calls, 15);
    rig.click("Use Trace filter");
    rig.settle();
    assert_eq!(rig.window.applied_filter(), "syscall.name == openat");
    assert_eq!(rig.window.worker.shown().unwrap().1.calls, 5);
    // An invalid edit shows its message and leaves the walk and the result alone.
    let started = rig.window.worker.started;
    rig.window.filter = "syscall.typo == 9".into();
    rig.window.apply();
    rig.frame(vec![]);
    assert!(rig.window.filter_error.is_some());
    assert_eq!(rig.window.applied_filter(), "syscall.name == openat");
    assert_eq!(rig.window.worker.started, started);
    assert_eq!(rig.window.worker.shown().unwrap().1.calls, 5);
    // Clear applies the empty filter again.
    rig.click("Clear");
    rig.settle();
    assert_eq!(rig.window.worker.shown().unwrap().1.calls, 15);
    assert!(rig.window.filter_error.is_none());
}

#[test]
fn b8_the_trace_button_opens_the_window_with_the_traces_filter() {
    let mut window = StatisticsWindow::default();
    window.open_with_filter("syscall.success == false");
    assert!(window.open);
    assert_eq!(window.applied_filter(), "syscall.success == false");
    assert_eq!(window.filter, "syscall.success == false");
    // A filter that does not compile is not applied, and the window still opens.
    let mut window = StatisticsWindow::default();
    window.open_with_filter("syscall.typo == 9");
    assert!(window.open);
    assert_eq!(window.applied_filter(), "");
    assert!(window.filter_error.is_some());
}

#[test]
fn b9_copy_puts_tab_separated_text_on_the_clipboard_and_export_writes_under_exports_statistics() {
    let (mut rig, _fixture) = rig_with_run();
    rig.window.request_open(Some(Tab::Hierarchy));
    rig.settle();
    let target = rig.target.clone().unwrap();
    let stats = rig.window.worker.shown().unwrap().1.clone();
    let ctx = rig.ctx.clone();
    let window = &mut rig.window;
    let output = ctx.run_ui(Default::default(), |root| {
        window.copy(&root.ctx().clone(), &target, &stats);
    });
    let copied = output
        .platform_output
        .commands
        .iter()
        .find_map(|command| match command {
            egui::OutputCommand::CopyText(text) => Some(text.clone()),
            _ => None,
        });
    let text = copied.expect("copy text");
    assert!(
        text.starts_with("group\tcall\tresult\tcalls\tfailed\n"),
        "{text}"
    );
    assert!(
        text.contains("\topenat\t") || text.contains("openat"),
        "{text}"
    );

    // Export writes a CSV under <data>/exports/statistics and says where.
    let view = AppView {
        target: None,
        trace_filter: "",
        hidden: &[],
        data_dir: &rig.data,
    };
    rig.window
        .export(&ctx, &view, &target, &stats, toolbar::Export::Csv);
    let folder = rig.data.join("exports").join("statistics");
    let files: Vec<_> = std::fs::read_dir(&folder).unwrap().flatten().collect();
    assert_eq!(files.len(), 1, "{files:?}");
    let name = files[0].file_name().to_string_lossy().into_owned();
    assert!(
        name.starts_with("antinomie-statistics-hierarchy-runa-") && name.ends_with("Z.csv"),
        "{name}"
    );
    let csv = std::fs::read_to_string(files[0].path()).unwrap();
    assert!(
        csv.starts_with("group,call,result,calls,failed\r\n"),
        "{csv}"
    );
    let note = rig.window.note.clone().unwrap();
    assert!(note.contains("exports/statistics"), "{note}");
    rig.window
        .export(&ctx, &view, &target, &stats, toolbar::Export::All);
    let json = std::fs::read_dir(&folder)
        .unwrap()
        .flatten()
        .find(|f| f.file_name().to_string_lossy().contains("statistics-all"))
        .expect("all-statistics file");
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(json.path()).unwrap()).unwrap();
    assert_eq!(parsed["schema"], "antinomie.statistics/1");
}
