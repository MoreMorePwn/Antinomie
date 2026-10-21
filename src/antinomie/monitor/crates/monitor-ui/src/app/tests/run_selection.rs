// SPDX-License-Identifier: MIT
//! The selected run and what shows its health: it survives VM restarts,
//! filters and queued reads, leaves with a deleted VM, and says when its
//! recording is incomplete.
use super::*;

const SIZE: egui::Vec2 = egui::vec2(1400.0, 900.0);

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

fn running_app() -> MonitorApp {
    let mut app = app();
    observer_fixture(&mut app);
    app
}

fn past_run(id: &str, path: &str, started_ms: u64) -> RunSummary {
    let mut run = run(id);
    run.state = RunState::Finalized;
    run.started_ms = Some(started_ms);
    run.request.path = path.into();
    run.directory = PathBuf::from(format!("/runs/{id}"));
    run
}

fn frames(app: &mut MonitorApp, ctx: &egui::Context, count: usize) -> egui::FullOutput {
    let mut out = egui::FullOutput::default();
    for frame in 0..count {
        out = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                time: Some(frame as f64 * 0.05),
                ..Default::default()
            },
            |ctx| app.draw(ctx),
        );
    }
    out
}

/// Every text drawn for `panel` that is in view. A glyph's overhang may cross
/// the clip rectangle by a pixel, so the clip is widened by that much.
fn shown(app: &mut MonitorApp, ctx: &egui::Context, panel: Panel) -> Vec<String> {
    fn collect(shape: &egui::Shape, clip: egui::Rect, out: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(text) => {
                if clip.expand(2.0).contains_rect(text.visual_bounding_rect()) {
                    out.push(text.galley.text().trim().to_owned());
                }
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, clip, out)),
            _ => {}
        }
    }
    app.focus_panel = Some(panel);
    let output = frames(app, ctx, 4);
    let mut texts = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, shape.clip_rect, &mut texts);
    }
    texts
}

fn mentions(shown: &[String], needle: &str) -> bool {
    shown
        .iter()
        .any(|text| text.to_lowercase().contains(&needle.to_lowercase()))
}

fn add_vm(app: &mut MonitorApp, id: &str) {
    app.snapshot.vms.push(VmConfig {
        id: id.into(),
        name: id.into(),
        ..Default::default()
    });
}

/// Delivers `next` the way a backend notification does.
fn deliver(app: &mut MonitorApp, next: Snapshot) {
    let mut activity = Vec::new();
    app.accept_snapshot(next, &mut activity);
}

fn recording_directory(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("run-selection-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn live_app() -> MonitorApp {
    let mut app = running_app();
    app.snapshot.runs.push(run("r1"));
    app.snapshot.events = vec![event(1, 0), event(2, 0)];
    app.selected_run = Some("r1".into());
    app
}

fn specimen_request(view_key: &str) -> Request {
    Request::Specimen {
        view_key: view_key.into(),
        generation: 1,
        directory: PathBuf::from("/x"),
        report_id: "r".into(),
        offset: 0,
        data_len: 64,
    }
}

fn waiting_view() -> AnalysisView {
    AnalysisView {
        pending: Some((1, 0, 64)),
        ..Default::default()
    }
}

// --- Runs of an earlier boot stay listed across a VM restart -------------

fn restarted_vm_app() -> MonitorApp {
    let mut app = app();
    add_vm(&mut app, "vm");
    app.selected = Some("vm".into());
    // History was listed when the VM was selected, before this boot's runs.
    app.history = vec![past_run("older", "/bin/older", 1_800_000_000_000)];
    let mut ran = past_run("ran-in-boot-1", "/bin/sample", 1_800_000_900_000);
    ran.boot_id = "boot-1".into();
    app.snapshot.runs = vec![ran];
    app.snapshot.boot_id = Some("boot-1".into());
    app.select_run(Some("ran-in-boot-1".into()));
    app
}

fn boot_two(app: &MonitorApp) -> Snapshot {
    let mut next = app.snapshot.clone();
    next.runs.clear();
    next.state = VmState::Running;
    next.active_vm = Some("vm".into());
    next.boot_id = Some("boot-2".into());
    next
}

#[test]
fn runs_of_a_stopped_boot_stay_in_history_and_dropdowns_when_the_vm_restarts() {
    let mut app = restarted_vm_app();
    assert!(app.triage_runs().iter().any(|r| r.id == "ran-in-boot-1"));
    let next = boot_two(&app);
    deliver(&mut app, next);
    app.drain();
    let ids: Vec<_> = app.triage_runs().iter().map(|run| run.id.clone()).collect();
    assert!(ids.contains(&"ran-in-boot-1".to_owned()), "{ids:?}");
    assert!(ids.contains(&"older".to_owned()), "{ids:?}");
    assert_eq!(app.selected_run.as_deref(), Some("ran-in-boot-1"));
    assert!(app.selected_triage_run().is_some());
    assert_eq!(
        app.history
            .iter()
            .filter(|run| run.id == "ran-in-boot-1")
            .count(),
        1
    );
}

#[test]
fn a_boot_starting_or_ending_asks_for_the_run_list_again() {
    let mut app = restarted_vm_app();
    app.pending_archive = None;
    let next = boot_two(&app);
    deliver(&mut app, next);
    app.drain();
    assert!(
        matches!(&app.pending_archive, Some(Request::ListVm { vm_id, .. }) if vm_id == "vm"),
        "no run list was requested for the new boot"
    );
    // The VM stops: the list is asked for again.
    app.pending_archive = None;
    let mut stopped = app.snapshot.clone();
    stopped.state = VmState::Stopped;
    stopped.active_vm = None;
    deliver(&mut app, stopped);
    app.drain();
    assert!(matches!(app.pending_archive, Some(Request::ListVm { .. })));
}

#[test]
fn a_run_ending_asks_for_the_run_list_and_a_busy_request_slot_defers_it() {
    let mut app = running_app();
    app.snapshot.runs.push(run("r1"));
    app.pending_archive = Some(specimen_request("w"));
    app.analysis_views.insert("w".into(), waiting_view());
    let mut next = app.snapshot.clone();
    next.runs[0].state = RunState::Finalized;
    deliver(&mut app, next);
    app.drain();
    assert!(
        matches!(app.pending_archive, Some(Request::Specimen { .. })),
        "the refresh replaced a read that a view waits on"
    );
    assert!(app.analysis_views["w"].pending.is_some());
    app.pending_archive = None;
    app.drain();
    assert!(matches!(app.pending_archive, Some(Request::ListVm { .. })));
}

#[test]
fn a_run_list_replaced_by_another_read_is_asked_for_again() {
    let mut app = running_app();
    app.refresh_history();
    assert!(matches!(app.pending_archive, Some(Request::ListVm { .. })));
    app.snapshot.state = VmState::Stopped;
    app.snapshot.active_vm = None;
    app.history.push(past_run("old", "/bin/old", 1));
    app.select_run(Some("old".into()));
    assert!(matches!(
        app.pending_archive,
        Some(Request::Invocations { .. })
    ));
    app.pending_archive = None;
    app.drain();
    assert!(
        matches!(app.pending_archive, Some(Request::ListVm { .. })),
        "the replaced run list was never asked for again"
    );
}

#[test]
fn replacing_one_history_list_kind_defers_a_refresh_for_that_kind() {
    let mut app = running_app();
    let options = app.options.clone();
    app.pending_archive = Some(Request::ListVm {
        options: options.clone(),
        vm_id: "vm".into(),
        generation: 1,
        carried: Vec::new(),
    });
    app.queue_archive(Request::ListCaptures {
        options: options.clone(),
        vm_id: "vm".into(),
        generation: 2,
    });
    assert!(app.history_sync.refresh_due);
    app.pending_archive = None;
    app.refresh_history_when_idle();
    assert!(matches!(app.pending_archive, Some(Request::ListVm { .. })));

    let mut app = running_app();
    app.pending_archive = Some(Request::ListCaptures {
        options: options.clone(),
        vm_id: "vm".into(),
        generation: 1,
    });
    app.queue_archive(Request::ListVm {
        options,
        vm_id: "vm".into(),
        generation: 2,
        carried: Vec::new(),
    });
    assert!(app.history_sync.captures_refresh_due);
    app.pending_archive = None;
    app.refresh_history_when_idle();
    assert!(matches!(
        app.pending_archive,
        Some(Request::ListCaptures { .. })
    ));
}

#[test]
fn stale_capture_list_reply_after_run_refresh_requeues_capture_history() {
    let mut app = running_app();
    app.selected = Some("vm".into());
    app.capture_tab = true;
    app.capture_history = vec![observer("existing", CaptureState::Finalized)];
    app.refresh_captures();
    let capture_generation = app.history_generation;
    // The capture request is now in flight, freeing the single queued slot.
    app.pending_archive = None;
    app.refresh_run_history();
    assert!(app.history_generation > capture_generation);
    assert!(matches!(app.pending_archive, Some(Request::ListVm { .. })));

    app.handle_archive_answer(Answer::ListCaptures {
        vm_id: "vm".into(),
        generation: capture_generation,
        result: Ok(vec![observer("late", CaptureState::Finalized)]),
    });
    assert_eq!(app.capture_history[0].id, "existing");
    assert!(app.history_sync.captures_refresh_due);

    // Once the run list leaves the queue, the lost capture refresh is replayed.
    app.pending_archive = None;
    app.refresh_history_when_idle();
    assert!(matches!(
        app.pending_archive,
        Some(Request::ListCaptures { vm_id, .. }) if vm_id == "vm"
    ));
}

#[test]
fn a_run_list_read_before_the_run_was_saved_does_not_drop_the_run() {
    let mut app = restarted_vm_app();
    let directory = recording_directory("late-list");
    app.snapshot.runs[0].directory = directory.clone();
    let next = boot_two(&app);
    deliver(&mut app, next);
    app.refresh_history();
    let generation = app.history_generation;
    // The listing was made before the run's recording was listable.
    app.handle_archive_answer(Answer::ListVm {
        vm_id: "vm".into(),
        generation,
        result: Ok(vec![past_run("older", "/bin/older", 1_800_000_000_000)]),
        checked: vec!["ran-in-boot-1".into()],
        retained: vec!["ran-in-boot-1".into()],
    });
    assert!(app.history.iter().any(|run| run.id == "ran-in-boot-1"));
    // A later listing that has it replaces the kept copy.
    let mut saved = past_run("ran-in-boot-1", "/bin/sample", 1_800_000_900_000);
    saved.directory = directory.clone();
    app.refresh_history();
    let generation = app.history_generation;
    app.handle_archive_answer(Answer::ListVm {
        vm_id: "vm".into(),
        generation,
        result: Ok(vec![saved]),
        checked: vec!["ran-in-boot-1".into()],
        retained: Vec::new(),
    });
    assert_eq!(
        app.history
            .iter()
            .filter(|run| run.id == "ran-in-boot-1")
            .count(),
        1
    );
    // A recording that was removed from disk is not kept.
    let mut gone = past_run("removed", "/bin/gone", 1);
    gone.directory = directory.join("removed");
    let mut next = app.snapshot.clone();
    next.runs = vec![gone];
    deliver(&mut app, next);
    let next = boot_two(&app);
    deliver(&mut app, next);
    app.refresh_history();
    let generation = app.history_generation;
    app.handle_archive_answer(Answer::ListVm {
        vm_id: "vm".into(),
        generation,
        result: Ok(Vec::new()),
        checked: vec!["removed".into()],
        retained: Vec::new(),
    });
    assert!(app.history.is_empty(), "{:?}", app.history.len());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn carried_run_path_validation_uses_bounded_batches_without_dropping_runs() {
    let mut app = running_app();
    app.selected = Some("vm".into());
    let directory = recording_directory("path-budget");
    let mut live = app.snapshot.clone();
    live.boot_id = Some("boot-one".into());
    live.active_vm = Some("vm".into());
    live.runs = (0..257)
        .map(|index| {
            let mut run = past_run(&format!("run-{index}"), "/bin/sample", index);
            run.vm_id = "vm".into();
            run.directory = directory.clone();
            run
        })
        .collect();
    deliver(&mut app, live);
    let mut restarted = app.snapshot.clone();
    restarted.boot_id = Some("boot-two".into());
    restarted.runs.clear();
    deliver(&mut app, restarted);

    app.refresh_history();
    let (generation, first_batch) = match &app.pending_archive {
        Some(Request::ListVm {
            generation,
            carried,
            ..
        }) => (*generation, carried.clone()),
        _ => panic!("expected bounded run listing"),
    };
    assert_eq!(first_batch.len(), 256);
    let first_ids: Vec<_> = first_batch.iter().map(|(id, _)| id.clone()).collect();
    app.pending_archive = None;
    app.handle_archive_answer(Answer::ListVm {
        vm_id: "vm".into(),
        generation,
        result: Ok(Vec::new()),
        checked: first_ids.clone(),
        retained: first_ids,
    });
    assert!(app.history_sync.refresh_due);
    app.refresh_history_when_idle();
    let (generation, next_batch) = match &app.pending_archive {
        Some(Request::ListVm {
            generation,
            carried,
            ..
        }) => (*generation, carried.clone()),
        _ => panic!("expected next bounded run listing"),
    };
    assert_eq!(next_batch.len(), 1);
    let final_id = next_batch[0].0.clone();
    app.pending_archive = None;
    app.handle_archive_answer(Answer::ListVm {
        vm_id: "vm".into(),
        generation,
        result: Ok(Vec::new()),
        checked: vec![final_id.clone()],
        retained: vec![final_id],
    });
    assert_eq!(app.history.len(), 257);
    assert!(!app.history_sync.refresh_due);
    std::fs::remove_dir_all(directory).unwrap();
}

// --- A Run History filter never changes the selection ---------------------

#[test]
fn run_history_filter_keeps_a_run_chosen_in_the_dropdown_and_says_it_is_hidden() {
    let mut app = running_app();
    app.history = vec![past_run("old", "/bin/old", 1_800_000_000_000)];
    let ctx = context();
    // Run History is on "Live"; the user picks a past run in a dropdown.
    app.run_filter = RunFilter::Live;
    app.select_run(Some("old".into()));
    let text = shown(&mut app, &ctx, Panel::RunHistory);
    assert_eq!(
        app.selected_run.as_deref(),
        Some("old"),
        "Run History drawing cleared the selection the user just made"
    );
    assert!(mentions(&text, "hidden by this filter"), "{text:?}");
    assert!(mentions(&text, "Clear filter"), "{text:?}");
}

#[test]
fn a_typed_run_filter_keeps_the_selected_run_and_clearing_it_shows_the_run_again() {
    let mut app = running_app();
    app.history = vec![past_run("old", "/bin/old", 1_800_000_000_000)];
    let ctx = context();
    app.select_run(Some("old".into()));
    app.run_query = "pid == 99999".into();
    let text = shown(&mut app, &ctx, Panel::RunHistory);
    assert_eq!(app.selected_run.as_deref(), Some("old"));
    assert!(mentions(&text, "hidden by this filter"), "{text:?}");
    app.run_filter = RunFilter::Live;
    app.clear_run_filter();
    let text = shown(&mut app, &ctx, Panel::RunHistory);
    assert_eq!(app.selected_run.as_deref(), Some("old"));
    assert!(app.run_query.is_empty() && app.run_filter == RunFilter::All);
    assert!(!mentions(&text, "hidden by this filter"), "{text:?}");
}

#[test]
fn capture_history_filter_keeps_its_selected_capture_and_identifies_it_as_hidden() {
    let mut app = running_app();
    app.capture_tab = true;
    app.capture_history
        .push(observer("selected-capture", CaptureState::Stopped));
    app.selected_capture = Some("selected-capture".into());
    let ctx = context();
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let filter_id = ui.id().with(("table-filter", "capture-history"));
                ui.data_mut(|data| data.insert_temp(filter_id, "cookie == 7".to_owned()));
                app.run_history(ui);
                assert_eq!(app.selected_capture.as_deref(), Some("selected-capture"));
            });
        },
    );
    let text: Vec<_> = super::texts(&output)
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    assert!(mentions(&text, "hidden by this filter"), "{text:?}");
    assert!(mentions(&text, "clear filter"), "{text:?}");
}

// --- A run whose saving stopped says so wherever the run is shown ---------

#[test]
fn a_run_whose_saving_stopped_says_so_in_its_trace_history_details_and_triage() {
    let mut app = live_app();
    app.snapshot.runs[0].recording_error = Some("disk full while saving the recording".into());
    app.snapshot.health.persistence_error = None;
    let ctx = context();
    for panel in [
        Panel::Trace,
        Panel::RunHistory,
        Panel::Details,
        Panel::Triage,
    ] {
        let title = panel.title().to_owned();
        let text = shown(&mut app, &ctx, panel);
        assert!(
            mentions(&text, "disk full") || mentions(&text, "saving stopped"),
            "{title} presents the run as healthy: {text:?}"
        );
    }
}

#[test]
fn summary_omits_saved_run_causes_which_remain_in_the_selected_run_details() {
    let mut app = running_app();
    let mut saved = past_run("saved-run", "/bin/older", 1);
    saved.vm_id = "vm".into();
    saved.recording_error = Some("disk full in an earlier boot".into());
    saved.notes = vec!["an earlier recording note".into()];
    app.history.push(saved);

    let text = shown(&mut app, &context(), Panel::Summary);
    assert!(!mentions(&text, "disk full"), "{text:?}");
    assert!(!mentions(&text, "an earlier recording note"), "{text:?}");
    app.select_run(Some("saved-run".into()));
    let text = shown(&mut app, &context(), Panel::Details);
    assert!(mentions(&text, "disk full in an earlier boot"), "{text:?}");
    assert!(mentions(&text, "an earlier recording note"), "{text:?}");
}

#[test]
fn run_history_marks_the_row_of_a_run_whose_saving_stopped() {
    let mut app = live_app();
    let ctx = context();
    let healthy = shown(&mut app, &ctx, Panel::RunHistory);
    assert!(!mentions(&healthy, "saving stopped"), "{healthy:?}");
    app.snapshot.runs[0].recording_error = Some("disk full".into());
    let text = shown(&mut app, &ctx, Panel::RunHistory);
    assert!(mentions(&text, "saving stopped"), "{text:?}");
}

#[test]
fn recording_notes_show_as_notes_and_never_as_a_saving_failure() {
    let mut app = live_app();
    let note = "3 telemetry packets arrived before the launch was acknowledged";
    app.snapshot.runs[0].notes = vec![note.into()];
    let ctx = context();
    for panel in [Panel::Trace, Panel::Details, Panel::Triage] {
        let title = panel.title().to_owned();
        let text = shown(&mut app, &ctx, panel);
        assert!(mentions(&text, note), "{title} hides the note: {text:?}");
        assert!(
            !mentions(&text, "incomplete") && !mentions(&text, "saving stopped"),
            "{title} reports a note as a saving failure: {text:?}"
        );
    }
    let text = shown(&mut app, &ctx, Panel::RunHistory);
    assert!(!mentions(&text, "saving stopped"), "{text:?}");
    let text = shown(&mut app, &ctx, Panel::Summary);
    // The selected run's Details pane remains visible below Summary.
    assert!(!mentions(&text, "run(s) have recording notes"), "{text:?}");
    assert!(!mentions(&text, "saving stopped"), "{text:?}");
}

#[test]
fn the_recording_state_text_names_the_cause_and_each_note() {
    let mut run = run("r");
    assert!(crate::run_recording::badge(&run).is_none());
    assert!(crate::run_recording::tooltip(&run).is_empty());
    run.notes = vec!["a note".into()];
    assert!(crate::run_recording::badge(&run).is_none());
    run.recording_error = Some("disk full".into());
    assert_eq!(crate::run_recording::badge(&run), Some("Saving stopped"));
    assert_eq!(
        crate::run_recording::tooltip(&run),
        "Recording incomplete: saving stopped: disk full\nNote: a note"
    );
}

#[test]
fn opening_another_run_does_not_show_the_previous_runs_saving_failure() {
    let mut app = running_app();
    let mut partial = past_run("partial", "/bin/partial", 1);
    partial.recording_error = Some("unique retained first cause".into());
    // Reopening persisted metadata must preserve the cause without requiring
    // an active VM or a backend error banner.
    let partial = serde_json::from_str(&serde_json::to_string(&partial).unwrap()).unwrap();
    app.history = vec![partial, past_run("intact", "/bin/intact", 2)];
    let ctx = context();
    for id in ["partial", "intact", "partial"] {
        app.select_run(Some(id.into()));
        let text = shown(&mut app, &ctx, Panel::Details);
        assert_eq!(
            mentions(&text, "unique retained first cause"),
            id == "partial"
        );
    }
}

#[test]
fn full_run_warning_is_dismissible_and_deduplicates_with_activity_without_hiding_other_runs() {
    let ctx = context();
    let mut partial = run("partial-one");
    let reason = format!("{} retained final cause", "long diagnostic ".repeat(40));
    partial.recording_error = Some(reason.clone());
    let message = crate::run_recording::warning_message(&partial).unwrap();
    let mut journal = crate::activity::Journal::default();
    let draw = |run: &RunSummary, events| {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                events,
                ..Default::default()
            },
            |ctx| {
                crate::activity::report(ctx, crate::activity::Level::Warn, &message);
                egui::CentralPanel::default().show(ctx, |ui| crate::run_recording::show(ui, run));
            },
        )
    };
    let _ = draw(&partial, vec![]);
    let output = draw(&partial, vec![]);
    let text = super::texts(&output);
    assert!(text.iter().any(|(text, _)| text.contains(&reason)));
    let pos = text
        .iter()
        .find(|(text, _)| text == "×")
        .unwrap()
        .1
        .center();
    for pressed in [true, false] {
        draw(
            &partial,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
    }
    assert!(!super::texts(&draw(&partial, vec![]))
        .iter()
        .any(|(text, _)| text.contains("retained final cause")));
    journal.ingest(&ctx);
    assert_eq!(journal.counts(), (1, 0));
    let mut other = partial.clone();
    other.id = "partial-two".into();
    assert!(super::texts(&draw(&other, vec![]))
        .iter()
        .any(|(text, _)| text.contains("retained final cause")));
    journal.ingest(&ctx);
    assert_eq!(journal.counts(), (2, 0));
    assert_eq!(partial.recording_error.as_deref(), Some(reason.as_str()));
}

// --- Deleting the selected VM ----------------------------------------------

#[test]
fn deleting_the_selected_vm_clears_its_run_capture_process_and_archive_views() {
    let mut app = app();
    add_vm(&mut app, "a");
    add_vm(&mut app, "b");
    app.selected = Some("a".into());
    let mut old = past_run("ra", "/bin/a", 1_800_000_000_000);
    old.vm_id = "a".into();
    app.history = vec![old];
    app.capture_history = vec![{
        let mut capture = observer("ca", CaptureState::Stopped);
        capture.vm_id = "a".into();
        capture
    }];
    app.select_run(Some("ra".into()));
    app.selected_capture = Some("ca".into());
    app.selected_process = Some(5);
    app.archive_selected = true;
    app.analysis_views
        .insert("workspace".into(), waiting_view());
    app.run_tree = Some(("ra".into(), Ok((Vec::new(), Vec::new()))));
    app.snapshot.vms.retain(|vm| vm.id != "a");
    app.drain();
    assert_eq!(app.selected.as_deref(), Some("b"));
    assert_eq!(app.selected_run, None);
    assert_eq!(app.selected_capture, None);
    assert_eq!(app.selected_process, None);
    assert!(!app.archive_selected);
    assert!(app.run_tree.is_none());
    assert!(!app.analysis_views.contains_key("workspace"));
    assert!(app.history.iter().all(|run| run.vm_id != "a"));
    assert!(app.capture_history.is_empty());
    assert!(app.trace_archive_directory().is_none());
}

#[test]
fn deleting_a_vm_clears_its_queued_analysis_sections_and_report_views() {
    use antinomie_monitor_core::AnalysisKind;

    let mut app = app();
    add_vm(&mut app, "a");
    add_vm(&mut app, "b");
    app.selected = Some("a".into());
    let mut deleted = past_run("ra", "/bin/a", 1);
    deleted.vm_id = "a".into();
    deleted.analysis = Some(section_report("report-a", "A"));
    let mut retained = past_run("rb", "/bin/b", 2);
    retained.vm_id = "b".into();
    retained.analysis = Some(section_report("report-b", "B"));
    app.history = vec![deleted, retained];
    app.analysis_windows
        .insert("report-a".into(), section_report("report-a", "A"));
    app.analysis_windows
        .insert("report-b".into(), section_report("report-b", "B"));
    app.analysis_directories
        .insert("report-a".into(), PathBuf::from("/runs/a/analysis"));
    app.analysis_directories
        .insert("report-b".into(), PathBuf::from("/runs/b/analysis"));
    app.analysis_views.insert(
        "section:report-a:Metadata".into(),
        AnalysisView {
            report_id: Some("report-a".into()),
            pending: Some((1, 0, 64)),
            ..Default::default()
        },
    );
    app.analysis_views.insert(
        "section:report-b:Metadata".into(),
        AnalysisView {
            report_id: Some("report-b".into()),
            pending: Some((2, 0, 64)),
            ..Default::default()
        },
    );
    app.pending_analysis_sections
        .push(("report-a".into(), AnalysisKind::Metadata));
    app.pending_analysis_sections
        .push(("report-b".into(), AnalysisKind::Metadata));
    app.pending_archive = Some(Request::Specimen {
        view_key: "section:report-a:Metadata".into(),
        generation: 1,
        directory: PathBuf::from("/runs/a/analysis"),
        report_id: "report-a".into(),
        offset: 0,
        data_len: 64,
    });

    app.snapshot.vms.retain(|vm| vm.id != "a");
    app.drain();

    assert_eq!(app.selected.as_deref(), Some("b"));
    assert!(!app.analysis_windows.contains_key("report-a"));
    assert!(!app.analysis_directories.contains_key("report-a"));
    assert!(!app.analysis_views.contains_key("section:report-a:Metadata"));
    assert!(!app
        .pending_analysis_sections
        .iter()
        .any(|(id, _)| id == "report-a"));
    assert!(app.analysis_windows.contains_key("report-b"));
    assert!(app.analysis_views.contains_key("section:report-b:Metadata"));
    assert!(app
        .pending_analysis_sections
        .iter()
        .any(|(id, _)| id == "report-b"));
    assert!(matches!(
        app.pending_archive,
        Some(Request::ListVm { vm_id, .. }) if vm_id == "b"
    ));
}

#[test]
fn a_run_of_another_vm_is_never_the_offline_trace_of_the_selected_vm() {
    let mut app = app();
    add_vm(&mut app, "a");
    add_vm(&mut app, "b");
    app.selected = Some("b".into());
    let mut other = past_run("ra", "/bin/a", 1);
    other.vm_id = "a".into();
    app.history = vec![other];
    app.selected_run = Some("ra".into());
    assert!(app.offline_run().is_none());
    assert!(app.trace_archive_directory().is_none());
    app.selected = Some("a".into());
    assert!(app.trace_archive_directory().is_some());
}

#[test]
fn deleting_a_vm_that_is_not_selected_keeps_the_selection() {
    let mut app = app();
    add_vm(&mut app, "a");
    add_vm(&mut app, "b");
    app.selected = Some("a".into());
    let mut old = past_run("ra", "/bin/a", 1);
    old.vm_id = "a".into();
    app.history = vec![old];
    app.select_run(Some("ra".into()));
    app.snapshot.vms.retain(|vm| vm.id != "b");
    app.drain();
    assert_eq!(app.selected.as_deref(), Some("a"));
    assert_eq!(app.selected_run.as_deref(), Some("ra"));
    assert_eq!(app.history.len(), 1);
}

// --- A new selection never drops a read someone waits on -------------------

#[test]
fn select_run_keeps_a_queued_specimen_read_for_a_view_that_still_waits() {
    let mut app = app();
    app.analysis_views
        .insert("report-window".into(), waiting_view());
    app.pending_archive = Some(specimen_request("report-window"));
    app.select_run(None);
    assert!(
        matches!(&app.pending_archive, Some(Request::Specimen { view_key, .. }) if view_key == "report-window"),
        "the read vanished while its analysis view waits for the answer"
    );
    assert!(app.analysis_views["report-window"].pending.is_some());
}

#[test]
fn select_run_keeps_a_queued_listing_and_the_run_lists() {
    let mut app = app();
    app.analysis_views.insert("w".into(), {
        AnalysisView {
            listing_pending: Some((
                1,
                antinomie_monitor_core::AnalysisKind::Strings,
                0,
                String::new(),
                None,
            )),
            ..Default::default()
        }
    });
    app.pending_archive = Some(Request::Listing {
        view_key: "w".into(),
        generation: 1,
        directory: PathBuf::from("/x"),
        report_id: "r".into(),
        kind: antinomie_monitor_core::AnalysisKind::Strings,
        start: 0,
        query: String::new(),
        sort: None,
        record_context: Vec::new(),
    });
    app.select_run(None);
    assert!(matches!(app.pending_archive, Some(Request::Listing { .. })));
    app.pending_archive = None;
    app.selected = Some("vm".into());
    app.refresh_history();
    app.select_run(None);
    assert!(matches!(app.pending_archive, Some(Request::ListVm { .. })));
}

#[test]
fn select_run_drops_a_read_whose_view_the_selection_removed() {
    let mut app = app();
    app.analysis_views
        .insert("workspace".into(), waiting_view());
    app.pending_archive = Some(specimen_request("workspace"));
    app.select_run(None);
    assert!(app.pending_archive.is_none());
    assert!(!app.analysis_views.contains_key("workspace"));
}

#[test]
fn select_run_replaces_the_trace_read_of_the_old_run_with_one_for_the_new_run() {
    let mut app = running_app();
    app.snapshot.state = VmState::Stopped;
    app.snapshot.active_vm = None;
    app.history = vec![
        past_run("first", "/bin/first", 1),
        past_run("second", "/bin/second", 2),
    ];
    app.select_run(Some("first".into()));
    let Some(Request::Invocations {
        cancel, directory, ..
    }) = app.pending_archive.take()
    else {
        panic!("no trace read for the first run");
    };
    assert_eq!(directory, PathBuf::from("/runs/first"));
    app.pending_archive = Some(Request::Invocations {
        generation: app.archive_generation,
        directory,
        offset: 0,
        limit: 100,
        capture: false,
        pid: None,
        query: String::new(),
        hidden_categories: Vec::new(),
        cancel: Arc::clone(&cancel),
    });
    app.archive_pending = true;
    app.select_run(Some("second".into()));
    assert!(cancel.load(Ordering::Relaxed), "the old read keeps running");
    assert!(
        matches!(&app.pending_archive, Some(Request::Invocations { directory, .. }) if directory == &PathBuf::from("/runs/second"))
    );
    assert!(app.archive_pending);
}

#[test]
fn select_run_ends_a_queued_process_tree_read_of_the_old_run() {
    let mut app = running_app();
    app.pending_archive = Some(Request::ProcessTree {
        run_id: "old".into(),
        directory: PathBuf::from("/runs/old"),
        root_pid: 1,
        path: String::new(),
    });
    app.run_tree_pending = Some("old".into());
    app.select_run(None);
    assert!(app.pending_archive.is_none() && app.run_tree_pending.is_none());
}

#[test]
fn a_finished_run_of_the_live_session_is_read_from_its_archive() {
    let mut app = live_app();
    assert!(
        app.offline_run().is_none(),
        "a running program shows its live events"
    );
    let run = app
        .snapshot
        .runs
        .iter_mut()
        .find(|run| run.id == "r1")
        .unwrap();
    run.state = RunState::Finished;
    run.terminal_eof = true;
    assert_eq!(
        app.offline_run().map(|run| run.id.as_str()),
        Some("r1"),
        "the backend drops a complete run's live events, so its archive is read"
    );
}

#[test]
fn the_cached_run_lists_follow_new_and_changed_runs() {
    let mut app = live_app();
    let ctx = context();
    let text = shown(&mut app, &ctx, Panel::RunHistory);
    assert!(mentions(&text, "1 of 1 runs"), "{text:?}");
    let before: Vec<_> = app.triage_runs().iter().map(|run| run.id.clone()).collect();
    assert_eq!(before, ["r1"]);
    let mut second = run("r2");
    second.started_ms = Some(u64::MAX);
    app.snapshot.runs.push(second);
    let after: Vec<_> = app.triage_runs().iter().map(|run| run.id.clone()).collect();
    assert_eq!(after, ["r2", "r1"], "a new run appears, newest first");
    let text = shown(&mut app, &ctx, Panel::RunHistory);
    assert!(
        mentions(&text, "2 of 2 runs"),
        "Run History lists the new run: {text:?}"
    );
}
