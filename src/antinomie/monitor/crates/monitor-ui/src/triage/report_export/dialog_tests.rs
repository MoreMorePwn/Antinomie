// SPDX-License-Identifier: GPL-3.0-only
//! The dialog's behaviour: bound to one run, kept open while it writes, closed
//! by its Close button and Escape, and no second set on a second click.
use super::*;

fn input<'a>(archive: &'a Path, run: &'a str) -> TriageInput<'a> {
    TriageInput {
        archive: Some(archive),
        vm_id: Some("vm"),
        boot_id: Some("boot"),
        run_id: Some(run),
        run_finished: true,
        ..TriageInput::empty()
    }
}

/// A view that has run `run` on screen, as `tick` leaves it.
fn on_screen(view: &mut TriageView, run: &str) {
    view.scan_request.identity = Some(("vm".into(), "boot".into(), run.into()));
    view.scan_request.root_cookie = 55;
}

fn frame_with(
    ctx: &egui::Context,
    view: &mut TriageView,
    events: Vec<egui::Event>,
    time: f64,
) -> egui::FullOutput {
    ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 900.0),
            )),
            events,
            time: Some(time),
            ..Default::default()
        },
        |root| {
            let ctx = &root.ctx().clone();
            view.show_report_dialog(ctx)
        },
    )
}

fn escape() -> Vec<egui::Event> {
    [true, false]
        .into_iter()
        .map(|pressed| egui::Event::Key {
            key: egui::Key::Escape,
            physical_key: None,
            pressed,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        })
        .collect()
}

fn running() -> State {
    let (_tx, rx) = mpsc::channel();
    // The sender is dropped: the dialog sees a worker that never answers.
    std::mem::forget(_tx);
    State::Running {
        rx,
        cancel: Arc::new(AtomicBool::new(false)),
        status: "Indexing".into(),
        progress: Arc::new(scan_progress::ScanProgress::default()),
        began: Instant::now(),
    }
}

#[test]
fn switching_runs_with_the_dialog_open_rebinds_it_and_its_request() {
    let (a, b) = (PacketSpool::new().unwrap(), PacketSpool::new().unwrap());
    let mut view = TriageView::default();
    on_screen(&mut view, "aaaaaaaa-run");
    view.open_report(&input(&a.directory, "aaaaaaaa-run"));
    view.report.state = State::Done(Written {
        files: vec![("HTML".into(), a.directory.join("report/a.html"))],
        bundle: None,
    });
    view.report.exported = true;
    let first = view.report.target.clone().unwrap();
    assert!(first.title.contains("[aaaaaaaa]") || first.title.contains("run aaaaaaaa"));
    assert_eq!(first.request.identity.as_ref().unwrap().2, "aaaaaaaa-run");

    // The person picks another run: the same dialog follows it.
    on_screen(&mut view, "bbbbbbbb-run");
    view.follow_report(&input(&b.directory, "bbbbbbbb-run"));
    let second = view.report.target.clone().unwrap();
    assert_eq!(second.archive, b.directory);
    assert!(second.title.contains("bbbbbbbb"), "{}", second.title);
    assert_eq!(second.request.identity.as_ref().unwrap().2, "bbbbbbbb-run");
    assert_eq!(second.run.run_id, "bbbbbbbb-run");
    assert!(
        matches!(view.report.state, State::Idle),
        "A's Written list is gone"
    );
    assert!(!view.report.exported);
    assert!(view.report.open);

    // The same run again changes nothing.
    view.report.exported = true;
    view.follow_report(&input(&b.directory, "bbbbbbbb-run"));
    assert!(view.report.exported);

    // No recording (a run that never started): nothing to export, the dialog closes.
    view.follow_report(&TriageInput {
        run_id: Some("cccccccc-run"),
        ..TriageInput::empty()
    });
    assert!(!view.report.open && view.report.target.is_none());
}

#[test]
fn a_dialog_that_is_writing_stays_bound_to_the_run_it_writes() {
    let (a, b) = (PacketSpool::new().unwrap(), PacketSpool::new().unwrap());
    let mut view = TriageView::default();
    on_screen(&mut view, "aaaaaaaa-run");
    view.open_report(&input(&a.directory, "aaaaaaaa-run"));
    view.report.state = running();
    view.follow_report(&input(&b.directory, "bbbbbbbb-run"));
    let target = view.report.target.as_ref().unwrap();
    assert_eq!(target.archive, a.directory);
    assert!(matches!(view.report.state, State::Running { .. }));
}

#[test]
fn escape_and_close_end_an_idle_dialog_and_nothing_ends_a_running_one() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let a = PacketSpool::new().unwrap();
    let mut view = TriageView::default();
    on_screen(&mut view, "aaaaaaaa-run");
    view.open_report(&input(&a.directory, "aaaaaaaa-run"));
    let mut time = 0.0;
    for _ in 0..6 {
        time += 0.05;
        frame_with(&ctx, &mut view, vec![], time);
    }
    time += 0.05;
    frame_with(&ctx, &mut view, escape(), time);
    assert!(!view.report.open, "Escape closes an idle dialog");

    view.open_report(&input(&a.directory, "aaaaaaaa-run"));
    view.report.state = running();
    for _ in 0..4 {
        time += 0.05;
        frame_with(&ctx, &mut view, vec![], time);
    }
    time += 0.05;
    frame_with(&ctx, &mut view, escape(), time);
    assert!(view.report.open, "Escape does not end a running export");
}

#[test]
fn export_waits_for_a_change_after_the_files_are_written() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let a = PacketSpool::new().unwrap();
    let mut view = TriageView::default();
    on_screen(&mut view, "aaaaaaaa-run");
    view.open_report(&input(&a.directory, "aaaaaaaa-run"));
    view.report.state = State::Done(Written {
        files: vec![("HTML".into(), a.directory.join("report/a.html"))],
        bundle: None,
    });
    view.report.exported = true;
    let mut time = 0.0;
    let mut out = frame_with(&ctx, &mut view, vec![], time);
    for _ in 0..6 {
        time += 0.05;
        out = frame_with(&ctx, &mut view, vec![], time);
    }
    let texts = crate::app::tests::texts(&out);
    let at = |name: &str| {
        texts
            .iter()
            .find(|(t, _)| t == name)
            .map(|(_, r)| r.center())
    };
    let export = at("Export").unwrap_or_else(|| {
        panic!(
            "Export is drawn: {:?}",
            texts
                .iter()
                .map(|(t, r)| format!("{t}@{:?}", r.min))
                .collect::<Vec<_>>()
        )
    });
    let click = |view: &mut TriageView, time: &mut f64, at: egui::Pos2| {
        for pressed in [true, false] {
            *time += 0.05;
            frame_with(
                &ctx,
                view,
                vec![
                    egui::Event::PointerMoved(at),
                    egui::Event::PointerButton {
                        pos: at,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                *time,
            );
        }
    };
    click(&mut view, &mut time, export);
    assert!(
        matches!(view.report.state, State::Done(_)),
        "a second click writes no second set"
    );
    // The Written list shows every file, with Close in reach below it.
    assert!(at("Close").is_some() && at("Written").is_some());
    click(&mut view, &mut time, at("Close").unwrap());
    assert!(!view.report.open, "the Close button closes it");
}

#[test]
fn the_window_keeps_its_top_edge_as_the_content_grows() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let a = PacketSpool::new().unwrap();
    let mut view = TriageView::default();
    on_screen(&mut view, "aaaaaaaa-run");
    view.open_report(&input(&a.directory, "aaaaaaaa-run"));
    let mut time = 0.0;
    for _ in 0..8 {
        time += 0.05;
        frame_with(&ctx, &mut view, vec![], time);
    }
    let id = egui::Id::new("triage-report-dialog");
    let top = |ctx: &egui::Context| ctx.memory(|m| m.area_rect(id)).unwrap().top();
    let before = top(&ctx);
    view.report.state = State::Done(Written {
        files: (0..7)
            .map(|i| ("File".into(), a.directory.join(format!("report/{i}.html"))))
            .collect(),
        bundle: None,
    });
    for _ in 0..8 {
        time += 0.05;
        frame_with(&ctx, &mut view, vec![], time);
    }
    assert!(
        (top(&ctx) - before).abs() < 0.5,
        "{} then {}",
        before,
        top(&ctx)
    );
}

#[test]
fn a_large_recording_is_warned_about_before_the_export_starts() {
    let temp = PacketSpool::new().unwrap();
    let raw = std::fs::File::create(temp.directory.join("telemetry.raw")).unwrap();
    // A sparse 2 GB recording: no disk used.
    raw.set_len(2_000_000_000).unwrap();
    drop(raw);
    let mut view = TriageView::default();
    on_screen(&mut view, "aaaaaaaa-run");
    view.open_report(&input(&temp.directory, "aaaaaaaa-run"));
    let large = view.large_run_warning().expect("a 2 GB recording is large");
    assert_eq!(large.bytes, 2_000_000_000);
    let text = large.warning();
    assert!(
        text.contains("1.9 GiB") && text.contains("estimate"),
        "{text}"
    );
    // The dialog draws without a panic and the answer is kept for a moment.
    let ctx = egui::Context::default();
    frame_with(&ctx, &mut view, Vec::new(), 0.0);
    assert!(view.report.large.as_ref().is_some_and(|(_, l)| l.is_some()));

    // A small recording is not warned about.
    let small = PacketSpool::new().unwrap();
    std::fs::write(small.directory.join("telemetry.raw"), b"").unwrap();
    on_screen(&mut view, "bbbbbbbb-run");
    view.follow_report(&input(&small.directory, "bbbbbbbb-run"));
    assert!(view.large_run_warning().is_none());
}
