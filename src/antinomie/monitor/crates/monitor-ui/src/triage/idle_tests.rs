// SPDX-License-Identifier: GPL-3.0-only
//! An idle Triage view asks for no repaint sooner than a second: a window that
//! repaints every frame with nothing happening burns a core (on software GL,
//! several) for no change on screen.
use super::tests::write_rwx_calls;
use super::*;

fn input<'a>(archive: &'a Path, finished: bool) -> TriageInput<'a> {
    TriageInput {
        vm_id: Some("vm"),
        boot_id: Some("boot"),
        run_id: Some("run"),
        archive: Some(archive),
        // No run root, so the view starts no rule-loading thread: such a thread
        // asks the window for one repaint when it ends, whenever the machine
        // lets it, which is a change on screen and not what is measured here.
        root_cookie: 0,
        run_finished: finished,
        ..TriageInput::empty()
    }
}

/// One frame of the view; the delay until it wants to be drawn again.
fn frame(
    ctx: &egui::Context,
    view: &mut TriageView,
    archive: &Path,
    finished: bool,
    time: f64,
) -> Duration {
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 800.0),
            )),
            time: Some(time),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                view.show(ui, input(archive, finished));
            });
            view.show_finding_windows(ctx);
        },
    );
    output
        .viewport_output
        .get(&egui::ViewportId::ROOT)
        .map_or(Duration::MAX, |viewport| viewport.repaint_delay)
}

/// Draw until the index has arrived and the view has settled, then return
/// the delay each of five further frames asked for.
fn idle_delays(
    section: Section,
    process: ProcessTab,
    finished: bool,
    toast: bool,
) -> Vec<Duration> {
    let spool = PacketSpool::new().unwrap();
    let mut raw = std::fs::File::create(spool.directory.join("telemetry.raw")).unwrap();
    write_rwx_calls(&mut raw, 0..6);
    raw.sync_all().unwrap();
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut view = TriageView::default();
    // The 5 s re-read of a live run is a wall-clock timer; push it out of reach
    // so how fast the machine is cannot start a read in the middle of the test.
    view.refresh_seconds = 3600;
    view.set_toast_high(toast);
    view.section = section;
    view.process = process;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut time = 0.0;
    while view.scan.is_none() || view.scan_rx.is_some() {
        frame(&ctx, &mut view, &spool.directory, finished, time);
        time += 0.02;
        assert!(Instant::now() < deadline, "the index never arrived");
        std::thread::sleep(Duration::from_millis(5));
    }
    // Let first-frame layout and focus settle.
    for _ in 0..12 {
        frame(&ctx, &mut view, &spool.directory, finished, time);
        time += 0.02;
    }
    (0..5)
        .map(|_| {
            time += 0.02;
            frame(&ctx, &mut view, &spool.directory, finished, time)
        })
        .collect()
}

#[test]
fn an_idle_triage_view_does_not_repaint_every_frame() {
    let views = [
        ("Summary", Section::Summary, ProcessTab::Tree),
        ("Process tree", Section::Process, ProcessTab::Tree),
        (
            "Suspicious activity",
            Section::Process,
            ProcessTab::Suspicious,
        ),
        ("Graph", Section::Process, ProcessTab::Graph),
    ];
    for (name, section, process) in views {
        for finished in [true, false] {
            for toast in [false, true] {
                let delays = idle_delays(section, process, finished, toast);
                for delay in &delays {
                    assert!(
                        *delay >= Duration::from_secs(1),
                        "{name}, finished {finished}, toast {toast}: asked to repaint in {delay:?} while idle ({delays:?})"
                    );
                }
            }
        }
    }
}

/// While an index is being read the views show a spinner. It may move, but a
/// frame must not ask for the next one at once: that is the full frame rate
/// for as long as the read takes, and a live run is read again every few
/// seconds.
#[test]
fn a_view_waiting_for_its_index_repaints_ten_times_a_second_at_most() {
    let views = [
        ("Summary", Section::Summary, ProcessTab::Tree),
        ("Process tree", Section::Process, ProcessTab::Tree),
        (
            "Suspicious activity",
            Section::Process,
            ProcessTab::Suspicious,
        ),
        ("Graph", Section::Process, ProcessTab::Graph),
    ];
    for (name, section, process) in views {
        for with_index in [true, false] {
            let spool = PacketSpool::new().unwrap();
            let mut raw = std::fs::File::create(spool.directory.join("telemetry.raw")).unwrap();
            write_rwx_calls(&mut raw, 0..3);
            raw.sync_all().unwrap();
            let ctx = egui::Context::default();
            theme::install(&ctx);
            let mut view = TriageView::default();
            view.section = section;
            view.process = process;
            if with_index {
                view.scan = Some(
                    scan_archive(&spool.directory, None, false, &AtomicBool::new(false)).unwrap(),
                );
            }
            // The keys the view makes from this run's ids and directory, so that
            // it keeps the read in flight instead of starting its own (which
            // would end, and change the screen, whenever it happened to).
            view.context_key = Some(format!("vm\nboot\nrun\n{}", spool.directory.display()));
            view.refresh_seconds = 3600;
            // A read that never answers.
            view.scan_key = Some(format!("{}\n\nvm\nboot\nrun", spool.directory.display()));
            let (_keep, rx) = mpsc::channel();
            view.scan_rx = Some(rx);
            view.pending_generation = Some(view.scan_generation);
            let mut delays = Vec::new();
            for step in 0..12 {
                let delay = frame(
                    &ctx,
                    &mut view,
                    &spool.directory,
                    true,
                    f64::from(step) * 0.02,
                );
                if step >= 8 {
                    delays.push(delay);
                }
            }
            assert!(
                view.scan_rx.is_some() && view.scan_generation == 0,
                "{name}: the read in flight was kept, not replaced by a real one"
            );
            for delay in &delays {
                assert!(
                    *delay >= Duration::from_millis(50),
                    "{name}, index shown {with_index}: asked to repaint in {delay:?} while waiting ({delays:?})"
                );
            }
        }
    }
}
