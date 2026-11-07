// SPDX-License-Identifier: GPL-3.0-only
use super::*;

#[test]
fn kill_confirms_exact_run_and_never_sends_vm_stop() {
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.runs = vec![run("live")];
    assert_eq!(app.kill_target().unwrap().id, "live");
    app.request_kill(None);
    assert!(app.submitted.is_empty());
    let Some(Confirm::KillRun(target)) = app.confirm.take() else {
        panic!("kill confirmation");
    };
    app.submit_kill(target);
    assert!(matches!(&app.submitted[..], [Command::StopRun { run_id }] if run_id == "live"));
    assert_eq!(app.snapshot.state, VmState::Running);
}

#[test]
fn multiple_runs_require_selection_and_stale_confirmation_is_rejected() {
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.runs = vec![run("first"), run("second")];
    // No selection: the newest live run (the later one when start times tie).
    assert_eq!(app.kill_target().unwrap().id, "second");
    app.selected_run = Some("first".into());
    assert_eq!(app.kill_target().unwrap().id, "first");
    app.selected_run = Some("second".into());
    assert_eq!(app.kill_target().unwrap().id, "second");
    app.request_kill(None);
    let Some(Confirm::KillRun(target)) = app.confirm.take() else {
        panic!("kill confirmation");
    };
    app.snapshot.boot_id = Some("new-boot".into());
    app.submit_kill(target);
    assert!(app.submitted.is_empty());
    app.snapshot.boot_id = Some("boot".into());
    // A run already being stopped is not a target; the other live one is.
    app.snapshot.runs[1].state = RunState::StopRequested;
    assert_eq!(app.kill_target().unwrap().id, "first");
    app.snapshot.runs[0].state = RunState::StopRequested;
    assert!(app.kill_target().is_none());
    app.snapshot.runs[0].state = RunState::Running;
    app.snapshot.runs[1].state = RunState::Running;
    app.snapshot.runs[1].started_ms = Some(5);
    app.snapshot.runs[0].started_ms = Some(9);
    app.selected_run = Some("past".into());
    assert_eq!(
        app.kill_target().unwrap().id,
        "first",
        "a historical selection does not grey Stop run; the newest live run is stopped"
    );
    app.request_kill(None);
    let Some(Confirm::KillRun(target)) = app.confirm.take() else {
        panic!("kill confirmation");
    };
    assert!(target
        .label(&app.snapshot)
        .contains("newest of 2 live runs"));
}

#[test]
fn toolbar_kill_opens_confirmation_and_cancel_keeps_run_untouched() {
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.runs = vec![run("live")];
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1440.0, 900.0);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    let label = texts(&output)
        .into_iter()
        .find(|(text, _)| text.ends_with("Stop run"))
        .unwrap()
        .0;
    click_label(&mut app, &ctx, size, &label);
    assert!(matches!(app.confirm, Some(Confirm::KillRun(_))));
    assert!(app.submitted.is_empty());
    click_label(&mut app, &ctx, size, "Cancel");
    assert!(app.confirm.is_none());
    assert!(app.submitted.is_empty());
    assert_eq!(app.snapshot.runs[0].state, RunState::Running);
}

#[test]
fn a_confirmation_is_a_plain_window_with_no_dim_that_the_title_drags() {
    let mut app = app();
    app.confirm = Some(Confirm::Reset("vm".into()));
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1440.0, 900.0);
    let mut output = render(&mut app, &ctx, size);
    for _ in 0..3 {
        output = render(&mut app, &ctx, size);
    }
    // A modal paints a backdrop layer over the whole app; this one does not.
    let dimmed = ctx.memory(|memory| {
        memory
            .areas()
            .visible_layer_ids()
            .iter()
            .any(|layer| layer.order == egui::Order::Foreground)
    });
    assert!(!dimmed, "nothing dims behind the confirmation");
    let title = |output: &egui::FullOutput| {
        texts(output)
            .into_iter()
            .filter(|(text, _)| text == "Reset disk")
            .map(|(_, rect)| rect)
            .min_by(|a, b| a.top().total_cmp(&b.top()))
            .expect("the window title")
    };
    let before = title(&output);
    let from = before.center();
    let to = from + egui::vec2(-300.0, 120.0);
    let frame = |app: &mut MonitorApp, events| {
        draw_input(
            app,
            &ctx,
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events,
                ..Default::default()
            },
        )
    };
    let button = |pos, pressed| egui::Event::PointerButton {
        pos,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::NONE,
    };
    frame(&mut app, vec![egui::Event::PointerMoved(from)]);
    frame(&mut app, vec![button(from, true)]);
    frame(
        &mut app,
        vec![egui::Event::PointerMoved(from + (to - from) * 0.5)],
    );
    frame(&mut app, vec![egui::Event::PointerMoved(to)]);
    frame(&mut app, vec![button(to, false)]);
    let output = render(&mut app, &ctx, size);
    let after = title(&output);
    assert!(
        (after.center() - before.center() - (to - from)).length() < 4.0,
        "the window follows the drag: {before:?} -> {after:?}"
    );
    assert!(app.confirm.is_some(), "dragging does not cancel it");
}

pub(super) fn orphaned(id: &str, live: u64) -> RunSummary {
    use antinomie_monitor_core::{RunExecution, WaitStatus};
    let mut run = run(id);
    run.execution = Some(RunExecution {
        generation: 3,
        live_task_count: live,
        pending_async_count: 0,
        flags: 9,
        root_wait_status: Some(0),
        root_exit: Some(WaitStatus::Exited { code: 0 }),
        async_loss_count: 0,
        total_task_count: 2,
    });
    run
}

#[test]
fn stop_run_stays_available_while_a_child_lives_after_the_root_exited() {
    let mut app = app();
    observer_fixture(&mut app);
    // The root exited 0 and one child runs on: the run is still going.
    app.snapshot.runs = vec![orphaned("orphan", 1)];
    assert_eq!(app.kill_target().unwrap().id, "orphan");
    app.request_kill(None);
    let Some(Confirm::KillRun(target)) = app.confirm.take() else {
        panic!("stop confirmation");
    };
    app.submit_kill(target);
    assert!(matches!(&app.submitted[..], [Command::StopRun { run_id }] if run_id == "orphan"));
    // The terminal closed with the root: the run is still stoppable.
    app.submitted.clear();
    app.snapshot.runs[0].state = RunState::TerminalClosed;
    app.pending_kill = None;
    assert_eq!(app.kill_target().unwrap().id, "orphan");
    // Once the guest reports no live task the run has ended and cannot be stopped.
    app.snapshot.runs[0].state = RunState::Finished;
    assert!(app.kill_target().is_none());
}

#[test]
fn the_action_and_the_toolbar_call_it_stop_run() {
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.runs = vec![orphaned("orphan", 1)];
    assert_eq!(Action::KillRun.label(&app), "Stop run");
}

#[test]
fn run_lists_say_who_ended_the_run() {
    use super::super::run_state_text::run_status;
    // The VM stopped under a live child: not "Interrupted", not a failure.
    for state in [RunState::Interrupted, RunState::Finalized] {
        let mut cut = orphaned("cut", 1);
        cut.state = state;
        assert_eq!(run_status(&cut), "Ended by VM stop");
    }
    // Stop run is the user's own act.
    let mut stopped = orphaned("stopped", 0);
    stopped.state = RunState::Stopped;
    assert_eq!(run_status(&stopped), "Stopped by you");
    // A recording that ended with nothing alive keeps its plain words.
    let mut quiet = orphaned("quiet", 0);
    quiet.state = RunState::Finalized;
    assert_eq!(run_status(&quiet), "Recording ended");
    // And an interruption with no status from the guest stays "Interrupted".
    let mut unknown = run("unknown");
    unknown.state = RunState::Interrupted;
    assert_eq!(run_status(&unknown), "Interrupted");
}
