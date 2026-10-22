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
    assert!(app.kill_target().is_none());
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
    app.snapshot.runs[1].state = RunState::StopRequested;
    assert!(app.kill_target().is_none());
    app.selected_run = Some("past".into());
    assert!(
        app.kill_target().is_none(),
        "never substitute another run for a historical selection"
    );
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
        .find(|(text, _)| text.ends_with("Kill"))
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
