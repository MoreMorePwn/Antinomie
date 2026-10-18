// SPDX-License-Identifier: MIT
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
