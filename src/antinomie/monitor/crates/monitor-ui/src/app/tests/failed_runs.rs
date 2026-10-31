// SPDX-License-Identifier: GPL-3.0-only
//! Runs whose program never ran: a definite state in Run History with the
//! reason, a Delete like other evidence, and no recording look. Also the Run
//! form's buttons to the settings a run needs.
use super::*;
use crate::evidence_delete::Kind;

fn draw(app: &mut MonitorApp, ctx: &egui::Context, events: Vec<egui::Event>) -> egui::FullOutput {
    ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1500.0, 900.0),
            )),
            events,
            ..Default::default()
        },
        |ctx| app.draw(ctx),
    )
}

fn find(output: &egui::FullOutput, label: &str) -> Option<egui::Pos2> {
    texts(output)
        .into_iter()
        .find(|(text, _)| text == label)
        .map(|(_, rect)| rect.center())
}

fn click(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    at: egui::Pos2,
    button: egui::PointerButton,
) -> egui::FullOutput {
    for pressed in [true, false] {
        draw(
            app,
            ctx,
            vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
    }
    let mut output = draw(app, ctx, Vec::new());
    for _ in 0..2 {
        output = draw(app, ctx, Vec::new());
    }
    output
}

fn failed(id: &str, state: RunState, error: &str) -> RunSummary {
    let mut run = run(id);
    run.root_task_cookie = 0;
    run.pid = 0;
    run.state = state;
    run.recording_error = Some(error.into());
    run
}

#[test]
fn each_state_of_a_run_that_did_not_run_has_its_own_words_and_no_saving_badge() {
    let refused = failed(
        "f1",
        RunState::FailedToStart,
        "launch rejected by the guest, nothing was started: no such file",
    );
    assert_eq!(
        super::super::history::run_status(&refused),
        "Failed to start"
    );
    assert_eq!(super::super::history::root_exit(&refused), "Not started");
    assert_eq!(crate::run_recording::badge(&refused), None);
    let tip = crate::run_recording::tooltip(&refused);
    assert!(tip.starts_with("Failed to start: launch rejected"), "{tip}");
    assert!(tip.contains("Nothing of the program was recorded"), "{tip}");
    assert!(!tip.contains("saving stopped"), "{tip}");
    assert!(crate::run_recording::warning_message(&refused)
        .unwrap()
        .contains("Failed to start"));

    let unconfirmed = failed(
        "f2",
        RunState::LaunchUnconfirmed,
        "execution acknowledgement failed: VM exited; launch outcome may be unknown",
    );
    assert_eq!(
        super::super::history::run_status(&unconfirmed),
        "Launch unconfirmed"
    );
    assert_eq!(
        super::super::history::root_exit(&unconfirmed),
        "Not recorded"
    );
    assert_eq!(crate::run_recording::badge(&unconfirmed), None);
    assert!(crate::run_recording::tooltip(&unconfirmed).contains("may have started"));

    let mut interrupted = run("i1");
    interrupted.state = RunState::Interrupted;
    assert_eq!(
        super::super::history::run_status(&interrupted),
        "Interrupted"
    );
    assert!(crate::run_recording::tooltip(&interrupted).contains("Interrupted"));
    // A recording whose saving stopped keeps its own words.
    let mut partial = run("p1");
    partial.state = RunState::Finished;
    partial.recording_error = Some("disk full".into());
    assert_eq!(
        crate::run_recording::badge(&partial),
        Some("Saving stopped")
    );
    assert!(crate::run_recording::tooltip(&partial).contains("saving stopped: disk full"));
}

#[test]
fn run_history_deletes_a_run_that_failed_to_start_and_offers_no_delete_for_a_recording() {
    let mut app = super::ui_polish_shots::history_fixture();
    app.focus_panel = Some(Panel::RunHistory);
    app.snapshot.runs.clear();
    let dir = std::env::temp_dir().join(format!("ant-failed-run-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut refused = failed(
        "run-failed",
        RunState::FailedToStart,
        "this VM has no network card, so there is nothing to capture",
    );
    refused.request.path = "/tmp/never-ran".into();
    refused.started_ms = Some(1_760_000_900_000);
    refused.directory = dir.clone();
    app.history.push(refused);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut output = draw(&mut app, &ctx, Vec::new());
    for _ in 0..3 {
        output = draw(&mut app, &ctx, Vec::new());
    }
    let row = find(&output, "Failed to start").expect("the run reads as failed to start");
    assert!(
        find(&output, "Not started").is_some(),
        "its root exit says it never started, not Unknown"
    );
    let output = click(&mut app, &ctx, row, egui::PointerButton::Secondary);
    let delete = find(&output, "Delete…").unwrap_or_else(|| {
        panic!(
            "a run that never ran can be deleted: {:?}",
            texts(&output)
                .into_iter()
                .map(|(text, _)| text)
                .collect::<Vec<_>>()
        )
    });
    click(&mut app, &ctx, delete, egui::PointerButton::Primary);
    match &app.confirm {
        Some(Confirm::DeleteEvidence(deletion)) => {
            assert_eq!(deletion.kind, Kind::Run);
            assert_eq!(deletion.path(), dir.as_path());
            assert!(deletion.text().contains("run that never started"));
        }
        other => panic!(
            "the deletion is confirmed first (a dialog is open: {})",
            other.is_some()
        ),
    }
    assert!(
        app.submitted.is_empty(),
        "nothing is sent before confirming"
    );
    // The app forgets the run once the backend removed it.
    let Some(Confirm::DeleteEvidence(deletion)) = app.confirm.take() else {
        unreachable!()
    };
    app.selected_run = Some("run-failed".into());
    app.evidence_deleted(&deletion);
    assert!(app.history.iter().all(|run| run.id != "run-failed"));
    assert_ne!(app.selected_run.as_deref(), Some("run-failed"));

    // A finished recording: its menu has no Delete.
    let mut output = draw(&mut app, &ctx, Vec::new());
    for _ in 0..2 {
        output = draw(&mut app, &ctx, Vec::new());
    }
    let finished = find(&output, "Finished").expect("a finished run is listed");
    let output = click(&mut app, &ctx, finished, egui::PointerButton::Secondary);
    assert!(find(&output, "Rename…").is_some(), "the row's menu is open");
    assert!(find(&output, "Delete…").is_none());
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn the_run_form_turns_off_capture_without_a_network_card_and_opens_the_settings_a_run_needs() {
    use antinomie_monitor_core::{
        route::{RouteConfig, RouteKind},
        VmNetwork,
    };
    let frame = |request: &mut ExecRequest, network: VmNetwork, events: Vec<egui::Event>| {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut outcome = crate::analysis::LaunchOutcome::default();
        let mut routes = false;
        let mut output = egui::FullOutput::default();
        for events in [Vec::new(), events.clone(), Vec::new()] {
            output = ctx.run(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let mut step = crate::analysis::LaunchOutcome::default();
                        crate::analysis::capture_selection_for_tests(
                            ui,
                            request,
                            crate::route_ui::RouteChoice::new(network, &RouteConfig::default()),
                            &mut step,
                        );
                        outcome.open_vm_settings |= step.open_vm_settings;
                    });
                },
            );
            routes |= crate::settings_link::take(&ctx) == Some("Network routes");
        }
        (output, outcome, routes)
    };
    let press = |at: egui::Pos2| {
        vec![
            egui::Event::PointerMoved(at),
            egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            },
            egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            },
        ]
    };
    // No network card: the capture is off and the VM settings are a click away.
    let mut request = ExecRequest {
        capture_network: true,
        ..ExecRequest::default()
    };
    let (output, _, _) = frame(&mut request, VmNetwork::Disconnected, Vec::new());
    assert!(
        !request.capture_network,
        "a capture that cannot start is cleared"
    );
    let button = find(&output, "VM settings…").expect("a button to the VM's settings");
    let (_, outcome, _) = frame(&mut request, VmNetwork::Disconnected, press(button));
    assert!(outcome.open_vm_settings);
    // Routed: the capture stays (the gateway's card is captured like any).
    let mut routed = ExecRequest {
        capture_network: true,
        route: Some(RouteKind::Internet),
        ..ExecRequest::default()
    };
    let (output, _, _) = frame(&mut routed, VmNetwork::Routed, Vec::new());
    assert!(routed.capture_network);
    assert!(find(&output, "VM settings…").is_none());
    // A route whose settings are missing has a button to them.
    let mut vpn = ExecRequest {
        route: Some(RouteKind::Vpn),
        ..ExecRequest::default()
    };
    let (output, _, _) = frame(&mut vpn, VmNetwork::Routed, Vec::new());
    let button =
        find(&output, "Open Network routes settings").expect("a button to the route settings");
    let (_, _, routes) = frame(&mut vpn, VmNetwork::Routed, press(button));
    assert!(routes, "the button asks for Settings > Network routes");
}
