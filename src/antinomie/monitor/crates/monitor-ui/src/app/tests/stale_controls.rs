// SPDX-License-Identifier: MIT
//! Controls and messages that must not stay stuck after the VM, boot or
//! backend state moves on.
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

/// (median, max) milliseconds over `count` frames after a warm-up.
// ---------------------------------------------------------------------------
// Confirmed logic bugs

#[test]
fn a_newer_status_message_replaces_an_old_backend_error() {
    let mut app = app();
    let ctx = context();
    app.snapshot.last_error = Some("old failure from ten minutes ago".into());
    app.status = "Uploaded: review program settings, then press Run".into();
    let mut out = egui::FullOutput::default();
    for frame in 0..4 {
        out = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                time: Some(f64::from(frame)),
                ..Default::default()
            },
            |ctx| app.health(ctx),
        );
    }
    let shown = texts(&out);
    assert!(
        shown.iter().any(|(text, _)| text.contains("Uploaded")),
        "the newer status message is shown: {shown:?}"
    );
}

#[test]
fn an_unbound_pending_launch_clears_when_the_vm_stops() {
    let mut app = running_app();
    // Execute was accepted, but neither RunStarted nor its CommandResult was
    // delivered (the notification queue is bounded and drops when full).
    app.pending_launch = Some(7);
    app.snapshot.state = VmState::Stopped;
    app.snapshot.active_vm = None;
    app.drain();
    app.snapshot.state = VmState::Running;
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.boot_id = Some("boot-2".into());
    app.drain();
    assert!(
        app.launch_admission().is_ok(),
        "Run program is available in the next boot: {:?}",
        app.launch_admission()
    );
}

#[test]
fn run_program_cancel_works_while_the_vm_is_stopped() {
    let mut app = analysis_setup_fixture();
    app.snapshot.state = VmState::Stopped;
    app.snapshot.active_vm = None;
    let ctx = context();
    click_label(&mut app, &ctx, SIZE, "Cancel");
    assert!(
        !app.launch_open,
        "Cancel closes the dialog while the VM is stopped"
    );
}

#[test]
fn guest_commands_are_held_quietly_while_the_ram_dump_pauses_the_vm() {
    let mut app = running_app();
    assert!(app.running());
    app.snapshot.memory_dump = Some(antinomie_monitor_core::memory::DumpProgress {
        completed: 41,
        total: 100,
        ..Default::default()
    });
    assert!(!app.running(), "Run, upload and captures are disabled");
    let sent = app.submitted.len();
    app.status = "ready".into();
    app.send(Command::TerminalResize {
        run_id: "run".into(),
        rows: 24,
        cols: 80,
    });
    assert_eq!(app.status, "ready", "automatic commands change nothing");
    app.send(Command::ListProcesses { after_pid: 0 });
    assert_eq!(app.status, "Writing RAM dump 41% - VM paused");
    assert_eq!(app.submitted.len(), sent, "nothing reached the backend");
    app.snapshot.memory_dump = None;
    app.send(Command::ListProcesses { after_pid: 0 });
    assert_eq!(app.submitted.len(), sent + 1);
}
