// SPDX-License-Identifier: MIT
//! The debugger picker and session window.
use super::*;

fn identity() -> antinomie_monitor_core::GuestProcessIdentity {
    antinomie_monitor_core::GuestProcessIdentity {
        boot_id: "boot".into(),
        task_cookie: 55,
        tgid: 42,
        start_boot_ns: 100,
    }
}

fn info() -> antinomie_monitor_core::DebugSessionInfo {
    antinomie_monitor_core::DebugSessionInfo {
        target: identity(),
        architecture: "x86-64".into(),
        unix_socket: PathBuf::from("/tmp/ant-dbg/debug-1.sock"),
        tcp_port: 40123,
        gdb_command: "gdb -ex 'target remote 127.0.0.1:40123'".into(),
        gdb_unix_command:
            "gdb -ex 'target remote | socat - UNIX-CONNECT:/tmp/ant-dbg/debug-1.sock'".into(),
        client_connected: false,
        clients_served: 0,
        target_state: "attached".into(),
        ended: None,
    }
}

#[test]
fn the_debugger_needs_a_running_revision_17_guest_and_one_session() {
    let mut app = app();
    assert!(app.debugger_unavailable().unwrap().contains("Start"));
    observer_fixture(&mut app);
    assert!(app.debugger_unavailable().unwrap().contains("revision 17"));
    app.snapshot.guest_kernel.as_mut().unwrap().revision = Some(16);
    assert!(app.debugger_unavailable().is_some());
    app.open_debug_picker();
    assert!(
        !app.process_picker.open,
        "refused: no process list is requested"
    );
    app.snapshot.guest_kernel.as_mut().unwrap().revision = Some(17);
    assert_eq!(app.debugger_unavailable(), None);
    app.snapshot.debug = Some(info());
    assert!(app
        .debugger_unavailable()
        .unwrap()
        .contains("already attached"));
}

#[test]
fn picking_a_process_attaches_the_debugger_with_its_complete_identity() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.guest_kernel.as_mut().unwrap().revision = Some(17);
    app.snapshot.process_page = Some(antinomie_monitor_core::GuestProcessPage {
        boot_id: "boot".into(),
        after_pid: 0,
        next_pid: 42,
        processes: vec![antinomie_monitor_core::GuestProcess {
            identity: identity(),
            parent_tgid: 1,
            uid: 0,
            gid: 0,
            thread_count: 3,
            command: "debug-target".into(),
        }],
    });
    app.open_debug_picker();
    assert!(matches!(
        app.submitted.last(),
        Some(Command::ListProcesses { after_pid: 0 })
    ));
    let size = egui::vec2(800.0, 600.0);
    click_label(&mut app, &ctx, size, "debug-target");
    assert_eq!(app.process_picker.selected.as_ref(), Some(&identity()));
    click_label(
        &mut app,
        &ctx,
        size,
        &format!("{} Attach debugger", egui_phosphor::regular::BUG),
    );
    assert!(matches!(
        app.submitted.last(),
        Some(Command::DebugAttach { identity: selected }) if selected == &identity()
    ));
    assert!(!app.process_picker.open);
    assert!(
        !app.submitted
            .iter()
            .any(|command| matches!(command, Command::AttachProcess { .. })),
        "the debugger does not start a capture"
    );
}

#[test]
fn the_session_window_offers_the_endpoint_and_detach() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.debug = Some(info());
    let size = egui::vec2(900.0, 700.0);
    for _ in 0..2 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    let shown = texts(&output);
    assert!(shown
        .iter()
        .any(|(text, _)| text == "gdb -ex 'target remote 127.0.0.1:40123'"));
    assert!(shown.iter().any(|(text, _)| text == "Detach"));
    click_label(&mut app, &ctx, size, "Detach");
    assert!(matches!(
        app.submitted.last(),
        Some(Command::DebugDetach { kill: false })
    ));
    click_label(&mut app, &ctx, size, "Detach and kill process");
    assert!(matches!(
        app.submitted.last(),
        Some(Command::DebugDetach { kill: true })
    ));
}
