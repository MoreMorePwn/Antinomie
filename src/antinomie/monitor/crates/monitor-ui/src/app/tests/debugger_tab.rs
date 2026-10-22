// SPDX-License-Identifier: GPL-3.0-only
//! The Debugger tab beside Static Analysis: when it exists, its folded panes,
//! the one-controller chip and the gdb console.
use super::*;
use crate::app::debugger::{
    panes::{self, Pane},
    GdbFlavour,
};
use antinomie_monitor_core::{
    analysis_tools::ToolStatus,
    debug::{
        view::{
            BreakpointEntry, BreakpointKind, Controller, DebugThread, DebugView, MemoryWindow,
            RegisterEntry, RegisterSnapshot, RunState, StopReason, ViewCaps, WindowKind,
        },
        RegKind,
    },
    DebugSessionInfo,
};
use std::sync::Arc;

pub(super) fn info() -> DebugSessionInfo {
    DebugSessionInfo {
        target: antinomie_monitor_core::GuestProcessIdentity {
            boot_id: "boot".into(),
            task_cookie: 55,
            tgid: 42,
            start_boot_ns: 100,
        },
        architecture: "x86-64".into(),
        unix_socket: PathBuf::from("/tmp/ant-dbg/debug-1.sock"),
        tcp_port: 40123,
        gdb_command: "gdb -ex 'target remote 127.0.0.1:40123'".into(),
        gdb_unix_command: "gdb -ex 'target remote | socat - UNIX-CONNECT:/x.sock'".into(),
        client_connected: false,
        clients_served: 0,
        target_state: "attached".into(),
        ended: None,
    }
}

pub(super) const PC: u64 = 0x401136;

pub(super) fn stopped() -> DebugView {
    let mut view = DebugView::new(ViewCaps {
        software_breakpoints: true,
        single_step: true,
        hardware_breakpoints: 0,
        hardware_watchpoints: 0,
        follow: false,
    });
    view.run = RunState::Stopped {
        reason: StopReason::Breakpoint {
            addr: PC,
            kind: BreakpointKind::Software,
        },
        tid: 77,
        pc: PC,
        sequence: 3,
    };
    view.selected_tid = Some(77);
    view.threads = vec![DebugThread {
        tid: 77,
        stopped: true,
        pc: PC,
        signal: 0,
    }];
    view.registers = Some(RegisterSnapshot {
        tid: 77,
        sequence: 3,
        entries: vec![
            RegisterEntry {
                name: "rip",
                value: PC,
                kind: RegKind::CodePointer,
            },
            RegisterEntry {
                name: "rsp",
                value: 0x7ffd_0000,
                kind: RegKind::DataPointer,
            },
        ],
    });
    let window = |kind, address, bytes: Vec<u8>| MemoryWindow {
        kind,
        sequence: 3,
        address,
        requested_size: bytes.len(),
        bytes,
        error: None,
    };
    view.code = Some(window(
        WindowKind::Code,
        PC,
        vec![0x55, 0x48, 0x89, 0xe5, 0xc3],
    ));
    view.stack = Some(window(WindowKind::Stack, 0x7ffd_0000, (0..32).collect()));
    view.breakpoints = vec![BreakpointEntry {
        addr: PC,
        kind: BreakpointKind::Software,
        enabled: true,
    }];
    view
}

pub(super) fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

/// An app with a session attached and its view published.
pub(super) fn attached() -> MonitorApp {
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.debug = Some(info());
    app.snapshot.debug_view = Some(Arc::new(stopped()));
    // The remembered choices go out once; these tests are about other things.
    app.debugger.track_session(Some(u64::from(info().tcp_port)));
    app.debugger.take_announce();
    app
}

fn frames(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    size: egui::Vec2,
) -> Vec<(String, egui::Rect)> {
    for _ in 0..3 {
        render(app, ctx, size);
    }
    texts(&render(app, ctx, size))
}

/// Click the strip tab of `pane` (the dock has tabs of the same names).
fn click_pane_tab(app: &mut MonitorApp, ctx: &egui::Context, size: egui::Vec2, pane: Pane) {
    let shown = frames(app, ctx, size);
    let pos = shown
        .iter()
        .filter(|(text, rect)| text == pane.label() && rect.top() > 200.0 && rect.left() > 270.0)
        .map(|(_, rect)| rect.center())
        .next()
        .unwrap_or_else(|| panic!("no strip tab {}: {shown:?}", pane.label()));
    for pressed in [true, false] {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events: vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                ..Default::default()
            },
            |ctx| app.draw(ctx),
        );
    }
}

/// Whether `wanted` is drawn, ignoring the column padding the listing adds.
fn has(shown: &[(String, egui::Rect)], wanted: &str) -> bool {
    let words = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    shown.iter().any(|(text, _)| words(text) == wanted)
}

#[test]
fn attaching_or_debug_on_start_opens_and_focuses_the_tab_and_the_end_closes_it() {
    let ctx = context();
    let mut app = app();
    observer_fixture(&mut app);
    assert_eq!(app.layout.debugger_position(), None, "no session, no tab");
    // Run > Attach debugger and a run started with Debug on start both end
    // in the backend publishing a debug session.
    app.snapshot.debug = Some(info());
    app.snapshot.debug_view = Some(Arc::new(stopped()));
    frames(&mut app, &ctx, egui::vec2(1280.0, 820.0));
    assert_eq!(
        app.layout.debugger_position(),
        Some((Some(Panel::StaticAnalysis), true)),
        "right after Static Analysis, and showing"
    );
    // Detach, stop the run or stop the VM: the session goes, so does the tab.
    app.snapshot.debug = None;
    app.snapshot.debug_view = None;
    frames(&mut app, &ctx, egui::vec2(1280.0, 820.0));
    assert_eq!(app.layout.debugger_position(), None);
    // A later session opens it again.
    app.snapshot.debug = Some(info());
    app.snapshot.debug_view = Some(Arc::new(stopped()));
    frames(&mut app, &ctx, egui::vec2(1280.0, 820.0));
    assert!(app.layout.debugger_position().is_some());
}

#[test]
fn the_tab_takes_the_focus_once_and_the_user_can_leave_it() {
    let ctx = context();
    let mut app = attached();
    frames(&mut app, &ctx, egui::vec2(1280.0, 820.0));
    assert_eq!(app.layout.debugger_position().map(|p| p.1), Some(true));
    app.layout.focus(Panel::Trace);
    frames(&mut app, &ctx, egui::vec2(1280.0, 820.0));
    assert_eq!(
        app.layout.debugger_position().map(|p| p.1),
        Some(false),
        "the session did not pull the user back"
    );
}

#[test]
fn a_saved_arrangement_never_brings_the_tab_back() {
    let mut app = attached();
    let ctx = context();
    frames(&mut app, &ctx, egui::vec2(1280.0, 820.0));
    app.layout.validate();
    assert_eq!(app.layout.debugger_position(), None);
}

#[test]
fn panes_are_folded_until_opened_and_remembered() {
    let ctx = context();
    let mut app = attached();
    let size = egui::vec2(1280.0, 820.0);
    let shown = frames(&mut app, &ctx, size);
    // The listing and registers are the main view.
    for wanted in ["push rbp", "mov rbp, rsp", "ret", "rip", "rsp"] {
        assert!(has(&shown, wanted), "{wanted}: {shown:?}");
    }
    // The strip names every pane; none of their content is on screen.
    for pane in Pane::ALL {
        assert!(has(&shown, pane.label()), "{}: {shown:?}", pane.label());
    }
    assert!(app.settings.debugger.open_panes.is_empty());
    for hidden in [
        "address e.g. 0x401136",
        "address e.g. 0x7ffd0000",
        "Reset to defaults",
        "SIGHUP (1)",
        "State",
    ] {
        assert!(!has(&shown, hidden), "{hidden} is folded: {shown:?}");
    }
    // Open Memory: its input shows, the others stay folded.
    click_pane_tab(&mut app, &ctx, size, Pane::Memory);
    let shown = frames(&mut app, &ctx, size);
    assert!(has(&shown, "address e.g. 0x7ffd0000"), "{shown:?}");
    assert!(!has(&shown, "Reset to defaults"));
    assert_eq!(app.settings.debugger.open_panes, ["memory"]);
    // It is remembered with the settings, per user.
    let saved = serde_json::to_string(&app.settings).unwrap();
    let back: Settings = serde_json::from_str(&saved).unwrap();
    assert!(back.debugger.pane_open(Pane::Memory));
    assert!(!back.debugger.pane_open(Pane::Threads));
    // And folds again with a click on the lit tab.
    click_pane_tab(&mut app, &ctx, size, Pane::Memory);
    let shown = frames(&mut app, &ctx, size);
    assert!(!has(&shown, "address e.g. 0x7ffd0000"));
    assert!(app.settings.debugger.open_panes.is_empty());
}

#[test]
fn the_listing_and_strip_fit_the_two_screen_sizes_with_a_pane_open() {
    for size in [egui::vec2(1280.0, 820.0), egui::vec2(1000.0, 700.0)] {
        let ctx = context();
        let mut app = attached();
        app.settings.debugger.toggle_pane(Pane::Breakpoints);
        let shown = frames(&mut app, &ctx, size);
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, size);
        for wanted in ["push rbp", "Threads", "Breakpoints", "Add"] {
            let rect = shown
                .iter()
                .find(|(text, _)| text.split_whitespace().collect::<Vec<_>>().join(" ") == wanted)
                .unwrap_or_else(|| panic!("{wanted} at {size:?}: {shown:?}"))
                .1;
            assert!(screen.contains_rect(rect), "{wanted} {rect:?} at {size:?}");
        }
    }
}

#[test]
fn there_is_no_rule_or_action_history_in_the_tab() {
    let ctx = context();
    let mut app = attached();
    for pane in Pane::ALL {
        app.settings.debugger.toggle_pane(pane);
    }
    let shown = frames(&mut app, &ctx, egui::vec2(1280.0, 820.0));
    // The tab is the area right of the sidebar, between the dock's tab bar
    // and the Details strip; the dock itself has a Run History tab.
    let top = shown
        .iter()
        .find(|(text, _)| text == "Process")
        .unwrap()
        .1
        .top();
    let bottom = shown
        .iter()
        .find(|(text, _)| text == "Details")
        .unwrap()
        .1
        .top();
    let inside: Vec<_> = shown
        .iter()
        .filter(|(_, rect)| rect.left() > 280.0 && rect.top() >= top && rect.bottom() <= bottom)
        .collect();
    assert!(inside.len() > 20, "the tab's own texts: {inside:?}");
    assert!(
        inside.iter().all(|(text, _)| {
            let lower = text.to_lowercase();
            !lower.contains("history") && !lower.contains("rule")
        }),
        "{inside:?}"
    );
    assert!(Pane::ALL
        .iter()
        .all(|pane| !pane.label().to_lowercase().contains("history")));
}

#[test]
fn while_gdb_drives_the_tab_says_so_and_stays_read_only() {
    let ctx = context();
    let mut app = attached();
    let size = egui::vec2(1280.0, 820.0);
    let shown = frames(&mut app, &ctx, size);
    assert!(!has(&shown, "gdb is driving; panel is read-only"));
    let mut view = stopped();
    view.controller = Controller::Gdb;
    app.snapshot.debug_view = Some(Arc::new(view.clone()));
    let shown = frames(&mut app, &ctx, size);
    assert!(
        has(&shown, "gdb is driving; panel is read-only"),
        "{shown:?}"
    );
    assert_eq!(
        panes::driving_chip(Some(&view)),
        Some("gdb is driving; panel is read-only")
    );
    assert_eq!(panes::driving_chip(Some(&stopped())), None);
    assert_eq!(panes::driving_chip(None), None);
    let play = format!("{} Continue", egui_phosphor::regular::PLAY);
    click_label(&mut app, &ctx, size, &play);
    assert!(app
        .submitted
        .iter()
        .all(|command| !matches!(command, Command::DebugUi(_))));
}

pub(super) fn tool(id: &str, installed: bool) -> ToolStatus {
    ToolStatus {
        id: id.into(),
        name: id.into(),
        version: "1".into(),
        installed: installed.then(|| "1".to_owned()),
        ..Default::default()
    }
}

#[test]
fn a_missing_front_end_or_gdb_says_so_and_links_to_the_tools_page() {
    let ctx = context();
    let size = egui::vec2(1280.0, 820.0);
    // gdb is there, GEF is not.
    let mut app = attached();
    app.settings.debugger.toggle_pane(Pane::Console);
    app.snapshot.analysis_tools = vec![tool("gef", false), tool("pwndbg", false)];
    app.debugger.console.set_gdb(Some("/usr/bin/gdb".into()));
    let shown = frames(&mut app, &ctx, size);
    assert!(
        shown
            .iter()
            .any(|(text, _)| text.starts_with("GEF (bata24) is not installed")),
        "{shown:?}"
    );
    assert!(has(&shown, "Install…"));
    assert!(!app.debugger.console.running(), "nothing was started");
    click_label(&mut app, &ctx, size, "Install…");
    assert_eq!(
        app.take_library_pages(),
        [crate::workspace::LibraryPage::Tools]
    );
    // GEF is installed, gdb is not.
    app.snapshot.analysis_tools = vec![tool("gef", true)];
    app.debugger.console.set_gdb(None);
    let shown = frames(&mut app, &ctx, size);
    assert!(
        shown
            .iter()
            .any(|(text, _)| text.contains("not found in PATH")),
        "{shown:?}"
    );
    assert!(has(&shown, "Install…"));
    // pwndbg is chosen and missing.
    app.settings.debugger.gdb_flavour = GdbFlavour::Pwndbg;
    app.snapshot.analysis_tools = vec![tool("pwndbg", false)];
    let shown = frames(&mut app, &ctx, size);
    assert!(
        shown
            .iter()
            .any(|(text, _)| text.starts_with("pwndbg is not installed")),
        "{shown:?}"
    );
}

#[test]
fn the_console_runs_gdb_on_a_terminal_connected_to_the_session_port() {
    use std::{io::Read, net::TcpListener, os::unix::fs::PermissionsExt};
    let ctx = context();
    let size = egui::vec2(1280.0, 820.0);
    // A stand-in for the RSP server: it only sees the connection.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = std::env::temp_dir().join(format!("ant-console-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    // A fake gdb: names its arguments, connects to the target like gdb would
    // and then reads commands from the terminal.
    let gdb = root.join("gdb");
    std::fs::write(
        &gdb,
        "#!/bin/bash\n\
         echo \"FAKE-GDB $*\"\n\
         port=${@: -1}; port=${port##*:}\n\
         exec 3<>/dev/tcp/127.0.0.1/$port\n\
         echo connected\n\
         while read -r line; do echo \"ran:$line\"; done\n",
    )
    .unwrap();
    std::fs::set_permissions(&gdb, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut session = info();
    session.tcp_port = port;
    let mut app = attached();
    app.snapshot.debug = Some(session);
    app.debugger.track_session(Some(u64::from(port)));
    app.debugger.take_announce();
    app.options.data_dir = root.clone();
    app.snapshot.analysis_tools = vec![tool("gef", true)];
    app.settings.debugger.toggle_pane(Pane::Console);
    app.debugger.console.set_gdb(Some(gdb.clone()));
    // The tab sees gdb's output arrive, frame by frame.
    let mut screen = String::new();
    for _ in 0..200 {
        render(&mut app, &ctx, size);
        screen = app.debugger.console.contents();
        if screen.contains("connected") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(app.debugger.console.running());
    assert!(screen.contains("FAKE-GDB -nx -q -x"), "{screen}");
    assert!(
        screen.contains(&format!("target remote 127.0.0.1:{port}")),
        "{screen}"
    );
    assert!(screen.contains("connected"), "{screen}");
    // gdb connected to the session's port.
    listener.set_nonblocking(false).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_millis(50)))
        .ok();
    let _ = stream.read(&mut [0u8; 1]);
    // Restart starts a new one; closing the session ends it.
    app.debugger.console.restart();
    render(&mut app, &ctx, size);
    assert!(app.debugger.console.running());
    app.debugger.track_session(None);
    assert!(!app.debugger.console.running());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_gdb_that_will_not_run_is_reported_in_the_pane() {
    let ctx = context();
    let size = egui::vec2(1280.0, 820.0);
    let mut app = attached();
    app.settings.debugger.toggle_pane(Pane::Console);
    app.snapshot.analysis_tools = vec![tool("gef", true)];
    app.debugger
        .console
        .set_gdb(Some("/nonexistent/gdb".into()));
    let shown = frames(&mut app, &ctx, size);
    assert!(
        shown.iter().any(|(text, _)| text.contains("did not start")),
        "{shown:?}"
    );
    assert!(!app.debugger.console.running());
}

#[test]
fn the_flavour_is_chosen_in_settings_and_defaults_to_gef() {
    let ctx = context();
    let size = egui::vec2(1000.0, 800.0);
    let mut app = app();
    assert_eq!(app.settings.debugger.gdb_flavour, GdbFlavour::Gef);
    app.settings_open = true;
    app.settings_page = crate::app::settings_window::SettingsPage::AnalysisTools;
    let shown = frames(&mut app, &ctx, size);
    assert!(has(&shown, "Debugger console"), "{shown:?}");
    assert!(has(&shown, "GEF (bata24)") && has(&shown, "pwndbg"));
    click_label(&mut app, &ctx, size, "pwndbg");
    assert_eq!(app.settings.debugger.gdb_flavour, GdbFlavour::Pwndbg);
    let saved = serde_json::to_string(&app.settings).unwrap();
    let back: Settings = serde_json::from_str(&saved).unwrap();
    assert_eq!(back.debugger.gdb_flavour, GdbFlavour::Pwndbg);
    // Settings saved before the choice existed read as GEF.
    let old: Settings = serde_json::from_str(r#"{"debugger":{"follow":"ask"}}"#).unwrap();
    assert_eq!(old.debugger.gdb_flavour, GdbFlavour::Gef);
}

#[test]
fn every_table_in_the_panes_sorts_by_its_headers() {
    let ctx = context();
    let size = egui::vec2(1400.0, 900.0);
    let mut app = attached();
    let mut view = stopped();
    view.threads.push(DebugThread {
        tid: 5,
        stopped: true,
        pc: 0x10,
        signal: 0,
    });
    app.snapshot.debug_view = Some(Arc::new(view));
    for pane in [Pane::Threads, Pane::Breakpoints, Pane::Signals] {
        app.settings.debugger.toggle_pane(pane);
    }
    let shown = frames(&mut app, &ctx, size);
    // Threads: 77 then 5 as given; a click on the Thread header sorts.
    let row = |shown: &[(String, egui::Rect)], text: &str| {
        shown
            .iter()
            .find(|(label, _)| label == text)
            .unwrap_or_else(|| panic!("{text}: {shown:?}"))
            .1
    };
    assert!(row(&shown, "77").top() < row(&shown, "5").top());
    click_label(&mut app, &ctx, size, "Thread");
    let shown = frames(&mut app, &ctx, size);
    assert!(
        row(&shown, "5").top() < row(&shown, "77").top(),
        "ascending by thread id"
    );
    for header in [
        "State", "PC", "Address", "Kind", "Signal", "Stop", "Print", "Pass",
    ] {
        assert!(has(&shown, header), "sortable header {header}: {shown:?}");
    }
}
