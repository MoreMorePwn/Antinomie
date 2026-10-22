// SPDX-License-Identifier: GPL-3.0-only
//! Native fixture for the Debugger tab, for screenshots in each theme and
//! size. Needs an X11 display; exits by itself.
//!
//! ANTINOMIE_QA_THEME = dark | light | blue, ANTINOMIE_QA_SIZE = 1280x820,
//! ANTINOMIE_QA_PANES = comma list of pane keys to open (default none),
//! ANTINOMIE_QA_CONSOLE = missing | nogdb | running (opens the console pane),
//! ANTINOMIE_QA_SECONDS = 25.
use super::debugger_tab::{attached, stopped, tool, PC};
use super::*;
use crate::app::debugger::panes::Pane;
use crate::theme::Theme;
use antinomie_monitor_core::debug::{
    signal_policy::{SignalAction, SignalNote},
    view::{BreakpointEntry, BreakpointKind, DebugThread, MemoryWindow, RegisterEntry, WindowKind},
    RegKind,
};
use std::sync::Arc;

/// A fuller stop than the unit tests use: the registers of a real x86-64
/// process, a function's worth of code, several threads and breakpoints.
fn fixture_view() -> antinomie_monitor_core::debug::view::DebugView {
    let mut view = stopped();
    let entry = |name, value, kind| RegisterEntry { name, value, kind };
    let mut entries = vec![
        entry("rax", 0x0000_0000_0000_0001, RegKind::General),
        entry("rbx", 0x0000_7fff_f7fa_a2e8, RegKind::General),
        entry("rcx", 0x0000_7fff_f7e9_8a37, RegKind::General),
        entry("rdx", 0x0000_0000_0000_0020, RegKind::General),
        entry("rsi", 0x0000_7fff_ffff_e0c8, RegKind::General),
        entry("rdi", 0x0000_0000_0000_0001, RegKind::General),
        entry("rbp", 0x0000_7fff_ffff_dfe0, RegKind::DataPointer),
        entry("rsp", 0x0000_7fff_ffff_dfc0, RegKind::DataPointer),
    ];
    for (index, name) in ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        .into_iter()
        .enumerate()
    {
        entries.push(entry(name, 0x1000 * (index as u64 + 1), RegKind::General));
    }
    entries.push(entry("rip", PC, RegKind::CodePointer));
    entries.push(entry("eflags", 0x246, RegKind::Flags));
    for name in ["cs", "ss", "ds", "es", "fs", "gs"] {
        entries.push(entry(name, 0x2b, RegKind::Segment));
    }
    entries.push(entry("fs_base", 0x7fff_f7d8_a740, RegKind::System));
    entries.push(entry("gs_base", 0, RegKind::System));
    if let Some(registers) = view.registers.as_mut() {
        registers.entries = entries;
    }
    let code: Vec<u8> = vec![
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x89, 0x7d, 0xec, 0x48, 0x89, 0x75, 0xe0,
        0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x1a, 0x8b, 0x45, 0xfc, 0x48, 0x98, 0x48,
        0x8d, 0x14, 0x85, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x45, 0xe0, 0x48, 0x01, 0xd0, 0x48,
        0x8b, 0x00, 0x48, 0x89, 0xc7, 0xe8, 0x12, 0xfe, 0xff, 0xff, 0x83, 0x45, 0xfc, 0x01, 0x8b,
        0x45, 0xfc, 0x3b, 0x45, 0xec, 0x7c, 0xde, 0xb8, 0x00, 0x00, 0x00, 0x00, 0xc9, 0xc3,
    ];
    let window = |kind, address, bytes: Vec<u8>| MemoryWindow {
        kind,
        sequence: 3,
        address,
        requested_size: bytes.len(),
        bytes,
        error: None,
    };
    view.code = Some(window(WindowKind::Code, PC, code));
    view.stack = Some(window(
        WindowKind::Stack,
        0x7fff_ffff_dfc0,
        (0..64).map(|byte| (byte * 7 + 3) as u8).collect(),
    ));
    view.memory = Some(window(
        WindowKind::Memory,
        0x412b40,
        b"http://cdn-update.example.net/p.\x00\x00\x00\x00ELF\x02\x01\x01\x00".to_vec(),
    ));
    for (tid, pc) in [(78, 0x401200), (79, 0x7fff_f7e9_8a37)] {
        view.threads.push(DebugThread {
            tid,
            stopped: tid == 78,
            pc,
            signal: 0,
        });
    }
    view.breakpoints.push(BreakpointEntry {
        addr: 0x401200,
        kind: BreakpointKind::Software,
        enabled: false,
    });
    view.signals.set(
        14,
        SignalAction {
            stop: false,
            print: false,
            pass: true,
        },
    );
    view.signal_log = vec![SignalNote {
        tid: 78,
        number: 17,
        passed: true,
        stopped: false,
    }];
    view
}

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_debugger_fixture() {
    use std::os::unix::fs::PermissionsExt;
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::update(&mut self.app, ctx, frame);
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => Theme::Light,
        "blue" => Theme::Blue,
        _ => Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1280.0, 820.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse::<u64>().unwrap_or(25);
    let panes = var("ANTINOMIE_QA_PANES");
    let console = var("ANTINOMIE_QA_CONSOLE");
    eframe::run_native(
        "Antinomie Debugger QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            let mut app = attached();
            app.snapshot.debug_view = Some(Arc::new(fixture_view()));
            app.settings.set_theme(theme_choice);
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            for key in panes.split(',').filter(|key| !key.is_empty()) {
                if let Some(pane) = Pane::from_key(key) {
                    app.settings.debugger.toggle_pane(pane);
                }
            }
            if !console.is_empty() {
                app.settings.debugger.toggle_pane(Pane::Console);
            }
            match console.as_str() {
                "missing" => {
                    app.snapshot.analysis_tools = vec![tool("gef", false), tool("pwndbg", false)];
                    app.debugger.console.set_gdb(Some("/usr/bin/gdb".into()));
                }
                "nogdb" => {
                    app.snapshot.analysis_tools = vec![tool("gef", true)];
                    app.debugger.console.set_gdb(None);
                }
                "running" => {
                    // A stand-in gdb that prints what GEF prints and echoes input.
                    let root = std::env::temp_dir().join("ant-debugger-qa");
                    std::fs::create_dir_all(&root).expect("qa dir");
                    let gdb = root.join("gdb");
                    let script = [
                        "#!/bin/bash",
                        r"printf 'GEF for linux ready, 134 commands loaded and 5 functions added\r\n'",
                        r"printf '\033[32mgef>\033[0m target remote 127.0.0.1:40123\r\n'",
                        r"printf 'Remote debugging using 127.0.0.1:40123\r\n'",
                        r"printf '0x0000000000401136 in main ()\r\n'",
                        r"printf '\033[1;32mgef>\033[0m '",
                        "exec cat",
                    ]
                    .join("\n");
                    std::fs::write(&gdb, script).expect("fake gdb");
                    std::fs::set_permissions(&gdb, std::fs::Permissions::from_mode(0o755))
                        .expect("mode");
                    app.snapshot.analysis_tools = vec![tool("gef", true)];
                    app.debugger.console.set_gdb(Some(gdb));
                }
                _ => {}
            }
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .expect("native debugger fixture");
}
