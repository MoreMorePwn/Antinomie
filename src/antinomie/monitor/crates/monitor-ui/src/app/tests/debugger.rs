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
        "refused: no process list is requested_size"
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
    click_label(&mut app, &ctx, size, "Detach and kill");
    assert!(matches!(
        app.submitted.last(),
        Some(Command::DebugDetach { kill: true })
    ));
}

mod panel {
    use super::*;
    use crate::app::debugger::panes::Pane;
    use antinomie_monitor_core::debug::{
        signal_policy::{SignalAction, SignalNote, SignalTable},
        view::{
            BreakpointEntry, BreakpointKind, Controller, DebugAction, DebugRequest, DebugThread,
            DebugView, FollowMode, ForkChoice, ForkPolicy, ForkPrompt, InferiorState, InferiorView,
            MemoryWindow, Pending, RegisterEntry, RegisterSnapshot, RunState, StopReason, ViewCaps,
            WindowKind,
        },
        RegKind,
    };
    use std::sync::Arc;

    const SIZE: egui::Vec2 = egui::vec2(2000.0, 1600.0);
    const PC: u64 = 0x401136;

    fn window(kind: WindowKind, sequence: u32, address: u64, bytes: Vec<u8>) -> MemoryWindow {
        MemoryWindow {
            kind,
            sequence,
            address,
            requested_size: bytes.len(),
            bytes,
            error: None,
        }
    }

    /// Stopped at a software breakpoint at `PC`, push rbp; mov rbp, rsp; ret.
    fn stopped(sequence: u32) -> DebugView {
        let mut view = DebugView::new(ViewCaps {
            software_breakpoints: true,
            single_step: true,
            hardware_breakpoints: 0,
            hardware_watchpoints: 0,
            follow: false,
        });
        view.epoch = 5;
        view.run = RunState::Stopped {
            reason: StopReason::Breakpoint {
                addr: PC,
                kind: BreakpointKind::Software,
            },
            tid: 77,
            pc: PC,
            sequence,
        };
        view.selected_tid = Some(77);
        view.threads = vec![
            DebugThread {
                tid: 77,
                stopped: true,
                pc: PC,
                signal: 0,
            },
            DebugThread {
                tid: 78,
                stopped: true,
                pc: 0x401200,
                signal: 0,
            },
        ];
        let entry = |name, value, kind| RegisterEntry { name, value, kind };
        view.registers = Some(RegisterSnapshot {
            tid: 77,
            sequence,
            entries: vec![
                entry("rax", 0x1122, RegKind::General),
                entry("rsp", 0x7ffd_0000, RegKind::DataPointer),
                entry("rip", PC, RegKind::CodePointer),
                entry("eflags", 0x246, RegKind::Flags),
                entry("cs", 0x33, RegKind::Segment),
                entry("fs_base", 0x7fff_1234_0000, RegKind::System),
                entry("gs_base", 0, RegKind::System),
            ],
        });
        view.code = Some(window(
            WindowKind::Code,
            sequence,
            PC,
            vec![0x55, 0x48, 0x89, 0xe5, 0xc3],
        ));
        view.stack = Some(window(
            WindowKind::Stack,
            sequence,
            0x7ffd_0000,
            (0..32).collect(),
        ));
        view.breakpoints = vec![BreakpointEntry {
            addr: PC,
            kind: BreakpointKind::Software,
            enabled: true,
        }];
        view
    }

    /// A session with every pane but the console open: the tab folds them by
    /// default, and these tests are about what is in them.
    fn open(app: &mut MonitorApp, view: DebugView) {
        open_folded(app, view);
        for pane in Pane::ALL {
            if pane != Pane::Console {
                app.settings.debugger.toggle_pane(pane);
            }
        }
    }

    fn open_folded(app: &mut MonitorApp, view: DebugView) {
        observer_fixture(app);
        app.snapshot.debug = Some(info());
        app.snapshot.debug_view = Some(Arc::new(view));
        // The remembered choices go out once; tests of other things skip them.
        app.debugger.track_session(Some(u64::from(info().tcp_port)));
        app.debugger.take_announce();
    }

    fn shown(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<String> {
        for _ in 0..3 {
            render(app, ctx, SIZE);
        }
        let output = render(app, ctx, SIZE);
        texts(&output).into_iter().map(|(text, _)| text).collect()
    }

    /// Every text drawn, including parts a scroll area clips: wide hex rows
    /// scroll sideways in a real window.
    fn unclipped(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<String> {
        fn walk(shape: &egui::Shape, out: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(text) => out.push(text.galley.text().trim().to_owned()),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| walk(shape, out)),
                _ => {}
            }
        }
        for _ in 0..3 {
            render(app, ctx, SIZE);
        }
        let output = render(app, ctx, SIZE);
        let mut out = Vec::new();
        for clipped in &output.shapes {
            walk(&clipped.shape, &mut out);
        }
        out
    }

    fn context() -> egui::Context {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        ctx
    }

    fn requests(app: &MonitorApp) -> Vec<DebugRequest> {
        app.submitted
            .iter()
            .filter_map(|command| match command {
                Command::DebugUi(request) => Some(request.clone()),
                _ => None,
            })
            .collect()
    }

    fn play(label: &str) -> String {
        format!("{} {label}", egui_phosphor::regular::PLAY)
    }

    #[test]
    fn a_stop_shows_status_registers_flags_disassembly_stack_and_breakpoints() {
        let ctx = context();
        let mut app = app();
        open(&mut app, stopped(3));
        let shown = shown(&mut app, &ctx);
        let has = |text: &str| shown.iter().any(|shown| shown == text);
        assert!(has("Stopped: swbreak @ 0x401136"), "{shown:?}");
        assert!(has("Thread 77"), "the selected thread: {shown:?}");
        // Registers, decoded flags, and the extra base registers.
        for text in [
            "rip",
            "0x0000000000401136",
            "[PF ZF IF]",
            "fs_base",
            "0x00007fff12340000",
            "gs_base",
            "0x0033",
        ] {
            assert!(has(text), "{text}: {shown:?}");
        }
        // Disassembly from the shared decoder, with the current instruction marked.
        assert!(
            has("push     rbp") && has("mov      rbp, rsp") && has("ret"),
            "{shown:?}"
        );
        assert!(has("▶"));
        // Stack rows through the shared hex rows, with the stack pointer arrow.
        let all = unclipped(&mut app, &ctx);
        assert!(
            all.iter()
                .any(|text| text.starts_with("→ 000000007ffd0000  00 01 02 03")),
            "{all:?}"
        );
        // Breakpoint list and the threads list.
        assert!(has("0x401136") && has("sw"));
        assert!(
            has("77") && has("78") && has("0x401200"),
            "thread rows: {shown:?}"
        );
        // The gray placeholder of the address input.
        assert!(has("address e.g. 0x401136"));
    }

    #[test]
    fn the_buttons_send_requests_for_the_stop_on_screen() {
        let ctx = context();
        let mut app = app();
        open(&mut app, stopped(3));
        click_label(&mut app, &ctx, SIZE, &play("Continue"));
        let sent = requests(&app);
        assert_eq!(sent.len(), 1);
        assert_eq!(
            (sent[0].sequence, &sent[0].action),
            (3, &DebugAction::Continue)
        );
        // While that request is in flight nothing else is sent.
        click_label(&mut app, &ctx, SIZE, &play("Continue"));
        assert_eq!(requests(&app).len(), 1, "waiting for the first answer");
        assert!(shown(&mut app, &ctx).iter().any(|text| text == "Working…"));

        // The backend answered: buttons work again, for the new stop.
        let mut view = stopped(4);
        view.handled = sent[0].id;
        app.snapshot.debug_view = Some(Arc::new(view));
        click_label(
            &mut app,
            &ctx,
            SIZE,
            &format!("{} Step", egui_phosphor::regular::ARROW_BEND_DOWN_RIGHT),
        );
        let sent = requests(&app);
        assert_eq!(sent.len(), 2);
        assert_eq!(
            (sent[1].sequence, &sent[1].action),
            (4, &DebugAction::Step { tid: 77 })
        );
        assert!(sent[1].id > sent[0].id);
    }

    #[test]
    fn stop_is_offered_only_while_running() {
        let ctx = context();
        let mut app = app();
        open(&mut app, stopped(3));
        click_label(
            &mut app,
            &ctx,
            SIZE,
            &format!("{} Stop", egui_phosphor::regular::STOP),
        );
        assert!(requests(&app).is_empty(), "disabled while stopped");

        let mut view = stopped(3);
        view.run = RunState::Running {
            pending: Pending::Nothing,
        };
        view.registers = None;
        view.code = None;
        view.stack = None;
        view.threads.clear();
        app.snapshot.debug_view = Some(Arc::new(view));
        let texts = shown(&mut app, &ctx);
        assert!(texts.iter().any(|text| text == "Running"));
        assert!(texts
            .iter()
            .any(|text| text == "Registers are shown while the process is stopped."));
        click_label(
            &mut app,
            &ctx,
            SIZE,
            &format!("{} Stop", egui_phosphor::regular::STOP),
        );
        let sent = requests(&app);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].action, DebugAction::Stop);
        assert!(!requests(&app).iter().any(|request| matches!(
            request.action,
            DebugAction::Continue | DebugAction::Step { .. }
        )));
    }

    #[test]
    fn loading_text_has_a_spinner_beside_it_and_stale_data_is_hidden() {
        let ctx = context();
        let mut app = app();
        // Registers have not arrived for the new stop; the old windows belong
        // to the previous one.
        let mut view = stopped(5);
        view.loading = true;
        view.registers = None;
        view.code = Some(window(WindowKind::Code, 4, PC, vec![0x90; 8]));
        view.stack = None;
        open(&mut app, view);
        let output = {
            for _ in 0..3 {
                render(&mut app, &ctx, SIZE);
            }
            render(&mut app, &ctx, SIZE)
        };
        let all = texts(&output);
        for wanted in ["Reading registers…", "Reading code…", "Reading memory…"] {
            assert!(
                all.iter().any(|(text, _)| text == wanted),
                "{wanted}: {all:?}"
            );
        }
        // The same window with everything loaded draws fewer spinners.
        let loaded = {
            app.snapshot.debug_view = Some(Arc::new(stopped(5)));
            for _ in 0..3 {
                render(&mut app, &ctx, SIZE);
            }
            render(&mut app, &ctx, SIZE)
        };
        assert!(
            theme::spinners_in(&output.shapes) >= theme::spinners_in(&loaded.shapes) + 3,
            "a spinner beside each loading text"
        );
        assert!(all.iter().all(|(text, _)| text != "nop"));
    }

    #[test]
    fn while_gdb_controls_the_process_the_panel_is_read_only() {
        let ctx = context();
        let mut app = app();
        let mut view = stopped(3);
        view.controller = Controller::Gdb;
        view.run = RunState::Unknown;
        view.registers = None;
        view.code = None;
        view.stack = None;
        view.threads.clear();
        open(&mut app, view);
        let texts = shown(&mut app, &ctx);
        assert!(texts
            .iter()
            .any(|text| text == "Controlled by gdb (read-only here until it disconnects)"));
        click_label(&mut app, &ctx, SIZE, &play("Continue"));
        click_label(&mut app, &ctx, SIZE, "Detach");
        assert!(
            requests(&app).is_empty(),
            "nothing is sent while gdb drives"
        );
        assert!(matches!(
            app.submitted.last(),
            Some(Command::DebugDetach { kill: false })
        ));
    }

    #[test]
    fn a_breakpoint_is_added_by_address_and_a_bad_address_is_reported() {
        let ctx = context();
        let mut app = app();
        open(&mut app, stopped(3));
        // The first frame starts the panel's session state.
        shown(&mut app, &ctx);
        app.debugger_input_for_tests("0x401200", "");
        click_label(&mut app, &ctx, SIZE, "Add");
        let sent = requests(&app);
        assert_eq!(
            sent.last().map(|request| &request.action),
            Some(&DebugAction::AddBreakpoint {
                addr: 0x401200,
                kind: BreakpointKind::Software
            })
        );
        let mut answered = stopped(3);
        answered.handled = sent.last().unwrap().id;
        app.snapshot.debug_view = Some(Arc::new(answered));
        app.debugger_input_for_tests("main", "");
        click_label(&mut app, &ctx, SIZE, "Add");
        assert_eq!(requests(&app).len(), 1, "a bad address is not sent");
        let all = shown(&mut app, &ctx);
        assert!(
            all.iter()
                .any(|text| text.contains("\"main\" is not a hexadecimal address")),
            "{all:?}"
        );
    }

    #[test]
    fn a_breakpoint_can_be_removed_and_memory_read_within_bounds() {
        let ctx = context();
        let mut app = app();
        open(&mut app, stopped(3));
        click_label(&mut app, &ctx, SIZE, egui_phosphor::regular::TRASH);
        assert_eq!(
            requests(&app).last().map(|request| &request.action),
            Some(&DebugAction::RemoveBreakpoint { addr: PC })
        );
        let mut view = stopped(3);
        view.handled = requests(&app).last().unwrap().id;
        view.breakpoints.clear();
        app.snapshot.debug_view = Some(Arc::new(view));
        app.debugger_input_for_tests("", "7ffd0010");
        click_label(&mut app, &ctx, SIZE, "Read");
        assert_eq!(
            requests(&app).last().map(|request| &request.action),
            Some(&DebugAction::ReadMemory {
                addr: 0x7ffd_0010,
                size: 256
            })
        );
    }

    #[test]
    fn a_new_session_forgets_the_old_ones_requests() {
        let mut app = app();
        open(&mut app, stopped(3));
        app.debugger.track_session(Some(1));
        let view = app.debug_view().unwrap();
        app.debug_action(&view, DebugAction::Refresh);
        assert!(app.debugger.waiting(&view));
        app.debugger.track_session(None);
        assert!(!app.debugger.waiting(&view));
    }

    fn inferior(
        pid: u32,
        parent: Option<u32>,
        selected: bool,
        state: InferiorState,
    ) -> InferiorView {
        InferiorView {
            pid,
            parent,
            selected,
            vfork: false,
            state,
        }
    }

    fn with_children() -> DebugView {
        let mut view = stopped(3);
        view.caps.follow = true;
        view.selected_pid = 42;
        view.inferiors = vec![
            inferior(
                42,
                None,
                true,
                InferiorState::Stopped(StopReason::Breakpoint {
                    addr: PC,
                    kind: BreakpointKind::Software,
                }),
            ),
            inferior(43, Some(42), false, InferiorState::Held),
            inferior(44, Some(42), false, InferiorState::Running),
        ];
        view
    }

    #[test]
    fn processes_are_listed_and_hidden_when_there_is_nothing_to_follow() {
        let ctx = context();
        let mut app = app();
        let mut lone = stopped(3);
        lone.caps.follow = false;
        lone.inferiors = vec![inferior(42, None, true, InferiorState::Running)];
        open(&mut app, lone);
        let texts = shown(&mut app, &ctx);
        assert!(
            texts.iter().any(|text| text.starts_with("One process;")),
            "{texts:?}"
        );
        assert!(!texts.iter().any(|text| text == "Let go"));
        app.snapshot.debug_view = Some(Arc::new(with_children()));
        let texts = shown(&mut app, &ctx);
        let has = |wanted: &str| texts.iter().any(|text| text.trim() == wanted);
        assert!(has("stopped (swbreak)"), "{texts:?}");
        assert!(has("43") && has("held"), "{texts:?}");
        assert!(has("44") && has("running"), "{texts:?}");
        assert!(has("Let go") && has("Show"));
    }

    #[test]
    fn show_and_let_go_send_the_process_actions() {
        let ctx = context();
        let mut app = app();
        open(&mut app, with_children());
        click_label(&mut app, &ctx, SIZE, "Show");
        assert_eq!(
            requests(&app).last().map(|request| &request.action),
            Some(&DebugAction::SelectInferior { pid: 43 }),
            "the selected process has no Show"
        );
        app.snapshot.debug_view = Some(Arc::new(with_children()));
        click_label(&mut app, &ctx, SIZE, "Let go");
        assert!(requests(&app)
            .iter()
            .any(|request| matches!(request.action, DebugAction::DetachInferior { pid: 42 })));
    }

    #[test]
    fn the_fork_prompt_appears_and_sends_the_choice() {
        let ctx = context();
        let mut app = app();
        let mut view = with_children();
        open(&mut app, view.clone());
        assert!(!shown(&mut app, &ctx)
            .iter()
            .any(|text| text.contains("forked child")));
        view.fork_prompt = Some(ForkPrompt {
            parent: 42,
            child: 45,
            vfork: false,
        });
        app.snapshot.debug_view = Some(Arc::new(view));
        let texts = shown(&mut app, &ctx);
        assert!(
            texts
                .iter()
                .any(|text| text == "Process 42 forked child 45"),
            "{texts:?}"
        );
        click_label(&mut app, &ctx, SIZE, "Follow child");
        assert_eq!(
            requests(&app).last().map(|request| &request.action),
            Some(&DebugAction::ForkDecision {
                follow: ForkChoice::Child,
                detach_other: true
            })
        );
        let mut vfork = with_children();
        vfork.fork_prompt = Some(ForkPrompt {
            parent: 42,
            child: 46,
            vfork: true,
        });
        app.snapshot.debug_view = Some(Arc::new(vfork));
        assert!(shown(&mut app, &ctx)
            .iter()
            .any(|text| text == "Process 42 vforked child 46"));
    }

    #[test]
    fn the_fork_policy_is_chosen_and_greyed_for_a_base_that_cannot_follow() {
        let ctx = context();
        let mut app = app();
        open(&mut app, with_children());
        click_label(&mut app, &ctx, SIZE, "Let the other process run");
        assert_eq!(
            requests(&app).last().map(|request| &request.action),
            Some(&DebugAction::SetForkPolicy(ForkPolicy {
                follow: FollowMode::Parent,
                detach_other: false
            }))
        );
        assert!(!app.settings.debugger.detach_other, "and it is remembered");
        let mut cannot = with_children();
        cannot.caps.follow = false;
        app.snapshot.debug_view = Some(Arc::new(cannot));
        let before = requests(&app).len();
        click_label(&mut app, &ctx, SIZE, "Let the other process run");
        assert_eq!(requests(&app).len(), before, "disabled without caps.follow");
    }

    #[test]
    fn thread_rows_show_running_and_the_pending_signal() {
        let running = DebugThread {
            tid: 9,
            stopped: false,
            pc: 0x10,
            signal: 0,
        };
        let faulted = DebugThread {
            tid: 10,
            stopped: true,
            pc: 0x20,
            signal: 11,
        };
        assert_eq!(
            crate::app::debugger::lists::thread_state(&running),
            "running"
        );
        assert_eq!(
            crate::app::debugger::lists::thread_state(&faulted),
            "stopped SIGSEGV"
        );
        let ctx = context();
        let mut app = app();
        let mut view = stopped(3);
        view.threads.push(running);
        view.threads.push(faulted);
        open(&mut app, view);
        let texts = shown(&mut app, &ctx);
        for wanted in ["9", "running", "0x10", "10", "stopped SIGSEGV", "0x20"] {
            assert!(
                texts.iter().any(|text| text == wanted),
                "{wanted}: {texts:?}"
            );
        }
    }

    #[test]
    fn threads_and_processes_stay_visible_read_only_while_gdb_controls() {
        let ctx = context();
        let mut app = app();
        let mut view = with_children();
        view.controller = Controller::Gdb;
        open(&mut app, view);
        let texts = shown(&mut app, &ctx);
        assert!(texts.iter().any(|text| text == "43"));
        assert!(texts.iter().any(|text| text == "held"));
        assert!(texts.iter().any(|text| text == "77"));
        click_label(&mut app, &ctx, SIZE, "Show");
        assert!(requests(&app).is_empty());
    }

    #[test]
    fn the_signal_editor_sends_one_request_per_change_and_marks_differences() {
        let ctx = context();
        let mut app = app();
        let mut view = stopped(3);
        view.signals.set(
            1,
            SignalAction {
                stop: false,
                print: true,
                pass: true,
            },
        );
        view.signal_log = vec![
            SignalNote {
                tid: 12,
                number: 17,
                passed: true,
                stopped: false,
            },
            SignalNote {
                tid: 12,
                number: 11,
                passed: true,
                stopped: true,
            },
        ];
        open_folded(&mut app, view);
        app.settings.debugger.toggle_pane(Pane::Signals);
        // The recent signals are folded under their header.
        let folded = unclipped(&mut app, &ctx);
        assert!(folded.iter().any(|text| text == "Recent signals · 2"));
        assert!(!folded.iter().any(|text| text.starts_with("SIGCHLD to")));
        click_label(&mut app, &ctx, SIZE, "Recent signals · 2");
        let texts = unclipped(&mut app, &ctx);
        assert!(texts
            .iter()
            .any(|text| text == "SIGCHLD to thread 12 passed"));
        assert!(texts.iter().any(|text| text == "SIGSEGV stopped thread 12"));
        assert!(texts.iter().any(|text| text == "SIGHUP (1)"));
        assert_eq!(
            texts.iter().filter(|text| *text == "changed").count(),
            1,
            "only SIGHUP differs"
        );
        click_label(&mut app, &ctx, SIZE, "Reset to defaults");
        assert_eq!(
            requests(&app).last().map(|request| &request.action),
            Some(&DebugAction::SetSignalTable(SignalTable::default()))
        );
        assert!(app.settings.debugger.signals.is_default());
    }

    fn click_at(app: &mut MonitorApp, ctx: &egui::Context, pos: egui::Pos2) {
        for pressed in [true, false] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
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

    #[test]
    fn a_checkbox_sends_that_signals_new_action_and_it_is_remembered() {
        let ctx = context();
        let mut app = app();
        open_folded(&mut app, stopped(3));
        app.settings.debugger.toggle_pane(Pane::Signals);
        for _ in 0..3 {
            render(&mut app, &ctx, SIZE);
        }
        let output = render(&mut app, &ctx, SIZE);
        let all = texts(&output);
        let find = |wanted: &str| {
            all.iter()
                .find(|(text, _)| text == wanted)
                .unwrap_or_else(|| panic!("{wanted}: {all:?}"))
                .1
        };
        let print_head = find("Print");
        let row = find("SIGHUP (1)");
        click_at(
            &mut app,
            &ctx,
            egui::pos2(print_head.left() + 7.0, row.center().y),
        );
        let action = SignalAction {
            stop: true,
            print: false,
            pass: true,
        };
        assert_eq!(
            requests(&app).last().map(|request| &request.action),
            Some(&DebugAction::SetSignalPolicy { signal: 1, action })
        );
        assert_eq!(app.settings.debugger.signals.action(1), action);
    }

    #[test]
    fn a_fork_policy_edit_is_remembered() {
        let mut app = app();
        app.remember_debug_choice(&DebugAction::SetForkPolicy(ForkPolicy {
            follow: FollowMode::Child,
            detach_other: false,
        }));
        assert_eq!(
            app.settings.debugger.fork_policy().follow,
            FollowMode::Child
        );
        assert!(!app.settings.debugger.fork_policy().detach_other);
    }

    #[test]
    fn a_new_session_sends_the_remembered_choices_once() {
        let ctx = context();
        let mut app = app();
        app.settings.debugger.signals.set(
            11,
            SignalAction {
                stop: false,
                print: false,
                pass: true,
            },
        );
        app.settings.debugger.remember_policy(ForkPolicy {
            follow: FollowMode::Ask,
            detach_other: false,
        });
        observer_fixture(&mut app);
        app.snapshot.debug = Some(info());
        app.snapshot.debug_view = Some(Arc::new(stopped(3)));
        for _ in 0..4 {
            render(&mut app, &ctx, SIZE);
        }
        let sent = requests(&app);
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert!(
            matches!(&sent[0].action, DebugAction::SetSignalTable(table) if table.action(11).pass)
        );
        assert_eq!(
            sent[1].action,
            DebugAction::SetForkPolicy(ForkPolicy {
                follow: FollowMode::Ask,
                detach_other: false
            })
        );
    }
}
