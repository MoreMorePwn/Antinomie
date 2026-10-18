// SPDX-License-Identifier: MIT
//! Workspace panels and live capture reads.
use super::*;

#[test]
fn all_live_capture_reads_use_the_invocation_owner_directory() {
    let mut app = app();
    let mut first = run("one");
    first.directory = "/archive/one".into();
    let mut second = run("two");
    second.root_task_cookie = 8;
    second.directory = "/archive/two".into();
    app.snapshot.runs = vec![first, second];
    app.snapshot.capture_dir = Some("/archive/unassigned".into());
    let mut event = event(1, 0);
    event.root_task_cookie = 8;
    let invocation = pair_events(&[event.clone()]).remove(0);
    assert_eq!(
        app.invocation_directory(Some(&invocation)),
        Some(PathBuf::from("/archive/two"))
    );
    event.root_task_cookie = 0;
    let legacy = pair_events(&[event.clone()]).remove(0);
    assert_eq!(
        app.invocation_directory(Some(&legacy)),
        app.snapshot.capture_dir
    );
    event.root_task_cookie = 999;
    let unknown = pair_events(&[event]).remove(0);
    assert!(app.invocation_directory(Some(&unknown)).is_none());
}

#[test]
fn imported_archive_selection_survives_run_list_refresh() {
    let mut app = app();
    app.selected = Some("vm".into());
    let mut imported = run("archive:/legacy");
    imported.state = RunState::Finalized;
    app.history.push(imported);
    app.select_run(Some("archive:/legacy".into()));
    app.handle_archive_answer(Answer::List(Ok(vec![run("listed")])));
    assert_eq!(app.offline_run().unwrap().id, "archive:/legacy");
    assert_eq!(app.history.len(), 2);
}

#[test]
#[ignore = "requires explicit X11 native automation; exits after 120 seconds"]
fn native_workspace_fixture() {
    use std::sync::{Arc, Mutex};
    use winit::platform::x11::EventLoopBuilderExtX11;

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("remove QA fixture");
        }
    }
    #[derive(Default)]
    struct Evidence {
        first: Vec<u8>,
        second: Vec<u8>,
        archive_selected: bool,
        first_preserved: bool,
        second_preserved: bool,
    }
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
        evidence: Arc<Mutex<Evidence>>,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            let close = ctx.input(|input| input.viewport().close_requested())
                || Instant::now() >= self.deadline;
            if close {
                let mut evidence = self.evidence.lock().expect("QA evidence");
                *evidence = Evidence::default();
                for command in &self.app.submitted {
                    if let Command::TerminalInput { run_id, data } = command {
                        match run_id.as_str() {
                            "terminal-a" => evidence.first.extend(data),
                            "terminal-b" => evidence.second.extend(data),
                            _ => {}
                        }
                    }
                }
                evidence.archive_selected = self.app.archive_selected
                    && self.app.selected_run.as_deref() == Some("saved-run")
                    && !self.app.archive_page.is_empty()
                    && self.app.snapshot.events.len() == 1;
                evidence.first_preserved = self.app.terminals["terminal-a"]
                    .terminal
                    .contents()
                    .contains("TERMINAL A RETAINED");
                evidence.second_preserved = self.app.terminals["terminal-b"]
                    .terminal
                    .contents()
                    .contains("TERMINAL B RETAINED");
                self.app.snapshot.active_vm = None;
                self.app.snapshot.state = VmState::Stopped;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::update(&mut self.app, ctx, frame);
        }
    }
    let fixture = Fixture(std::env::temp_dir().join(format!(
            "antinomie-native-qa-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )));
    std::fs::create_dir_all(&fixture.0).expect("QA directory");
    let mut first = run("terminal-a");
    first.request.path = "/bin/terminal-a".into();
    first.directory = fixture.0.clone();
    first.execution = Some(antinomie_monitor_core::RunExecution {
        generation: 1,
        live_task_count: 2,
        pending_async_count: 1,
        flags: 1,
        root_wait_status: Some(7 << 8),
        root_exit: Some(WaitStatus::Exited { code: 7 }),
        async_loss_count: 0,
        total_task_count: 3,
    });
    let mut second = run("terminal-b");
    second.request.path = "/bin/terminal-b".into();
    second.pid = 43;
    second.root_task_cookie = 8;
    second.directory = fixture.0.clone();
    let mut saved = run("saved-run");
    saved.request.path = "/usr/bin/saved-program".into();
    saved.request.args = vec!["--output".into(), "/tmp/path with spaces".into()];
    saved.request.env.push("QA=value with spaces".into());
    saved.root_task_cookie = 9;
    saved.state = RunState::Finished;
    saved.terminal_eof = true;
    saved.directory = fixture.0.clone();
    saved.boot_id = "previous-boot".into();
    saved.execution = Some(antinomie_monitor_core::RunExecution {
        generation: 1,
        live_task_count: 0,
        pending_async_count: 0,
        flags: 7,
        root_wait_status: Some(0),
        root_exit: Some(WaitStatus::Exited { code: 0 }),
        async_loss_count: 0,
        total_task_count: 1,
    });
    let mut entry = event(1, 0);
    entry.root_task_cookie = 9;
    entry.syscall_nr = 257;
    entry.syscall_name = "openat".into();
    entry.args = Some([u64::MAX - 99, 0x1000, 0x80002 | (1 << 60), 0, 0, 0]);
    entry.fields.push(antinomie_monitor_core::FieldSummary {
        object_id: 1,
        key: "path".into(),
        layout: "char[]".into(),
        logical_len: Some(20),
        captured_len: 20,
        status: Some(0),
        capture_error: 0,
        complete: true,
        preview: b"/tmp/native-fixture\0".to_vec(),
        raw_path: None,
        ranges: vec![(0, 20)],
    });
    let mut exit = entry.clone();
    exit.phase = 2;
    exit.args = None;
    exit.result = Some(3);
    std::fs::write(
        fixture.0.join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({"run":saved,"terminal_rows":4,"terminal_cols":40}))
            .expect("manifest"),
    )
    .expect("write manifest");
    std::fs::write(
        fixture.0.join("events.json"),
        serde_json::to_vec(&vec![entry.clone(), exit.clone()]).expect("events"),
    )
    .expect("write events");
    let mut raw = Vec::new();
    for event in [entry, exit] {
        for fragment in [1, 5] {
            let mut body = vec![0; if fragment == 1 { 120 } else { 32 }];
            if fragment == 1 {
                if let Some(args) = event.args {
                    for (index, value) in args.iter().enumerate() {
                        body[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
                    }
                    body[48] = 4;
                }
                if let Some(result) = event.result {
                    body[49] = 1;
                    body[56..64].copy_from_slice(&result.to_le_bytes());
                }
            }
            let mut packet = vec![0; 136];
            packet[..4].copy_from_slice(b"ANTT");
            packet[4..6].copy_from_slice(&1u16.to_le_bytes());
            packet[6..8].copy_from_slice(&1u16.to_le_bytes());
            packet[8..10].copy_from_slice(&136u16.to_le_bytes());
            packet[10..12].copy_from_slice(&1u16.to_le_bytes());
            packet[12..16].copy_from_slice(&(136u32 + body.len() as u32).to_le_bytes());
            packet[20..24].copy_from_slice(&1u32.to_le_bytes());
            packet[24..32].copy_from_slice(&event.stream_id.to_le_bytes());
            packet[32..40].copy_from_slice(&event.task_cookie.to_le_bytes());
            packet[40..48].copy_from_slice(&event.call_id.to_le_bytes());
            packet[48..56]
                .copy_from_slice(&(event.event_seq + u64::from(event.phase)).to_le_bytes());
            packet[56..64].copy_from_slice(&(raw.len() as u64).to_le_bytes());
            packet[64..72].copy_from_slice(&event.timestamp_ns.to_le_bytes());
            packet[76..80].copy_from_slice(&event.tid.to_le_bytes());
            packet[88..96].copy_from_slice(&event.syscall_nr.to_le_bytes());
            packet[96..98].copy_from_slice(&1u16.to_le_bytes());
            packet[98] = event.phase;
            packet[99] = fragment;
            packet[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
            packet[128..136].copy_from_slice(&event.root_task_cookie.to_le_bytes());
            packet.extend(body);
            raw.extend((packet.len() as u32).to_le_bytes());
            raw.extend(packet);
        }
    }
    std::fs::write(fixture.0.join("telemetry.raw"), raw).expect("write raw recording");
    let output = b"SAVED TERMINAL HISTORY\r\n";
    let mut journal = vec![1];
    journal.extend((output.len() as u32).to_le_bytes());
    journal.extend(output);
    std::fs::write(fixture.0.join("terminal.journal"), journal).expect("write journal");
    std::fs::write(fixture.0.join("terminal-screen.ansi"), output).expect("write screen");
    let evidence = Arc::new(Mutex::new(Evidence::default()));
    let finish = Arc::clone(&evidence);
    eframe::run_native(
        "Antinomie Native QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 820.0]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            let mut app = app();
            app.selected = Some("vm".into());
            app.snapshot.active_vm = Some("vm".into());
            app.snapshot.state = VmState::Running;
            app.snapshot.vms = vec![
                VmConfig {
                    id: "vm".into(),
                    name: "Native workspace QA".into(),
                    ..VmConfig::default()
                },
                VmConfig {
                    id: "other-vm".into(),
                    name: "Other VM".into(),
                    ..VmConfig::default()
                },
            ];
            app.snapshot.runs = vec![first.clone(), second.clone()];
            app.snapshot.events = vec![event(1, 0)];
            app.history = vec![saved];
            let mut a = RunTerminal::new(first);
            a.terminal.process(b"TERMINAL A RETAINED\r\n$ ");
            app.terminals.insert(a.run.id.clone(), a);
            let mut b = RunTerminal::new(second);
            b.terminal.process(b"TERMINAL B RETAINED\r\n$ ");
            app.terminals.insert(b.run.id.clone(), b);
            app.archive = Some(ArchiveWorker::new(None).expect("archive worker"));
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(120),
                evidence: finish,
            }))
        }),
    )
    .expect("native QA window");
    let evidence = evidence.lock().expect("QA evidence");
    assert_eq!(
        evidence.first, b"qa-a\r",
        "input must have one terminal-a owner"
    );
    assert_eq!(
        evidence.second, b"qa-b\r",
        "input must have one terminal-b owner"
    );
    assert!(
        evidence.archive_selected,
        "double-click saved history while live snapshot remains"
    );
    assert!(
        evidence.first_preserved && evidence.second_preserved,
        "panel moves and close/reopen preserve terminal parsers"
    );
}
