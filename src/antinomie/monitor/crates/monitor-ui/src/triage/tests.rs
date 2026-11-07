// SPDX-License-Identifier: GPL-3.0-only
use super::*;
pub(super) use antinomie_triage::tests::*;

mod async_files;
mod async_previews;
mod layout;
mod scroll;
mod suspicious;
mod theme_switch;


#[test]
#[ignore = "requires X11 native rendering; synthetic triage evidence fixture"]
fn native_triage_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct Fixture {
        view: TriageView,
        deadline: Instant,
        details_width: f32,
    }
    impl eframe::App for Fixture {
        fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
            let ctx = &root.ctx().clone();
            self.view.show_report_dialog(ctx);
            egui::Panel::right("shared-details-fixture")
                .exact_size(self.details_width)
                .show(root, |ui| {
                    ui.heading("Details");
                    self.view.details(ui);
                });
            egui::CentralPanel::default().show(root, |ui| {
                ui.heading("Run triage — synthetic fixture");
                let _ = self.view.show(
                    ui,
                    TriageInput {
                        vm_id: Some("vm"),
                        boot_id: Some("boot"),
                        run_id: Some("run"),
                        ..TriageInput::empty()
                    },
                );
            });
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    // Cells keep the colours they are made with, so the theme comes first.
    if let Ok(name) = std::env::var("ANTINOMIE_QA_THEME") {
        let chosen = match name.as_str() {
            "light" => theme::Theme::Light,
            "blue" => theme::Theme::Blue,
            _ => theme::Theme::Dark,
        };
        theme::apply_theme(&egui::Context::default(), chosen);
    }
    let temp = PacketSpool::new().unwrap();
    let mut raw = Vec::new();
    write_rwx_calls(&mut raw, 0..3);
    std::fs::write(temp.directory.join("telemetry.raw"), raw).unwrap();
    let scene = std::env::var("ANTINOMIE_TRIAGE_QA_SCENE").unwrap_or_else(|_| "changed".into());
    let pcap = temp.directory.join("fixture.pcap");
    std::fs::write(
        &pcap,
        if scene == "http" {
            http_pcap()
        } else {
            dns_pcap()
        },
    )
    .unwrap();
    let mut scan =
        scan_archive(&temp.directory, Some(&pcap), false, &AtomicBool::new(false)).unwrap();
    let clock = Some(antinomie_monitor_core::HostClockAnchor {
        guest_ns: 0,
        host_us: 1_700_000_000_000_000,
    });
    scan.clock_anchor = clock;
    let mut calls = [
        path_call(1, 2, "open", 3, "/tmp/analysis-note.txt"),
        call(1, 0, "read", 5),
        call(1, 0, "read", 0),
        call(1, 18, "pwrite64", 2),
    ];
    calls[0].entry.as_mut().unwrap().args = Some([0, 2, 0, 0, 0, 0]);
    calls[1].entry.as_mut().unwrap().args = Some([3, 0, 5, 0, 0, 0]);
    calls[1]
        .exit
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg1.data", "", b"hello"));
    calls[2].entry.as_mut().unwrap().args = Some([3, 0, 5, 0, 0, 0]);
    calls[3].entry.as_mut().unwrap().args = Some([3, 0, 2, 1, 0, 0]);
    calls[3]
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg1.data", "", b"XY"));
    let mut state = FdState::default();
    let mut index = files::FileIndex::default();
    for (at, call) in calls.iter_mut().enumerate() {
        call.call_id = at as u64 + 1;
        for event in call.entry.iter_mut().chain(call.exit.iter_mut()) {
            event.call_id = call.call_id;
            event.timestamp_ns = at as u64 * 1_000_000_000;
        }
        let event = trace::representative(call).unwrap();
        remember_open(&mut state, call, event);
        // Opened rows are the index's own, in the Opened table's column order.
        for hit in file_category::classify(&state, call, event) {
            if hit.category.tab() == FileTab::Opened {
                scan.opened
                    .push(file_category::category_row(&state, call, event, hit));
                scan.counts.opened += 1;
            }
        }
        if let Some(row) = index.observe(&state, call, event, None) {
            scan.read.push(row);
        }
    }
    let (changes, activity) = index.finish_all();
    scan.file_changes = changes;
    scan.file_activity = Arc::new(activity);
    scan.changed = scan
        .file_changes
        .iter()
        .map(|change| change.row(clock))
        .collect();
    // Synthetic process tree and eBPF rows for the UI polish screenshots.
    if scene == "tree" {
        let mut calls = vec![
            call(1, FORK, "fork", 42),
            call(42, 59, "execve", 0),
            call(1, FORK, "fork", 43),
            call(43, 59, "execve", 0),
        ];
        for (at, call) in calls.iter_mut().enumerate() {
            call.call_id = at as u64 + 1;
        }
        scan.process = process_nodes(&calls);
        scan.suspicious = [
            ((1, 1), (4, rules::Tier::High)),
            ((42, 42), (2, rules::Tier::Medium)),
            ((43, 43), (1, rules::Tier::Low)),
        ]
        .into();
        if let Some(template) = scan.findings.first().cloned() {
            scan.findings.clear();
            for (pid, tier) in [
                (42, rules::Tier::High),
                (42, rules::Tier::Medium),
                (42, rules::Tier::Low),
                (42, rules::Tier::Info),
            ] {
                let mut finding = template.clone();
                finding.cells[1] = cell(tier.tag(), tier.tone(), false);
                for (key, value) in &mut finding.values {
                    match *key {
                        "process.pid" | "process.cookie" => *value = RowValue::Number(pid),
                        _ => {}
                    }
                }
                scan.findings.push(finding);
            }
        }
    }
    if scene == "bpf" {
        let mut load = call(1, 321, "bpf", 3);
        load.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        let mut filter = call(1, 317, "seccomp", 0);
        filter.entry.as_mut().unwrap().args = Some([1, 0, 0, 0, 0, 0]);
        let mut denied = call(1, 321, "bpf", -13);
        denied.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        let mut prctl = call(1, 157, "prctl", 0);
        prctl.entry.as_mut().unwrap().args = Some([22, 2, 0, 0, 0, 0]);
        for (at, call) in [&mut load, &mut filter, &mut denied, &mut prctl]
            .into_iter()
            .enumerate()
        {
            call.call_id = at as u64 + 1;
        }
        scan.bpf = page_notes(&[load, filter, denied, prctl]);
    }
    let mut view = TriageView::default();
    view.scan = Some(scan);
    view.last_refresh = Some(Instant::now());
    view.context_key = Some("vm\nboot\nrun\n".into());
    match scene.as_str() {
        "findings" => {
            view.section = Section::Process;
            view.process = ProcessTab::Suspicious;
        }
        "bpf" => view.section = Section::Bpf,
        "detection" => {
            view.section = Section::Detection;
            view.detection.qa_scene();
        }
        "opened" => {
            view.section = Section::Files;
            view.files = FileTab::Opened;
        }
        "read" => {
            view.section = Section::Files;
            view.files = FileTab::Read;
        }
        "changed" => {
            view.section = Section::Files;
            view.files = FileTab::Changed;
        }
        "history" => {
            view.section = Section::Files;
            view.files = FileTab::Changed;
            view.file_history.open_on("/tmp/analysis-note.txt");
            view.history_tab = true;
        }
        "reconstruct" | "reconstruct-gaps" | "reconstruct-text" => {
            let (activity, start) =
                file_activity::reconstruct_tests::scene(scene.trim_start_matches("reconstruct-"));
            let file = activity
                .files
                .iter()
                .find(|file| file.path == "/etc/crontab")
                .unwrap()
                .clone();
            view.file_history
                .preview(&file, start, scene == "reconstruct-text");
            view.scan.as_mut().unwrap().file_activity = Arc::new(activity);
            view.section = Section::Files;
            view.files = FileTab::Changed;
            view.history_tab = true;
        }
        "report" => {
            // The Export report dialog over the Summary.
            view.section = Section::Summary;
            view.report.open_for_screenshot(temp.directory.clone());
        }
        "http" => {
            view.section = Section::Network;
            view.new_tab = NewTab::Urls;
        }
        "domains" => {
            view.section = Section::Network;
            view.new_tab = NewTab::Domains;
        }
        "endpoints" => {
            view.section = Section::Network;
            view.new_tab = NewTab::Endpoints;
        }
        _ => {
            view.section = Section::Process;
        }
    }
    // ANTINOMIE_QA_SIZE = 1280x820 and ANTINOMIE_QA_THEME = dark | light | blue
    // are the screenshot controls; the width variable stays for the narrow QA.
    let size = std::env::var("ANTINOMIE_QA_SIZE").ok().and_then(|value| {
        let (w, h) = value.split_once('x')?;
        Some((w.parse::<u32>().ok()?, h.parse::<f32>().ok()?))
    });
    let width = size
        .map(|size| size.0)
        .or_else(|| {
            std::env::var("ANTINOMIE_TRIAGE_QA_WIDTH")
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
        })
        .unwrap_or(1280)
        .clamp(420, 1920);
    let height = size.map_or(880.0, |size| size.1);
    let palette = match std::env::var("ANTINOMIE_QA_THEME").as_deref() {
        Ok("light") => theme::Theme::Light,
        Ok("blue") => theme::Theme::Blue,
        _ => theme::Theme::Dark,
    };
    let font = if width < 700 { 24.0 } else { 16.0 };
    eframe::run_native(
        "Antinomie Triage QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([width as f32, height])
                .with_position([16.0, 16.0]),
            persist_window: false,
            persistence_path: Some(temp.directory.join("native-ui.ron")),
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11();
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            theme::apply_theme(&cc.egui_ctx, palette);
            theme::text_size(&cc.egui_ctx, font);
            let initial = view.scan.as_ref().and_then(|scan| match scene.as_str() {
                "changed" => scan.changed.first().cloned().map(|row| {
                    (
                        "triage-changed",
                        vec!["Time", "Path", "Process", "Diff count", "Evidence"],
                        row,
                    )
                }),
                "read" => scan.read.first().cloned().map(|row| {
                    (
                        "triage-read",
                        vec![
                            "Time",
                            "Path",
                            "Process",
                            "Transferred / content",
                            "Result",
                            "Evidence",
                        ],
                        row,
                    )
                }),
                "http" => scan
                    .http
                    .first()
                    .cloned()
                    .map(|row| ("triage-http", HTTP_HEADERS.to_vec(), row)),
                "bpf" => scan.bpf.first().map(|note| {
                    (
                        "triage-bpf",
                        vec!["Time", "Observation", "Outcome", "Evidence"],
                        bpf_row(note, scan.clock_anchor),
                    )
                }),
                "tree" => {
                    let mut row = vec![cell("PID 42 · TID 42 (main)", tone::text(), true)];
                    row[0].values = vec![
                        ("process.pid", RowValue::Number(42)),
                        ("process.cookie", RowValue::Number(42)),
                        ("process.suspicious", RowValue::Number(4)),
                    ];
                    Some(("triage-process", vec!["Process"], row))
                }
                "findings" => scan.findings.first().map(|finding| {
                    let mut row = finding.cells.clone();
                    row[0].values.clone_from(&finding.values);
                    (
                        "triage-findings",
                        vec![
                            "Rule",
                            "Severity",
                            "Process",
                            "Summary",
                            "Source",
                            "Time",
                            "Confidence",
                            "Evidence",
                            "Version",
                            "Outcome",
                        ],
                        row,
                    )
                }),
                _ => None,
            });
            if let Some((table_id, headers, row)) = initial {
                details::select(&cc.egui_ctx, table_id, &headers, &row);
                let selected = evidence_key(&row);
                cc.egui_ctx.data_mut(|data| {
                    data.insert_temp(egui::Id::new(("triage-selected-row", table_id)), selected)
                });
            }
            Ok(Box::new(Fixture {
                view,
                deadline: Instant::now() + Duration::from_secs(10),
                details_width: (width as f32 * 0.38).min(420.0),
            }))
        }),
    )
    .unwrap();
}

#[test]
fn evidence_navigation_uses_stream_task_and_call_identity() {
    let context = egui::Context::default();
    let values = [
        ("stream.id", RowValue::Number(7)),
        ("process.cookie", RowValue::Number(9)),
        ("event.id", RowValue::Number(1)),
    ];
    request_evidence_jump(&context, &values);
    assert_eq!(
        context.data_mut(
            |data| data.remove_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump"))
        ),
        Some((7, 9, 1))
    );
    let first = call(9, 0, "read", 1);
    let other = call(10, 0, "read", 1);
    let query = query::compile_note("stream.id == 1 && process.cookie == 9 && call.id == 1");
    assert!(query.error.is_none());
    assert!(query.keep(&first));
    assert!(!query.keep(&other));
    request_evidence_jump(&context, &[("frame.number", RowValue::Number(520))]);
    assert_eq!(
        context.data_mut(|data| data.remove_temp::<u64>(egui::Id::new("triage-packet-jump"))),
        Some(520)
    );
}

#[test]
fn double_click_table_text_requests_its_exact_evidence() {
    for packet in [false, true] {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut c = cell("click this evidence", tone::text(), false);
        c.values = if packet {
            vec![("frame.number", RowValue::Number(520))]
        } else {
            vec![
                ("stream.id", RowValue::Number(7)),
                ("process.cookie", RowValue::Number(9)),
                ("event.id", RowValue::Number(1)),
            ]
        };
        let rows = vec![vec![c]];
        let draw = |events, time| {
            ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 600.0),
                    )),
                    events,
                    time: Some(time),
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        table(ui, "pointer-evidence", &["Evidence"], &rows)
                    });
                },
            )
        };
        for n in 0..3 {
            draw(vec![], f64::from(n) * 0.01);
        }
        let out = draw(vec![], 0.04);
        let pos = crate::app::tests::texts(&out)
            .into_iter()
            .find(|(text, _)| text == "click this evidence")
            .unwrap()
            .1
            .center();
        for (index, pressed) in [true, false, true, false].into_iter().enumerate() {
            draw(
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                0.1 + index as f64 * 0.05,
            );
        }
        if packet {
            assert_eq!(
                ctx.data(|data| data.get_temp::<u64>(egui::Id::new("triage-packet-jump"))),
                Some(520)
            );
        } else {
            assert_eq!(
                ctx.data(
                    |data| data.get_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump"))
                ),
                Some((7, 9, 1))
            );
        }
    }
}

#[test]
fn hidden_tick_indexes_once_a_shown_pane_refreshes_growth_preserves_selection_and_rejects_prior_run(
) {
    fn input<'a>(archive: &'a Path, run: &'a str) -> TriageInput<'a> {
        TriageInput {
            analysis: None,
            invocations: &[],
            vm_id: Some("vm"),
            boot_id: Some("boot"),
            run_id: Some(run),
            archive: Some(archive),
            pcap: None,
            pcap_open: false,
            clock_anchor: None,
            started_ms: None,
            root_cookie: 55,
            run_finished: false,
            current_boot: false,
        }
    }
    fn wait(view: &mut TriageView, ctx: &egui::Context, archive: &Path, run: &str, count: u64) {
        // Only a bound on a hang; the refresh timer runs on the view's clock.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            // Intentionally never call show: another panel owns the workspace.
            view.clock.advance(Duration::from_secs(1));
            view.tick(ctx, input(archive, run));
            // The calls of one task fold into one row: growth shows in the call count.
            if view
                .scan
                .as_ref()
                .is_some_and(|scan| scan.counts.calls == count && scan.findings.len() == 1)
                && view.scan_rx.is_none()
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "hidden index stalled: expected {count}; error {:?}; findings {:?}; calls {:?}; pending {}; generation {}",
                view.scan_error,
                view.scan.as_ref().map(|scan| scan.findings.len()),
                view.scan.as_ref().map(|scan| scan.counts.calls),
                view.scan_rx.is_some(),
                view.scan_generation
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let first = PacketSpool::new().unwrap();
    let second = PacketSpool::new().unwrap();
    let mut raw = std::fs::File::create(first.directory.join("telemetry.raw")).unwrap();
    write_rwx_calls(&mut raw, 0..1);
    raw.sync_all().unwrap();
    let ctx = egui::Context::default();
    let mut view = TriageView::default();
    view.refresh_seconds = 1;
    view.scan_request.filters[0] = "finding.rule == \"memory.rwx\"".into();
    wait(&mut view, &ctx, &first.directory, "first", 1);
    view.selected_call_id = Some((1, 55, 0));
    let first_refresh = view.last_refresh.unwrap();
    write_rwx_calls(&mut raw, 1..2);
    raw.sync_all().unwrap();
    // Hidden, a live run keeps the index it has: the pane refreshes it when shown.
    let generation = view.scan_generation;
    for _ in 0..3 {
        view.clock.advance(Duration::from_secs(1));
        view.tick(&ctx, input(&first.directory, "first"));
    }
    assert_eq!(view.scan_generation, generation, "re-indexed while hidden");
    view.mark_shown(&ctx);
    wait(&mut view, &ctx, &first.directory, "first", 2);
    assert!(view.last_refresh.unwrap() > first_refresh);
    assert_eq!(view.selected_call_id, Some((1, 55, 0)));
    assert_eq!(
        view.scan_request.filters[0],
        "finding.rule == \"memory.rwx\""
    );
    // Hold a completed worker reply to exercise refresh pressure deterministically.
    view.refresh_requested = true;
    view.ensure_scan(
        Some(&first.directory),
        None,
        false,
        Some("vm"),
        Some("boot"),
        Some("first"),
    );
    let actual = view.scan_rx.take().unwrap();
    let (held_tx, held_rx) = mpsc::channel();
    view.scan_rx = Some(held_rx);
    let generation = view.scan_generation;
    for _ in 0..100 {
        view.refresh_requested = true;
        view.tick(&ctx, input(&first.directory, "first"));
        assert_eq!(view.scan_generation, generation);
    }
    assert!(view.refresh_queued);
    held_tx
        .send(actual.recv_timeout(Duration::from_secs(60)).unwrap())
        .unwrap();
    view.tick(&ctx, input(&first.directory, "first"));
    assert_eq!(view.scan_generation, generation + 1);
    let stale_cancel = Arc::clone(view.scan_cancel.as_ref().unwrap());
    let mut other = std::fs::File::create(second.directory.join("telemetry.raw")).unwrap();
    write_rwx_calls(&mut other, 7..8);
    other.sync_all().unwrap();
    view.tick(&ctx, input(&second.directory, "second"));
    assert!(stale_cancel.load(Ordering::Relaxed));
    assert!(view.scan.is_none());
    assert!(view.selected_call_id.is_none());
    wait(&mut view, &ctx, &second.directory, "second", 1);
    assert_eq!(view.scan.as_ref().unwrap().findings[0].call_id, 7);
}

#[test]
fn a_long_content_cell_shows_a_bounded_hover_and_keeps_the_full_value() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    crate::theme::text_size(&ctx, 22.0);
    let long = format!("4096 B: {}", "ELF\\x02\\x01".repeat(200));
    let rows = vec![vec![
        cell("12:00:00", tone::text(), true),
        cell("/tmp/sample", tone::text(), true),
        cell(long.clone(), tone::text(), true),
    ]];
    let headers = ["Time", "Path", "Transferred / content"];
    let draw = |events, time| {
        ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 600.0),
                )),
                events,
                time: Some(time),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default()
                    .show(root, |ui| table(ui, "triage-read", &headers, &rows));
            },
        )
    };
    fn shown(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
        fn all(shape: &egui::Shape, out: &mut Vec<(String, egui::Rect)>) {
            match shape {
                egui::Shape::Text(t) => {
                    out.push((t.galley.text().to_owned(), t.visual_bounding_rect()))
                }
                egui::Shape::Vec(v) => v.iter().for_each(|s| all(s, out)),
                _ => {}
            }
        }
        let mut out = Vec::new();
        output.shapes.iter().for_each(|s| all(&s.shape, &mut out));
        out
    }
    let first = draw(vec![], 0.0);
    let cell_rect = shown(&first)
        .into_iter()
        .find(|(text, _)| text.starts_with("4096 B:"))
        .unwrap()
        .1;
    let mut output = first;
    for frame in 0..40 {
        // A pointer reports a move once; egui 0.36 restarts the tooltip delay
        // on every repeated move event.
        output = draw(
            if frame == 0 {
                vec![egui::Event::PointerMoved(
                    cell_rect.left_center() + egui::vec2(30.0, 0.0),
                )]
            } else {
                Vec::new()
            },
            0.1 + f64::from(frame) * 0.05,
        );
    }
    let texts: Vec<_> = shown(&output)
        .into_iter()
        .filter(|(text, _)| text.starts_with("4096 B:"))
        .collect();
    assert!(texts.len() >= 2, "the cell and its hover text are drawn");
    for (text, rect) in &texts {
        assert!(
            text.chars().count() <= 240 + 30,
            "{} characters",
            text.chars().count()
        );
        assert!(rect.height() < 600.0, "hover box fits the window: {rect:?}");
    }
    assert_eq!(rows[0][2].text, long, "Details keeps the full value");
}

#[test]
fn every_filter_slot_draws_its_filter_bar() {
    // The Sessions slot once had no table id, so its filter bar indexed past
    // the end of the list and the Network › Sessions tab panicked.
    let ctx = egui::Context::default();
    let mut view = TriageView::default();
    for index in 0..SLOTS {
        let _ = ctx.run_ui(egui::RawInput::default(), |root| {
            egui::CentralPanel::default().show(root, |ui| {
                view.query_bar(
                    ui,
                    index,
                    network::TLS_FIELDS,
                    "session.alpn contains h2",
                    (0, 0),
                    Bar::Plain,
                );
            });
        });
    }
    assert_eq!(TABLE_IDS[SESSION_SLOT], "triage-sessions");
}