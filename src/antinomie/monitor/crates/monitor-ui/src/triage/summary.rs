// SPDX-License-Identifier: GPL-3.0-only
//! Whole-run counts, independent of table visibility, filters and query pages.
use super::*;
use antinomie_monitor_core::analysis::detection::{Engine, State};
mod report;

#[derive(Clone, Copy)]
enum Destination {
    Properties,
    Tasks,
    Findings,
    Graph,
    Opened,
    Reads,
    Changed,
    Ips,
    Hosts,
    Http,
    Dns,
    Ioc,
    Detection(Engine),
}

fn metric(ui: &mut egui::Ui, title: &str, value: Option<u64>) -> bool {
    ui.add(egui::Label::new(title).wrap());
    let clicked = ui
        .add_enabled(
            value.is_some(),
            egui::Button::new(
                RichText::new(value.map_or("Unavailable".into(), |value| value.to_string()))
                    .strong()
                    .color(if value.is_some() {
                        theme::text()
                    } else {
                        theme::muted()
                    }),
            )
            .frame(false),
        )
        .clicked();
    ui.end_row();
    clicked
}

pub(super) fn show(view: &mut TriageView, ui: &mut egui::Ui, input: &TriageInput<'_>) {
    let destination = report::content(view, ui, input);
    if let Some(destination) = destination {
        match destination {
            Destination::Properties => view.section = Section::Properties,
            Destination::Tasks => {
                view.section = Section::Process;
                view.process = ProcessTab::Tree;
            }
            Destination::Findings => {
                view.section = Section::Process;
                view.process = ProcessTab::Suspicious;
            }
            Destination::Graph => {
                view.section = Section::Process;
                view.process = ProcessTab::Graph;
            }
            Destination::Opened => {
                view.section = Section::Files;
                view.files = FileTab::Opened;
            }
            Destination::Reads => {
                view.section = Section::Files;
                view.files = FileTab::Read;
            }
            Destination::Changed => {
                view.section = Section::Files;
                view.files = FileTab::Changed;
            }
            Destination::Ips => {
                view.section = Section::Network;
                view.network = NetTab::Ips;
                view.new_tab = NewTab::Endpoints;
            }
            Destination::Hosts => {
                view.section = Section::Network;
                view.network = NetTab::Hosts;
                view.new_tab = NewTab::Domains;
            }
            Destination::Http => {
                view.section = Section::Network;
                view.network = NetTab::Http;
                view.new_tab = NewTab::Urls;
            }
            Destination::Dns => {
                view.section = Section::Network;
                view.network = NetTab::Dns;
                view.new_tab = NewTab::Domains;
            }
            Destination::Ioc => view.section = Section::Ioc,
            Destination::Detection(engine) => {
                view.section = Section::Detection;
                view.detection.selected = engine;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn summary_observation_opens_shared_details_and_exact_syscall_evidence() {
        let files = PacketSpool::new().unwrap();
        let mut raw = std::fs::File::create(files.directory.join("telemetry.raw")).unwrap();
        super::super::tests::write_rwx_calls(&mut raw, 0..1);
        raw.sync_all().unwrap();
        let scan = scan_archive(&files.directory, None, false, &AtomicBool::new(false)).unwrap();
        let expected = scan.findings[0].key;
        let mut view = TriageView::default();
        view.scan = Some(scan);
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut draw = |events, time| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1100.0, 1600.0),
                    )),
                    time: Some(time),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        show(&mut view, ui, &TriageInput::empty());
                    });
                },
            )
        };
        draw(vec![], 0.0);
        let output = draw(vec![], 0.01);
        let position = crate::app::tests::texts(&output)
            .into_iter()
            .find(|(text, _)| text == "memory.rwx")
            .expect("visible observation")
            .1
            .center();
        for (index, pressed) in [true, false, true, false].into_iter().enumerate() {
            draw(
                vec![
                    egui::Event::PointerMoved(position),
                    egui::Event::PointerButton {
                        pos: position,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                0.1 + index as f64 * 0.05,
            );
        }
        assert!(ctx
            .data(|data| data.get_temp::<bool>(egui::Id::new("triage-details-focus")))
            .unwrap_or(false));
        assert_eq!(
            ctx.data(
                |data| data.get_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump"))
            ),
            Some(expected)
        );
    }

    #[test]
    #[ignore = "requires owned isolated X11; synthetic Summary / Detection fixture"]
    fn native_summary_and_detection_fixture() {
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct Fixture {
            view: TriageView,
            analysis: antinomie_monitor_core::AnalysisReport,
            deadline: Instant,
            detection: bool,
            _files: PacketSpool,
        }
        impl eframe::App for Fixture {
            fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let input = TriageInput {
                        analysis: Some(&self.analysis),
                        run_finished: true,
                        ..TriageInput::empty()
                    };
                    presentation::navigation(&mut self.view, ui, &input);
                    if self.detection {
                        self.view.detection.show(ui, self.view.scan.as_ref());
                    } else {
                        show(&mut self.view, ui, &input);
                    }
                });
                if Instant::now() > self.deadline {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }
        let width = std::env::var("ANTINOMIE_PROPERTIES_QA_WIDTH")
            .ok()
            .and_then(|value| value.parse::<f32>().ok())
            .unwrap_or(900.0)
            .clamp(420.0, 1600.0);
        let detection = std::env::var("ANTINOMIE_TRIAGE_QA_SCENE").as_deref() == Ok("detection");
        let files = PacketSpool::new().unwrap();
        let mut raw = std::fs::File::create(files.directory.join("telemetry.raw")).unwrap();
        super::super::tests::write_rwx_calls(&mut raw, 0..3);
        raw.sync_all().unwrap();
        let mut scan =
            scan_archive(&files.directory, None, false, &AtomicBool::new(false)).unwrap();
        scan.network_counts = Some((641, 2, 3));
        scan.network_warning = None;
        scan.counts.http = 4;
        scan.counts.dns = 8;
        let mut view = TriageView::default();
        view.scan = Some(scan);
        view.section = if detection {
            Section::Detection
        } else {
            Section::Summary
        };
        let mut analysis = antinomie_monitor_core::AnalysisReport {
            id: "synthetic-artifact".into(),
            state: antinomie_monitor_core::AnalysisState::Complete,
            source_path: "/tmp/triage-sample".into(),
            specimen_sha256: Some("abcdef0123456789".repeat(4)),
            specimen_len: Some(85904),
            reason: None,
            sections: vec![],
        };
        use antinomie_monitor_core::analysis::detection::{Evidence, Finding, Identity, Report};
        let identity = Identity {
            vm_id: "synthetic".into(),
            boot_id: "fixture".into(),
            run_id: "sample".into(),
            root_cookie: 55,
        };
        for (index, engine) in [Engine::Yara, Engine::Ids, Engine::Sigma]
            .into_iter()
            .enumerate()
        {
            let mut report = Report::empty(engine, identity.clone());
            report.scanned_rules = Some(2096);
            report.scanned_objects = 1;
            report.findings.push(Finding {
                rule_id: "fixture.shell_execution".into(),
                title: "Shell execution observed".into(),
                severity: "informational".into(),
                source: "Synthetic fixture".into(),
                license: "MIT".into(),
                author: "Synthetic author".into(),
                mitre: vec!["T1059.004".into()],
                count: 2,
                evidence: vec![Evidence::Call {
                    stream: 1,
                    cookie: 55,
                    call: 1,
                }],
                events: vec![],
                details: "Synthetic match for native layout review".into(),
                rule_text: String::new(),
            });
            view.detection.results[index] = Some(Ok(report));
            view.detection.rows(index);
        }
        if let Some(path) = std::env::var_os("ANTINOMIE_TRIAGE_SAMPLE") {
            let path = std::path::PathBuf::from(path);
            let run: antinomie_monitor_core::RunSummary =
                serde_json::from_slice(&std::fs::read(path.join("run.json")).unwrap()).unwrap();
            analysis =
                antinomie_monitor_core::analysis::open_report(&path.join("analysis")).unwrap();
            let artifacts = antinomie_monitor_core::RunArtifacts::load(&path)
                .unwrap()
                .unwrap();
            let request = ScanRequest {
                root_cookie: run.root_task_cookie,
                clock_anchor: run.clock_anchor,
                started_ms: run.started_ms,
                run_finished: true,
                identity: Some((run.vm_id, run.boot_id, run.id)),
                ..Default::default()
            };
            view.scan = Some(
                scan_archive_query(
                    &path,
                    artifacts
                        .network_captures
                        .first()
                        .map(|path| path.as_path()),
                    false,
                    &Arc::new(AtomicBool::new(false)),
                    &request,
                )
                .unwrap(),
            );
            for (index, engine) in [Engine::Yara, Engine::Ids, Engine::Sigma]
                .into_iter()
                .enumerate()
            {
                let report: Report = serde_json::from_slice(
                    &std::fs::read(
                        antinomie_monitor_core::analysis::detection::result_directory(
                            &path, engine,
                        )
                        .join("report.json"),
                    )
                    .unwrap(),
                )
                .unwrap();
                view.detection.results[index] = Some(Ok(report));
                view.detection.rows(index);
            }
        }
        eframe::run_native(
            "Antinomie triage QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size([width, 880.0])
                    .with_position([16.0, 16.0]),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11();
                    builder.with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                theme::install(&cc.egui_ctx);
                theme::apply(
                    &cc.egui_ctx,
                    std::env::var_os("ANTINOMIE_TRIAGE_QA_LIGHT").is_some(),
                );
                theme::text_size(&cc.egui_ctx, if width < 700.0 { 24.0 } else { 16.0 });
                Ok(Box::new(Fixture {
                    view,
                    analysis,
                    deadline: Instant::now() + Duration::from_secs(4),
                    detection,
                    _files: files,
                }))
            }),
        )
        .unwrap();
    }
    #[test]
    fn summary_counts_do_not_depend_on_table_filters_or_pages_and_missing_network_is_unavailable() {
        let temp = PacketSpool::new().unwrap();
        let mut raw = std::fs::File::create(temp.directory.join("telemetry.raw")).unwrap();
        super::super::tests::write_rwx_calls(&mut raw, 0..3);
        raw.sync_all().unwrap();
        let request = ScanRequest {
            root_cookie: 55,
            offsets: [20; SLOTS],
            filters: std::array::from_fn(|_| String::new()),
            ..Default::default()
        };
        let mut request = request;
        request.filters[0] = "finding.rule == \"never\"".into();
        let scan = scan_archive_query(
            &temp.directory,
            None,
            false,
            &Arc::new(AtomicBool::new(false)),
            &request,
        )
        .unwrap();
        assert!(scan.findings.is_empty());
        assert_eq!(scan.counts.calls, 3);
        // The three calls of one task are one row.
        assert_eq!(scan.counts.findings, 1);
        assert!(scan.network_counts.is_none());
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut view = TriageView::default();
        view.scan = Some(scan);
        for width in [900.0, 480.0] {
            theme::text_size(&ctx, if width < 700.0 { 24.0 } else { 16.0 });
            for _ in 0..3 {
                let mut bounds = egui::Rect::NOTHING;
                let output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 880.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            show(&mut view, ui, &TriageInput::empty());
                            bounds = ui.min_rect();
                        });
                    },
                );
                assert!(
                    bounds.max.x <= width + 1.0 && bounds.max.y <= 881.0,
                    "{bounds:?}"
                );
                assert!(crate::app::tests::texts(&output)
                    .iter()
                    .any(|(text, _)| text == "Unavailable"));
            }
        }
    }
}
