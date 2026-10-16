// SPDX-License-Identifier: MIT
//! Whole-run counts, independent of table visibility, filters and query pages.
use super::*;
use antinomie_monitor_core::analysis::detection::{Engine, State};

#[derive(Clone, Copy)]
enum Destination {
    Properties,
    Tasks,
    Findings,
    Opened,
    Reads,
    Changed,
    Ips,
    Hosts,
    Http,
    Dns,
    Detection(Engine),
}

fn metric(ui: &mut egui::Ui, title: &str, value: Option<u64>) -> bool {
    ui.add(egui::Label::new(title).wrap());
    let clicked = ui
        .add_enabled(
            value.is_some(),
            egui::Button::new(
                RichText::new(value.map_or("Unavailable".into(), |value| value.to_string()))
                    .strong(),
            )
            .frame(false),
        )
        .clicked();
    ui.end_row();
    clicked
}

pub(super) fn show(view: &mut TriageView, ui: &mut egui::Ui, input: &TriageInput<'_>) {
    let mut destination = None;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(input.archive.is_some(), egui::Button::new("Refresh"))
            .clicked()
        {
            view.refresh_requested = true;
        }
        if view.scan_rx.is_some() {
            ui.spinner();
        }
    });
    egui::ScrollArea::vertical()
        .id_salt("triage-summary")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if let Some(report) = input.analysis {
                ui.weak("Submitted executable");
                ui.add(egui::Label::new(RichText::new(&report.source_path).strong()).wrap());
                if let Some(sha256) = &report.specimen_sha256 {
                    ui.add(egui::Label::new(RichText::new(sha256).monospace()).wrap());
                }
            } else {
                ui.weak("No executable properties were retained for this run.");
            }
            if ui.button("Open properties").clicked() {
                destination = Some(Destination::Properties);
            }
            ui.separator();
            let Some(scan) = &view.scan else {
                ui.weak("Whole-run counts are not available yet.");
                if let Some(error) = &view.scan_error {
                    ui.add(egui::Label::new(RichText::new(error).color(theme::warn())).wrap());
                }
                return;
            };
            if scan.partial || !input.run_finished {
                ui.colored_label(
                    theme::warn(),
                    "Retained prefix · counts may be lower bounds",
                );
            }
            if let Some(error) = &scan.event_error {
                ui.add(egui::Label::new(RichText::new(error).color(theme::warn())).wrap());
            }
            let counts = &scan.counts;
            ui.strong("Activity");
            egui::Grid::new("triage-summary-activity")
                .num_columns(2)
                .max_col_width(ui.available_width() * 0.6)
                .spacing(egui::vec2(16.0, 5.0))
                .show(ui, |ui| {
                    for (title, value, target) in [
                        ("Syscalls", counts.calls, Destination::Tasks),
                        (
                            "Observed task identities",
                            scan.process.len() as u64,
                            Destination::Tasks,
                        ),
                        (
                            "Suspicious activity observations",
                            counts.findings,
                            Destination::Findings,
                        ),
                        ("Opened-file operations", counts.opened, Destination::Opened),
                        ("Read-file operations", counts.reads, Destination::Reads),
                        ("Changed-file groups", counts.changed, Destination::Changed),
                    ] {
                        if metric(ui, title, Some(value)) {
                            destination = Some(target);
                        }
                    }
                });
            ui.separator();
            ui.strong("Network");
            if let Some(warning) = &scan.network_warning {
                ui.add(egui::Label::new(RichText::new(warning).color(theme::warn())).wrap());
            }
            egui::Grid::new("triage-summary-network")
                .num_columns(2)
                .max_col_width(ui.available_width() * 0.6)
                .spacing(egui::vec2(16.0, 5.0))
                .show(ui, |ui| {
                    for (title, value, target) in [
                        (
                            "Capture frames",
                            scan.network_counts.map(|counts| counts.0),
                            Destination::Http,
                        ),
                        (
                            "Destination IPs",
                            scan.network_counts.map(|counts| counts.1),
                            Destination::Ips,
                        ),
                        (
                            "Observed hostnames",
                            scan.network_counts.map(|counts| counts.2),
                            Destination::Hosts,
                        ),
                        (
                            "HTTP/1 requests",
                            scan.network_counts.map(|_| counts.http),
                            Destination::Http,
                        ),
                        (
                            "DNS questions",
                            scan.network_counts.map(|_| counts.dns),
                            Destination::Dns,
                        ),
                    ] {
                        if metric(ui, title, value) {
                            destination = Some(target);
                        }
                    }
                });
            ui.weak("VM traffic · encrypted requests unavailable");
            ui.separator();
            ui.strong("Detection");
            egui::Grid::new("triage-summary-detection")
                .num_columns(2)
                .max_col_width(ui.available_width() * 0.6)
                .spacing(egui::vec2(16.0, 5.0))
                .show(ui, |ui| {
                    for (index, engine) in [Engine::Yara, Engine::Ids, Engine::Sigma]
                        .into_iter()
                        .enumerate()
                    {
                        ui.label(detection::name(engine));
                        let label = match &view.detection.results[index] {
                            None => "Not scanned".into(),
                            Some(Err(_)) => "Failed".into(),
                            Some(Ok(report)) => {
                                let state = match report.state {
                                    State::Complete => "Complete",
                                    State::Partial => "Partial",
                                    State::Unavailable => "Unavailable",
                                };
                                view.detection.counts[index].as_ref().map_or_else(
                                    || state.into(),
                                    |counts| {
                                        format!(
                                            "{} rules · {} occurrences · {state}",
                                            counts.rules, counts.occurrences
                                        )
                                    },
                                )
                            }
                        };
                        if ui
                            .add(egui::Button::new(label).wrap().frame(false))
                            .clicked()
                        {
                            destination = Some(Destination::Detection(engine));
                        }
                        ui.end_row();
                    }
                });
            ui.label(format!(
                "{} rule-supplied ATT&CK references",
                view.detection.references.len()
            ));
        });
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
            }
            Destination::Hosts => {
                view.section = Section::Network;
                view.network = NetTab::Hosts;
            }
            Destination::Http => {
                view.section = Section::Network;
                view.network = NetTab::Http;
            }
            Destination::Dns => {
                view.section = Section::Network;
                view.network = NetTab::Dns;
            }
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
    #[ignore = "requires owned isolated X11; synthetic Summary / Detection fixture"]
    fn native_summary_and_detection_fixture() {
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct Fixture {
            view: TriageView,
            deadline: Instant,
            detection: bool,
            _files: PacketSpool,
        }
        impl eframe::App for Fixture {
            fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading(if self.detection {
                        "Detection — synthetic fixture"
                    } else {
                        "Summary — synthetic fixture"
                    });
                    if self.detection {
                        self.view.detection.show(ui, self.view.scan.as_ref());
                    } else {
                        show(&mut self.view, ui, &TriageInput::empty());
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
                mitre: vec!["T1059.004".into()],
                count: 2,
                evidence: vec![Evidence::Call {
                    stream: 1,
                    cookie: 55,
                    call: 1,
                }],
                details: "Synthetic match for native layout review".into(),
            });
            view.detection.results[index] = Some(Ok(report));
            view.detection.rows(index);
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
                theme::text_size(&cc.egui_ctx, if width < 700.0 { 24.0 } else { 16.0 });
                Ok(Box::new(Fixture {
                    view,
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
            offsets: [20; 8],
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
        assert_eq!(scan.counts.findings, 3);
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
