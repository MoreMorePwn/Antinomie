// SPDX-License-Identifier: GPL-3.0-only
//! Whole-run counts, independent of table visibility, filters and query pages.
use super::*;
use antinomie_monitor_core::analysis::detection::{Engine, State};
// The model of the Summary is in `antinomie_triage::summary`.
use antinomie_triage::summary::{indicators, insight, sample};
mod attack_list;
mod header;
mod panels;
mod relations;
mod report;
mod rows;
mod state;
mod thumb;

#[cfg(test)]
pub(super) use state::Mode as SummaryMode;
pub(super) use state::State as SummaryState;

/// The sentences of the Summary's Key findings, one per finding (LOW and
/// above, worst first, at most `limit`): "MEDIUM Waiting for chosen packets:
/// BPF on raw socket - pid 1352 (x2)". For the exported report.
pub(super) fn key_finding_lines(findings: &[Finding], limit: usize) -> Vec<String> {
    insight::key_findings(findings, limit)
        .1
        .into_iter()
        .map(|key| {
            let mut line = format!("{} {}", key.tier.tag().to_uppercase(), key.title);
            if !key.target.is_empty() {
                line.push_str(&format!(" - {}", key.target));
            }
            if key.pid != 0 {
                line.push_str(&format!(" (pid {})", key.pid));
            }
            if key.count > 1 {
                line.push_str(&format!(" x{}", key.count));
            }
            if !key.why.is_empty() {
                line.push_str(&format!(". {}", key.why.trim_end_matches('.')));
            }
            line
        })
        .collect()
}

/// The Summary's Key findings for the exported report: (place in `findings`,
/// tier tag, rule, title, object, pid, cookie, executable, count, first ns,
/// why), worst first, at most `limit`, and how many there are in all.
pub(super) fn key_findings_for_report(
    findings: &[Finding],
    limit: usize,
) -> (usize, Vec<KeyFindingRow>) {
    let (total, keys) = insight::key_findings(findings, limit);
    let rows = keys
        .into_iter()
        .map(|key| KeyFindingRow {
            index: key.index,
            tier: key.tier.tag().to_owned(),
            rule: key.rule,
            title: key.title,
            target: key.target,
            pid: key.pid,
            cookie: key.cookie,
            exe: key.exe,
            count: key.count,
            first_ns: key.first_ns,
            why: key.why,
        })
        .collect();
    (total, rows)
}

/// One of [`key_findings_for_report`].
pub(super) struct KeyFindingRow {
    pub index: usize,
    pub tier: String,
    pub rule: String,
    pub title: String,
    pub target: String,
    pub pid: u32,
    pub cookie: u64,
    pub exe: String,
    pub count: u64,
    pub first_ns: u64,
    pub why: String,
}

/// How many findings each tier has (high, medium, low, info), hidden ones left
/// out, as the Summary's tier chips count them.
pub(super) fn tier_counts(findings: &[Finding]) -> [u64; 4] {
    let mut counts = [0u64; 4];
    for finding in findings {
        if let Some(tier) = insight::tier_of(finding) {
            let hidden = finding.values.iter().any(|(name, value)| {
                *name == "finding.hidden" && matches!(value, RowValue::Bool(true))
            });
            if !hidden {
                counts[tier.index()] += 1;
            }
        }
    }
    counts
}

/// What the app knows about the run that Triage does not read from the
/// recording: the base image's name and the run's last screenshot.
#[derive(Clone, Default)]
pub(super) struct RunFacts {
    pub base: Option<String>,
    pub screenshot: Option<std::path::PathBuf>,
}

/// What a click in the Summary asks for, applied once the frame is drawn.
enum Act {
    Go(Destination),
    /// Suspicious activity with only this tier.
    Tier(rules::Tier),
    /// The finding at this place in the scan's findings: its Details.
    Finding(usize),
    Process((u32, u64)),
    File,
    Endpoint,
    /// A double click on a Key finding: the call that made it.
    Evidence(usize),
    ExportIndicators,
    Screenshot(std::path::PathBuf),
}

#[derive(Clone, Copy)]
enum Destination {
    Tasks,
    Findings,
    Graph,
    Changed,
    Executed,
    Ips,
    Http,
    Dns,
    Ioc,
    Detection(Engine),
}

pub(super) fn show(view: &mut TriageView, ui: &mut egui::Ui, input: &TriageInput<'_>) {
    let destination = report::content(view, ui, input);
    if let Some(jump) = view.attack_jump.take() {
        match jump {
            attack::Jump::Suspicious(id) => {
                view.section = Section::Process;
                view.process = ProcessTab::Suspicious;
                view.filter_findings_by_technique(ui.ctx(), &id);
            }
            attack::Jump::Detection(engine, id) => {
                view.section = Section::Detection;
                view.detection.focus_technique(&engine, &id);
            }
            attack::Jump::Calls(id) => {
                if let Some(finding) = view.technique_finding(&id) {
                    request_evidence_jump(ui.ctx(), &finding.values);
                }
            }
        }
    }
    if let Some(destination) = destination {
        view.go_to(ui.ctx(), destination);
    }
}

impl TriageView {
    /// Open the section a Summary click leads to.
    fn go_to(&mut self, ctx: &egui::Context, destination: Destination) {
        match destination {
            Destination::Tasks => {
                self.section = Section::Process;
                self.process = ProcessTab::Tree;
            }
            Destination::Findings => {
                self.section = Section::Process;
                self.process = ProcessTab::Suspicious;
            }
            Destination::Graph => {
                self.section = Section::Process;
                self.process = ProcessTab::Graph;
                self.clear_finding_filters(ctx);
            }
            Destination::Changed => {
                self.section = Section::Files;
                self.files = FileTab::Changed;
                self.history_tab = false;
                self.by_file = false;
            }
            Destination::Executed => {
                self.section = Section::Files;
                self.files = FileTab::Executed;
                self.history_tab = false;
                self.by_file = false;
            }
            Destination::Ips => {
                self.section = Section::Network;
                self.new_tab = NewTab::Endpoints;
            }
            Destination::Http => {
                self.section = Section::Network;
                self.new_tab = NewTab::Urls;
            }
            Destination::Dns => {
                self.section = Section::Network;
                self.new_tab = NewTab::Domains;
            }
            Destination::Ioc => self.section = Section::Ioc,
            Destination::Detection(engine) => {
                self.section = Section::Detection;
                self.detection.selected = engine;
            }
        }
    }

    /// Carry out a click of the Summary that needs the whole view.
    fn apply_act(&mut self, ctx: &egui::Context, act: Act, destination: &mut Option<Destination>) {
        match act {
            Act::Go(target) => *destination = Some(target),
            Act::Tier(tier) => {
                self.clear_finding_filters(ctx);
                self.toggle_tier_chip(tier);
                *destination = Some(Destination::Findings);
            }
            Act::Finding(index) => {
                let Some(finding) = self.scan.as_ref().and_then(|scan| scan.findings.get(index))
                else {
                    return;
                };
                let mut cells = finding.cells.clone();
                if let Some(first) = cells.first_mut() {
                    first.values.clone_from(&finding.values);
                }
                details::select(ctx, "triage-findings", rules::HEADERS, &cells);
                details::clicked(ctx, "triage-findings");
            }
            Act::Evidence(index) => {
                if let Some(finding) = self.scan.as_ref().and_then(|scan| scan.findings.get(index))
                {
                    request_evidence_jump(ctx, &finding.values);
                }
            }
            Act::Process((pid, cookie)) => {
                self.section = Section::Process;
                self.process = ProcessTab::Tree;
                process_details::open_process(self, ctx, pid, cookie);
                details::clicked(ctx, "triage-process");
            }
            Act::File => *destination = Some(Destination::Changed),
            Act::Endpoint => *destination = Some(Destination::Ips),
            Act::ExportIndicators => self.export_indicators(ctx),
            Act::Screenshot(path) => self.summary_state.open_screenshot = Some(path),
        }
    }

    /// Write the Summary's indicators as JSON beside the run's files.
    fn export_indicators(&mut self, ctx: &egui::Context) {
        let (Some(dir), Some(built)) = (
            self.details_directory.clone(),
            self.summary_state.built.as_ref(),
        ) else {
            self.summary_state.status = Some("This run has no folder to write to.".into());
            return;
        };
        let run = dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = crate::export_dirs::stamped("indicators", &run, "json");
        self.summary_state.status = Some(
            match write_new(&dir.join("ioc"), &name, built.indicators.json().as_bytes()) {
                Ok(path) => {
                    crate::export_dirs::reported(ctx, "Indicators", &path);
                    format!(
                        "Exported {} indicators to {}",
                        built.indicators.total(),
                        path.display()
                    )
                }
                Err(error) => error,
            },
        );
    }

    /// The run's last screenshot was clicked in the Summary.
    pub(crate) fn take_open_screenshot(&mut self) -> Option<std::path::PathBuf> {
        self.summary_state.open_screenshot.take()
    }

    /// The base image and last screenshot of the selected run.
    pub(crate) fn set_run_facts(
        &mut self,
        base: Option<String>,
        screenshot: Option<std::path::PathBuf>,
    ) {
        if self.run_facts.base != base || self.run_facts.screenshot != screenshot {
            self.run_facts = RunFacts { base, screenshot };
        }
    }
}

/// Create `dir/name` (private, never replacing a file) and write `bytes`.
fn write_new(
    dir: &std::path::Path,
    name: &str,
    bytes: &[u8],
) -> Result<std::path::PathBuf, String> {
    use std::{
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|error| format!("{}: {error}", dir.display()))?;
    let path = dir.join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod ui_tests;

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
            ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1100.0, 3000.0),
                    )),
                    time: Some(time),
                    events,
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        show(&mut view, ui, &TriageInput::empty());
                    });
                },
            )
        };
        draw(vec![], 0.0);
        let output = draw(vec![], 0.01);
        let position = crate::app::tests::texts(&output)
            .into_iter()
            .find(|(text, _)| text == rules::rule_title("memory.rwx"))
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
    fn summary_names_the_runs_network_route_and_old_runs_read_not_recorded() {
        let files = PacketSpool::new().unwrap();
        let mut raw = std::fs::File::create(files.directory.join("telemetry.raw")).unwrap();
        super::super::tests::write_rwx_calls(&mut raw, 0..1);
        raw.sync_all().unwrap();
        let scan = scan_archive(&files.directory, None, false, &AtomicBool::new(false)).unwrap();
        let mut view = TriageView::default();
        view.scan = Some(scan);
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let draw = |view: &mut TriageView| {
            let mut texts = Vec::new();
            for time in [0.0, 0.01] {
                let output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1100.0, 3000.0),
                        )),
                        time: Some(time),
                        ..Default::default()
                    },
                    |root| {
                        egui::CentralPanel::default().show(root, |ui| {
                            show(view, ui, &TriageInput::empty());
                        });
                    },
                );
                texts = crate::app::tests::texts(&output);
            }
            texts
        };
        // A view nobody has told the route yet reads as not recorded.
        let before = draw(&mut view);
        assert!(
            before.iter().any(|(t, _)| t.contains("route not recorded")),
            "{before:?}"
        );
        let route = antinomie_monitor_core::route::RouteRecord {
            kind: antinomie_monitor_core::route::RouteKind::Tor,
            label: "Tor via 127.0.0.1:9050".into(),
            via: antinomie_monitor_core::route::RouteVia::Gateway,
            checked_ms: Some(1),
            stats: None,
            blocked_ports: Vec::new(),
        };
        view.set_route_text(crate::route_ui::describe(Some(&route), None));
        let after = draw(&mut view);
        assert!(
            after
                .iter()
                .any(|(t, _)| t.contains("route Tor via 127.0.0.1:9050")),
            "{after:?}"
        );
        assert!(!after.iter().any(|(t, _)| t.contains("route not recorded")));
    }

    #[test]
    fn run_notes_are_listed_in_a_notes_section_at_the_bottom_of_the_summary() {
        let files = PacketSpool::new().unwrap();
        let mut raw = std::fs::File::create(files.directory.join("telemetry.raw")).unwrap();
        super::super::tests::write_rwx_calls(&mut raw, 0..1);
        raw.sync_all().unwrap();
        let scan = scan_archive(&files.directory, None, false, &AtomicBool::new(false)).unwrap();
        let mut view = TriageView::default();
        view.scan = Some(scan);
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let draw = |view: &mut TriageView| {
            let mut texts = Vec::new();
            for time in [0.0, 0.01] {
                let output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1100.0, 3000.0),
                        )),
                        time: Some(time),
                        ..Default::default()
                    },
                    |root| {
                        egui::CentralPanel::default().show(root, |ui| {
                            show(view, ui, &TriageInput::empty());
                        });
                    },
                );
                texts = crate::app::tests::texts(&output);
            }
            texts
        };
        let bare = draw(&mut view);
        assert!(
            !bare.iter().any(|(t, _)| t == "Notes"),
            "no notes, no section"
        );
        let note = "Cloud metadata service is off: it needs a Routed network. Set Network to Routed to turn it on.";
        view.set_notes(vec![note.to_owned()]);
        let shown = draw(&mut view);
        let y = |wanted: &str| {
            shown
                .iter()
                .find(|(t, _)| t == wanted)
                .unwrap_or_else(|| panic!("{wanted} not shown: {shown:?}"))
                .1
                .min
                .y
        };
        assert!(y("Notes") > y("Open results"));
        assert!(y(note) > y("Notes"));
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
            fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
                let ctx = &root.ctx().clone();
                egui::CentralPanel::default().show(root, |ui| {
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
        let height = std::env::var("ANTINOMIE_PROPERTIES_QA_HEIGHT")
            .ok()
            .and_then(|value| value.parse::<f32>().ok())
            .unwrap_or(880.0)
            .clamp(420.0, 1600.0);
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
        view.set_notes(vec![
            "Cloud metadata service is off: it needs a Routed network. Set Network to Routed to turn it on."
                .into(),
            "Device profile setting not applied: Guest network 192.168.1.0/24 needs a base with DHCP (built by 0.7.0 or later); 10.0.2.0/24 is used instead; this base sets 10.0.2.15 itself"
                .into(),
        ]);
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
            layer: None,
            specimen_source: None,
            time_limit_seconds: None,
            limits: None,
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
                    .with_inner_size([width, height])
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
                theme::text_size(
                    &cc.egui_ctx,
                    theme::qa_text_size(if width < 700.0 { 24.0 } else { 16.0 }),
                );
                Ok(Box::new(Fixture {
                    view,
                    analysis,
                    deadline: Instant::now()
                        + Duration::from_secs(
                            std::env::var("ANTINOMIE_QA_SECONDS")
                                .ok()
                                .and_then(|seconds| seconds.parse().ok())
                                .unwrap_or(4),
                        ),
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
                let output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 880.0),
                        )),
                        ..Default::default()
                    },
                    |root| {
                        egui::CentralPanel::default().show(root, |ui| {
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
