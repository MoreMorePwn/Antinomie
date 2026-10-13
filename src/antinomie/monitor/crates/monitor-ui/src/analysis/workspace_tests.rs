use super::*;
use antinomie_monitor_core::{
    AnalysisAddressKind, AnalysisLocation, AnalysisRange, AnalysisRecord, AnalysisSectionState,
};

fn fixture() -> AnalysisReport {
    let mut report = AnalysisReport {
        id: "workspace-fixture".into(),
        state: AnalysisState::Partial,
        source_path: "/fixture/synthetic-object".into(),
        specimen_sha256: None,
        specimen_len: Some(65536),
        reason: Some("Synthetic UI evidence; no analyzer was run".into()),
        sections: Vec::new(),
    };
    let mut structures = vec![AnalysisEntry {
        label: "Format".into(),
        value: "ELF64 (synthetic)".into(),
        offset: None,
        record: Some(AnalysisRecord {
            revision: 1,
            id: 1,
            location: None,
            data: AnalysisData::Field {
                group: "Headers".into(),
            },
        }),
    }];
    for index in 0..20 {
        let offset = index * 256;
        structures.push(AnalysisEntry {
            label: format!("section {index}"),
            value: "Synthetic section evidence".into(),
            offset: Some(offset),
            record: Some(AnalysisRecord {
                revision: 1,
                id: index + 2,
                location: Some(AnalysisLocation {
                    kind: AnalysisAddressKind::ObjectAddress,
                    value: 0x400000 + offset,
                    file_range: Some(AnalysisRange { offset, len: 256 }),
                }),
                data: AnalysisData::Section {
                    name: format!(".fixture{index}"),
                    address: 0x400000 + offset,
                    virtual_size: 512,
                    file_size: Some(256),
                    raw_flags: "0x6".into(),
                    flags: vec!["ALLOC".into(), "EXECINSTR".into()],
                },
            }),
        });
    }
    structures.push(AnalysisEntry {
        label: "puts".into(),
        value: "Undefined imported symbol".into(),
        offset: None,
        record: Some(AnalysisRecord {
            revision: 1,
            id: 100,
            location: None,
            data: AnalysisData::Import {
                name: Some("puts".into()),
                library: None,
                ordinal: None,
            },
        }),
    });
    report.sections.push(AnalysisSection {
        kind: AnalysisKind::Structures,
        state: AnalysisSectionState::Complete,
        summary: "Synthetic headers, section flags and import".into(),
        tools: Vec::new(),
        listing: None,
        entries: structures,
    });
    report.sections.push(AnalysisSection {
        kind: AnalysisKind::Strings,
        state: AnalysisSectionState::Partial,
        summary: "1024 retained synthetic strings; text bounded".into(),
        tools: Vec::new(),
        listing: None,
        entries: (0..1024)
            .map(|index| AnalysisEntry {
                label: format!("String {index}"),
                value: format!("fixture string {index}"),
                offset: Some(index * 32),
                record: Some(AnalysisRecord {
                    revision: 1,
                    id: index + 200,
                    location: Some(AnalysisLocation {
                        kind: AnalysisAddressKind::FileOffset,
                        value: index * 32,
                        file_range: Some(AnalysisRange {
                            offset: index * 32,
                            len: format!("fixture string {index}").len() as u64,
                        }),
                    }),
                    data: AnalysisData::String {
                        encoding: "ASCII".into(),
                        byte_len: format!("fixture string {index}").len() as u64,
                        retained_len: format!("fixture string {index}").len() as u64,
                    },
                }),
            })
            .collect(),
    });
    report.sections.push(AnalysisSection {
        kind: AnalysisKind::Rules,
        state: AnalysisSectionState::Unavailable,
        summary: "No rule engine is installed".into(),
        tools: Vec::new(),
        listing: None,
        entries: Vec::new(),
    });
    report
}

fn texts(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
    fn collect(shape: &egui::epaint::Shape, out: &mut Vec<(String, egui::Rect)>) {
        match shape {
            egui::epaint::Shape::Text(text) => out.push((
                text.galley.text().to_owned(),
                egui::Rect::from_min_size(text.pos, text.galley.size()),
            )),
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect(shape, out);
                }
            }
            _ => {}
        }
    }
    let mut result = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, &mut result);
    }
    result
}

fn render(
    ctx: &egui::Context,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    size: egui::Vec2,
    events: Vec<egui::Event>,
    preview: Option<&Result<AnalysisSpecimenPage, String>>,
) -> (egui::FullOutput, Option<ReportAction>) {
    let mut action = None;
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                action = workspace_section(
                    ui,
                    Some(report),
                    AnalysisKind::Strings,
                    state,
                    preview,
                    None,
                );
            });
        },
    );
    (output, action)
}

fn click(
    ctx: &egui::Context,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    size: egui::Vec2,
    pos: egui::Pos2,
) -> Option<ReportAction> {
    let mut action = None;
    for events in [
        vec![egui::Event::PointerMoved(pos)],
        vec![egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        }],
        vec![egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        }],
    ] {
        action = render(ctx, report, state, size, events, None).1.or(action);
    }
    action
}

#[test]
fn virtualized_rows_and_large_text_narrow_tabs_keep_selection_and_read_actions() {
    for (size, font) in [
        (egui::vec2(1280.0, 820.0), 18.0),
        (egui::vec2(800.0, 600.0), 24.0),
    ] {
        let report = fixture();
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        crate::theme::text_size(&ctx, font);
        let mut state = WorkspaceState::default();
        let mut output = render(&ctx, &report, &mut state, size, Vec::new(), None).0;
        for _ in 0..2 {
            output = render(&ctx, &report, &mut state, size, Vec::new(), None).0;
        }
        let shown = texts(&output);
        assert!(
            shown
                .iter()
                .filter(|(text, _)| text.starts_with("fixture string"))
                .count()
                < 40
        );
        let pos = shown
            .iter()
            .find(|(text, _)| text == "0x0")
            .expect("first virtualized row visible")
            .1
            .center();
        assert!(egui::Rect::from_min_size(egui::Pos2::ZERO, size).contains(pos));
        assert!(click(&ctx, &report, &mut state, size, pos).is_none());
        let view = state.views.get_mut("Strings/All").unwrap();
        assert_eq!(view.selected, Some((true, 200)));
        view.detail_tab = 2;
        let output = render(&ctx, &report, &mut state, size, Vec::new(), None).0;
        let pos = texts(&output)
            .into_iter()
            .find(|(text, _)| text.ends_with(" Bytes"))
            .expect("byte request control visible")
            .1
            .center();
        assert!(egui::Rect::from_min_size(egui::Pos2::ZERO, size).contains(pos));
        assert_eq!(
            click(&ctx, &report, &mut state, size, pos),
            Some(ReportAction::ReadSpecimen {
                report_id: report.id.clone(),
                offset: 0,
                data_len: 16
            })
        );
        assert!(
            render(&ctx, &report, &mut state, size, Vec::new(), None)
                .1
                .is_none(),
            "rendering does not resubmit reads"
        );
    }
}

#[test]
fn stale_preview_and_category_switch_cannot_replace_selected_evidence() {
    let report = fixture();
    let page = AnalysisSpecimenPage {
        report_id: report.id.clone(),
        offset: 0,
        total_len: 65536,
        data: vec![0; 16],
    };
    assert!(preview_matches(&page, &report, 0, 16));
    assert!(!preview_matches(&page, &report, 16, 16));
    let mut other = page.clone();
    other.report_id = "other-report".into();
    assert!(!preview_matches(&other, &report, 0, 16));
    let ctx = egui::Context::default();
    let mut state = WorkspaceState::default();
    state.bind(&report.id);
    state.active_view = Some("Structures/All".into());
    state.views.insert(
        "Strings/All".into(),
        ViewState {
            selected: Some((true, 200)),
            requested: Some((0, 16)),
            ..Default::default()
        },
    );
    render(
        &ctx,
        &report,
        &mut state,
        egui::vec2(800.0, 600.0),
        Vec::new(),
        Some(&Ok(page)),
    );
    assert!(state.views["Strings/All"].requested.is_none());
    assert_eq!(state.views["Strings/All"].selected, Some((true, 200)));
}

#[test]
fn export_controls_emit_report_scoped_actions_and_wrap_long_failure_reason() {
    let mut report = fixture();
    report.reason =
        Some("The worker retained partial evidence after its time budget expired. ".repeat(12));
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut state = WorkspaceState::default();
    let size = egui::vec2(800.0, 900.0);
    let mut output = render(&ctx, &report, &mut state, size, Vec::new(), None).0;
    for _ in 0..2 {
        output = render(&ctx, &report, &mut state, size, Vec::new(), None).0;
    }
    // Result panes reserve their height for evidence; the report warning belongs in Overview.
    assert!(!texts(&output)
        .iter()
        .any(|(text, _)| Some(text.as_str()) == report.reason.as_deref()));
    let mut overview_state = WorkspaceState::default();
    let mut overview_output = egui::FullOutput::default();
    for _ in 0..3 {
        overview_output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    workspace(ui, Some(&report), &mut overview_state, None, None);
                });
            },
        );
    }
    let reason = overview_output
        .shapes
        .iter()
        .find_map(|shape| match &shape.shape {
            egui::Shape::Text(text) if text.galley.text() == report.reason.as_deref().unwrap() => {
                Some(text)
            }
            _ => None,
        })
        .expect("full failure reason is rendered");
    assert!(
        reason.galley.rows.len() > 1,
        "failure reasons wrap instead of truncating"
    );
    let pos = texts(&output)
        .into_iter()
        .find(|(text, _)| text == "Open result directory")
        .unwrap()
        .1
        .center();
    assert_eq!(
        click(&ctx, &report, &mut state, size, pos),
        Some(ReportAction::ShowDirectory {
            report_id: report.id.clone()
        })
    );
    // Rendering produces UI values only and never launches an export or tool.
    assert!(render(&ctx, &report, &mut state, size, Vec::new(), None)
        .1
        .is_none());
}

#[test]
#[ignore = "native X11 workspace preview, synthetic evidence, exits automatically"]
fn native_analysis_workspace_fixture() {
    use std::time::{Duration, Instant};
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct FixtureApp {
        report: AnalysisReport,
        state: WorkspaceState,
        preview: Option<Result<AnalysisSpecimenPage, String>>,
        deadline: Instant,
    }
    impl eframe::App for FixtureApp {
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            egui::CentralPanel::default().show(ctx, |ui| {
                if let Some(action) = workspace(
                    ui,
                    Some(&self.report),
                    &mut self.state,
                    self.preview.as_ref(),
                    None,
                ) {
                    match action {
                        ReportAction::ReadSpecimen {
                            report_id,
                            offset,
                            data_len,
                        } => {
                            self.preview = Some(Ok(AnalysisSpecimenPage {
                                report_id,
                                offset,
                                total_len: 65536,
                                data: (0..data_len).map(|index| (index % 256) as u8).collect(),
                            }));
                        }
                        action => eprintln!("Synthetic workspace action: {action:?}"),
                    }
                }
            });
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    let small = std::env::var_os("ANTINOMIE_ANALYSIS_WORKSPACE_SMALL").is_some();
    let seconds = std::env::var("ANTINOMIE_ANALYSIS_QA_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(15)
        .clamp(1, 120);
    eframe::run_native(
        "Antinomie Analysis Workspace QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size(if small {
                [800.0, 600.0]
            } else {
                [1280.0, 820.0]
            }),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            crate::theme::install(&cc.egui_ctx);
            crate::theme::text_size(&cc.egui_ctx, if small { 24.0 } else { 18.0 });
            let report = fixture();
            let mut state = WorkspaceState::default();
            state.bind(&report.id);
            state.kind = Some(AnalysisKind::Structures);
            state.structure = Structure::Sections;
            state.active_view = Some("Structures/Sections".into());
            state.views.insert(
                "Structures/Sections".into(),
                ViewState {
                    selected: Some((true, 2)),
                    ..Default::default()
                },
            );
            Ok(Box::new(FixtureApp {
                report,
                state,
                preview: None,
                deadline: Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .unwrap();
}

#[test]
fn unfinished_analysis_shows_progress_until_it_completes() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut report = fixture();
    report.state = AnalysisState::Running;
    let mut entropy = AnalysisSection::new(AnalysisKind::Entropy);
    entropy.summary = "pending acquisition".into();
    report.sections.push(entropy);
    let mut state = WorkspaceState::default();
    let size = egui::vec2(1200.0, 800.0);
    let overview = |report: &AnalysisReport, state: &mut WorkspaceState| {
        let mut output = None;
        for _ in 0..3 {
            output = Some(ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        workspace(ui, Some(report), state, None, None);
                    });
                },
            ));
        }
        texts(&output.unwrap())
            .into_iter()
            .map(|(text, _)| text)
            .collect::<Vec<_>>()
    };
    let shown = overview(&report, &mut state);
    assert!(
        shown
            .iter()
            .any(|text| text == "Analysis in progress: Entropy"),
        "{shown:?}"
    );
    assert!(shown.iter().any(|text| text == "Running… / 0 rows"));
    assert!(shown
        .iter()
        .any(|text| text == &format!("{} Entropy", egui_phosphor::regular::HOURGLASS_MEDIUM)));
    let (output, _) = render(&ctx, &report, &mut state, size, Vec::new(), None);
    assert!(texts(&output)
        .iter()
        .any(|(text, _)| text == "Analysis in progress: Entropy"));

    report.state = AnalysisState::Complete;
    report.sections.last_mut().unwrap().state = AnalysisSectionState::Complete;
    let shown = overview(&report, &mut state);
    assert!(!shown
        .iter()
        .any(|text| text.starts_with("Analysis in progress")));
    assert!(!shown.iter().any(|text| text.starts_with("Running…")));
}
