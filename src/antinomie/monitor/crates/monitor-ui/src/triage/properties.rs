// SPDX-License-Identifier: MIT
//! Property jobs are isolated, on demand and tied to an exact run specimen.
use super::*;
use antinomie_monitor_core::analysis::properties::{self as engine, FileProperties};

type Identity = (std::path::PathBuf, String, Option<String>);

fn saved_properties(report: &antinomie_monitor_core::AnalysisReport) -> FileProperties {
    use antinomie_monitor_core::AnalysisKind;
    let metadata = report
        .sections
        .iter()
        .find(|section| section.kind == AnalysisKind::Metadata);
    let mut fields: Vec<_> = engine::LABELS
        .iter()
        .map(|label| engine::Property {
            label: (*label).into(),
            value: "Not computed".into(),
            available: false,
            source: "Saved report".into(),
        })
        .collect();
    for (index, len) in [(0, 32), (1, 40), (2, 64)] {
        let value = if index == 2 {
            report.specimen_sha256.as_deref()
        } else {
            metadata
                .and_then(|section| {
                    section
                        .entries
                        .iter()
                        .find(|entry| entry.label == engine::LABELS[index])
                })
                .map(|entry| entry.value.as_str())
        };
        if let Some(value) = value.filter(|value| {
            value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            fields[index].value = value.into();
            fields[index].available = true;
        }
    }
    if let Some(len) = report.specimen_len {
        fields[10].value = len.to_string();
        fields[10].available = true;
    }
    if let Some(section) = metadata {
        let kind = ["Format", "Object kind", "Architecture"]
            .iter()
            .filter_map(|label| section.entries.iter().find(|entry| entry.label == *label))
            .map(|entry| entry.value.chars().take(256).collect::<String>())
            .collect::<Vec<_>>()
            .join(" ");
        if !kind.is_empty() {
            fields[6].value = kind;
            fields[6].available = true;
        }
    }
    if let Some(magic) = report
        .sections
        .iter()
        .filter(|section| section.kind == AnalysisKind::Identification)
        .flat_map(|section| &section.entries)
        .find(|entry| entry.label == "format: file magic")
    {
        fields[7].value = magic.value.chars().take(4096).collect();
        fields[7].available = true;
    }
    for field in &mut fields {
        if field.available {
            field.source = "Saved analysis report; not reverified".into();
        }
    }
    FileProperties {
        report_id: report.id.clone(),
        source_path: report.source_path.clone(),
        sha256: report.specimen_sha256.clone().unwrap_or_default(),
        fields,
        warnings: vec![],
    }
}

#[derive(Default)]
pub(super) struct View {
    identity: Option<Identity>,
    result: Option<Result<FileProperties, String>>,
    rx: Option<Receiver<Result<FileProperties, String>>>,
    cancel: Option<Arc<AtomicBool>>,
}

impl View {
    pub fn reset(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        self.rx = None;
        self.result = None;
        self.identity = None;
    }

    pub fn tick(&mut self, ctx: &egui::Context, input: &TriageInput<'_>) {
        let identity = input
            .archive
            .zip(input.analysis)
            .map(|(directory, report)| {
                (
                    directory.join("analysis"),
                    report.id.clone(),
                    report.specimen_sha256.clone(),
                )
            });
        if self.identity != identity {
            self.reset();
            self.identity = identity;
        }
        let ready = self.rx.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Disconnected) => {
                Some(Err("Property worker ended without a result".into()))
            }
            Err(mpsc::TryRecvError::Empty) => None,
        });
        if let Some(result) = ready {
            self.result = Some(result);
            self.rx = None;
            self.cancel = None;
        }
        if self.rx.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn start(&mut self, ctx: &egui::Context) {
        let Some((directory, id, Some(_))) = self.identity.clone() else {
            return;
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (tx, rx) = mpsc::sync_channel(1);
        let ctx = ctx.clone();
        match std::thread::Builder::new()
            .name("triage-properties".into())
            .spawn(move || {
                let result = engine::run(&directory, &id, &worker_cancel);
                if tx.send(result).is_ok() {
                    ctx.request_repaint_of(egui::ViewportId::ROOT);
                }
            }) {
            Ok(_) => {
                self.rx = Some(rx);
                self.cancel = Some(cancel);
            }
            Err(error) => {
                self.result = Some(Err(format!("Could not start property analysis: {error}")))
            }
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) {
        let ready = self
            .identity
            .as_ref()
            .is_some_and(|identity| identity.2.is_some());
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    ready && self.rx.is_none(),
                    egui::Button::new("Refresh properties"),
                )
                .clicked()
            {
                self.result = None;
            }
            if let Some(directory) = input.archive.map(|directory| directory.join("analysis")) {
                if ui.button("Open result directory").clicked() {
                    crate::evidence::reveal(ui.ctx(), &directory);
                }
            }
            if self.rx.is_some() {
                ui.spinner();
                ui.label("Computing properties…");
            }
        });
        if ready && self.result.is_none() && self.rx.is_none() {
            self.start(ui.ctx());
        }
        if let Some(report) = input.analysis {
            ui.add(egui::Label::new(RichText::new(&report.source_path).monospace()).wrap());
            ui.weak(format!("Artifact {}", report.id));
        } else {
            ui.colored_label(theme::warn(), "This run has no retained executable. Enable static analysis before starting a new run.");
        }
        match &self.result {
            Some(Err(error)) => {
                ui.add(egui::Label::new(RichText::new(error).color(theme::warn())).wrap());
            }
            Some(Ok(result)) => {
                for warning in &result.warnings {
                    ui.add(egui::Label::new(RichText::new(warning).color(theme::warn())).wrap());
                }
            }
            _ if !ready && input.analysis.is_some() => {
                ui.weak("Waiting for complete executable acquisition.");
            }
            _ => {}
        }
        let saved = input.analysis.map(saved_properties);
        let result = self
            .result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .or(saved.as_ref());
        let width = (ui.available_width() - 130.0).max(100.0);
        egui::ScrollArea::vertical()
            .id_salt("triage-properties")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("triage-property-fields")
                    .num_columns(2)
                    .striped(true)
                    .spacing(egui::vec2(12.0, 8.0))
                    .max_col_width(width)
                    .show(ui, |ui| {
                        for label in engine::LABELS {
                            let field = result.and_then(|result| {
                                result.fields.iter().find(|field| field.label == *label)
                            });
                            ui.strong(*label);
                            ui.vertical(|ui| {
                                let value =
                                    field.map_or("Unavailable", |field| field.value.as_str());
                                let available = field.is_some_and(|field| field.available);
                                let response = ui.add(
                                    egui::Label::new(RichText::new(value).monospace().color(
                                        if available {
                                            theme::text()
                                        } else {
                                            theme::muted()
                                        },
                                    ))
                                    .wrap(),
                                );
                                if let Some(field) = field {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&field.source)
                                                .small()
                                                .color(theme::muted()),
                                        )
                                        .wrap(),
                                    );
                                }
                                response.context_menu(|ui| {
                                    if ui.button("Copy value").clicked() {
                                        ui.ctx().copy_text(value.into());
                                        ui.close_menu();
                                    }
                                    if let Some(result) = result {
                                        if ui.button("Copy properties as JSON").clicked() {
                                            if let Ok(json) = serde_json::to_string_pretty(result) {
                                                ui.ctx().copy_text(json);
                                            }
                                            ui.close_menu();
                                        }
                                    }
                                    if let Some(directory) =
                                        input.archive.map(|directory| directory.join("analysis"))
                                    {
                                        crate::evidence::menu(ui, &directory);
                                    }
                                });
                            });
                            ui.end_row();
                        }
                    });
            });
    }
}

impl Drop for View {
    fn drop(&mut self) {
        self.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_properties() -> (antinomie_monitor_core::AnalysisReport, FileProperties) {
        let report = antinomie_monitor_core::AnalysisReport {
            id: "synthetic-artifact".into(),
            state: antinomie_monitor_core::AnalysisState::Complete,
            source_path: "/usr/bin/long-application-name-for-the-selected-run".into(),
            specimen_sha256: Some("abcdef0123456789".repeat(4)),
            specimen_len: Some(129736),
            reason: None,
            sections: vec![],
        };
        let fields = engine::LABELS.iter().map(|label| engine::Property {
            label: (*label).into(),
            value: match *label {
                "MD5" => "abcdef0123456789".repeat(2),
                "SHA-1" => "abcdef0123".repeat(4),
                "SHA-256" => "abcdef0123456789".repeat(4),
                "File size" => "129736".into(),
                "Magic" => "ELF 64-bit LSB shared object, x86-64, dynamically linked, stripped".into(),
                "File type" => "Elf Dynamic X86_64".into(),
                "vhash" => "Provider-specific hash; local computation is unavailable. No online lookup is performed.".into(),
                _ => "Local tool is not installed".into(),
            },
            available: matches!(*label, "MD5" | "SHA-1" | "SHA-256" | "File size" | "Magic" | "File type"),
            source: "Local verified specimen".into(),
        }).collect();
        let result = FileProperties {
            report_id: report.id.clone(),
            source_path: report.source_path.clone(),
            sha256: report.specimen_sha256.clone().unwrap(),
            fields,
            warnings: vec![],
        };
        (report, result)
    }

    #[test]
    fn property_layout_wraps_hashes_and_stays_inside_normal_and_narrow_panes() {
        for width in [900.0, 480.0] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, if width < 700.0 { 24.0 } else { 16.0 });
            let (report, result) = fixture_properties();
            let mut view = View::default();
            for frame in 0..3 {
                let mut bounds = egui::Rect::NOTHING;
                let output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 880.0),
                        )),
                        time: Some(f64::from(frame) / 60.0),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            let input = TriageInput {
                                analysis: Some(&report),
                                archive: Some(Path::new("/fixture/run")),
                                ..TriageInput::empty()
                            };
                            view.tick(ctx, &input);
                            view.result = Some(Ok(result.clone()));
                            view.show(ui, &input);
                            bounds = ui.min_rect();
                        });
                    },
                );
                assert!(bounds.max.x <= width + 1.0, "width {width}: {bounds:?}");
                assert!(bounds.max.y <= 881.0, "height {width}: {bounds:?}");
                for shape in output.shapes {
                    if let egui::epaint::Shape::Text(text) = shape.shape {
                        assert!(
                            text.pos.x + text.galley.size().x <= width + 3.0,
                            "text overflow {width}: {}",
                            text.galley.job.text
                        );
                    }
                }
                assert!(view.rx.is_none());
            }
        }
    }
    #[test]
    #[ignore = "requires isolated X11; synthetic properties layout fixture"]
    fn native_properties_fixture() {
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct Fixture {
            view: View,
            report: antinomie_monitor_core::AnalysisReport,
            result: FileProperties,
            deadline: Instant,
        }
        impl eframe::App for Fixture {
            fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("Properties — synthetic fixture");
                    let input = TriageInput {
                        analysis: Some(&self.report),
                        archive: Some(Path::new("/fixture/run")),
                        ..TriageInput::empty()
                    };
                    self.view.tick(ctx, &input);
                    if self.view.result.is_none() {
                        self.view.result = Some(Ok(self.result.clone()));
                    }
                    self.view.show(ui, &input);
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
        let report = antinomie_monitor_core::AnalysisReport {
            id: "synthetic-artifact".into(),
            state: antinomie_monitor_core::AnalysisState::Complete,
            source_path: "/usr/bin/long-application-name-for-the-selected-run".into(),
            specimen_sha256: Some("abcdef0123456789".repeat(4)),
            specimen_len: Some(129736),
            reason: None,
            sections: vec![],
        };
        let fields = engine::LABELS.iter().map(|label| engine::Property { label: (*label).into(), value: match *label { "MD5" => "abcdef0123456789".repeat(2), "SHA-1" => "abcdef0123".repeat(4), "SHA-256" => "abcdef0123456789".repeat(4), "File size" => "129736".into(), "Magic" => "ELF 64-bit LSB shared object, x86-64, dynamically linked, stripped".into(), "File type" => "Elf Dynamic X86_64".into(), "vhash" => "Provider-specific hash; local computation is unavailable. No online lookup is performed.".into(), _ => "Local tool is not installed".into() }, available: matches!(*label, "MD5" | "SHA-1" | "SHA-256" | "File size" | "Magic" | "File type"), source: "Local verified specimen".into() }).collect();
        let result = FileProperties {
            report_id: report.id.clone(),
            source_path: report.source_path.clone(),
            sha256: report.specimen_sha256.clone().unwrap(),
            fields,
            warnings: vec![],
        };
        eframe::run_native(
            "Antinomie Properties QA",
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
                    view: View::default(),
                    report,
                    result,
                    deadline: Instant::now() + Duration::from_secs(4),
                }))
            }),
        )
        .unwrap();
    }
    #[test]
    fn run_change_cancels_and_discards_a_previous_property_reply() {
        let ctx = egui::Context::default();
        let report = antinomie_monitor_core::AnalysisReport {
            id: "first".into(),
            state: antinomie_monitor_core::AnalysisState::Complete,
            source_path: "/bin/a".into(),
            specimen_sha256: Some("a".repeat(64)),
            specimen_len: Some(1),
            reason: None,
            sections: vec![],
        };
        let mut view = View::default();
        let input = TriageInput {
            analysis: Some(&report),
            archive: Some(Path::new("/archive/run")),
            ..TriageInput::empty()
        };
        view.tick(&ctx, &input);
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel(1);
        view.cancel = Some(Arc::clone(&cancel));
        view.rx = Some(rx);
        view.tick(&ctx, &TriageInput::empty());
        assert!(cancel.load(Ordering::Relaxed));
        assert!(tx.send(Err("old worker result".into())).is_err());
        assert!(view.result.is_none());
    }

    #[test]
    fn saved_hash_and_size_remain_available_when_reverification_is_unavailable() {
        let (report, _) = fixture_properties();
        let saved = saved_properties(&report);
        assert!(saved.fields[2].available);
        assert_eq!(saved.fields[2].value, report.specimen_sha256.unwrap());
        assert_eq!(saved.fields[10].value, "129736");
        assert!(!saved.fields[0].available);
        assert!(saved.fields[2].source.contains("not reverified"));
    }
}
