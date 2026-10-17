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
    // Labels, not positions: the set of properties changes between versions.
    let mut set = |label: &str, value: &str| {
        if let Some(field) = fields.iter_mut().find(|field| field.label == label) {
            field.value = value.into();
            field.available = true;
        }
    };
    for (label, len) in [("MD5", 32), ("SHA-1", 40), ("SHA-256", 64)] {
        let value = if label == "SHA-256" {
            report.specimen_sha256.as_deref()
        } else {
            metadata
                .and_then(|section| section.entries.iter().find(|entry| entry.label == label))
                .map(|entry| entry.value.as_str())
        };
        if let Some(value) = value.filter(|value| {
            value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            set(label, value);
        }
    }
    if let Some(len) = report.specimen_len {
        set("File size", &len.to_string());
    }
    if let Some(section) = metadata {
        let kind = ["Format", "Object kind", "Architecture"]
            .iter()
            .filter_map(|label| section.entries.iter().find(|entry| entry.label == *label))
            .map(|entry| entry.value.chars().take(256).collect::<String>())
            .collect::<Vec<_>>()
            .join(" ");
        if !kind.is_empty() {
            set("File type", &kind);
        }
    }
    if let Some(magic) = report
        .sections
        .iter()
        .filter(|section| section.kind == AnalysisKind::Identification)
        .flat_map(|section| &section.entries)
        .find(|entry| entry.label == "format: file magic")
    {
        set("Magic", &magic.value.chars().take(4096).collect::<String>());
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
    /// `<data>/tools`, for the managed tools the sandbox mounts (Magika).
    tools_dir: Option<std::path::PathBuf>,
}

impl TriageView {
    pub(crate) fn set_tools_dir(&mut self, dir: &std::path::Path) {
        if self.properties.tools_dir.as_deref() != Some(dir) {
            self.properties.tools_dir = Some(dir.to_owned());
        }
    }
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
        let tools_dir = self.tools_dir.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (tx, rx) = mpsc::sync_channel(1);
        let ctx = ctx.clone();
        match std::thread::Builder::new()
            .name("triage-properties".into())
            .spawn(move || {
                let result = engine::run(&directory, &id, tools_dir.as_deref(), &worker_cancel);
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
        if input.analysis.is_none() {
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
        egui::ScrollArea::vertical()
            .id_salt("triage-properties")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (title, subtitle, labels) in [
                    (
                        "File identification",
                        "Format and size of the retained executable",
                        &["File type", "Magic", "File size"][..],
                    ),
                    (
                        "Exact hashes",
                        "Identity of the captured specimen",
                        &["SHA-256", "SHA-1", "MD5"][..],
                    ),
                    (
                        "Similarity & classifiers",
                        "Fuzzy hashes computed locally, and Magika when it is installed",
                        &["ssdeep", "TLSH", "Magika"][..],
                    ),
                ] {
                    presentation::frame().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        presentation::heading(ui, title, subtitle);
                        let width = (ui.available_width() - 125.0).max(80.0);
                        egui::Grid::new(("triage-property-fields", title))
                            .num_columns(2)
                            .striped(true)
                            .spacing(egui::vec2(12.0, 8.0))
                            .max_col_width(width)
                            .show(ui, |ui| {
                                for label in labels {
                                    let field = result.and_then(|result| {
                                        result.fields.iter().find(|field| field.label == *label)
                                    });
                                    ui.label(RichText::new(*label).strong().color(theme::text()));
                                    let stored =
                                        field.map_or("Unavailable", |field| field.value.as_str());
                                    let available = field.is_some_and(|field| field.available);
                                    // The stored size is the plain byte count.
                                    let value = match stored.parse::<u64>() {
                                        Ok(size) if available && *label == "File size" => {
                                            crate::values::file_size(size)
                                        }
                                        _ => stored.to_owned(),
                                    };
                                    let display = if available || value == "Not computed" {
                                        value.as_str()
                                    } else {
                                        "Unavailable"
                                    };
                                    let text = RichText::new(display).color(if available {
                                        theme::text()
                                    } else {
                                        theme::muted()
                                    });
                                    let text = if title == "Exact hashes" {
                                        text.monospace()
                                    } else {
                                        text
                                    };
                                    let response = ui.add(egui::Label::new(text).wrap());
                                    if let Some(field) = field {
                                        response
                                            .clone()
                                            .on_hover_text(format!("{value}\n{}", field.source));
                                    }
                                    response.context_menu(|ui| {
                                        if ui.button("Copy value").clicked() {
                                            ui.ctx().copy_text(value.clone());
                                            ui.close_menu();
                                        }
                                        if let Some(result) = result {
                                            if ui.button("Copy properties as JSON").clicked() {
                                                if let Ok(json) =
                                                    serde_json::to_string_pretty(result)
                                                {
                                                    ui.ctx().copy_text(json);
                                                }
                                                ui.close_menu();
                                            }
                                        }
                                        if let Some(directory) = input
                                            .archive
                                            .map(|directory| directory.join("analysis"))
                                        {
                                            crate::evidence::menu(ui, &directory);
                                        }
                                    });
                                    ui.end_row();
                                }
                            });
                    });
                    ui.add_space(10.0);
                }
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
                "ssdeep" => "3072:LylQMXZZ86ZnAD1XBRPIHnh+m7m8z+kijtJNBPoEteKQvO6ysX:LyS0bxARPIHh15REteh2e".into(),
                "TLSH" => "The file is too small: TLSH needs at least 50 bytes".into(),
                _ => "Magika is not installed".into(),
            },
            available: matches!(*label, "MD5" | "SHA-1" | "SHA-256" | "File size" | "Magic" | "File type" | "ssdeep"),
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
                    let input = TriageInput {
                        analysis: Some(&self.report),
                        archive: Some(Path::new("/fixture/run")),
                        run_finished: true,
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
        let fields = engine::LABELS.iter().map(|label| engine::Property { label: (*label).into(), value: match *label { "MD5" => "abcdef0123456789".repeat(2), "SHA-1" => "abcdef0123".repeat(4), "SHA-256" => "abcdef0123456789".repeat(4), "File size" => "129736".into(), "Magic" => "ELF 64-bit LSB shared object, x86-64, dynamically linked, stripped".into(), "File type" => "Elf Dynamic X86_64".into(), "ssdeep" => "3072:LylQMXZZ86ZnAD1XBRPIHnh+m7m8z+kijtJNBPoEteKQvO6ysX:LyS0bxARPIHh15REteh2e".into(), _ => "Magika is not installed".into() }, available: matches!(*label, "MD5" | "SHA-1" | "SHA-256" | "File size" | "Magic" | "File type" | "ssdeep"), source: "Local verified specimen".into() }).collect();
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
                theme::apply(
                    &cc.egui_ctx,
                    std::env::var_os("ANTINOMIE_TRIAGE_QA_LIGHT").is_some(),
                );
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
        let field = |label: &str| {
            saved
                .fields
                .iter()
                .find(|field| field.label == label)
                .unwrap()
        };
        assert!(field("SHA-256").available);
        assert_eq!(field("SHA-256").value, report.specimen_sha256.unwrap());
        assert_eq!(field("File size").value, "129736");
        assert!(!field("MD5").available);
        assert!(field("SHA-256").source.contains("not reverified"));
        // Every label the panel shows has a saved entry, and none is stale.
        assert_eq!(
            saved
                .fields
                .iter()
                .map(|f| f.label.as_str())
                .collect::<Vec<_>>(),
            engine::LABELS
        );
    }

    #[test]
    fn property_rows_center_label_and_value_and_show_file_size_with_a_unit() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let (report, result) = fixture_properties();
        let mut view = View::default();
        let mut rows = Vec::new();
        let mut texts = Vec::new();
        for frame in 0..3 {
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 880.0),
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
                    });
                },
            );
            rows.clear();
            texts.clear();
            for shape in output.shapes {
                if let egui::epaint::Shape::Text(text) = shape.shape {
                    let rect = egui::Rect::from_min_size(text.pos, text.galley.size());
                    texts.push(text.galley.job.text.clone());
                    rows.push((text.galley.job.text.clone(), rect.center().y));
                }
            }
        }
        assert!(
            texts.iter().any(|text| text == "129736 bytes (126.7 KB)"),
            "{texts:?}"
        );
        for (label, value) in [
            ("File size", "129736 bytes (126.7 KB)"),
            ("MD5", &"abcdef0123456789".repeat(2)),
            (
                "ssdeep",
                "3072:LylQMXZZ86ZnAD1XBRPIHnh+m7m8z+kijtJNBPoEteKQvO6ysX:LyS0bxARPIHh15REteh2e",
            ),
        ] {
            let y = |wanted: &str| {
                rows.iter()
                    .find(|(text, _)| text == wanted)
                    .unwrap_or_else(|| panic!("{wanted} not drawn: {texts:?}"))
                    .1
            };
            assert!(
                (y(label) - y(value)).abs() <= 1.0,
                "{label}: label at {}, value at {}",
                y(label),
                y(value)
            );
        }
    }
}
