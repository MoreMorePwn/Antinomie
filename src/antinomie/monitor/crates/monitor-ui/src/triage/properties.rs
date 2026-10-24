// SPDX-License-Identifier: GPL-3.0-only
//! Property jobs are isolated, on demand and tied to an exact run specimen.
use super::*;
use antinomie_monitor_core::analysis::properties::{self as engine, FileProperties};

type Identity = (std::path::PathBuf, String, Option<String>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpecimenStatus {
    NotRecorded,
    Acquiring,
    Waiting,
    Captured,
    Cancelled,
    Incomplete,
    Unavailable,
}

impl SpecimenStatus {
    fn from_report(
        report: Option<&antinomie_monitor_core::AnalysisReport>,
        current_boot: bool,
    ) -> Self {
        use antinomie_monitor_core::AnalysisState;
        let Some(report) = report else {
            return Self::NotRecorded;
        };
        if report.state == AnalysisState::Acquiring {
            return if current_boot {
                Self::Acquiring
            } else {
                Self::Incomplete
            };
        }
        if report.specimen_sha256.is_some() && report.specimen_len.is_some() {
            return Self::Captured;
        }
        match report.state {
            AnalysisState::Queued | AnalysisState::Running if !current_boot => Self::Incomplete,
            AnalysisState::Queued | AnalysisState::Running => Self::Waiting,
            AnalysisState::Cancelled => Self::Cancelled,
            AnalysisState::Partial => Self::Incomplete,
            _ => Self::Unavailable,
        }
    }
}

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
    report_state: Option<antinomie_monitor_core::AnalysisState>,
    attempt_state: Option<antinomie_monitor_core::AnalysisState>,
    result: Option<Result<FileProperties, String>>,
    refresh_error: Option<String>,
    rx: Option<Receiver<Result<FileProperties, String>>>,
    cancel: Option<Arc<AtomicBool>>,
    /// `<data>/tools`, for the managed tools the sandbox mounts (Magika).
    tools_dir: Option<std::path::PathBuf>,
}

impl TriageView {
    /// The app's data folder, where installed bases are (guest user names).
    pub(crate) fn set_data_dir(&mut self, dir: &std::path::Path) {
        if self.scan_request.data_dir.as_deref() != Some(dir) {
            self.scan_request.data_dir = Some(dir.to_owned());
        }
    }

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
        self.refresh_error = None;
        self.identity = None;
        self.report_state = None;
        self.attempt_state = None;
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
            self.accept_result(result);
            self.rx = None;
            self.cancel = None;
        }
        self.report_state = input.analysis.map(|report| report.state);
        // A reply can arrive after static analysis published a newer report.
        // Retry a failed attempt once for that new state, never every frame.
        if self.result.as_ref().is_some_and(Result::is_err)
            && self.attempt_state != self.report_state
            && SpecimenStatus::from_report(input.analysis, input.current_boot)
                == SpecimenStatus::Captured
        {
            self.result = None;
        }
        if self.rx.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn start(&mut self, ctx: &egui::Context) {
        if self.rx.is_some() {
            return;
        }
        let Some((directory, id, Some(_))) = self.identity.clone() else {
            return;
        };
        self.refresh_error = None;
        let tools_dir = self.tools_dir.clone();
        self.attempt_state = self.report_state;
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
                self.accept_result(Err(format!("Could not start property analysis: {error}")))
            }
        }
    }

    fn accept_result(&mut self, result: Result<FileProperties, String>) {
        self.refresh_error = None;
        match result {
            Ok(mut result) => {
                if let Some(Ok(previous)) = &self.result {
                    for field in &mut result.fields {
                        if let Some(known) = previous
                            .fields
                            .iter()
                            .find(|known| known.label == field.label && known.available)
                        {
                            field.clone_from(known);
                        }
                    }
                }
                self.result = Some(Ok(result));
            }
            Err(error) if self.result.as_ref().is_some_and(Result::is_ok) => {
                self.refresh_error = Some(error);
            }
            Err(error) => self.result = Some(Err(error)),
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) {
        let status = SpecimenStatus::from_report(input.analysis, input.current_boot);
        let ready = status == SpecimenStatus::Captured && self.identity.is_some();
        if ready && self.result.is_none() && self.rx.is_none() {
            self.start(ui.ctx());
        }
        self.show_specimen_status(ui, input, status);
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    ready && self.rx.is_none(),
                    egui::Button::new("Refresh properties"),
                )
                .clicked()
            {
                self.start(ui.ctx());
            }
            if let Some(directory) = input.archive.map(|directory| directory.join("analysis")) {
                if ui.button("Open result directory").clicked() {
                    crate::evidence::reveal(ui.ctx(), &directory);
                }
            }
        });
        if let Some(error) = &self.refresh_error {
            crate::activity::warning(ui, format!("Property refresh failed: {error}"));
        }
        if input.analysis.is_none() {
            crate::activity::warning(ui, "This run has no executable capture record. Enable static analysis before starting a new run.");
        } else if matches!(
            status,
            SpecimenStatus::Cancelled | SpecimenStatus::Incomplete | SpecimenStatus::Unavailable
        ) {
            let reason = input.analysis.and_then(|report| report.reason.as_deref()).unwrap_or("No complete executable was retained for this run. Start a new run with static analysis enabled.");
            crate::activity::warning(ui, reason);
        }
        match &self.result {
            Some(Err(error)) if ready => {
                crate::activity::warning(ui, error);
            }
            Some(Ok(result)) => {
                for warning in &result.warnings {
                    crate::activity::warning(ui, warning);
                }
            }
            _ => {}
        }
        let saved = input.analysis.map(saved_properties);
        let result = self
            .result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .or(saved.as_ref());
        let mut refresh_requested = false;
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
                        let unavailable = labels.iter().any(|label| {
                            result
                                .and_then(|result| {
                                    result.fields.iter().find(|field| field.label == *label)
                                })
                                .is_none_or(|field| !field.available)
                        });
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(title)
                                    .strong()
                                    .color(theme::heading())
                                    .size(ui.text_style_height(&egui::TextStyle::Body) + 1.0),
                            );
                            if unavailable {
                                if self.rx.is_some() {
                                    crate::theme::spinner(ui);
                                }
                                refresh_requested |= ui
                                    .add_enabled(
                                        ready && self.rx.is_none(),
                                        egui::Button::new(egui_phosphor::regular::ARROW_CLOCKWISE)
                                            .small(),
                                    )
                                    .on_hover_text("Refresh unavailable properties for this file")
                                    .clicked();
                            }
                        });
                        ui.add(
                            egui::Label::new(RichText::new(subtitle).small().color(theme::muted()))
                                .wrap(),
                        );
                        ui.add_space(8.0);
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
        if refresh_requested {
            self.start(ui.ctx());
        }
    }

    fn show_specimen_status(
        &self,
        ui: &mut egui::Ui,
        input: &TriageInput<'_>,
        status: SpecimenStatus,
    ) {
        let verified = self.result.as_ref().is_some_and(Result::is_ok);
        let (label, color, pending) = match status {
            SpecimenStatus::NotRecorded => ("Not recorded", theme::muted(), false),
            SpecimenStatus::Acquiring => ("Acquiring from guest…", theme::blue(), true),
            SpecimenStatus::Waiting => ("Waiting for metadata…", theme::blue(), true),
            SpecimenStatus::Captured if verified => ("Verified", theme::good(), false),
            SpecimenStatus::Captured => ("Captured", theme::text(), false),
            SpecimenStatus::Cancelled => ("Capture cancelled", theme::warn(), false),
            SpecimenStatus::Incomplete => ("Capture incomplete", theme::warn(), false),
            SpecimenStatus::Unavailable => ("Unavailable", theme::warn(), false),
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Executable").strong());
            // Captured shows its own spinner beside "Computing properties…".
            if pending || (self.rx.is_some() && status != SpecimenStatus::Captured) {
                theme::spinner(ui);
            }
            presentation::badge(ui, label, color);
            if status == SpecimenStatus::Captured {
                if let Some(size) = input.analysis.and_then(|report| report.specimen_len) {
                    ui.weak(crate::values::file_size(size));
                }
                if self.rx.is_some() {
                    theme::spinner(ui);
                    ui.label("Computing properties…");
                } else if self.result.as_ref().is_some_and(Result::is_err) {
                    ui.colored_label(theme::warn(), "Properties unavailable");
                }
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
    fn refresh_keeps_known_values_and_only_replaces_unavailable_properties() {
        let ctx = egui::Context::default();
        let (report, old) = fixture_properties();
        let input = TriageInput {
            analysis: Some(&report),
            archive: Some(Path::new("/fixture/run")),
            ..TriageInput::empty()
        };
        let mut view = View::default();
        view.tick(&ctx, &input);
        view.result = Some(Ok(old.clone()));
        let (tx, rx) = mpsc::sync_channel(1);
        view.rx = Some(rx);
        view.tick(&ctx, &input);
        assert_eq!(view.result.as_ref().unwrap().as_ref().unwrap(), &old);
        let mut refreshed = old.clone();
        for field in &mut refreshed.fields {
            field.value = format!("refreshed {}", field.label);
            field.available = field.label == "Magika";
        }
        tx.send(Ok(refreshed)).unwrap();
        view.tick(&ctx, &input);
        let result = view.result.as_ref().unwrap().as_ref().unwrap();
        for field in old.fields.iter().filter(|field| field.available) {
            assert_eq!(
                result
                    .fields
                    .iter()
                    .find(|new| new.label == field.label)
                    .unwrap(),
                field
            );
        }
        assert!(result
            .fields
            .iter()
            .any(|field| field.label == "Magika" && field.available));
        let known = result.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        view.rx = Some(rx);
        tx.send(Err("optional tool failed".into())).unwrap();
        view.tick(&ctx, &input);
        assert_eq!(view.result.as_ref().unwrap().as_ref().unwrap(), &known);
        assert_eq!(view.refresh_error.as_deref(), Some("optional tool failed"));
    }

    #[test]
    fn unavailable_section_refresh_dispatches_one_worker_and_is_disabled_while_pending() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let (report, result) = fixture_properties();
        let mut view = View::default();
        let input = TriageInput {
            analysis: Some(&report),
            archive: Some(Path::new("/fixture/run")),
            ..TriageInput::empty()
        };
        view.tick(&ctx, &input);
        view.result = Some(Ok(result.clone()));
        let draw = |view: &mut View, events| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 900.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| view.show(ui, &input));
                },
            )
        };
        let _ = draw(&mut view, vec![]);
        let output = draw(&mut view, vec![]);
        let buttons: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| {
                if let egui::Shape::Text(text) = &shape.shape {
                    (text.galley.text() == egui_phosphor::regular::ARROW_CLOCKWISE)
                        .then(|| egui::Rect::from_min_size(text.pos, text.galley.size()))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            buttons.len(),
            1,
            "one control for the two missing classifiers"
        );
        let pos = buttons[0].center();
        for pressed in [true, false] {
            draw(
                &mut view,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
        assert!(
            view.rx.is_some(),
            "section click must dispatch the existing worker"
        );
        let cancel = Arc::clone(view.cancel.as_ref().unwrap());
        for pressed in [true, false] {
            draw(
                &mut view,
                vec![egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                }],
            );
        }
        assert!(Arc::ptr_eq(view.cancel.as_ref().unwrap(), &cancel));
        assert_eq!(view.result.as_ref().unwrap().as_ref().unwrap(), &result);
        view.reset();
        assert!(cancel.load(Ordering::Relaxed));
    }

    #[test]
    fn acquisition_status_separates_capture_from_static_analysis_state() {
        use antinomie_monitor_core::AnalysisState;
        assert_eq!(
            SpecimenStatus::from_report(None, false),
            SpecimenStatus::NotRecorded
        );
        let (mut report, _) = fixture_properties();
        for state in [
            AnalysisState::Queued,
            AnalysisState::Running,
            AnalysisState::Complete,
            AnalysisState::Partial,
            AnalysisState::Unavailable,
            AnalysisState::Cancelled,
        ] {
            report.state = state;
            assert_eq!(
                SpecimenStatus::from_report(Some(&report), false),
                SpecimenStatus::Captured
            );
        }
        report.specimen_sha256 = None;
        report.specimen_len = None;
        for (state, status) in [
            (AnalysisState::Acquiring, SpecimenStatus::Acquiring),
            (AnalysisState::Queued, SpecimenStatus::Waiting),
            (AnalysisState::Running, SpecimenStatus::Waiting),
            (AnalysisState::Complete, SpecimenStatus::Unavailable),
            (AnalysisState::Partial, SpecimenStatus::Incomplete),
            (AnalysisState::Unavailable, SpecimenStatus::Unavailable),
            (AnalysisState::Cancelled, SpecimenStatus::Cancelled),
        ] {
            report.state = state;
            assert_eq!(SpecimenStatus::from_report(Some(&report), true), status);
            if matches!(
                state,
                AnalysisState::Acquiring | AnalysisState::Queued | AnalysisState::Running
            ) {
                assert_eq!(
                    SpecimenStatus::from_report(Some(&report), false),
                    SpecimenStatus::Incomplete
                );
            }
        }
    }

    #[test]
    fn late_property_error_retries_only_after_its_report_advances() {
        use antinomie_monitor_core::AnalysisState;
        let ctx = egui::Context::default();
        let (mut report, result) = fixture_properties();
        report.state = AnalysisState::Running;
        let input = TriageInput {
            analysis: Some(&report),
            archive: Some(Path::new("/fixture/run")),
            ..TriageInput::empty()
        };
        let mut view = View::default();
        view.tick(&ctx, &input);
        view.attempt_state = Some(AnalysisState::Running);
        let (tx, rx) = mpsc::sync_channel(1);
        view.rx = Some(rx);
        report.state = AnalysisState::Complete;
        let input = TriageInput {
            analysis: Some(&report),
            archive: Some(Path::new("/fixture/run")),
            ..TriageInput::empty()
        };
        view.tick(&ctx, &input);
        tx.send(Err("old acquisition result".into())).unwrap();
        view.tick(&ctx, &input);
        assert!(view.rx.is_none() && view.result.is_none());
        view.attempt_state = Some(AnalysisState::Complete);
        view.result = Some(Err("actual sandbox failure".into()));
        view.tick(&ctx, &input);
        assert!(matches!(&view.result, Some(Err(error)) if error == "actual sandbox failure"));
        view.result = Some(Ok(result));
        report.state = AnalysisState::Partial;
        view.tick(
            &ctx,
            &TriageInput {
                analysis: Some(&report),
                archive: Some(Path::new("/fixture/run")),
                ..TriageInput::empty()
            },
        );
        assert!(matches!(view.result, Some(Ok(_))));
    }

    #[test]
    fn specimen_status_row_wraps_at_narrow_and_large_text_widths() {
        for width in [320.0, 760.0] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, 24.0);
            let (report, result) = fixture_properties();
            for (status, expected, verified, pending) in [
                (
                    SpecimenStatus::Acquiring,
                    "Acquiring from guest…",
                    false,
                    false,
                ),
                (
                    SpecimenStatus::Waiting,
                    "Waiting for metadata…",
                    false,
                    false,
                ),
                (SpecimenStatus::Captured, "Captured", false, true),
                (SpecimenStatus::Captured, "Verified", true, false),
                (SpecimenStatus::Unavailable, "Unavailable", false, false),
                (SpecimenStatus::Cancelled, "Capture cancelled", false, false),
            ] {
                let mut view = View::default();
                if verified {
                    view.result = Some(Ok(result.clone()));
                }
                let (_tx, rx) = mpsc::sync_channel(1);
                if pending {
                    view.rx = Some(rx);
                }
                for _ in 0..2 {
                    let mut bounds = egui::Rect::NOTHING;
                    let output = ctx.run(
                        egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(
                                egui::Pos2::ZERO,
                                egui::vec2(width, 600.0),
                            )),
                            ..Default::default()
                        },
                        |ctx| {
                            egui::CentralPanel::default().show(ctx, |ui| {
                                view.show_specimen_status(
                                    ui,
                                    &TriageInput {
                                        analysis: Some(&report),
                                        ..TriageInput::empty()
                                    },
                                    status,
                                );
                                bounds = ui.min_rect();
                            });
                        },
                    );
                    assert!(bounds.max.x <= width + 1.0, "{width}: {bounds:?}");
                    let mut text = String::new();
                    for shape in output.shapes {
                        if let egui::epaint::Shape::Text(shape) = shape.shape {
                            assert!(
                                shape.pos.x + shape.galley.size().x <= width + 3.0,
                                "{width}: {}",
                                shape.galley.job.text
                            );
                            text.push_str(&shape.galley.job.text);
                        }
                    }
                    assert!(
                        text.contains("Executable") && text.contains(expected),
                        "{text}"
                    );
                    if pending {
                        assert!(text.contains("Computing properties"));
                    }
                }
            }
        }
    }

    #[test]
    fn computing_properties_shows_one_spinner_until_the_result_arrives() {
        let ctx = egui::Context::default();
        let (report, _) = fixture_properties();
        let mut view = View::default();
        let (_tx, rx) = mpsc::sync_channel(1);
        view.rx = Some(rx);
        let show = |view: &mut View| {
            let mut shapes = Vec::new();
            for _ in 0..2 {
                shapes = ctx
                    .run(egui::RawInput::default(), |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            view.show_specimen_status(
                                ui,
                                &TriageInput {
                                    analysis: Some(&report),
                                    ..TriageInput::empty()
                                },
                                SpecimenStatus::Captured,
                            );
                        });
                    })
                    .shapes;
            }
            shapes
        };
        let pending = show(&mut view);
        assert_eq!(theme::spinners_in(&pending), 1);
        view.rx = None;
        let done = show(&mut view);
        assert_eq!(theme::spinners_in(&done), 0);
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
                // The captured size is also in the header; the table is drawn last.
                rows.iter()
                    .rfind(|(text, _)| text == wanted)
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
