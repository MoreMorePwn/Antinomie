// SPDX-License-Identifier: MIT
use super::*;
use antinomie_monitor_core::analysis::detection::{
    self as engine, Engine, Evidence, Identity, Report, State,
};
use std::path::PathBuf;

const FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("finding.rule", "Engine rule identifier"),
    FieldSpec::text("finding.title", "Rule title"),
    FieldSpec::text("finding.severity", "Rule-supplied severity"),
    FieldSpec::text("finding.source", "Rule namespace or local source"),
    FieldSpec::text("finding.license", "Rule license metadata"),
    FieldSpec::tags("finding.mitre", "Rule-supplied ATT&CK references"),
    FieldSpec::number("finding.count", "Matched events or byte targets/blocks"),
    FieldSpec::text("finding.engine", "YARA, IDS or Sigma"),
    FieldSpec::number("stream.id", "Original syscall stream"),
    FieldSpec::number("process.cookie", "Original stable task identity"),
    FieldSpec::number("event.id", "Original syscall invocation"),
    FieldSpec::number("frame.number", "Original packet frame"),
    FieldSpec::text("capture.path", "Owning capture segment"),
    FieldSpec::text("evidence.path", "Retained byte source"),
    FieldSpec::number(
        "evidence.offset",
        "Matched file offset; missing for file-level conditions",
    ),
    FieldSpec::number("evidence.address", "Known process virtual address"),
    FieldSpec::text("evidence.report", "Retained specimen report identity"),
    FieldSpec::text("evidence.block", "Verified scanned block digest and extent"),
];
const HEADERS: &[&str] = &[
    "Rule",
    "Title",
    "Severity",
    "Occurrences",
    "MITRE",
    "Source",
    "License",
];
const ENGINES: [Engine; 3] = [Engine::Yara, Engine::Ids, Engine::Sigma];
const TABLES: [&str; 3] = ["triage-yara", "triage-ids", "triage-sigma"];
pub(super) fn name(engine: Engine) -> &'static str {
    match engine {
        Engine::Yara => "YARA",
        Engine::Ids => "IDS",
        Engine::Sigma => "Sigma",
    }
}
fn state(state: &State) -> &'static str {
    match state {
        State::Complete => "Complete",
        State::Partial => "Partial",
        State::Unavailable => "Unavailable",
    }
}
type Loaded = [Option<Report>; 3];
type BytePreview = Result<(Evidence, Vec<u8>), String>;
pub(super) struct Counts {
    pub rules: u64,
    pub occurrences: u128,
    references: std::collections::BTreeSet<String>,
}
enum Reply {
    Loaded(Box<Loaded>),
    Scanned(usize, Box<Result<Report, String>>),
}

#[derive(Default)]
pub(super) struct View {
    pub settings: engine::Settings,
    pub selected: Engine,
    identity: Option<(PathBuf, Identity)>,
    pub results: [Option<Result<Report, String>>; 3],
    pub counts: [Option<Counts>; 3],
    pub references: std::collections::BTreeSet<String>,
    rows: [Vec<Vec<Cell>>; 3],
    filtered: [Vec<Vec<Cell>>; 3],
    applied: [Option<String>; 3],
    rx: Option<Receiver<Reply>>,
    cancel: Option<Arc<AtomicBool>>,
    busy: Option<usize>,
    byte_rx: Option<Receiver<BytePreview>>,
    bytes: Option<BytePreview>,
    pending_byte: Option<Evidence>,
}

impl View {
    fn reset(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        self.rx = None;
        self.busy = None;
        self.byte_rx = None;
        self.pending_byte = None;
        self.bytes = None;
        self.results = Default::default();
        self.counts = Default::default();
        self.references.clear();
        self.rows = Default::default();
        self.filtered = Default::default();
        self.applied = Default::default();
    }
    fn request(&self, engine: Engine, digest: Option<String>) -> Option<engine::Request> {
        self.identity
            .as_ref()
            .map(|(directory, identity)| engine::Request {
                engine,
                identity: identity.clone(),
                directory: directory.clone(),
                settings: self.settings.clone(),
                source_digest: digest,
            })
    }
    pub(super) fn rows(&mut self, index: usize) {
        self.counts[index] = self.results[index]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .filter(|report| report.state != State::Unavailable || !report.findings.is_empty())
            .map(|report| Counts {
                rules: report.findings.len() as u64,
                occurrences: report
                    .findings
                    .iter()
                    .map(|finding| u128::from(finding.count))
                    .sum(),
                references: report
                    .findings
                    .iter()
                    .flat_map(|finding| &finding.mitre)
                    .cloned()
                    .collect(),
            });
        self.references = self
            .counts
            .iter()
            .flatten()
            .flat_map(|counts| &counts.references)
            .cloned()
            .collect();
        self.applied[index] = None;
        self.rows[index] = self.results[index]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|report| {
                report
                    .findings
                    .iter()
                    .map(|finding| {
                        let mut row = vec![
                            cell(&finding.rule_id, theme::text(), true),
                            cell(&finding.title, theme::text(), false),
                            cell(&finding.severity, theme::warn(), false),
                            cell(finding.count.to_string(), theme::text(), true),
                            cell(finding.mitre.join(", "), theme::text(), true),
                            cell(&finding.source, theme::text(), false),
                            cell(&finding.license, theme::muted(), false),
                        ];
                        row[0].values = vec![
                            ("finding.rule", RowValue::Text(finding.rule_id.clone())),
                            ("finding.title", RowValue::Text(finding.title.clone())),
                            ("finding.severity", RowValue::Text(finding.severity.clone())),
                            ("finding.source", RowValue::Text(finding.source.clone())),
                            ("finding.license", RowValue::Text(finding.license.clone())),
                            ("finding.count", RowValue::Number(i128::from(finding.count))),
                            ("finding.mitre", RowValue::List(finding.mitre.clone())),
                            ("finding.engine", RowValue::Text(name(report.engine).into())),
                        ];
                        if let Some(evidence) = finding.evidence.first() {
                            row[0].values.extend(evidence_values(evidence));
                        }
                        row
                    })
                    .collect()
            })
            .unwrap_or_default();
    }
    pub fn tick(&mut self, ctx: &egui::Context, input: &TriageInput<'_>) {
        let identity = input
            .archive
            .zip(input.vm_id.zip(input.boot_id).zip(input.run_id))
            .filter(|_| input.root_cookie != 0)
            .map(|(directory, ((vm, boot), run))| {
                (
                    directory.to_path_buf(),
                    Identity {
                        vm_id: vm.into(),
                        boot_id: boot.into(),
                        run_id: run.into(),
                        root_cookie: input.root_cookie,
                    },
                )
            });
        if self.identity != identity {
            self.reset();
            self.identity = identity;
            if let Some(request) = self.request(Engine::Yara, None) {
                let (tx, rx) = mpsc::sync_channel(1);
                let ctx = ctx.clone();
                match std::thread::Builder::new()
                    .name("triage-detector-load".into())
                    .spawn(move || {
                        let loaded = ENGINES.map(|engine| {
                            let mut request = request.clone();
                            request.engine = engine;
                            engine::load(&request).ok()
                        });
                        let _ = tx.send(Reply::Loaded(Box::new(loaded)));
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                    }) {
                    Ok(_) => self.rx = Some(rx),
                    Err(error) => self.results[0] = Some(Err(error.to_string())),
                }
            }
        }
        if let Some(rx) = &self.rx {
            let reply = match rx.try_recv() {
                Ok(reply) => Some(Ok(reply)),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("Detector worker ended without a result".to_owned()))
                }
            };
            if let Some(reply) = reply {
                match reply {
                    Ok(Reply::Loaded(loaded)) => {
                        self.results = (*loaded).map(|report| report.map(Ok));
                        for index in 0..3 {
                            self.rows(index);
                        }
                    }
                    Ok(Reply::Scanned(index, result)) => {
                        self.results[index] = Some(*result);
                        self.rows(index);
                    }
                    Err(error) => {
                        self.results[self.busy.unwrap_or(0)] = Some(Err(error));
                    }
                }
                self.rx = None;
                self.cancel = None;
                self.busy = None;
            }
        }
        if let Some(evidence) = ctx.data_mut(|data| {
            let id = egui::Id::new("triage-byte-jump");
            let evidence = data.get_temp::<Evidence>(id);
            data.remove::<Evidence>(id);
            evidence
        }) {
            self.read_bytes(ctx, evidence);
        }
        if let Some(rx) = &self.byte_rx {
            match rx.try_recv() {
                Ok(result) => {
                    self.bytes = Some(result);
                    self.byte_rx = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.bytes = Some(Err("Byte preview worker ended without a result".into()));
                    self.byte_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        let pending = self
            .byte_rx
            .is_none()
            .then(|| self.pending_byte.take())
            .flatten();
        if let Some(evidence) = pending {
            self.read_bytes(ctx, evidence);
        }
        if self.rx.is_some() || self.byte_rx.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    fn start(&mut self, ctx: &egui::Context, digest: Option<String>) {
        let Some(request) = self.request(self.selected, digest) else {
            return;
        };
        let index = ENGINES
            .iter()
            .position(|engine| *engine == self.selected)
            .unwrap_or(0);
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (tx, rx) = mpsc::sync_channel(1);
        let ctx = ctx.clone();
        match std::thread::Builder::new()
            .name("triage-detector".into())
            .spawn(move || {
                let result = engine::run(request, &worker_cancel);
                let _ = tx.send(Reply::Scanned(index, Box::new(result)));
                ctx.request_repaint_of(egui::ViewportId::ROOT);
            }) {
            Ok(_) => {
                self.rx = Some(rx);
                self.cancel = Some(cancel);
                self.busy = Some(index);
            }
            Err(error) => self.results[index] = Some(Err(error.to_string())),
        }
    }
    fn read_bytes(&mut self, ctx: &egui::Context, evidence: Evidence) {
        if self.byte_rx.is_some() {
            self.pending_byte = Some(evidence);
            return;
        }
        let Some(request) = self.request(Engine::Yara, None) else {
            return;
        };
        let (tx, rx) = mpsc::sync_channel(1);
        let ctx = ctx.clone();
        self.bytes = None;
        match std::thread::Builder::new()
            .name("triage-match-bytes".into())
            .spawn(move || {
                let result =
                    engine::read_evidence(&request, &evidence).map(|data| (evidence, data));
                let _ = tx.send(result);
                ctx.request_repaint_of(egui::ViewportId::ROOT);
            }) {
            Ok(_) => self.byte_rx = Some(rx),
            Err(error) => self.bytes = Some(Err(error.to_string())),
        }
    }
    pub fn show(&mut self, ui: &mut egui::Ui, scan: Option<&ArchiveScan>) {
        ui.horizontal_wrapped(|ui| {
            for engine in ENGINES {
                ui.selectable_value(&mut self.selected, engine, name(engine));
            }
        });
        let index = ENGINES
            .iter()
            .position(|engine| *engine == self.selected)
            .unwrap_or(0);
        egui::CollapsingHeader::new("Local rules and data sources").show(ui, |ui| {
            egui::ScrollArea::vertical().id_salt(("detector-settings", index)).max_height((ui.available_height() * 0.4).min(260.0)).show(ui, |ui| {
            ui.add(egui::Label::new(match self.selected {
                Engine::Yara => "Bundled Antinomie and YARA-Forge rules scan the verified executable. Optional targets: captured core/RAM blocks and Volatility recovered files.",
                Engine::Ids => "Local Suricata scans all retained run-owned PCAP segments. Packets cover VM traffic; encrypted contents and process attribution are unavailable.",
                Engine::Sigma => "Local pySigma 2.x and SQLite backend evaluate recorded Linux exec/file operations, BPF loads, HTTP/1 and DNS. Missing fields, unsupported logsources and conditions are reported. Complete command lines are not available from bounded argv previews.",
            }).wrap());
            let rules = match self.selected { Engine::Yara => &mut self.settings.yara_rules, Engine::Ids => &mut self.settings.ids_rules, Engine::Sigma => &mut self.settings.sigma_rules };
            ui.label("Additional local rule file or folder");
            ui.add(egui::TextEdit::singleline(rules).desired_width(ui.available_width()).hint_text("Optional local path"));
            if self.selected == Engine::Yara {
                ui.checkbox(&mut self.settings.scan_memory, "Scan recorded core / RAM extents");
                ui.checkbox(&mut self.settings.scan_recovered, "Scan recovered files");
            } else if self.selected == Engine::Sigma {
                ui.label("Python with pySigma and its SQLite backend");
                ui.add(egui::TextEdit::singleline(&mut self.settings.sigma_python).desired_width(ui.available_width()).hint_text("/usr/bin/python3 or a local venv/bin/python"));
            }
            ui.weak("Local analysis only. No automatic downloads or online lookups.");
            let (label, url) = match self.selected {
                Engine::Yara => ("YARA-Forge sources", "https://github.com/YARAHQ/yara-forge"),
                Engine::Ids => ("Emerging Threats Open sources", "https://rules.emergingthreats.net/"),
                Engine::Sigma => ("SigmaHQ Linux rule sources", "https://github.com/SigmaHQ/sigma/tree/master/rules/linux"),
            };
            if ui.add(egui::Button::new(format!("Copy {label} URL")).wrap()).clicked() { ui.ctx().copy_text(url.into()); }
            });
        });
        ui.horizontal_wrapped(|ui| {
            let ready = self.rx.is_none()
                && self.identity.is_some()
                && (self.selected != Engine::Sigma
                    || scan.is_some_and(|scan| scan.event_journal.is_some()));
            if ui.add_enabled(ready, egui::Button::new("Scan")).clicked() {
                self.start(
                    ui.ctx(),
                    scan.and_then(|scan| scan.event_journal.as_ref())
                        .map(|summary| summary.sha256.clone()),
                );
            }
            if self.rx.is_some() {
                ui.spinner();
                if let Some(cancel) = &self.cancel {
                    if ui.button("Cancel").clicked() {
                        cancel.store(true, Ordering::Relaxed);
                    }
                }
            }
            if let Some((directory, _)) = &self.identity {
                let directory = engine::result_directory(directory, self.selected);
                ui.menu_button("Result", |ui| {
                    crate::evidence::menu(ui, &directory);
                    if let Some(Ok(report)) = &self.results[index] {
                        if ui.button("Copy result as JSON").clicked() {
                            match serde_json::to_string_pretty(report) {
                                Ok(json) => ui.ctx().copy_text(json),
                                Err(error) => self.bytes = Some(Err(error.to_string())),
                            }
                            ui.close_menu();
                        }
                    }
                });
            }
        });
        if self.selected == Engine::Sigma {
            if let Some(error) = scan.and_then(|scan| scan.event_error.as_ref()) {
                ui.add(egui::Label::new(RichText::new(error).color(theme::warn())).wrap());
            }
        }
        let Some(result) = &self.results[index] else {
            ui.weak("Not scanned. Choose Scan to evaluate this run.");
            return;
        };
        let report = match result {
            Ok(report) => report,
            Err(error) => {
                ui.add(egui::Label::new(RichText::new(error).color(theme::warn())).wrap());
                return;
            }
        };
        if self.selected == Engine::Sigma
            && report
                .source_digest
                .as_ref()
                .zip(scan.and_then(|scan| scan.event_journal.as_ref()))
                .is_some_and(|(digest, journal)| *digest != journal.sha256)
        {
            ui.colored_label(
                theme::warn(),
                "Recorded events changed after this result. Scan again to update it.",
            );
        }
        ui.label(format!(
            "{} · {} matched rules · {} objects evaluated · {} rules evaluated",
            state(&report.state),
            report.findings.len(),
            report.scanned_objects,
            report
                .scanned_rules
                .map_or("Unknown".into(), |count| count.to_string())
        ));
        if report.omitted_evidence > 0 {
            ui.weak(format!(
                "{} evidence locations exceed the preview or have no recorded position",
                report.omitted_evidence
            ));
        }
        egui::CollapsingHeader::new("Coverage and provenance").show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(180.0)
                .id_salt(("detector-coverage", index))
                .show(ui, |ui| {
                    for warning in report.warnings.iter().chain(&report.skipped) {
                        ui.add(
                            egui::Label::new(RichText::new(warning).color(theme::warn())).wrap(),
                        );
                    }
                    for source in &report.sources {
                        ui.add(
                            egui::Label::new(format!(
                                "{}\n{}\n{}\nSHA-256 {}\n{}",
                                source.name,
                                source.version,
                                source.license,
                                source.sha256,
                                source.data
                            ))
                            .wrap(),
                        );
                        ui.separator();
                    }
                });
        });
        if report.findings.is_empty() {
            ui.weak(if report.state == State::Complete {
                "No rule matched the evaluated data."
            } else {
                "No retained matches. Coverage is incomplete or unavailable."
            });
        }
        let filter = query::table_filter(ui, TABLES[index], "Filter rule matches", FIELDS, &[]);
        let draft_id = ui.id().with(("table-filter", TABLES[index]));
        let draft = ui
            .data(|data| data.get_temp::<String>(draft_id))
            .unwrap_or_default();
        ui.ctx().data_mut(|data| {
            data.insert_temp(
                egui::Id::new(("triage-filter-target", TABLES[index])),
                draft_id,
            )
        });
        if self.applied[index].as_ref() != Some(&draft) {
            self.filtered[index] = self.rows[index]
                .iter()
                .filter(|row| filter.keep_table(&row[0].values))
                .cloned()
                .collect();
            self.applied[index] = Some(draft);
        }
        table(ui, TABLES[index], HEADERS, &self.filtered[index]);
    }
    pub fn details(&mut self, ui: &mut egui::Ui, values: &[(&str, RowValue)]) {
        let text = |name: &str| {
            values.iter().find_map(|(key, value)| {
                if *key == name {
                    if let RowValue::Text(value) = value {
                        Some(value.as_str())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        };
        let Some(index) = ENGINES
            .iter()
            .position(|engine| Some(name(*engine)) == text("finding.engine"))
        else {
            return;
        };
        let Some(Ok(report)) = &self.results[index] else {
            return;
        };
        let Some(finding) = report
            .findings
            .iter()
            .find(|finding| Some(finding.rule_id.as_str()) == text("finding.rule"))
        else {
            return;
        };
        ui.add(egui::Label::new(&finding.details).wrap());
        for reference in &finding.mitre {
            let url = format!(
                "https://attack.mitre.org/techniques/{}/",
                reference.replace('.', "/")
            );
            ui.add(egui::Label::new(&url).wrap());
            if ui.small_button(format!("Copy {reference} link")).clicked() {
                ui.ctx().copy_text(url);
            }
        }
        let mut selected = None;
        egui::CollapsingHeader::new(format!("Evidence locations ({})", finding.evidence.len()))
            .default_open(true)
            .show(ui, |ui| {
                for evidence in finding.evidence.iter().take(32) {
                    let label = match evidence {
                        Evidence::Call {
                            stream,
                            cookie,
                            call,
                        } => format!("Open syscall {stream}/{cookie}/{call}"),
                        Evidence::Packet { capture, frame } => format!(
                            "Open packet #{} — {}",
                            frame,
                            capture.file_name().unwrap_or_default().to_string_lossy()
                        ),
                        Evidence::Bytes { path, offset, .. } => format!(
                            "{} — {}",
                            path.file_name().unwrap_or_default().to_string_lossy(),
                            offset.map_or(
                                "file-level match; no byte position".into(),
                                |offset| format!("open bytes at 0x{offset:x}")
                            )
                        ),
                    };
                    if ui.add(egui::Button::new(label).wrap()).clicked() {
                        selected = Some(evidence.clone());
                    }
                }
                if finding.evidence.len() > 32 {
                    ui.weak("More locations are retained in the exported JSON result.");
                }
            });
        if let Some(evidence) = selected {
            match evidence {
                Evidence::Bytes { .. } => self.read_bytes(ui.ctx(), evidence),
                _ => request_evidence_jump(ui.ctx(), &evidence_values(&evidence)),
            }
        }
        if self.byte_rx.is_some() {
            ui.spinner();
        }
        if let Some(result) = &self.bytes {
            match result {
                Ok((evidence, data)) => {
                    if !self.results[index]
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .and_then(|report| {
                            report.findings.iter().find(|finding| {
                                Some(finding.rule_id.as_str()) == text("finding.rule")
                            })
                        })
                        .is_some_and(|finding| finding.evidence.contains(evidence))
                    {
                        return;
                    }
                    ui.add(egui::Label::new(format!("{evidence:?}")).wrap());
                    for (index, chunk) in data.chunks(16).enumerate() {
                        let offset = match evidence {
                            Evidence::Bytes {
                                offset: Some(offset),
                                ..
                            } => offset + (index * 16) as u64,
                            _ => (index * 16) as u64,
                        };
                        let hex = chunk
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!("{offset:016x}  {hex}")).monospace(),
                            )
                            .wrap(),
                        );
                    }
                }
                Err(error) => {
                    ui.add(egui::Label::new(RichText::new(error).color(theme::warn())).wrap());
                }
            }
        }
    }
}
impl Drop for View {
    fn drop(&mut self) {
        self.reset();
    }
}

fn evidence_values(evidence: &Evidence) -> Vec<(&'static str, RowValue)> {
    let number = |value: u64| RowValue::Number(i128::from(value));
    match evidence {
        Evidence::Call {
            stream,
            cookie,
            call,
        } => vec![
            ("stream.id", number(*stream)),
            ("process.cookie", number(*cookie)),
            ("event.id", number(*call)),
        ],
        Evidence::Packet { capture, frame } => vec![
            (
                "capture.path",
                RowValue::Text(capture.display().to_string()),
            ),
            ("frame.number", number(*frame)),
        ],
        Evidence::Bytes {
            path,
            offset,
            address,
            report_id,
            block,
        } => vec![
            (
                "evidence.block",
                block
                    .as_ref()
                    .and_then(|block| serde_json::to_string(block).ok())
                    .map_or(RowValue::Missing, RowValue::Text),
            ),
            ("evidence.path", RowValue::Text(path.display().to_string())),
            ("evidence.offset", offset.map_or(RowValue::Missing, number)),
            (
                "evidence.address",
                address.map_or(RowValue::Missing, number),
            ),
            (
                "evidence.report",
                report_id
                    .as_ref()
                    .map_or(RowValue::Missing, |value| RowValue::Text(value.clone())),
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn run_change_cancels_detector_and_discards_stale_results() {
        let mut view = View::default();
        let ctx = egui::Context::default();
        view.identity = Some((
            "/old".into(),
            Identity {
                vm_id: "v".into(),
                boot_id: "b".into(),
                run_id: "r".into(),
                root_cookie: 1,
            },
        ));
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel(1);
        view.cancel = Some(Arc::clone(&cancel));
        view.rx = Some(rx);
        view.tick(&ctx, &TriageInput::empty());
        assert!(cancel.load(Ordering::Relaxed));
        assert!(tx.send(Reply::Loaded(Box::default())).is_err());
        assert!(view.results.iter().all(Option::is_none));
    }
}
