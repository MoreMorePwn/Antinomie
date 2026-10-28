// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Triage > Export report: the dialog (a checkbox per section and per format,
//! the evidence bundle, defanging, the folder) and the worker that indexes
//! the whole run again with no filter, builds the report and writes the files.
//! The formats themselves are `antinomie_monitor_core::report`.
use super::*;
use antinomie_monitor_core::report::{self, export::Written, Choices, Format, Part};
use std::path::PathBuf;

mod build;
#[cfg(test)]
mod tests;

/// Everything the worker needs, owned.
pub(super) struct Job {
    pub archive: PathBuf,
    pub pcap: Option<PathBuf>,
    /// The scan's request with every filter, sort and page cleared.
    pub request: ScanRequest,
    pub choices: Choices,
    pub run: report::RunInfo,
    pub sample: Option<report::SampleInfo>,
    pub clock: Option<antinomie_monitor_core::HostClockAnchor>,
    pub data_dir: Option<PathBuf>,
    pub now_ms: u64,
    pub folder: PathBuf,
}

/// The run on screen when the dialog was opened.
#[derive(Clone)]
struct Target {
    archive: PathBuf,
    pcap: Option<PathBuf>,
    pcap_open: bool,
    run: report::RunInfo,
    sample: Option<report::SampleInfo>,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
}

enum State {
    Idle,
    Running {
        rx: Receiver<Message>,
        cancel: Arc<AtomicBool>,
        status: String,
    },
    Done(Written),
    Failed(String),
}

enum Message {
    Status(String),
    Done(Result<Written, String>),
}

pub(super) struct Dialog {
    open: bool,
    target: Option<Target>,
    state: State,
    choices: Choices,
    /// The person changed a choice that the app has not stored yet.
    changed: bool,
}

impl Default for Dialog {
    fn default() -> Self {
        Self {
            open: false,
            target: None,
            state: State::Idle,
            choices: Choices::default(),
            changed: false,
        }
    }
}

/// The scan's request as the screen has it, with every filter, sort, page and
/// toggle back to the default: the report is of the whole run, not of what
/// the tables are showing.
pub(super) fn whole_run_request(screen: &ScanRequest) -> ScanRequest {
    let mut request = screen.clone();
    request.filters = Default::default();
    request.offsets = [0; SLOTS];
    request.sorts = Default::default();
    request.file_visibility = Default::default();
    request.finding_view = Default::default();
    request.unchanged_since = None;
    request.before_copy = None;
    request.event_cache = None;
    request.ioc_cache = None;
    request
}

impl Dialog {
    /// The dialog open on `archive`, for the screenshots.
    #[cfg(test)]
    pub(super) fn open_for_screenshot(&mut self, archive: PathBuf) {
        self.target = Some(Target {
            archive,
            pcap: None,
            pcap_open: false,
            run: report::RunInfo::default(),
            sample: None,
            clock: None,
        });
        self.choices.set(Part::Network, false);
        self.choices.set_format(Format::Json, true);
        self.choices.defang = true;
        self.open = true;
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// Index the whole run, build the report and write it.
pub(super) fn run_job(
    job: &Job,
    cancel: &Arc<AtomicBool>,
    status: &dyn Fn(&str),
) -> Result<Written, String> {
    status("Indexing the whole run...");
    let scan = scan_archive_query(
        &job.archive,
        job.pcap.as_deref(),
        false,
        cancel,
        &job.request,
    )?;
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    status("Building the report...");
    let mut built = build::build(&scan, job)?;
    let mut scratch = None;
    if let Some(input) = &mut built.bundle {
        status("Reading the custody log...");
        if let Some((sample, data_dir)) = job.sample.as_ref().zip(job.data_dir.as_ref()) {
            let temp = job.folder.join(format!(".custody-{}", std::process::id()));
            let exported = std::fs::create_dir_all(&temp)
                .map_err(|e| e.to_string())
                .and_then(|()| {
                    let mut library = antinomie_monitor_core::samples::Library::open(data_dir)?;
                    library.export_custody(
                        &sample.sha256,
                        antinomie_monitor_core::samples::ExportFormat::Json,
                        &temp.join(format!(
                            "custody-{}.json",
                            &sample.sha256[..8.min(sample.sha256.len())]
                        )),
                        None,
                    )
                });
            match exported {
                Ok(done) => {
                    input.custody.push(done.path);
                    input.custody.extend(done.verifier);
                }
                Err(error) => input.skipped.push(("custody export".into(), error)),
            }
            scratch = Some(temp);
        } else {
            input.skipped.push((
                "custody export".into(),
                "the run has no sample record".into(),
            ));
        }
    }
    status("Writing the files...");
    let written = report::export::write(&built.report, &job.choices, &job.folder, built.bundle);
    if let Some(temp) = scratch {
        let _ = std::fs::remove_dir_all(temp);
    }
    written
}

impl TriageView {
    /// Settings > the choices the dialog starts with (applied unless the
    /// person has just changed them here).
    pub(crate) fn set_report_choices(&mut self, choices: Choices) {
        if !self.report.changed {
            self.report.choices = choices;
        }
    }

    /// The choices after a change, to store in the settings.
    pub(crate) fn take_report_choices(&mut self) -> Option<Choices> {
        std::mem::take(&mut self.report.changed).then(|| self.report.choices.clone())
    }

    /// Open the dialog for the run on screen.
    pub(super) fn open_report(&mut self, input: &TriageInput<'_>) {
        let Some(archive) = input.archive else {
            return;
        };
        let sample = input.analysis.and_then(|analysis| {
            let sha256 = analysis.specimen_sha256.clone()?;
            Some(report::SampleInfo {
                name: Path::new(&analysis.source_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                sha256,
                size: analysis.specimen_len,
            })
        });
        self.report.target = Some(Target {
            archive: archive.to_path_buf(),
            pcap: input.pcap.map(Path::to_path_buf),
            pcap_open: input.pcap_open,
            run: report::RunInfo {
                vm_id: input.vm_id.unwrap_or_default().into(),
                boot_id: input.boot_id.unwrap_or_default().into(),
                run_id: input.run_id.unwrap_or_default().into(),
                started_ms: input.started_ms,
                finished: input.run_finished,
            },
            sample,
            clock: input.clock_anchor,
        });
        if !matches!(self.report.state, State::Running { .. }) {
            self.report.state = State::Idle;
        }
        self.report.open = true;
    }

    fn start_report(&mut self, ctx: &egui::Context) {
        let Some(target) = self.report.target.clone() else {
            return;
        };
        let choices = self.report.choices.clone();
        let mut request = whole_run_request(&self.scan_request);
        request.run_finished = target.run.finished;
        request.event_cache = self.scan.as_ref().and_then(|scan| scan.event_cache.clone());
        request.ioc_cache = self
            .scan
            .as_ref()
            .and_then(|scan| scan.ioc.as_ref())
            .map(|ioc| ioc.cache.clone());
        let folder = if choices.folder.trim().is_empty() {
            target.archive.join("report")
        } else {
            PathBuf::from(choices.folder.trim())
        };
        let job = Job {
            archive: target.archive.clone(),
            pcap: target.pcap.clone(),
            request,
            choices,
            run: target.run.clone(),
            sample: target.sample.clone(),
            clock: target.clock,
            data_dir: self.scan_request.data_dir.clone(),
            now_ms: now_ms(),
            folder,
        };
        let _ = target.pcap_open;
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let wake = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("triage-report".into())
            .spawn(move || {
                let notify = |text: &str| {
                    let _ = tx.send(Message::Status(text.to_owned()));
                    wake.request_repaint();
                };
                let result = run_job(&job, &worker_cancel, &notify);
                let _ = tx.send(Message::Done(result));
                wake.request_repaint();
            });
        self.report.state = match spawned {
            Ok(_) => State::Running {
                rx,
                cancel,
                status: "Starting...".into(),
            },
            Err(error) => State::Failed(format!("could not start the export: {error}")),
        };
    }

    /// The dialog, drawn every frame while it is open.
    pub(super) fn show_report_dialog(&mut self, ctx: &egui::Context) {
        if let State::Running { rx, status, .. } = &mut self.report.state {
            let mut finished = None;
            while let Ok(message) = rx.try_recv() {
                match message {
                    Message::Status(text) => *status = text,
                    Message::Done(result) => finished = Some(result),
                }
            }
            match finished {
                Some(Ok(written)) => self.report.state = State::Done(written),
                Some(Err(error)) if error == "cancelled" => self.report.state = State::Idle,
                Some(Err(error)) => self.report.state = State::Failed(error),
                None => ctx.request_repaint_after(Duration::from_millis(200)),
            }
        }
        if !self.report.open {
            return;
        }
        let mut open = true;
        let mut start = false;
        let mut cancel_run = false;
        let running = matches!(self.report.state, State::Running { .. });
        let tall = (ctx.screen_rect().height() * 0.7).min(760.0);
        crate::widgets::window("Export report")
            .id(egui::Id::new("triage-report-dialog"))
            .open(&mut open)
            .resizable(false)
            .default_width(540.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(tall)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        let choices = &mut self.report.choices;
                        let mut edited = false;
                        ui.add_enabled_ui(!running, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Sections").strong().color(theme::heading()));
                                if ui.small_button("All").clicked() {
                                    choices.parts = Part::ALL.to_vec();
                                    edited = true;
                                }
                                if ui.small_button("None").clicked() {
                                    choices.parts.clear();
                                    edited = true;
                                }
                            });
                            for part in Part::ALL {
                                let mut on = choices.has(part);
                                if ui.checkbox(&mut on, part.label()).changed() {
                                    choices.set(part, on);
                                    edited = true;
                                }
                            }
                            ui.add_space(6.0);
                            ui.label(RichText::new("Formats").strong().color(theme::heading()));
                            ui.horizontal_wrapped(|ui| {
                                for format in Format::ALL {
                                    let mut on = choices.writes(format);
                                    if ui.checkbox(&mut on, format.label()).changed() {
                                        choices.set_format(format, on);
                                        edited = true;
                                    }
                                }
                            });
                            ui.add_space(6.0);
                            ui.label(RichText::new("Options").strong().color(theme::heading()));
                            edited |= ui
                                .checkbox(&mut choices.bundle, "Evidence bundle (.zip next to the report)")
                                .on_hover_text(
                                    "The packet captures, the files the run dropped in an inner \
                                     AES-256 zip (password: infected), the sample's custody \
                                     export and a SHA-256 manifest.",
                                )
                                .changed();
                            edited |= ui
                                .checkbox(&mut choices.defang, "Defang indicators in HTML and PDF")
                                .on_hover_text(
                                    "hxxp://example[.]com. JSON, MISP and STIX keep the raw values.",
                                )
                                .changed();
                            ui.add_space(6.0);
                            ui.label(RichText::new("Folder").strong().color(theme::heading()));
                            edited |= ui
                                .add(
                                    egui::TextEdit::singleline(&mut choices.folder)
                                        .hint_text("<recording>/report")
                                        .desired_width(f32::INFINITY),
                                )
                                .changed();
                        });
                        if edited {
                            self.report.changed = true;
                        }
                    });
                let choices = &self.report.choices;
                let ready = (!choices.formats.is_empty() || choices.bundle)
                    && self.report.target.is_some();
                crate::widgets::footer_split(
                    ui,
                    |ui| {
                        if running {
                            theme::spinner(ui);
                            if let State::Running { status, .. } = &self.report.state {
                                ui.label(status);
                            }
                        }
                    },
                    |ui| {
                        if running {
                            if ui.button("Cancel").clicked() {
                                cancel_run = true;
                            }
                        } else if ui
                            .add_enabled(ready, egui::Button::new("Export"))
                            .on_disabled_hover_text("Choose a format or the evidence bundle")
                            .clicked()
                        {
                            start = true;
                        }
                    },
                );
                match &self.report.state {
                    State::Done(written) => {
                        ui.label(RichText::new("Written").strong().color(theme::heading()));
                        for (label, path) in &written.files {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(format!("{label}:"));
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(path.display().to_string()).monospace(),
                                    )
                                    .wrap(),
                                );
                            });
                        }
                        if let Some(bundle) = &written.bundle {
                            for (what, why) in &bundle.skipped {
                                ui.weak(format!("Not in the bundle: {what} ({why})"));
                            }
                        }
                    }
                    State::Failed(error) => {
                        ui.add(
                            egui::Label::new(RichText::new(error).color(theme::error())).wrap(),
                        );
                    }
                    _ => {}
                }
            });
        if cancel_run {
            if let State::Running { cancel, .. } = &self.report.state {
                cancel.store(true, Ordering::Relaxed);
            }
        }
        if start {
            self.start_report(ctx);
        }
        if !open {
            self.report.open = false;
            if let State::Running { cancel, .. } = &self.report.state {
                cancel.store(true, Ordering::Relaxed);
            }
        }
    }
}
