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
mod build_sources;
#[cfg(test)]
mod dialog_tests;
mod not_started;
#[cfg(test)]
mod reexport_tests;
mod rows;
mod run_facts;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod timing;

/// The Triage context of `input`: equal keys are the same run in the same folder.
pub(super) fn context_key(input: &TriageInput<'_>) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        input.vm_id.unwrap_or(""),
        input.boot_id.unwrap_or(""),
        input.run_id.unwrap_or(""),
        input
            .archive
            .map(|path| path.display().to_string())
            .unwrap_or_default()
    )
}

pub(crate) use not_started::NotStartedRun;

/// Everything the worker needs, owned.
#[derive(Clone)]
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

/// The run the dialog is bound to: the one on screen when it was opened, or
/// when the person last switched runs with the dialog open. It carries the
/// whole-run request of that run, so a report never mixes one run's recording
/// with another run's request.
#[derive(Clone)]
struct Target {
    /// The Triage context (VM, boot, run and folder) this target was made for.
    key: String,
    /// What the window title says: the sample and the run's first characters.
    title: String,
    request: ScanRequest,
    /// The report is of a run that never started: no recording to read.
    not_started: Option<NotStartedRun>,
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
        /// How far the index has got, written by the worker.
        progress: Arc<scan_progress::ScanProgress>,
        began: Instant,
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
    /// The files of the last export are on offer: Export waits for a change of
    /// choice or of run before it writes a second set.
    exported: bool,
    /// The person tried to close the window while it was writing.
    close_refused: bool,
    /// The palette asked for the dialog: the Triage bar opens it on its next frame.
    pub(super) requested: bool,
}

impl Default for Dialog {
    fn default() -> Self {
        Self {
            open: false,
            target: None,
            state: State::Idle,
            choices: Choices::default(),
            changed: false,
            exported: false,
            close_refused: false,
            requested: false,
        }
    }
}

/// The request has no filter, sort, page or toggle: it reads the run whole,
/// as a report does.
pub(super) fn is_whole_run(request: &ScanRequest) -> bool {
    request.filters.iter().all(String::is_empty)
        && request.offsets == [0; SLOTS]
        && request.sorts.iter().all(Option::is_none)
        && request.file_visibility == Default::default()
        && request.finding_view == Default::default()
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
            key: String::new(),
            title: "Export report".into(),
            request: ScanRequest::default(),
            not_started: None,
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

/// Index the whole run, build the report and write it.
pub(super) fn run_job(
    job: &Job,
    cancel: &Arc<AtomicBool>,
    status: &dyn Fn(&str),
) -> Result<Written, String> {
    status(if job.request.reuse.is_some() {
        "Using the index Triage already made..."
    } else {
        "Indexing the whole run..."
    });
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
    // The run's state, command, sample and environment come from its record.
    let job = &run_facts::apply(job, &scan);
    let mut built = build::build(&scan, job)?;
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
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
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
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

    /// The target for the run `input` describes, with the request that reads
    /// that run whole. `None` when the run has no saved recording.
    fn report_target(&self, input: &TriageInput<'_>) -> Option<Target> {
        let archive = input.archive?;
        let sample = input.analysis.and_then(|analysis| {
            let sha256 = analysis.specimen_sha256.clone()?;
            Some(report::SampleInfo {
                name: Path::new(&analysis.source_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                sha256,
                size: analysis.specimen_len,
                role: String::new(),
            })
        });
        let run_id = input.run_id.unwrap_or_default();
        let title = match &sample {
            Some(sample) if !sample.name.is_empty() => format!(
                "Export report: {} [{}]",
                crate::widgets::short_name(&sample.name),
                run_id.chars().take(8).collect::<String>()
            ),
            _ => format!(
                "Export report: run {}",
                run_id.chars().take(8).collect::<String>()
            ),
        };
        let mut request = whole_run_request(&self.scan_request);
        request.run_finished = input.run_finished;
        Some(Target {
            key: context_key(input),
            title,
            request,
            not_started: None,
            archive: archive.to_path_buf(),
            pcap: input.pcap.map(Path::to_path_buf),
            pcap_open: input.pcap_open,
            run: report::RunInfo {
                vm_id: input.vm_id.unwrap_or_default().into(),
                boot_id: input.boot_id.unwrap_or_default().into(),
                run_id: run_id.into(),
                started_ms: input.started_ms,
                finished: input.run_finished,
                ..Default::default()
            },
            sample,
            clock: input.clock_anchor,
        })
    }

    /// Open the dialog for the run on screen.
    pub(super) fn open_report(&mut self, input: &TriageInput<'_>) {
        let Some(target) = self.report_target(input) else {
            return;
        };
        let same = self
            .report
            .target
            .as_ref()
            .is_some_and(|old| old.key == target.key);
        self.report.target = Some(target);
        if !matches!(self.report.state, State::Running { .. }) {
            self.report.state = State::Idle;
        }
        if !same {
            self.report.exported = false;
        }
        self.report.open = true;
    }

    /// Open the dialog for a run that never started.
    pub(crate) fn open_report_not_started(&mut self, run: NotStartedRun) {
        let id: String = run.run.run_id.chars().take(8).collect();
        self.report.target = Some(Target {
            key: format!("not-started\n{}", run.run.run_id),
            title: format!("Export report: run {id} (not started)"),
            request: ScanRequest::default(),
            not_started: Some(run.clone()),
            archive: run.directory.clone(),
            pcap: None,
            pcap_open: false,
            run: run.run.clone(),
            sample: run.sample.clone(),
            clock: None,
        });
        if !matches!(self.report.state, State::Running { .. }) {
            self.report.state = State::Idle;
        }
        self.report.exported = false;
        self.report.open = true;
    }

    /// A run that never started is on screen: an open dialog follows it.
    pub(crate) fn follow_report_not_started(&mut self, run: &NotStartedRun) {
        if !self.report.open || matches!(self.report.state, State::Running { .. }) {
            return;
        }
        let same = self.report.target.as_ref().is_some_and(|target| {
            target.not_started.as_ref().map(|old| &old.run.run_id) == Some(&run.run.run_id)
        });
        if !same {
            self.open_report_not_started(run.clone());
        }
    }

    /// The person switched runs: an open dialog follows the run on screen, so
    /// its Export always writes what its title says. A dialog that is writing
    /// stays bound to the run it is writing until it has finished.
    pub(super) fn follow_report(&mut self, input: &TriageInput<'_>) {
        if !self.report.open || matches!(self.report.state, State::Running { .. }) {
            return;
        }
        // A run that never started has no Triage: the page ticks with no run
        // while it is selected, and the dialog stays for it.
        if input.run_id.is_none()
            && self
                .report
                .target
                .as_ref()
                .is_some_and(|target| target.not_started.is_some())
        {
            return;
        }
        let key = context_key(input);
        if self
            .report
            .target
            .as_ref()
            .is_some_and(|old| old.key == key)
        {
            return;
        }
        match self.report_target(input) {
            Some(target) => {
                self.report.target = Some(target);
                self.report.state = State::Idle;
                self.report.exported = false;
            }
            // No run, or one with no recording: nothing to export.
            None => {
                self.report.open = false;
                self.report.target = None;
            }
        }
    }

    fn start_report(&mut self, ctx: &egui::Context) {
        let Some(target) = self.report.target.clone() else {
            return;
        };
        let choices = self.report.choices.clone();
        let mut request = target.request.clone();
        // The screen's caches only fit the run on screen.
        if self.context_key.as_deref() == Some(target.key.as_str()) {
            request.event_cache = self.scan.as_ref().and_then(|scan| scan.event_cache.clone());
            request.ioc_cache = self
                .scan
                .as_ref()
                .and_then(|scan| scan.ioc.as_ref())
                .map(|ioc| ioc.cache.clone());
            // The index Triage made of the whole run, when the recording is
            // as it saw it: the export builds from it and reads nothing again.
            // That is the hour a large run's second index took.
            let current = source_stamp(
                &target.archive,
                target.pcap.as_deref(),
                target.pcap_open,
                &request,
            );
            request.reuse = self
                .scan
                .as_ref()
                .filter(|scan| scan.whole_run && scan.stamp == current)
                .cloned();
        }
        let progress = Arc::new(scan_progress::ScanProgress::default());
        request.progress = Some(Arc::clone(&progress));
        let folder = if choices.folder.trim().is_empty() {
            target.archive.join("report")
        } else {
            PathBuf::from(choices.folder.trim())
        };
        if let Some(run) = target.not_started.clone() {
            // No recording to read: the report is made from the run's record.
            let now_ms = crate::time_format::now_ms();
            self.spawn_report(ctx, progress, move |_, status| {
                status("Writing the files...");
                let built = not_started::build(&run, now_ms);
                report::export::write(&built, &choices, &folder, None)
            });
            return;
        }
        let job = Job {
            archive: target.archive.clone(),
            pcap: target.pcap.clone(),
            request,
            choices,
            run: target.run.clone(),
            sample: target.sample.clone(),
            clock: target.clock,
            data_dir: target.request.data_dir.clone(),
            now_ms: crate::time_format::now_ms(),
            folder,
        };
        let _ = target.pcap_open;
        self.spawn_report(ctx, progress, move |cancel, status| {
            run_job(&job, cancel, status)
        });
    }

    /// Run `work` on its own thread; the dialog follows it through its
    /// status messages and `progress`.
    fn spawn_report<F>(
        &mut self,
        ctx: &egui::Context,
        progress: Arc<scan_progress::ScanProgress>,
        work: F,
    ) where
        F: FnOnce(&Arc<AtomicBool>, &dyn Fn(&str)) -> Result<Written, String> + Send + 'static,
    {
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
                let result = work(&worker_cancel, &notify);
                let _ = tx.send(Message::Done(result));
                wake.request_repaint();
            });
        self.report.state = match spawned {
            Ok(_) => State::Running {
                rx,
                cancel,
                status: "Starting...".into(),
                progress,
                began: Instant::now(),
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
                Some(Ok(written)) => {
                    self.report.exported = !written.files.is_empty();
                    self.report.state = State::Done(written);
                }
                Some(Err(error)) if error == "cancelled" => self.report.state = State::Idle,
                Some(Err(error)) => self.report.state = State::Failed(error),
                None => ctx.request_repaint_after(Duration::from_millis(200)),
            }
        }
        if !self.report.open {
            return;
        }
        let Some(title) = self.report.target.as_ref().map(|t| t.title.clone()) else {
            self.report.open = false;
            return;
        };
        let mut open = true;
        let mut start = false;
        let mut cancel_run = false;
        let mut close = false;
        let running = matches!(self.report.state, State::Running { .. });
        // The window is capped at a share of the content area; what the scroll
        // area leaves for the title and the footer keeps Export and Close in view.
        let tall = (crate::widgets::cap_size(crate::title_bar::content_rect(ctx)).y - 180.0)
            .clamp(160.0, 760.0);
        let id = egui::Id::new("triage-report-dialog");
        // A run that never started has one short report: no sections, no bundle.
        let simple = self
            .report
            .target
            .as_ref()
            .is_some_and(|target| target.not_started.is_some());
        crate::widgets::window(title)
            .id(id)
            .open(&mut open)
            .resizable(false)
            .pivot(egui::Align2::CENTER_TOP)
            .default_pos(crate::widgets::top_anchor(ctx))
            .default_width(540.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(tall)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        match &self.report.state {
                            State::Done(written) => {
                                ui.label(theme::section_title(ui, "Written"));
                                let files: Vec<_> = written
                                    .files
                                    .iter()
                                    .map(|(l, p)| (l.to_string(), p.clone()))
                                    .collect();
                                // Every file shows: the window scrolls, not the list.
                                crate::widgets::written_files(ui, "report", &files, files.len());
                                if let Some(bundle) = &written.bundle {
                                    for (what, why) in &bundle.skipped {
                                        ui.weak(format!("Not in the bundle: {what} ({why})"));
                                    }
                                }
                            }
                            State::Failed(error) => {
                                ui.add_space(6.0);
                                ui.add(
                                    egui::Label::new(RichText::new(error).color(theme::error()))
                                        .wrap(),
                                );
                            }
                            _ => {}
                        }
                        if !matches!(self.report.state, State::Idle | State::Running { .. }) {
                            ui.separator();
                        }
                        let choices = &mut self.report.choices;
                        let mut edited = false;
                        ui.add_enabled_ui(!running, |ui| {
                            if !simple {
                                ui.horizontal(|ui| {
                                    ui.label(theme::section_title(ui, "Sections"));
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
                            }
                            ui.label(theme::section_title(ui, "Formats"));
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
                            ui.horizontal(|ui| {
                                ui.label(theme::section_title(ui, "Options"));
                                // The choices are remembered: say how to get the
                                // defaults back (Defang on, HTML and PDF).
                                let defaults = Choices {
                                    folder: choices.folder.clone(),
                                    ..Choices::default()
                                };
                                if *choices != defaults
                                    && ui
                                        .small_button("Reset to defaults")
                                        .on_hover_text(
                                            "Every section, HTML and PDF, Defang on, no bundle. \
                                             The folder stays.",
                                        )
                                        .clicked()
                                {
                                    *choices = defaults;
                                    edited = true;
                                }
                            });
                            if !simple {
                                edited |= ui
                                    .checkbox(
                                        &mut choices.bundle,
                                        "Evidence bundle (.zip next to the report)",
                                    )
                                    .on_hover_text(
                                        "The packet captures, the files the run dropped in an inner \
                                         AES-256 zip (password: infected), the sample's custody \
                                         export and a SHA-256 manifest.",
                                    )
                                    .changed();
                            }
                            edited |= ui
                                .checkbox(
                                    &mut choices.defang,
                                    "Defang indicators in HTML, PDF and Markdown",
                                )
                                .on_hover_text(
                                    "On by default: hxxp://example[.]com. JSON, MISP and STIX \
                                     keep the raw values.",
                                )
                                .changed();
                            ui.add_space(6.0);
                            ui.label(theme::section_title(ui, "Folder"));
                            edited |= ui
                                .add(
                                    egui::TextEdit::singleline(&mut choices.folder)
                                        .hint_text(crate::theme::placeholder(ui, "<recording>/report"))
                                        .desired_width(f32::INFINITY),
                                )
                                .changed();
                        });
                        if edited {
                            self.report.changed = true;
                            self.report.exported = false;
                        }
                    });
                let choices = &self.report.choices;
                let ready = (!choices.formats.is_empty() || (choices.bundle && !simple))
                    && self.report.target.is_some()
                    && !self.report.exported;
                let refused = std::mem::take(&mut self.report.close_refused);
                crate::widgets::footer_split(
                    ui,
                    |ui| {
                        if let State::Running {
                            status,
                            progress,
                            began,
                            ..
                        } = &self.report.state
                        {
                            theme::spinner(ui);
                            // The phase and how far it got; the job's own word
                            // for the steps that follow the index.
                            let line = match (progress.text(), status.as_str()) {
                                (Some(text), "Indexing the whole run...") => text,
                                _ => status.clone(),
                            };
                            ui.label(format!(
                                "{line} · {}",
                                crate::time_format::elapsed(began.elapsed().as_millis() as u64)
                            ));
                        } else if refused {
                            ui.weak("Cancel stops the export.");
                        }
                    },
                    |ui| {
                        if running {
                            if ui.button("Cancel").clicked() {
                                cancel_run = true;
                            }
                        } else {
                            if ui
                                .add_enabled(ready, egui::Button::new("Export"))
                                .on_hover_text("Write the chosen files")
                                .on_disabled_hover_text(if self.report.exported {
                                    "Already written. Change a choice to write another set."
                                } else {
                                    "Choose a format or the evidence bundle"
                                })
                                .clicked()
                            {
                                start = true;
                            }
                            if ui.button("Close").clicked() {
                                close = true;
                            }
                        }
                    },
                );
            });
        if cancel_run {
            if let State::Running { cancel, status, .. } = &mut self.report.state {
                cancel.store(true, Ordering::Relaxed);
                *status = "Cancelling: the export stops at its next step...".into();
            }
        }
        if start {
            self.start_report(ctx);
        }
        if running {
            // The window stays up while it writes: closing it would end the
            // export with no word. Cancel is the way to stop.
            if !open {
                self.report.close_refused = true;
            }
        } else if !open || close || crate::widgets::escape_closes(ctx, id) {
            self.report.open = false;
        }
    }
}
