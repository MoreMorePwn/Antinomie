// SPDX-License-Identifier: GPL-3.0-only
//! Export report… for a library sample: the window (formats, defanging,
//! folder), and the worker that reads the sample the way its window does,
//! builds the report with `antinomie_monitor_core::report::sample` and writes
//! the files. The export is noted in the sample's custody log. It is reached
//! from the sample window's header and from the Samples list's context menu.
use super::detail::{self, Data};
use crate::{theme, widgets};
use antinomie_monitor_core::{
    report::sample::{
        self, build, export::Written, Choices, Format, Identity, SampleReport, SimilarSection,
    },
    run_digest::RunDigest,
    samples::{build_lineage, Known, Library, LineageOptions, RunLineage, Similar},
    BackendOptions,
};
use eframe::egui::{self, RichText};
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::mpsc::{self, Receiver},
};

/// The dialog and the choices it starts with (kept while the app runs).
#[derive(Default)]
pub(super) struct Slot {
    dialog: Option<ReportDialog>,
    choices: Choices,
}

impl Slot {
    /// Open Export report… for a sample.
    pub(super) fn open(&mut self, sha256: &str, name: &str) {
        self.dialog = Some(ReportDialog::new(sha256, name, self.choices.clone()));
    }
}

enum State {
    Idle,
    Running {
        rx: Receiver<Message>,
        status: String,
    },
    Done(Written),
    Failed(String),
}

enum Message {
    Status(String),
    Done(Result<Written, String>),
}

pub(in crate::app) struct ReportDialog {
    sha256: String,
    name: String,
    choices: Choices,
    state: State,
    open: bool,
    /// The custody log changed: the sample window reads it again.
    wrote: bool,
}

/// Everything the worker needs, owned.
struct Job {
    options: BackendOptions,
    vms: Vec<(String, String)>,
    sha256: String,
    choices: Choices,
    folder: PathBuf,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// Where the files go when the folder is left empty.
fn default_folder(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("sample-reports")
}

/// A folder as the dialog shows it: relative to the data directory when it is
/// inside it (a folder outside stays as it is).
fn shown_folder(data_dir: &std::path::Path, folder: &std::path::Path) -> String {
    folder
        .strip_prefix(data_dir)
        .unwrap_or(folder)
        .display()
        .to_string()
}

/// The folder the files go to for what is typed in the field: empty is the
/// default, a relative path is inside the data directory, an absolute one is
/// used as given.
fn chosen_folder(data_dir: &std::path::Path, typed: &str) -> PathBuf {
    let typed = typed.trim();
    if typed.is_empty() {
        default_folder(data_dir)
    } else {
        data_dir.join(typed)
    }
}

/// The report of the sample `data` describes. `similar` is the library
/// comparison's answer.
pub(super) fn build_report(
    data: &Data,
    data_dir: &std::path::Path,
    vms: &[(String, String)],
    similar: Result<Vec<Similar>, String>,
    now_ms: u64,
) -> SampleReport {
    let vm_name = |id: &str| {
        vms.iter()
            .find(|(vm, _)| vm == id)
            .map_or(String::new(), |(_, name)| name.clone())
    };
    let mut runs: Vec<_> = data
        .runs
        .iter()
        .map(|entry| {
            build::run_row(
                entry.number,
                &entry.run.vm_id,
                &vm_name(&entry.run.vm_id),
                &entry.run.id,
                entry.run.started_ms,
                &super::exit_label(&entry.run),
                data_dir,
                &entry.run.directory,
                entry.folder,
                entry.digest.as_ref(),
            )
        })
        .collect();
    runs.sort_by_key(|run| run.number);
    let digests: Vec<(usize, &RunDigest)> = data
        .runs
        .iter()
        .filter_map(|entry| Some((entry.number, entry.digest.as_ref()?)))
        .collect();
    let identity: Identity = build::identity(
        &data.record,
        &data.tags,
        &data.aliases,
        &data.origins,
        data.archived,
        &runs,
        &data.events,
    );
    let mut report = SampleReport::new(identity, now_ms);
    let (static_analysis, mut rules) = build::static_analysis(
        data.report
            .as_ref()
            .map(|found| (&found.report, found.number)),
    );
    report.static_analysis = static_analysis;
    rules.extend(build::merge_detections(&digests));
    report.detections = rules;
    report.attack = build::merge_attack(&digests);
    report.indicators = build::merge_indicators(&digests);
    report.runs = runs;

    let lineage_runs: Vec<RunLineage<'_>> = data
        .runs
        .iter()
        .map(|entry| RunLineage {
            number: entry.number,
            sample: entry
                .run
                .request
                .sample
                .as_ref()
                .map_or("", |sample| sample.sha256.as_str()),
            sample_path: entry.run.request.path.as_str(),
            lineage: entry
                .digest
                .as_ref()
                .and_then(|digest| digest.lineage.as_ref()),
        })
        .collect();
    let known = |sha: &str| {
        data.known.get(sha).map(|(name, verdict)| Known {
            name: name.clone(),
            verdict: verdict.clone(),
        })
    };
    let options = LineageOptions {
        parents: 3,
        children: 3,
        system: std::sync::Arc::clone(&data.system),
        ..LineageOptions::default()
    };
    let graph = build_lineage(
        &data.record.sha256,
        &lineage_runs,
        &data.links,
        &known,
        &options,
    );
    let with_lineage = data
        .runs
        .iter()
        .filter(|entry| entry.digest.as_ref().is_some_and(|d| d.lineage.is_some()))
        .count();
    report.lineage = build::lineage(&graph, with_lineage, data.runs.len());

    let (custody, dropped) = build::custody(&data.chain, &data.events);
    report.custody = custody;
    report.omitted.custody = dropped;
    let (notes, dropped) = build::notes(&data.notes);
    report.notes = notes;
    report.omitted.notes = dropped;
    report.similar = match similar {
        _ if data.record.tlsh.is_empty() => SimilarSection {
            rows: Vec::new(),
            reason: "Too small or too uniform for a similarity hash, so it was not compared."
                .into(),
        },
        Ok(found) => SimilarSection {
            rows: build::similar(&found),
            reason: String::new(),
        },
        Err(error) => SimilarSection {
            rows: Vec::new(),
            reason: format!("The comparison with the library could not be made: {error}"),
        },
    };
    report.seal();
    report
}

fn run_job(job: &Job, status: &dyn Fn(&str)) -> Result<Written, String> {
    status("Reading the sample, its runs and its custody log...");
    let data = detail::load(&job.options, &job.vms, &job.sha256)?;
    status("Comparing with the rest of the library...");
    let exclude: HashSet<String> = data
        .links
        .iter()
        .flat_map(|link| [link.parent.clone(), link.child.clone()])
        .collect();
    let similar = if data.record.tlsh.is_empty() || !data.archived {
        Ok(Vec::new())
    } else {
        Library::open(&job.options.data_dir)
            .and_then(|library| library.similar_to(&job.sha256, &exclude))
    };
    status("Building the report...");
    let report = build_report(&data, &job.options.data_dir, &job.vms, similar, now_ms());
    status("Writing the files...");
    let library = Library::open(&job.options.data_dir)?;
    sample::export::write_and_note(&library, &report, &job.choices, &job.folder)
}

impl ReportDialog {
    pub(super) fn new(sha256: &str, name: &str, choices: Choices) -> Self {
        Self {
            sha256: sha256.to_owned(),
            name: name.to_owned(),
            choices,
            state: State::Idle,
            open: true,
            wrote: false,
        }
    }

    fn start(&mut self, ctx: &egui::Context, options: &BackendOptions, vms: &[(String, String)]) {
        let folder = chosen_folder(&options.data_dir, &self.choices.folder);
        let job = Job {
            options: options.clone(),
            vms: vms.to_vec(),
            sha256: self.sha256.clone(),
            choices: self.choices.clone(),
            folder,
        };
        let (tx, rx) = mpsc::channel();
        let wake = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("sample-report".into())
            .spawn(move || {
                let notify = |text: &str| {
                    let _ = tx.send(Message::Status(text.to_owned()));
                    wake.request_repaint();
                };
                let result = run_job(&job, &notify);
                let _ = tx.send(Message::Done(result));
                wake.request_repaint();
            });
        self.state = match spawned {
            Ok(_) => State::Running {
                rx,
                status: "Starting...".into(),
            },
            Err(error) => State::Failed(format!("could not start the export: {error}")),
        };
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let State::Running { rx, status } = &mut self.state else {
            return;
        };
        let mut finished = None;
        while let Ok(message) = rx.try_recv() {
            match message {
                Message::Status(text) => *status = text,
                Message::Done(result) => finished = Some(result),
            }
        }
        match finished {
            Some(Ok(written)) => {
                self.wrote = !written.files.is_empty();
                self.state = State::Done(written);
            }
            Some(Err(error)) => self.state = State::Failed(error),
            None => ctx.request_repaint_after(std::time::Duration::from_millis(200)),
        }
    }

    /// Draw the window; the folder the files go to is shown as a hint.
    fn show(&mut self, ctx: &egui::Context, options: &BackendOptions, vms: &[(String, String)]) {
        self.poll(ctx);
        let running = matches!(self.state, State::Running { .. });
        let mut open = true;
        let mut start = false;
        let mut close = false;
        let default = default_folder(&options.data_dir);
        let hint = shown_folder(&options.data_dir, &default);
        widgets::window(format!(
            "Export report: {}",
            crate::widgets::short_name(&self.name)
        ))
        .id(egui::Id::new("samples_export_report"))
        .open(&mut open)
        .resizable(false)
        .default_width(540.0)
        .show(ctx, |ui| {
            ui.add_enabled_ui(!running, |ui| {
                ui.label(
                    RichText::new(
                        "Identity, static analysis, rules, every run, lineage, merged \
                             indicators, the custody log, notes and similar samples. The \
                             report names the sample by its hashes and holds none of its bytes.",
                    )
                    .weak(),
                );
                ui.add_space(6.0);
                ui.label(theme::section_title(ui, "Formats"));
                ui.horizontal_wrapped(|ui| {
                    for format in Format::ALL {
                        let mut on = self.choices.writes(format);
                        if ui.checkbox(&mut on, format.label()).changed() {
                            self.choices.set_format(format, on);
                        }
                    }
                });
                ui.add_space(6.0);
                ui.label(theme::section_title(ui, "Options"));
                ui.checkbox(
                    &mut self.choices.defang,
                    "Defang indicators in HTML, PDF and Markdown",
                )
                .on_hover_text("hxxp://example[.]com. JSON, MISP and STIX keep the raw values.");
                ui.add_space(6.0);
                ui.label(theme::section_title(ui, "Folder"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.choices.folder)
                        .hint_text(theme::hint_text(hint))
                        .desired_width(f32::INFINITY),
                )
                .on_hover_text(format!(
                    "Empty: {}. A path that is not absolute is inside the data folder.",
                    default.display()
                ));
            });
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Writing the files adds an Exported entry to the sample's custody log.",
                )
                .weak()
                .small(),
            );
            match &self.state {
                State::Done(written) => {
                    ui.label(theme::section_title(ui, "Written"));
                    crate::widgets::written_files(
                        ui,
                        "report",
                        &written
                            .files
                            .iter()
                            .map(|(l, p)| (l.to_string(), p.clone()))
                            .collect::<Vec<_>>(),
                        4,
                    );
                }
                State::Failed(error) => {
                    ui.add(egui::Label::new(RichText::new(error).color(theme::error())).wrap());
                }
                _ => {}
            }
            let ready = !self.choices.formats.is_empty();
            widgets::footer_split(
                ui,
                |ui| {
                    if let State::Running { status, .. } = &self.state {
                        theme::spinner(ui);
                        ui.label(status);
                    }
                },
                |ui| {
                    if running {
                        close = ui.button("Cancel").clicked();
                    } else {
                        close = ui
                            .button(if matches!(self.state, State::Done(_)) {
                                "Close"
                            } else {
                                "Cancel"
                            })
                            .clicked();
                        start = ui
                            .add_enabled(ready, egui::Button::new("Export"))
                            .on_disabled_hover_text("Choose a format")
                            .clicked();
                    }
                },
            );
        });
        if start {
            self.start(ctx, options, vms);
        }
        if close || !open {
            self.open = false;
        }
    }
}

impl crate::app::MonitorApp {
    /// The Export report… window, drawn every frame while it is open.
    pub(super) fn report_export_window(&mut self, ctx: &egui::Context) {
        let vms: Vec<(String, String)> = self
            .snapshot
            .vms
            .iter()
            .map(|vm| (vm.id.clone(), vm.name.clone()))
            .collect();
        let slot = &mut self.samples_page.report;
        let Some(dialog) = &mut slot.dialog else {
            return;
        };
        dialog.show(ctx, &self.options, &vms);
        slot.choices = dialog.choices.clone();
        let refresh = std::mem::take(&mut dialog.wrote);
        if !dialog.open {
            slot.dialog = None;
        }
        if refresh {
            self.samples_page.refresh();
        }
    }
}

#[cfg(test)]
impl super::SamplesPage {
    /// Open Export report… for the open sample.
    pub(in crate::app) fn open_report_for_test(&mut self) {
        if let Some(data) = self.detail.as_ref().and_then(|detail| detail.data.clone()) {
            self.report.open(&data.record.sha256, &data.record.name);
        }
    }

    /// The Export report… window is open.
    pub(in crate::app) fn report_open(&self) -> bool {
        self.report.dialog.is_some()
    }

    /// Open Export report… for any sample, as the list's menu does.
    pub(in crate::app) fn open_report_for(&mut self, sha256: &str, name: &str) {
        self.report.open(sha256, name);
    }

    /// The files the window wrote, once it has finished.
    pub(in crate::app) fn report_written(&self) -> Option<Vec<PathBuf>> {
        match &self.report.dialog.as_ref()?.state {
            State::Done(written) => Some(written.files.iter().map(|(_, p)| p.clone()).collect()),
            _ => None,
        }
    }

    /// The window has failed, with why.
    pub(in crate::app) fn report_failure(&self) -> Option<String> {
        match &self.report.dialog.as_ref()?.state {
            State::Failed(why) => Some(why.clone()),
            _ => None,
        }
    }

    /// Click Export in the open window (formats and folder as given).
    pub(in crate::app) fn start_report_for_test(
        &mut self,
        ctx: &egui::Context,
        options: &BackendOptions,
        vms: &[(String, String)],
        formats: &[Format],
        folder: &str,
    ) {
        if let Some(dialog) = &mut self.report.dialog {
            dialog.choices.formats = formats.to_vec();
            dialog.choices.folder = folder.to_owned();
            dialog.start(ctx, options, vms);
        }
    }

    /// The report the worker would build for `sha256`, read the way the
    /// window reads the sample.
    pub(in crate::app) fn report_for_test(
        options: &BackendOptions,
        vms: &[(String, String)],
        sha256: &str,
    ) -> Result<SampleReport, String> {
        let data = detail::load(options, vms, sha256)?;
        Ok(build_report(
            &data,
            &options.data_dir,
            vms,
            Ok(Vec::new()),
            1_792_000_000_000,
        ))
    }
}

#[cfg(test)]
mod folder_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn the_folder_is_shown_inside_the_data_directory_and_whole_outside_it() {
        let data = Path::new("/home/analyst/.local/share/antinomie");
        assert_eq!(shown_folder(data, &default_folder(data)), "sample-reports");
        assert_eq!(shown_folder(data, &data.join("exports/a")), "exports/a");
        assert_eq!(
            shown_folder(data, Path::new("/mnt/usb/reports")),
            "/mnt/usb/reports"
        );
        assert!(!shown_folder(data, &default_folder(data)).contains("analyst"));
    }

    #[test]
    fn a_typed_folder_is_empty_for_the_default_relative_to_the_data_directory_or_absolute() {
        let data = Path::new("/d");
        assert_eq!(chosen_folder(data, "  "), Path::new("/d/sample-reports"));
        assert_eq!(chosen_folder(data, "exports"), Path::new("/d/exports"));
        assert_eq!(chosen_folder(data, " /mnt/x "), Path::new("/mnt/x"));
    }
}
