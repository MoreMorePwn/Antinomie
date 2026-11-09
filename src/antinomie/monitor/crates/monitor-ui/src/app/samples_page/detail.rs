// SPDX-License-Identifier: GPL-3.0-only
//! The sample window: one library sample with its Summary, its Runs and its
//! custody log. It replaces the list inside the Samples page (a back link
//! returns), and reads everything about the sample on a worker thread: the
//! library record, every VM's runs of it, and the regex scan of its static
//! report.
use super::*;
use crate::{
    sample_tags,
    widgets::{self, Tone},
};
use antinomie_monitor_core::{
    samples::{Alias, ChainCheck, EventRow, Origin, StringRow},
    AnalysisReport, RunArtifacts,
};
use std::{
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
};

mod artifact_rows;
mod custody;
mod family_field;
mod iocs;
mod iocs_details;
mod iocs_export;
mod lineage;
mod load;
pub(super) use load::load;
use load::scan;
mod notes_tab;
mod output_files;
mod parts;
mod run_box;
#[cfg(test)]
pub(crate) use run_box::fixture_run;
pub(crate) use run_box::{show as show_run_box, Open as ArtifactOpen, RunBoxState};
mod runs;
mod similar;
mod summary;
mod triage_parts;
mod written_files;

/// The width a column of texts needs, within `most` (see `parts`).
pub(super) fn fitted_up_to(
    ui: &egui::Ui,
    font: &egui::FontId,
    texts: impl IntoIterator<Item = String>,
    most: f32,
) -> f32 {
    parts::fitted_up_to(ui, font, texts, most)
}

/// A time as the event rows show it.
pub(super) fn second(ms: u64) -> String {
    parts::second(ms)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tab {
    Summary,
    Runs,
    Iocs,
    Custody,
    Notes,
}

/// One run of the sample, numbered in start order (run 1 is the oldest).
pub(super) struct RunEntry {
    pub(super) number: usize,
    /// How the run used this sample: empty when it ran the sample, else
    /// "preloaded", "audit library" or "named in arguments".
    pub(super) role: &'static str,
    /// Without the static-analysis rows; the report is in [`Data::report`].
    pub(super) run: RunSummary,
    /// The run's folder is still on disk.
    pub(super) folder: bool,
    pub(super) artifacts: Option<RunArtifacts>,
    /// What Triage found in the run, when it has read it.
    pub(super) digest: Option<antinomie_monitor_core::run_digest::RunDigest>,
}

/// The static report the Summary reads: the newest finished one.
pub(super) struct ReportRef {
    pub(super) vm_id: String,
    pub(super) run_id: String,
    pub(super) number: usize,
    /// The run's `analysis` folder.
    pub(super) directory: PathBuf,
    pub(super) report: AnalysisReport,
}

/// A library sample sent into a VM, to tell which process runs one.
pub(super) struct SentSample {
    pub(super) vm_id: String,
    pub(super) path: String,
    pub(super) sha256: String,
}

/// Everything the window shows, read once and read again on a change.
pub(super) struct Data {
    pub(super) record: SampleRecord,
    pub(super) tags: Vec<Tag>,
    pub(super) origins: Vec<Origin>,
    pub(super) aliases: Vec<Alias>,
    pub(super) events: Vec<EventRow>,
    /// The custody log checked against the library index.
    pub(super) chain: ChainCheck,
    pub(super) archive: std::path::PathBuf,
    pub(super) archived: bool,
    /// Newest first.
    pub(super) runs: Vec<RunEntry>,
    /// What the runs' Triage digests add up to.
    pub(super) rollup: antinomie_monitor_core::samples::Rollup,
    /// Every indicator over the runs, for the IOCs tab.
    pub(super) iocs: antinomie_monitor_core::samples::IocUnion,
    /// What the runs left behind, for Output files.
    pub(super) outputs: Vec<output_files::Output>,
    /// The notes of the sample, newest first.
    pub(super) notes: Vec<antinomie_monitor_core::samples::Note>,
    /// The data folder, for what the window reads later (file hashes).
    data_dir: std::path::PathBuf,
    /// Every library sample's name and verdict, by SHA-256, for the lineage
    /// graph's marks.
    pub(super) known: std::collections::BTreeMap<String, (String, String)>,
    /// Edges between library samples from their origins.
    pub(super) links: Vec<antinomie_monitor_core::samples::Link>,
    pub(super) report: Option<ReportRef>,
    /// Where every library sample was sent, for the process tree's tint.
    pub(super) sent: Vec<SentSample>,
    /// SHA-256 of the base-image programs the runs used, for the lineage
    /// graph's Hide system binaries.
    pub(super) system: Arc<std::collections::BTreeSet<String>>,
}

/// The rows the Summary draws from the report's regex scan.
pub(super) struct Strings {
    /// The 100 longest strings, longest first.
    pub(super) longest: Vec<StringRow>,
    pub(super) matches: Vec<StringRow>,
    /// Matches of the scan, repeats included: the Regex matches tab's count.
    pub(super) total: u64,
}

pub(super) enum Scanned {
    /// No report to scan.
    None,
    Reading,
    Done(Strings),
    Failed(String),
}

type Loaded = Result<Data, String>;

/// How long a failed read waits before it is tried again.
const RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(1);
type ScanResult = Result<Strings, String>;

pub(super) struct Detail {
    pub(super) sha256: String,
    pub(super) tab: Tab,
    pub(super) data: Option<Arc<Data>>,
    loading: Option<Receiver<Loaded>>,
    /// Read the sample again at the next frame.
    pub(super) stale: bool,
    pub(super) error: Option<String>,
    /// When a failed read is tried again: a busy library is not the end of
    /// the window.
    retry: Option<std::time::Instant>,
    /// What a note's chip named, until the tab it is on has centred on it.
    pub(super) focus: Option<antinomie_monitor_core::samples::NoteRef>,
    pub(super) scanned: Scanned,
    scanning: Option<(Receiver<ScanResult>, Arc<AtomicBool>, String)>,
    /// The report the scan above is of, to scan again when it changes.
    scanned_report: Option<String>,
    runs: runs::RunsTab,
    /// The IOCs tab's filters, selection and export window.
    iocs: iocs::State,
    /// The archive is being read back.
    pub(super) verify:
        Option<Receiver<Result<antinomie_monitor_core::samples::Verification, String>>>,
    /// The last read-back: whether it matched, and why not.
    pub(super) verified: Option<(bool, String)>,
    /// The Lineage section's options and view.
    lineage: lineage::State,
    /// The comparison with the rest of the library.
    similar: similar::State,
}

impl Drop for Detail {
    fn drop(&mut self) {
        if let Some((_, cancel, _)) = &self.scanning {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

impl Detail {
    pub(super) fn new(sha256: &str) -> Self {
        Self {
            sha256: sha256.to_owned(),
            tab: Tab::Summary,
            data: None,
            loading: None,
            stale: true,
            error: None,
            retry: None,
            focus: None,
            scanned: Scanned::None,
            scanning: None,
            scanned_report: None,
            runs: runs::RunsTab::default(),
            iocs: iocs::State::default(),
            verify: None,
            verified: None,
            lineage: lineage::State::default(),
            similar: similar::State::default(),
        }
    }
}

impl SamplesPage {
    /// Open the window of a sample.
    pub(in crate::app) fn open_detail(&mut self, sha256: &str) {
        self.detail = Some(Detail::new(sha256));
    }

    /// Open the window of a sample on its Notes tab.
    pub(super) fn open_notes(&mut self, sha256: &str) {
        let mut detail = Detail::new(sha256);
        detail.tab = Tab::Notes;
        self.detail = Some(detail);
    }

    /// Open the window of a sample on its Custody log tab.
    pub(super) fn open_custody(&mut self, sha256: &str) {
        let mut detail = Detail::new(sha256);
        detail.tab = Tab::Custody;
        self.detail = Some(detail);
    }

    /// Open the viewer on the archived sample.
    pub(super) fn open_viewer(
        &mut self,
        ctx: &egui::Context,
        record: &SampleRecord,
        archive: PathBuf,
    ) {
        self.viewer = Some(super::viewer::Viewer::open(
            ctx,
            &record.sha256,
            &record.name,
            record.size,
            archive,
        ));
    }

    /// Read the sample again at the next frame.
    pub(super) fn refresh_detail(&mut self) {
        if let Some(detail) = &mut self.detail {
            detail.stale = true;
        }
    }
}

impl Detail {
    fn start_load(&mut self, ctx: &egui::Context, options: &BackendOptions, vms: &[VmConfig]) {
        if self.loading.is_some() {
            return;
        }
        self.stale = false;
        let (sender, receiver) = mpsc::channel();
        let options = options.clone();
        let sha256 = self.sha256.clone();
        let vms: Vec<(String, String)> = vms
            .iter()
            .map(|vm| (vm.id.clone(), vm.name.clone()))
            .collect();
        let wake = ctx.clone();
        match std::thread::Builder::new()
            .name("sample-detail".into())
            .spawn(move || {
                let _ = sender.send(load(&options, &vms, &sha256));
                wake.request_repaint();
            }) {
            Ok(_) => self.loading = Some(receiver),
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn start_scan(&mut self, ctx: &egui::Context, data_dir: &std::path::Path, data: &Data) {
        let Some(reference) = &data.report else {
            self.scanned = Scanned::None;
            self.scanned_report = None;
            return;
        };
        if self.scanned_report.as_deref() == Some(reference.report.id.as_str()) {
            return;
        }
        if let Some((_, cancel, _)) = self.scanning.take() {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.scanned_report = Some(reference.report.id.clone());
        self.scanned = Scanned::Reading;
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker = Arc::clone(&cancel);
        let reference = ReportRef {
            vm_id: reference.vm_id.clone(),
            run_id: reference.run_id.clone(),
            number: reference.number,
            directory: reference.directory.clone(),
            report: reference.report.clone(),
        };
        let data_dir = data_dir.to_path_buf();
        let wake = ctx.clone();
        let id = reference.report.id.clone();
        match std::thread::Builder::new()
            .name("sample-strings".into())
            .spawn(move || {
                let _ = sender.send(scan(data_dir, &reference, &worker));
                wake.request_repaint();
            }) {
            Ok(_) => self.scanning = Some((receiver, cancel, id)),
            Err(error) => self.scanned = Scanned::Failed(error.to_string()),
        }
    }

    /// Read the archive back and compare its SHA-256.
    pub(super) fn start_verify(&mut self, ctx: &egui::Context, data_dir: &std::path::Path) {
        if self.verify.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let data_dir = data_dir.to_path_buf();
        let sha256 = self.sha256.clone();
        let wake = ctx.clone();
        match std::thread::Builder::new()
            .name("sample-verify".into())
            .spawn(move || {
                let _ = sender.send(Library::open(&data_dir).and_then(|l| l.verify(&sha256)));
                wake.request_repaint();
            }) {
            Ok(_) => self.verify = Some(receiver),
            Err(error) => self.verified = Some((false, error.to_string())),
        }
    }

    fn poll(&mut self) {
        self.similar.poll();
        if let Some(receiver) = &self.loading {
            if let Ok(result) = receiver.try_recv() {
                self.loading = None;
                match result {
                    Ok(data) => {
                        self.data = Some(Arc::new(data));
                        self.error = None;
                        self.retry = None;
                    }
                    Err(error) => {
                        self.error = Some(error);
                        self.retry = Some(std::time::Instant::now() + RETRY_AFTER);
                    }
                }
            }
        }
        if let Some(receiver) = &self.verify {
            if let Ok(result) = receiver.try_recv() {
                use antinomie_monitor_core::samples::Verification;
                self.verify = None;
                self.verified = Some(match result {
                    Ok(Verification::Matches) => (true, String::new()),
                    Ok(Verification::Missing) => (false, "the archive is missing".into()),
                    Ok(Verification::Mismatch(why)) => (false, why),
                    Err(error) => (false, error),
                });
                self.stale = true;
            }
        }
        if let Some((receiver, _, _)) = &self.scanning {
            if let Ok(result) = receiver.try_recv() {
                self.scanning = None;
                self.scanned = match result {
                    Ok(strings) => Scanned::Done(strings),
                    Err(error) => Scanned::Failed(error),
                };
            }
        }
    }
}

enum Action {
    Back,
    EditTags,
    EditText,
    RunInVm,
    /// Send the library into the VM and run this command line with it in `LD_PRELOAD`.
    LoadInto(String),
    Export,
    Report,
}

impl MonitorApp {
    /// The window of the open sample: header, tabs and the tab's body.
    pub(super) fn detail_view(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let vms = self.snapshot.vms.clone();
        let options = self.options.clone();
        let Some(detail) = &mut self.samples_page.detail else {
            return;
        };
        detail.poll();
        if let Some(at) = detail.retry {
            let now = std::time::Instant::now();
            if now >= at {
                detail.retry = None;
                detail.stale = true;
            } else {
                ctx.request_repaint_after(at - now);
            }
        }
        if detail.stale || detail.data.is_none() && detail.loading.is_none() {
            detail.start_load(&ctx, &options, &vms);
        }
        let data = detail.data.clone();
        if let Some(data) = &data {
            detail.similar.start(&ctx, &options.data_dir, data);
            detail.start_scan(&ctx, &options.data_dir, data);
        }
        let mut action = None;
        let Some(data) = data else {
            ui.horizontal(|ui| {
                if widgets::back_link(ui, "‹ All samples").clicked() {
                    action = Some(Action::Back);
                }
                if let Some(error) = &detail.error {
                    ui.colored_label(theme::error(), error);
                } else {
                    theme::spinner(ui);
                }
            });
            if matches!(action, Some(Action::Back)) {
                self.samples_page.detail = None;
            }
            return;
        };
        self.detail_header(ui, &data, &mut action);
        let Some(detail) = &mut self.samples_page.detail else {
            return;
        };
        widgets::tab_row(ui, |ui| {
            for (tab, label, count) in [
                (Tab::Summary, "Summary", None),
                (Tab::Runs, "Runs", Some(data.runs.len())),
                (Tab::Iocs, "IOCs", None),
                (Tab::Custody, "Custody log", Some(data.events.len())),
                (Tab::Notes, "Notes", Some(data.notes.len())),
            ] {
                let mut item = widgets::TabItem::new(label);
                if let Some(count) = count {
                    item = item.badge(count.to_string(), Tone::Neutral);
                }
                if tab == Tab::Iocs {
                    item = iocs::tab_item(label, &data);
                }
                if widgets::tab(ui, detail.tab == tab, &item).clicked() {
                    detail.tab = tab;
                }
            }
        });
        ui.separator();
        match detail.tab {
            Tab::Summary => self.summary_tab(ui, &data),
            Tab::Runs => self.runs_tab(ui, &data),
            Tab::Iocs => self.iocs_tab(ui, &data),
            Tab::Custody => {
                let verifying = detail.loading.is_some();
                // A note's chip named an entry: bring it to the middle.
                let entry = detail
                    .focus
                    .take_if(|reference| {
                        reference.kind == antinomie_monitor_core::samples::RefKind::Custody
                    })
                    .and_then(|reference| reference.target.parse::<u64>().ok());
                if let custody::Outcome::Verify =
                    custody::show(ui, &data, self.settings.font_size, verifying, entry)
                {
                    detail.stale = true;
                }
            }
            Tab::Notes => self.notes_tab(ui, &data),
        }
        match action {
            Some(Action::Back) => self.samples_page.detail = None,
            Some(Action::EditTags) => {
                self.samples_page.editing = Some((
                    data.record.sha256.clone(),
                    data.record.name.clone(),
                    picker::TagPicker::with(&data.tags),
                ));
            }
            Some(Action::EditText) => self.samples_page.edit_text_of(
                &data.record.sha256,
                &data.record.name,
                &data.record.description,
            ),
            Some(Action::RunInVm) => self.run_sample_in_vm(&data.record),
            Some(Action::LoadInto(program)) => self.load_sample_into(&data.record, &program),
            Some(Action::Export) => {
                self.samples_page.export = Some(super::export::ExportDialog::new(
                    &data.record,
                    data.chain.clone(),
                    crate::export_dirs::default_folder(&self.options.data_dir, "custody"),
                ));
            }
            Some(Action::Report) => self
                .samples_page
                .report
                .open(&data.record.sha256, &data.record.name),
            None => {}
        }
    }

    fn detail_header(&mut self, ui: &mut egui::Ui, data: &Data, action: &mut Option<Action>) {
        let guest = self
            .selected_vm()
            .map(|vm| crate::app::base_arch(&self.snapshot, vm.base_identity.as_deref()));
        let why = run_error(&data.record, guest);
        let can_run = self.running() && why.is_none();
        let mut back = false;
        let mut chosen = None;
        // The back link has a line of its own; the title bar with the
        // sample's actions sits under it.
        if widgets::back_link(ui, "‹ All samples").clicked() {
            back = true;
        }
        ui.add_space(2.0);
        // The buttons beside the title (about 70 font heights), the verdict
        // tags and the gaps are kept; a long name is cut to what is left,
        // and the whole name is on hover and in Identity.
        let wide = ui.available_width() >= self.settings.font_size * 80.0;
        let room = if wide {
            ui.available_width() - self.settings.font_size * 62.0
        } else {
            ui.available_width() - self.settings.font_size * 8.0
        }
        .max(120.0);
        let title = |ui: &mut egui::Ui| {
            ui.scope(|ui| {
                ui.set_max_width(room);
                ui.add(
                    egui::Label::new(
                        RichText::new(&data.record.name)
                            .strong()
                            .size(ui.text_style_height(&egui::TextStyle::Heading))
                            .color(theme::identity()),
                    )
                    .truncate(),
                )
                .on_hover_text(&data.record.name);
            });
            for tag in data
                .tags
                .iter()
                .filter(|tag| tag.kind == antinomie_monitor_core::samples::TagKind::Verdict)
            {
                sample_tags::tag(ui, tag);
            }
            if self.samples_page.loading_detail() {
                theme::spinner(ui);
            }
        };
        let buttons = |ui: &mut egui::Ui| {
            if ui
                .button("Export report…")
                .on_hover_text(
                    "A report of the sample: identity, static analysis, every run, lineage, \
                         indicators and custody. HTML, PDF, JSON, MISP, STIX or Markdown",
                )
                .clicked()
            {
                chosen = Some(Action::Report);
            }
            if ui
                .button("Export custody record…")
                .on_hover_text("JSON with a verifier, or HTML; optionally signed with your own key")
                .clicked()
            {
                chosen = Some(Action::Export);
            }
            if ui
                .add_enabled(can_run, egui::Button::new("Run in VM…"))
                .on_hover_text(
                    "Send the archive into the running VM (its SHA-256 is read back first) \
                         and open Run program with it",
                )
                .on_disabled_hover_text(why.clone().unwrap_or_else(|| "Start a VM first".into()))
                .clicked()
            {
                chosen = Some(Action::RunInVm);
            }
            if data.record.file_type.eq_ignore_ascii_case("elf") {
                // The program to run with this library preloaded.
                let memory = egui::Id::new(("load-into-program", &data.record.sha256));
                let mut program = ui
                    .data_mut(|d| d.get_temp::<String>(memory))
                    .unwrap_or_else(|| "/bin/sh".to_owned());
                ui.add_enabled_ui(can_run, |ui| {
                    ui.menu_button("Load into…", |ui| {
                        ui.label("Program (and arguments) to run with this library in LD_PRELOAD:");
                        ui.add(
                            egui::TextEdit::singleline(&mut program)
                                .desired_width(280.0)
                                .hint_text("/bin/sh -c ls"),
                        );
                        if ui
                            .add_enabled(!program.trim().is_empty(), egui::Button::new("Send and open Run program"))
                            .on_hover_text(
                                "Sends the library into the running VM, then opens Run program with the program and LD_PRELOAD set to the library",
                            )
                            .clicked()
                        {
                            chosen = Some(Action::LoadInto(program.trim().to_owned()));
                            ui.close();
                        }
                    })
                    .response
                    .on_hover_text("Run a program with this library preloaded into it");
                });
                ui.data_mut(|d| d.insert_temp(memory, program));
            }
            if ui.button("Edit tags…").clicked() {
                chosen = Some(Action::EditTags);
            }
            if ui.button("Edit name and description…").clicked() {
                chosen = Some(Action::EditText);
            }
        };
        // Four buttons beside the title need about 65 font heights; a
        // narrower window gives the buttons their own row.
        if !wide {
            ui.horizontal_wrapped(title);
            ui.horizontal_wrapped(buttons);
        } else {
            egui::Sides::new().show(ui, title, buttons);
        }
        if back {
            *action = Some(Action::Back);
        } else if chosen.is_some() {
            *action = chosen;
        }
        if guest.is_some() && data.record.removed_ms.is_none() {
            show_refusal(ui, why.as_deref());
        }
        if !data.archived {
            ui.colored_label(
                theme::error(),
                if data.record.removed_ms.is_some() {
                    "The archive was removed. Adding the same file again restores it."
                } else {
                    "The archive is not in the library folder."
                },
            );
        }
    }
}

impl SamplesPage {
    /// A run is selected on the open sample's Runs tab: Details show it.
    pub(in crate::app) fn wants_details(&self) -> bool {
        self.detail.as_ref().is_some_and(|detail| match detail.tab {
            Tab::Runs => detail.runs.has_selection(),
            Tab::Iocs => detail.iocs.has_selection(),
            _ => false,
        })
    }

    fn loading_detail(&self) -> bool {
        self.detail
            .as_ref()
            .is_some_and(|detail| detail.loading.is_some())
    }
}

/// The sample's mismatch with the selected VM, in words, under the buttons.
fn show_refusal(ui: &mut egui::Ui, why: Option<&str>) {
    if let Some(why) = why {
        ui.colored_label(theme::warn(), why);
    }
}

#[cfg(test)]
mod gate_tests;

/// Why the sample cannot be sent into a VM of architecture `guest` (any VM
/// when None) and run, when it cannot: the architecture rule is Run program's.
pub(super) fn run_error(
    record: &SampleRecord,
    guest: Option<antinomie_monitor_core::GuestArch>,
) -> Option<String> {
    if record.removed_ms.is_some() {
        return Some("The archive was removed".into());
    }
    let kind = record.file_type.to_ascii_lowercase();
    antinomie_monitor_core::samples::run_verdict(
        matches!(kind.as_str(), "sh" | "bash"),
        kind == "elf",
        Some(record.arch.as_str()),
        guest,
    )
    .err()
}

/// The ATT&CK techniques Triage mapped in the sample's runs, as tag labels,
/// leaving out those the sample already carries: the picker's From Triage.
pub(super) fn suggested_techniques(data: &Data) -> Vec<String> {
    use antinomie_monitor_core::samples::TagKind;
    let mut labels: Vec<String> = Vec::new();
    for technique in data
        .rollup
        .tactics
        .iter()
        .flat_map(|tactic| &tactic.techniques)
    {
        let label = antinomie_monitor_core::mitre::technique_label(&technique.id);
        let carried = data
            .tags
            .iter()
            .any(|tag| tag.kind == TagKind::Technique && tag.value == label);
        if !carried && !labels.contains(&label) {
            labels.push(label);
        }
    }
    labels
}

impl MonitorApp {
    /// Send the archive into the running VM (the worker reads it back and
    /// compares its SHA-256 first), then open Run program with it.
    fn run_sample_in_vm(&mut self, record: &SampleRecord) {
        let destination = record.guest_path();
        let script = matches!(
            record.file_type.to_ascii_lowercase().as_str(),
            "sh" | "bash"
        );
        let uid = 1000;
        let run = ExecRequest {
            path: if script {
                "/bin/sh".into()
            } else {
                destination.clone()
            },
            args: if script {
                vec![destination.clone()]
            } else {
                Vec::new()
            },
            uid,
            gid: uid,
            cwd: "/tmp".into(),
            ..ExecRequest::default()
        };
        self.samples.await_run(run);
        self.send(Command::UploadSample {
            sha256: record.sha256.clone(),
            destination,
            executable: true,
        });
    }
}

impl MonitorApp {
    /// Send the library into the running VM, then open Run program with
    /// `command` (a program and plain-space-separated arguments) and
    /// `LD_PRELOAD` set to where the library lands.
    fn load_sample_into(&mut self, record: &SampleRecord, command: &str) {
        let destination = record.guest_path();
        let mut words = command.split_whitespace().map(str::to_owned);
        let Some(path) = words.next() else { return };
        let mut run = ExecRequest {
            path,
            args: words.collect(),
            uid: 1000,
            gid: 1000,
            cwd: "/tmp".into(),
            ..ExecRequest::default()
        };
        run.env.push(format!("LD_PRELOAD={destination}"));
        self.samples.await_run(run);
        self.send(Command::UploadSample {
            sha256: record.sha256.clone(),
            destination,
            executable: true,
        });
    }
}

/// Runs read, whether a report was found, and the scan's rows once done.
#[cfg(test)]
pub(in crate::app) type Probe = (usize, bool, Option<(usize, usize, u64)>);

#[cfg(test)]
impl SamplesPage {
    /// The least widths of the Runs list's Arguments, Tree status, Root exit
    /// and VM columns.
    #[cfg(test)]
    pub(in crate::app) fn run_column_minimums() -> [f32; 4] {
        use runs::{RUN_ARGUMENTS_MIN, RUN_EXIT_MIN, RUN_STATUS_MIN, RUN_VM_MIN};
        [RUN_ARGUMENTS_MIN, RUN_STATUS_MIN, RUN_EXIT_MIN, RUN_VM_MIN]
    }

    /// Show the tab named `summary`, `runs` or `custody`.
    pub(in crate::app) fn show_detail_tab(&mut self, name: &str) {
        if let Some(detail) = &mut self.detail {
            detail.tab = match name {
                "runs" => Tab::Runs,
                "iocs" => Tab::Iocs,
                "custody" => Tab::Custody,
                "notes" => Tab::Notes,
                _ => Tab::Summary,
            };
        }
    }

    /// Scroll the Summary to the section titled `title`, once it is drawn.
    pub(in crate::app) fn scroll_detail_to(ctx: &egui::Context, title: &str) {
        parts::scroll_to_section(ctx, title);
    }

    /// Select the run at `index` of the Runs tab's list (screenshots).
    pub(in crate::app) fn select_detail_run(&mut self, index: usize) {
        if let Some(detail) = &mut self.detail {
            if let Some(entry) = detail.data.as_ref().and_then(|data| data.runs.get(index)) {
                let id = entry.run.id.clone();
                detail.runs.select_for_test(id);
            }
        }
    }

    /// Whether each list row's custody log verified, by SHA-256.
    pub(in crate::app) fn list_custody_ok(&self) -> Vec<(String, bool)> {
        self.rows
            .iter()
            .map(|row| (row.record.sha256.clone(), row.custody_ok))
            .collect()
    }

    /// What the tag picker offers under From Triage for the open sample.
    pub(in crate::app) fn detail_suggestions(&self) -> Vec<String> {
        self.detail
            .as_ref()
            .and_then(|detail| detail.data.as_ref())
            .map(|data| suggested_techniques(data))
            .unwrap_or_default()
    }

    pub(in crate::app) fn detail_open(&self) -> bool {
        self.detail.is_some()
    }

    pub(in crate::app) fn close_detail(&mut self) {
        self.detail = None;
    }

    /// Runs read, whether a static report was found, and the rows of the
    /// scan (longest strings, regex matches, match count) once done.
    pub(in crate::app) fn detail_probe(&self) -> Option<Probe> {
        let detail = self.detail.as_ref()?;
        let data = detail.data.as_ref()?;
        Some((
            data.runs.len(),
            data.report.is_some(),
            match &detail.scanned {
                Scanned::Done(strings) => {
                    Some((strings.longest.len(), strings.matches.len(), strings.total))
                }
                _ => None,
            },
        ))
    }

    /// The custody log as the window read it: entries listed, whether the
    /// chain verified, and the entry the first problem is at.
    pub(in crate::app) fn detail_custody(&self) -> Option<(usize, bool, Option<u64>)> {
        let data = self.detail.as_ref()?.data.as_ref()?;
        Some((
            data.events.len(),
            data.chain.ok(),
            data.chain.problem.as_ref().map(|problem| problem.at),
        ))
    }

    /// Open Export custody record… for the open sample.
    pub(in crate::app) fn open_export_for_test(&mut self) {
        if let Some(data) = self.detail.as_ref().and_then(|detail| detail.data.clone()) {
            self.export = Some(super::export::ExportDialog::new(
                &data.record,
                data.chain.clone(),
                std::env::temp_dir().join("antinomie-custody-test"),
            ));
        }
    }

    /// The run ids in the order the Runs tab lists them (newest first).
    pub(in crate::app) fn detail_run_ids(&self) -> Vec<String> {
        self.detail
            .as_ref()
            .and_then(|detail| detail.data.as_ref())
            .map(|data| data.runs.iter().map(|entry| entry.run.id.clone()).collect())
            .unwrap_or_default()
    }

    /// How each run used the open sample, in the Runs tab's order ("" when it ran it).
    pub(in crate::app) fn detail_run_roles(&self) -> Vec<&'static str> {
        self.detail
            .as_ref()
            .and_then(|detail| detail.data.as_ref())
            .map(|data| data.runs.iter().map(|entry| entry.role).collect())
            .unwrap_or_default()
    }

    /// What the runs' digests add up to, once the window has read them.
    pub(in crate::app) fn detail_rollup(&self) -> Option<antinomie_monitor_core::samples::Rollup> {
        Some(self.detail.as_ref()?.data.as_ref()?.rollup.clone())
    }

    /// The lineage graph the Summary draws, once built.
    pub(in crate::app) fn detail_lineage(
        &mut self,
    ) -> Option<antinomie_monitor_core::samples::LineageGraph> {
        let detail = self.detail.as_mut()?;
        let data = detail.data.clone()?;
        detail.lineage.graph_for_test(&data)
    }

    /// Set the lineage graph's levels and system-binary toggle (screenshots).
    pub(in crate::app) fn set_lineage(&mut self, parents: usize, children: usize, hide: bool) {
        if let Some(detail) = &mut self.detail {
            detail.lineage.set_levels(parents, children, hide);
        }
    }

    /// Open Add to Samples… on a file of the first run (screenshots).
    pub(in crate::app) fn open_promote_for_test(&mut self, data_dir: &std::path::Path) {
        let Some(data) = self.detail.as_ref().and_then(|detail| detail.data.clone()) else {
            return;
        };
        let runs = data
            .runs
            .iter()
            .map(|entry| super::promote::RunChoice {
                number: entry.number,
                run_id: entry.run.id.clone(),
                vm_id: entry.run.vm_id.clone(),
                vm_name: "Debian".into(),
                directory: entry.run.directory.clone(),
                dump: None,
            })
            .collect();
        self.promote = Some(super::promote::Promote::new(
            data_dir,
            "/tmp/.x".into(),
            "b5".repeat(32),
            data.record.sha256.clone(),
            "/tmp/install.sh".into(),
            runs,
        ));
    }

    /// Open the viewer on the open sample's archive.
    pub(in crate::app) fn view_content(&mut self, ctx: &egui::Context) {
        if let Some(data) = self.detail.as_ref().and_then(|detail| detail.data.clone()) {
            self.open_viewer(ctx, &data.record, data.archive.clone());
        }
    }

    pub(in crate::app) fn viewer_ready(&self) -> bool {
        self.viewer.as_ref().is_some_and(|viewer| viewer.is_ready())
    }

    pub(in crate::app) fn viewer_open(&self) -> bool {
        self.viewer.is_some()
    }

    /// What Output files lists: kind, run, availability, size.
    pub(in crate::app) fn detail_outputs(&self) -> Vec<(String, usize, String, Option<u64>)> {
        self.detail
            .as_ref()
            .and_then(|detail| detail.data.as_ref())
            .map(|data| {
                data.outputs
                    .iter()
                    .map(|output| {
                        (
                            output.kind_label().to_owned(),
                            output.number,
                            format!("{:?}", output.availability),
                            output.size,
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The Similar samples rows (name, distance, shared) once compared.
    pub(in crate::app) fn detail_similar(&self) -> Option<Vec<(String, i32, String)>> {
        let found = self.detail.as_ref()?.similar.rows()?;
        Some(
            found
                .iter()
                .map(|row| (row.name.clone(), row.distance, row.shared.label()))
                .collect(),
        )
    }

    /// A line for a failing test: what the window is waiting on.
    pub(in crate::app) fn detail_state(&self) -> String {
        let Some(detail) = &self.detail else {
            return "no window".into();
        };
        format!(
            "runs {:?}, report {}, error {:?}, scan {}",
            detail.data.as_ref().map(|data| data.runs.len()),
            detail
                .data
                .as_ref()
                .is_some_and(|data| data.report.is_some()),
            detail.error,
            match &detail.scanned {
                Scanned::None => "none".to_owned(),
                Scanned::Reading => "reading".to_owned(),
                Scanned::Done(_) => "done".to_owned(),
                Scanned::Failed(why) => format!("failed: {why}"),
            }
        )
    }

    pub(in crate::app) fn open_run_pending(&self) -> bool {
        self.open_run.is_some()
    }
}

/// Names and verdicts by SHA-256, and the edges between samples.
type LineageLinks = (
    std::collections::BTreeMap<String, (String, String)>,
    Vec<antinomie_monitor_core::samples::Link>,
);

/// The library's names and verdicts, and the edges its origins make between
/// samples (a sample dropped or promoted from another).
fn lineage_links(
    library: &Library,
    sha256: &str,
    entries: &[RunEntry],
) -> Result<LineageLinks, String> {
    use antinomie_monitor_core::samples::{EdgeKind, Link, OriginKind, TagKind};
    let numbers: std::collections::HashMap<&str, usize> = entries
        .iter()
        .map(|entry| (entry.run.id.as_str(), entry.number))
        .collect();
    let mut known = std::collections::BTreeMap::new();
    let mut links = Vec::new();
    for other in library.list()? {
        let verdict = library
            .tags(&other.sha256)?
            .into_iter()
            .find(|tag| tag.kind == TagKind::Verdict)
            .map(|tag| tag.value)
            .unwrap_or_default();
        for origin in library.origins(&other.sha256)? {
            if origin.parent.is_empty() || (other.sha256 != sha256 && origin.parent != sha256) {
                continue;
            }
            links.push(Link {
                parent: origin.parent.clone(),
                child: other.sha256.clone(),
                kind: if origin.kind == OriginKind::Download {
                    EdgeKind::Downloaded
                } else {
                    EdgeKind::Dropped
                },
                run: numbers.get(origin.run_id.as_str()).copied(),
            });
        }
        known.insert(other.sha256, (other.name, verdict));
    }
    Ok((known, links))
}
