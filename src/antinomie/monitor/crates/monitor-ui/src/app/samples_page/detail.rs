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
mod lineage;
mod notes_tab;
mod output_files;
mod parts;
mod runs;
mod similar;
mod summary;
mod triage_parts;

/// A time as the event rows show it.
pub(super) fn second(ms: u64) -> String {
    parts::second(ms)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tab {
    Summary,
    Runs,
    Custody,
    Notes,
}

/// One run of the sample, numbered in start order (run 1 is the oldest).
pub(super) struct RunEntry {
    pub(super) number: usize,
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
}

/// The rows the Summary draws from the report's regex scan.
pub(super) struct Strings {
    pub(super) interesting: Vec<StringRow>,
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
type ScanResult = Result<Strings, String>;

pub(super) struct Detail {
    pub(super) sha256: String,
    pub(super) tab: Tab,
    pub(super) data: Option<Arc<Data>>,
    loading: Option<Receiver<Loaded>>,
    /// Read the sample again at the next frame.
    pub(super) stale: bool,
    pub(super) error: Option<String>,
    pub(super) scanned: Scanned,
    scanning: Option<(Receiver<ScanResult>, Arc<AtomicBool>, String)>,
    /// The report the scan above is of, to scan again when it changes.
    scanned_report: Option<String>,
    runs: runs::RunsTab,
    /// The archive is being read back.
    pub(super) verify:
        Option<Receiver<Result<antinomie_monitor_core::samples::Verification, String>>>,
    /// The last read-back: whether it matched, and why not.
    pub(super) verified: Option<(bool, String)>,
    /// The Lineage section's options and view.
    lineage: lineage::State,
    /// The comparison with the rest of the library.
    similar: similar::State,
    /// Keep the Summary scrolled to this offset (set by the
    /// screenshot fixture only).
    pub(super) scroll_y: Option<f32>,
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
            scanned: Scanned::None,
            scanning: None,
            scanned_report: None,
            runs: runs::RunsTab::default(),
            verify: None,
            verified: None,
            lineage: lineage::State::default(),
            similar: similar::State::default(),
            scroll_y: None,
        }
    }
}

/// Read the sample and its runs on every VM.
fn load(options: &BackendOptions, vms: &[(String, String)], sha256: &str) -> Loaded {
    let mut library = Library::open(&options.data_dir)?;
    let record = library
        .get(sha256)?
        .ok_or_else(|| "the sample is no longer in the library".to_owned())?;
    let mut runs: Vec<RunSummary> = Vec::new();
    let mut seen = Vec::new();
    let mut sent = Vec::new();
    for (vm_id, vm_name) in vms {
        let Ok(listed) = antinomie_monitor_core::recording::list_vm_runs(options, vm_id) else {
            continue;
        };
        for run in listed {
            if run
                .request
                .sample
                .as_ref()
                .is_some_and(|sample| sample.sha256 == record.sha256)
            {
                seen.push(SeenRun {
                    sha256: record.sha256.clone(),
                    vm_id: run.vm_id.clone(),
                    vm_name: vm_name.clone(),
                    run_id: run.id.clone(),
                    started_ms: run.started_ms,
                    exit: super::exit_label(&run),
                    directory: run.directory.display().to_string(),
                });
                runs.push(run);
            }
        }
    }
    library.index_runs(&seen)?;
    for other in library.list()? {
        for push in library.pushes(&other.sha256)? {
            sent.push(SentSample {
                vm_id: push.vm_id,
                path: push.path,
                sha256: other.sha256.clone(),
            });
        }
    }
    // Runs deleted through the app stay listed from their records, so the
    // numbers of the other runs do not move.
    let mut retained = std::collections::HashSet::new();
    for run in library.retained_runs(&record.sha256)? {
        if !runs
            .iter()
            .any(|live| live.id == run.id && live.vm_id == run.vm_id)
        {
            retained.insert(run.id.clone());
            runs.push(run);
        }
    }
    runs.sort_by(|a, b| {
        a.started_ms
            .cmp(&b.started_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut report = None;
    let mut entries = Vec::new();
    for (index, run) in runs.into_iter().enumerate() {
        let number = index + 1;
        if let Some(found) = run.analysis.as_ref().filter(|found| finished(found)) {
            // The newest finished report wins: runs are in start order.
            report = Some(ReportRef {
                vm_id: run.vm_id.clone(),
                run_id: run.id.clone(),
                number,
                directory: run.directory.join("analysis"),
                report: found.clone(),
            });
        }
        let deleted = retained.contains(&run.id);
        let folder = !deleted && run.directory.is_dir();
        let artifacts = if deleted {
            None
        } else {
            RunArtifacts::load(&run.directory).ok().flatten()
        };
        entries.push(RunEntry {
            number,
            run: super::super::history::listed(&run),
            folder,
            artifacts,
            digest: antinomie_monitor_core::run_digest::RunDigest::read(&run.directory),
        });
    }
    let rollup = antinomie_monitor_core::samples::rollup(
        &entries
            .iter()
            .map(|entry| antinomie_monitor_core::samples::RunInput {
                number: entry.number,
                digest: entry.digest.as_ref(),
            })
            .collect::<Vec<_>>(),
    );
    entries.reverse();
    let kept = library.artifacts(&record.sha256)?;
    let outputs = output_files::read(&entries, &kept);
    let (known, links) = lineage_links(&library, &record.sha256, &entries)?;
    let archive = library.archive_path(&record.sha256)?;
    Ok(Data {
        tags: library.tags(&record.sha256)?,
        origins: library.origins(&record.sha256)?,
        aliases: library.aliases(&record.sha256)?,
        events: library.events(&record.sha256)?,
        chain: library.custody_check(&record.sha256)?,
        archived: record.removed_ms.is_none() && archive.is_file(),
        archive,
        runs: entries,
        rollup,
        outputs,
        notes: library.notes(&record.sha256)?,
        data_dir: options.data_dir.clone(),
        known,
        links,
        report,
        sent,
        record,
    })
}

/// A report whose strings can be read: the analysis ended with results.
fn finished(report: &AnalysisReport) -> bool {
    use antinomie_monitor_core::AnalysisState;
    matches!(
        report.state,
        AnalysisState::Complete | AnalysisState::Partial
    )
}

/// Scan the report's strings with the patterns as the rule manager has them.
fn scan(data_dir: PathBuf, reference: &ReportRef, cancel: &AtomicBool) -> ScanResult {
    use antinomie_monitor_core::strings_regex::{scan_report, Config, RuleSet};
    let config = Config::load(&data_dir)?;
    let rules = RuleSet::build(&config);
    let scan = scan_report(&reference.directory, &reference.report.id, &rules, cancel)?;
    Ok(Strings {
        interesting: antinomie_monitor_core::samples::interesting_strings(&scan),
        matches: antinomie_monitor_core::samples::regex_matches(&scan),
        total: scan.total(),
    })
}

impl SamplesPage {
    /// Open the window of a sample.
    pub(in crate::app) fn open_detail(&mut self, sha256: &str) {
        self.detail = Some(Detail::new(sha256));
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
                    }
                    Err(error) => self.error = Some(error),
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
    RunInVm,
    Export,
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
                if widgets::link(ui, "‹ All samples").clicked() {
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
                (Tab::Custody, "Custody log", Some(data.events.len())),
                (Tab::Notes, "Notes", Some(data.notes.len())),
            ] {
                let mut item = widgets::TabItem::new(label);
                if let Some(count) = count {
                    item = item.badge(count.to_string(), Tone::Neutral);
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
            Tab::Custody => {
                let verifying = detail.loading.is_some();
                if let custody::Outcome::Verify =
                    custody::show(ui, &data, self.settings.font_size, verifying)
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
            Some(Action::RunInVm) => self.run_sample_in_vm(&data.record),
            Some(Action::Export) => {
                self.samples_page.export = Some(super::export::ExportDialog::new(
                    &data.record,
                    data.chain.clone(),
                ));
            }
            None => {}
        }
    }

    fn detail_header(&mut self, ui: &mut egui::Ui, data: &Data, action: &mut Option<Action>) {
        let can_run = self.running() && self.samples_page.run_error(&data.record).is_none();
        let why = self.samples_page.run_error(&data.record);
        let mut back = false;
        let mut chosen = None;
        // The back link has a line of its own; the title bar with the
        // sample's actions sits under it.
        if widgets::link(ui, "‹ All samples").clicked() {
            back = true;
        }
        ui.add_space(2.0);
        egui::Sides::new().show(
            ui,
            |ui| {
                ui.label(
                    RichText::new(&data.record.name)
                        .strong()
                        .size(ui.text_style_height(&egui::TextStyle::Heading))
                        .color(theme::palette().heading),
                );
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
            },
            |ui| {
                if ui
                    .button("Export custody record…")
                    .on_hover_text(
                        "JSON with a verifier, or HTML; optionally signed with your own key",
                    )
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
                    .on_disabled_hover_text(why.unwrap_or_else(|| "Start a VM first".into()))
                    .clicked()
                {
                    chosen = Some(Action::RunInVm);
                }
                if ui.button("Edit tags…").clicked() {
                    chosen = Some(Action::EditTags);
                }
            },
        );
        if back {
            *action = Some(Action::Back);
        } else if chosen.is_some() {
            *action = chosen;
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
        self.detail
            .as_ref()
            .is_some_and(|detail| detail.tab == Tab::Runs && detail.runs.has_selection())
    }

    fn loading_detail(&self) -> bool {
        self.detail
            .as_ref()
            .is_some_and(|detail| detail.loading.is_some())
    }

    /// Why the sample cannot be sent into a VM and run, when it cannot.
    fn run_error(&self, record: &SampleRecord) -> Option<String> {
        if record.removed_ms.is_some() {
            return Some("The archive was removed".into());
        }
        let kind = record.file_type.to_ascii_lowercase();
        let runs = matches!(kind.as_str(), "sh" | "bash")
            || kind == "elf"
                && (record.arch.is_empty()
                    || antinomie_monitor_core::samples::arch_label(&record.arch) == "x86-64");
        (!runs).then(|| "Only x86-64 Linux programs and shell scripts run in the guests".into())
    }
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

/// The name a sample takes in the guest: safe characters only.
pub(super) fn guest_name(record: &SampleRecord) -> String {
    let name: String = record
        .name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    format!(
        "/tmp/{}-{}",
        &record.sha256[..8],
        if name.is_empty() { "sample" } else { &name }
    )
}

impl MonitorApp {
    /// Send the archive into the running VM (the worker reads it back and
    /// compares its SHA-256 first), then open Run program with it.
    fn run_sample_in_vm(&mut self, record: &SampleRecord) {
        let destination = guest_name(record);
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

/// Runs read, whether a report was found, and the scan's rows once done.
#[cfg(test)]
pub(in crate::app) type Probe = (usize, bool, Option<(usize, usize, u64)>);

#[cfg(test)]
impl SamplesPage {
    /// Show the tab named `summary`, `runs` or `custody`.
    pub(in crate::app) fn show_detail_tab(&mut self, name: &str) {
        if let Some(detail) = &mut self.detail {
            detail.tab = match name {
                "runs" => Tab::Runs,
                "custody" => Tab::Custody,
                "notes" => Tab::Notes,
                _ => Tab::Summary,
            };
        }
    }

    /// Scroll the Summary down by `y` points.
    pub(in crate::app) fn scroll_detail(&mut self, y: f32) {
        if let Some(detail) = &mut self.detail {
            detail.scroll_y = Some(y);
        }
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
    /// scan (interesting strings, regex matches, match count) once done.
    pub(in crate::app) fn detail_probe(&self) -> Option<Probe> {
        let detail = self.detail.as_ref()?;
        let data = detail.data.as_ref()?;
        Some((
            data.runs.len(),
            data.report.is_some(),
            match &detail.scanned {
                Scanned::Done(strings) => Some((
                    strings.interesting.len(),
                    strings.matches.len(),
                    strings.total,
                )),
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
