// SPDX-License-Identifier: MIT
//! Process cores stay separate from VM RAM. Metadata, page reads and decoding
//! run in a single bounded background job; rendering never loads a whole core.
use antinomie_monitor_core::core_dump::{self, CoreDump, CoreFunction, CoreRecord};
use antinomie_monitor_core::{ProcessCoreCapture, ProcessCorePhase};
use eframe::egui::{self, RichText};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    time::{Duration, Instant},
};

const PAGE_SIZE: usize = 16 * 1024;
const WINDOW_SIZE: u64 = 16 * 1024 * 1024;
enum Reply {
    Records(CoreCatalog),
    Open(Box<CoreRecord>, String),
    Chosen(Option<PathBuf>),
    Page(u64, Vec<Option<u8>>),
    Code(String),
    Functions(Vec<CoreFunction>),
    Done(String),
}

#[derive(Default)]
struct CoreCatalog {
    imported: Vec<CoreRecord>,
    acquired: Vec<AcquiredCore>,
    manual: Vec<ProcessCoreCapture>,
    issues: Vec<String>,
}

pub(crate) enum CoreAction {
    Dump,
    Cancel(String),
}

pub(crate) struct CoreControls<'a> {
    pub unavailable: Option<&'a str>,
    pub captures: &'a [ProcessCoreCapture],
    pub can_cancel: bool,
}

fn manual_status(core: &ProcessCoreCapture) -> String {
    match core.phase {
        ProcessCorePhase::Admission => "Requesting capture".into(),
        ProcessCorePhase::UnknownAdmission => "Admission outcome unknown; checking status".into(),
        ProcessCorePhase::GuestCapture => {
            "Capturing process; waiting for resume confirmation".into()
        }
        ProcessCorePhase::Transfer => core.guest_size.map_or_else(
            || format!("Saving {} octets", core.stored_size),
            |size| format!("Saving {} / {size} octets", core.stored_size),
        ),
        ProcessCorePhase::Seal => "Finalizing retained core".into(),
        ProcessCorePhase::Finished => crate::app::core_capture_status(core.state).into(),
    }
}

struct AcquiredCore {
    run_id: String,
    directory: PathBuf,
    file: Option<PathBuf>,
    state: antinomie_monitor_core::RunArtifactState,
}

/// Read bounded sidecars on the inspection worker; ELF data is read only on open.
fn catalog(roots: &[PathBuf], vm_id: Option<&str>) -> Result<CoreCatalog, String> {
    let mut result = CoreCatalog::default();
    match core_dump::list_records(roots) {
        Ok(records) => result.imported = records,
        Err(error) => result.issues.push(error.to_string()),
    }
    let Some(vm_id) = vm_id else {
        return Ok(result);
    };
    match antinomie_monitor_core::core_capture::list_with_issues(roots, Some(vm_id)) {
        Ok(catalog) => {
            result.manual = catalog.records;
            result.issues.extend(catalog.issues);
        }
        Err(error) => result.issues.push(format!("Manual core catalog: {error}")),
    }
    let mut entries_count = 0usize;
    let mut metadata_size = 0u64;
    for root in roots {
        let entries = match fs::read_dir(root.join("runs")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("Core run catalog: {error}")),
        };
        for entry in entries {
            entries_count += 1;
            if entries_count > 4096 {
                return Err(
                    "Core run catalog exceeds 4096 entries; select fewer recording folders".into(),
                );
            }
            let entry = entry.map_err(|error| error.to_string())?;
            if !entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_dir()
            {
                continue;
            }
            let path = entry.path();
            let sidecar = path.join("artifacts.json");
            let size = match fs::symlink_metadata(&sidecar) {
                Ok(metadata) if metadata.is_file() => metadata.len(),
                Ok(_) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.to_string()),
            };
            metadata_size = metadata_size.saturating_add(size);
            if metadata_size > 32 * 1024 * 1024 {
                return Err("Core run metadata exceeds 32 MiB".into());
            }
            let artifacts = match antinomie_monitor_core::RunArtifacts::load(&path) {
                Ok(Some(artifacts)) => artifacts,
                Ok(None) => continue,
                Err(error) => {
                    if result.issues.len() < 16 {
                        result.issues.push(format!("{}: {error}", path.display()));
                    }
                    continue;
                }
            };
            if artifacts.vm_id != vm_id
                || artifacts.core_state == antinomie_monitor_core::RunArtifactState::Disabled
            {
                continue;
            }
            for issue in &artifacts.issues {
                if result.issues.len() >= 16 {
                    break;
                }
                let mut issue_text: String = issue.chars().take(2048).collect();
                if issue.chars().count() > 2048 {
                    issue_text.push('…');
                }
                result
                    .issues
                    .push(format!("Run {}: {issue_text}", artifacts.run_id));
            }
            if result
                .acquired
                .iter()
                .any(|core| core.run_id == artifacts.run_id)
            {
                continue;
            }
            result.acquired.push(AcquiredCore {
                run_id: artifacts.run_id,
                directory: path.join("core"),
                file: artifacts.core_dump,
                state: artifacts.core_state,
            });
            if result.acquired.len() > 1024 {
                return Err("Core catalog exceeds 1024 runs".into());
            }
        }
    }
    result
        .acquired
        .sort_by(|left, right| right.run_id.cmp(&left.run_id));
    Ok(result)
}

fn acquired_record(source: &Path) -> Result<CoreRecord, String> {
    let core = CoreDump::open(source).map_err(|error| error.to_string())?;
    let directory = core
        .source
        .parent()
        .ok_or("Core file has no result directory")?
        .to_owned();
    const METADATA_LIMIT: u64 = 16 * 1024 * 1024;
    let record = match fs::File::open(directory.join("metadata.json")) {
        Ok(file) => {
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            if !metadata.is_file() || metadata.len() > METADATA_LIMIT {
                return Err("Core metadata must be a regular file of at most 16 MiB".into());
            }
            let mut saved: CoreRecord = serde_json::from_reader(file.take(METADATA_LIMIT + 1))
                .map_err(|error| format!("Core metadata: {error}"))?;
            if saved.core.source != core.source {
                return Err("Core metadata source identity does not match this run core".into());
            }
            saved.dir = directory;
            saved.core = core;
            saved
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => CoreRecord {
            label: source
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            tags: String::new(),
            dir: directory,
            core,
        },
        Err(error) => return Err(format!("Core metadata: {error}")),
    };
    record.save().map_err(|error| error.to_string())?;
    Ok(record)
}
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Tab {
    #[default]
    Context,
    Mappings,
    Code,
    Notes,
}

#[derive(Default)]
pub(crate) struct CoreView {
    roots: Vec<PathBuf>,
    vm_id: Option<String>,
    catalog_checked: Option<Instant>,
    records: Vec<CoreRecord>,
    acquired: Vec<AcquiredCore>,
    manual: Vec<ProcessCoreCapture>,
    catalog_issues: Vec<String>,
    selected: Option<CoreRecord>,
    selected_directory: Option<PathBuf>,
    import_open: bool,
    job: Option<Receiver<Result<Reply, String>>>,
    status: String,
    source_path: String,
    destination: usize,
    thread_index: usize,
    mapping_index: usize,
    tab: Tab,
    window_offset: u64,
    jump: String,
    page: Option<(u64, Vec<Option<u8>>)>,
    code_address: String,
    code: String,
    functions: Vec<CoreFunction>,
    symbol_path: String,
    symbol_status: String,
    cancelled: Arc<AtomicBool>,
}
impl CoreView {
    pub(crate) fn select_manual(&mut self, capture: ProcessCoreCapture) {
        let file = capture.file.clone();
        self.selected_directory = Some(capture.directory.clone());
        self.selected = None;
        self.status.clear();
        if let Some(existing) = self
            .manual
            .iter_mut()
            .find(|existing| existing.id == capture.id)
        {
            *existing = capture;
        } else {
            self.manual.insert(0, capture);
        }
        if let Some(file) = file {
            self.open(&file);
        }
    }
    /// Open retained guest evidence through the bounded metadata worker.
    pub(crate) fn open(&mut self, source: &Path) {
        self.poll();
        if self.job.is_some() {
            self.status =
                "Finish the current core-view operation, then open this core again.".into();
            return;
        }
        self.source_path = source.display().to_string();
        let previous = self
            .records
            .iter()
            .find(|record| record.core.source == source)
            .cloned();
        self.selected_directory = previous
            .as_ref()
            .map(|record| record.dir.clone())
            .or_else(|| source.parent().map(Path::to_owned));
        self.selected = None;
        let source = source.to_owned();
        self.start(move || {
            let record = match previous {
                Some(mut record) => {
                    record.core = CoreDump::open(&source).map_err(|error| error.to_string())?;
                    record
                }
                None => acquired_record(&source)?,
            };
            Ok(Reply::Open(Box::new(record), String::new()))
        });
    }

    fn start(&mut self, work: impl FnOnce() -> Result<Reply, String> + Send + 'static) {
        if self.job.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        match std::thread::Builder::new()
            .name("core-inspection".into())
            .spawn(move || {
                if sender.send(work()).is_err() {
                    eprintln!("core inspection view closed before job completed");
                }
            }) {
            Ok(_) => self.job = Some(receiver),
            Err(error) => self.status = error.to_string(),
        }
    }
    fn poll(&mut self) {
        let Some(receiver) = self.job.as_ref() else {
            return;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => {
                Err("core inspection worker stopped unexpectedly".into())
            }
        };
        self.job = None;
        match result {
            Err(error) => self.status = error,
            Ok(Reply::Records(catalog)) => {
                self.records = catalog.imported;
                self.acquired = catalog.acquired;
                self.manual = catalog.manual;
                self.catalog_issues = catalog.issues;
                self.catalog_checked = Some(Instant::now());
            }
            Ok(Reply::Chosen(path)) => {
                if let Some(path) = path {
                    self.source_path = path.display().to_string();
                }
            }
            Ok(Reply::Open(record, code)) => {
                let record = *record;
                if record.core.source.parent() != Some(record.dir.as_path())
                    && !self.records.iter().any(|old| old.dir == record.dir)
                {
                    self.records.insert(0, record.clone());
                }
                self.code_address = record
                    .core
                    .threads
                    .first()
                    .and_then(|thread| thread.register("rip"))
                    .map_or_else(String::new, |address| format!("{address:x}"));
                self.selected_directory = Some(record.dir.clone());
                self.selected = Some(record);
                self.import_open = false;
                self.thread_index = 0;
                self.mapping_index = 0;
                self.window_offset = 0;
                self.page = None;
                self.code = code;
                self.functions.clear();
                self.symbol_status.clear();
                self.status = "Core is referenced in place; retain its original file.".into();
            }
            Ok(Reply::Page(address, data)) => self.page = Some((address, data)),
            Ok(Reply::Code(code)) => {
                self.code = code;
                self.status = "Disassembly saved in the result directory.".into();
            }
            Ok(Reply::Functions(functions)) => {
                self.symbol_status = format!(
                    "{} functions from supplied binary; identity and load mapping must match the core.",
                    functions.len()
                );
                self.functions = functions;
            }
            Ok(Reply::Done(message)) => self.status = message,
        }
    }
    /// | Argument | Meaning |
    /// |---|---|
    /// | `ui` | Core panel surface |
    /// | `recording_roots` | User-configured durable recording directories |
    /// | `vm_id` | Selected VM identity; filters all retained capture records |
    /// | `active` | Whether to periodically refresh current recording metadata |
    /// | `controls` | Acquisition availability and owned live capture statuses |
    /// | Return | Optional capture/cancel intent for the backend owner |
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        recording_roots: &[PathBuf],
        vm_id: Option<&str>,
        active: bool,
        controls: CoreControls<'_>,
    ) -> Option<CoreAction> {
        self.poll();
        if active {
            ui.ctx().request_repaint_after(Duration::from_secs(5));
        }
        if self.job.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(75));
        }
        let changed = self.roots != recording_roots || self.vm_id.as_deref() != vm_id;
        let refresh = active
            && self
                .catalog_checked
                .is_none_or(|last| last.elapsed() >= Duration::from_secs(5));
        if (changed || refresh) && self.job.is_none() {
            if changed {
                self.acquired.clear();
                self.manual.clear();
                self.records.clear();
                self.catalog_issues.clear();
                self.import_open = false;
                if self.selected_directory.as_ref().is_some_and(|directory| {
                    !recording_roots
                        .iter()
                        .any(|root| directory.starts_with(root))
                }) {
                    self.selected = None;
                    self.selected_directory = None;
                }
            }
            self.roots = recording_roots.to_vec();
            self.destination = 0;
            self.vm_id = vm_id.map(str::to_owned);
            self.catalog_checked = Some(Instant::now());
            let roots = self.roots.clone();
            let vm_id = self.vm_id.clone();
            self.start(move || catalog(&roots, vm_id.as_deref()).map(Reply::Records));
        }
        for capture in controls
            .captures
            .iter()
            .filter(|capture| Some(capture.vm_id.as_str()) == vm_id)
        {
            if let Some(existing) = self
                .manual
                .iter_mut()
                .find(|existing| existing.id == capture.id)
            {
                *existing = capture.clone();
            } else {
                self.manual.insert(0, capture.clone());
            }
        }
        self.manual.truncate(4096);
        let mut action = None;
        egui::SidePanel::left("core_dump_list")
            .resizable(true)
            .default_width(240.0)
            .width_range(180.0..=480.0)
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                right: 8,
                ..Default::default()
            }))
            .show_inside(ui, |ui| {
                action = self.dump_list(ui, controls.unavailable, controls.can_cancel);
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new())
            .show_inside(ui, |ui| self.analysis(ui));
        self.import_dialog(ui.ctx());
        action
    }

    fn dump_list(
        &mut self,
        ui: &mut egui::Ui,
        unavailable: Option<&str>,
        can_cancel: bool,
    ) -> Option<CoreAction> {
        let mut action = None;
        ui.horizontal(|ui| {
            crate::theme::section(ui, "Core dumps");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(
                        self.job.is_none(),
                        egui::Button::new(egui_phosphor::regular::ARROW_CLOCKWISE).frame(false),
                    )
                    .on_hover_text("Refresh the list")
                    .clicked()
                {
                    let roots = self.roots.clone();
                    let vm_id = self.vm_id.clone();
                    self.start(move || catalog(&roots, vm_id.as_deref()).map(Reply::Records));
                }
            });
        });
        if ui.add_enabled(unavailable.is_none(), egui::Button::new(format!("{} Dump core", egui_phosphor::regular::FILE))
            .min_size(egui::vec2(ui.available_width(), 0.0)))
            .on_hover_text("Pause a selected process, capture its resident memory and thread context, then resume")
            .on_disabled_hover_text(unavailable.unwrap_or_default())
            .clicked() {
            action = Some(CoreAction::Dump);
        }
        if let Some(reason) = unavailable {
            ui.add(
                egui::Label::new(RichText::new(reason).small().color(crate::theme::muted())).wrap(),
            );
        }
        if ui
            .add_enabled(
                !self.roots.is_empty() && self.job.is_none(),
                egui::Button::new(format!(
                    "{} Import core…",
                    egui_phosphor::regular::FILE_ARROW_UP
                ))
                .min_size(egui::vec2(ui.available_width(), 0.0)),
            )
            .on_hover_text(
                "Reference a Linux x86-64 process core made elsewhere. The file stays where it is.",
            )
            .on_disabled_hover_text(
                "Select a VM with a recording folder; wait for any current operation to finish.",
            )
            .clicked()
        {
            self.import_open = true;
            self.status.clear();
        }
        if self.job.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Working…");
            });
        }
        let mut acquired_selection = None;
        let mut imported_selection = None;
        let font_size = egui::TextStyle::Body.resolve(ui.style()).size;
        egui::ScrollArea::vertical()
            .id_salt("core_capture_list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                if self.acquired.is_empty() && self.records.is_empty() && self.manual.is_empty() {
                    ui.add_space(8.0);
                    ui.add(egui::Label::new("No core dumps. Dump a live process, enable Core Dump on Exit in Run program, or import a core.").wrap());
                }
                for core in &self.manual {
                    let fallback = format!("PID {} · {}", core.target.tgid, core.id);
                    let title = crate::evidence::title(ui, &core.directory, &fallback);
                    let selected = self.selected_directory.as_ref() == Some(&core.directory);
                    let state = manual_status(core);
                    let color = if core.issue.is_some() { crate::theme::warn() } else { crate::theme::text() };
                    let row = crate::network_view::capture_row(ui, selected, (&title, color), &state, font_size)
                        .on_hover_text(format!("{title}\n{state}\n{}", core.directory.display()));
                    row.context_menu(|ui| {
                        crate::evidence::menu(ui, &core.directory);
                        if core.phase != ProcessCorePhase::Finished && can_cancel
                            && ui.button("Cancel capture and resume").clicked() {
                            action = Some(CoreAction::Cancel(core.id.clone()));
                            ui.close_menu();
                        }
                    });
                    if row.clicked() && self.job.is_none() {
                        acquired_selection = Some((core.directory.clone(), core.file.clone()));
                    }
                }
                for core in &self.acquired {
                    let fallback = format!("Run {}", core.run_id);
                    let title = crate::evidence::title(ui, &core.directory, &fallback);
                    let selected = self.selected_directory.as_ref() == Some(&core.directory)
                        || self.selected.as_ref().is_some_and(|record| record.dir == core.directory);
                    let state = crate::app::core_capture_status(core.state);
                    let color = match core.state {
                        antinomie_monitor_core::RunArtifactState::Failed => crate::theme::error(),
                        antinomie_monitor_core::RunArtifactState::Partial
                        | antinomie_monitor_core::RunArtifactState::Interrupted => crate::theme::warn(),
                        _ => crate::theme::text(),
                    };
                    let row = crate::network_view::capture_row(ui, selected, (&title, color), state, font_size)
                        .on_hover_text(format!("{title}\n{state}\n{}", core.directory.display()));
                    row.context_menu(|ui| crate::evidence::menu(ui, &core.directory));
                    if row.clicked() && self.job.is_none() {
                        acquired_selection = Some((core.directory.clone(), core.file.clone()));
                    }
                }
                if !self.records.is_empty() && !self.acquired.is_empty() {
                    ui.add_space(8.0);
                    crate::theme::section(ui, "Imported cores");
                }
                for record in &self.records {
                    let title = crate::evidence::title(ui, &record.dir, &record.label);
                    let selected = self.selected_directory.as_ref() == Some(&record.dir)
                        || self.selected.as_ref().is_some_and(|current| current.dir == record.dir);
                    let detail = format!("{} threads · {} mappings", record.core.threads.len(), record.core.mappings.len());
                    let row = crate::network_view::capture_row(ui, selected, (&title, crate::theme::text()), &detail, font_size)
                        .on_hover_text(record.core.source.display().to_string());
                    row.context_menu(|ui| crate::evidence::menu(ui, &record.dir));
                    if row.clicked() && self.job.is_none() {
                        imported_selection = Some(record.clone());
                    }
                }
            });
        if let Some((directory, file)) = acquired_selection {
            self.selected_directory = Some(directory);
            self.selected = None;
            self.status.clear();
            if let Some(file) = file {
                self.open(&file);
            }
        } else if let Some(mut record) = imported_selection {
            self.selected_directory = Some(record.dir.clone());
            self.selected = None;
            self.status.clear();
            self.start(move || {
                record.core =
                    CoreDump::open(&record.core.source).map_err(|error| error.to_string())?;
                let code = match fs::File::open(record.dir.join("disassembly.txt")) {
                    Ok(file) => {
                        let mut text = String::new();
                        file.take(1024 * 1024)
                            .read_to_string(&mut text)
                            .map_err(|error| error.to_string())?;
                        text
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(error) => return Err(error.to_string()),
                };
                Ok(Reply::Open(Box::new(record), code))
            });
        }
        action
    }

    fn import_dialog(&mut self, ctx: &egui::Context) {
        if !self.import_open {
            return;
        }
        let mut open = true;
        let mut cancel = false;
        egui::Window::new("Import process core")
            .id(egui::Id::new("core_import"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(480.0)
            .show(ctx, |ui| {
                ui.add(egui::Label::new("Linux x86-64 ELF process core. The original file stays in place; reference metadata is saved with the selected VM.").wrap());
                ui.label("Core file");
                ui.add(egui::TextEdit::singleline(&mut self.source_path).desired_width(f32::INFINITY));
                if ui.add_enabled(self.job.is_none(), egui::Button::new("Browse…")).clicked() {
                    let cancelled = self.cancelled.clone();
                    self.start(move || choose_file(false, &cancelled).map(Reply::Chosen));
                }
                ui.label("Recording folder");
                egui::ComboBox::from_id_salt("core_recording_root")
                    .width(ui.available_width())
                    .selected_text(self.roots.get(self.destination).map_or_else(
                        || "Select recording folder".into(),
                        |root| root.file_name().unwrap_or(root.as_os_str()).to_string_lossy().into_owned(),
                    ))
                    .show_ui(ui, |ui| {
                        for (index, root) in self.roots.iter().enumerate() {
                            ui.selectable_value(&mut self.destination, index, root.display().to_string());
                        }
                    });
                if self.roots.is_empty() {
                    ui.label("Select a VM with a recording folder first.");
                }
                if !self.status.is_empty() {
                    ui.add(egui::Label::new(&self.status).wrap());
                }
                if self.job.is_some() {
                    ui.spinner();
                }
                ui.horizontal_wrapped(|ui| {
                    if ui.add_enabled(self.job.is_none() && self.roots.get(self.destination).is_some() && !self.source_path.trim().is_empty(), egui::Button::new("Import core")).clicked() {
                        if let Some(root) = self.roots.get(self.destination).cloned() {
                            let path = crate::folders::user_path(&self.source_path);
                            self.start(move || CoreRecord::import(&path, &root).map(|record| Reply::Open(Box::new(record), String::new())).map_err(|error| error.to_string()));
                        }
                    }
                    cancel = ui.button(if self.job.is_some() { "Close" } else { "Cancel" }).clicked();
                });
            });
        self.import_open = open && !cancel;
    }

    fn analysis(&mut self, ui: &mut egui::Ui) {
        if !self.status.is_empty() {
            ui.add(egui::Label::new(&self.status).wrap());
        }
        if !self.catalog_issues.is_empty() {
            egui::CollapsingHeader::new(format!("Capture issues ({})", self.catalog_issues.len()))
                .show(ui, |ui| {
                    for issue in &self.catalog_issues {
                        ui.add(
                            egui::Label::new(RichText::new(issue).color(crate::theme::warn()))
                                .wrap(),
                        );
                    }
                });
        }
        let Some(record) = self.selected.clone() else {
            if let Some(core) = self
                .manual
                .iter()
                .find(|core| Some(&core.directory) == self.selected_directory.as_ref())
            {
                let title = crate::evidence::title(
                    ui,
                    &core.directory,
                    &format!("PID {} · {}", core.target.tgid, core.id),
                );
                crate::theme::section(ui, &title);
                ui.add(egui::Label::new(manual_status(core)).wrap());
                ui.label(format!(
                    "PID {} · task {} · start {} ns",
                    core.target.tgid, core.target.task_cookie, core.target.start_boot_ns
                ));
                if let Some(run_id) = &core.source_run_id {
                    ui.label(format!("Related run: {run_id}"));
                }
                ui.label(match core.pause_released {
                    Some(true) => "Capture pause released",
                    Some(false) => "Capture pause has not been released yet",
                    None => "Capture pause status unknown",
                });
                if let Some(issue) = &core.issue {
                    ui.add(
                        egui::Label::new(RichText::new(issue).color(crate::theme::warn())).wrap(),
                    );
                }
                if core.file.is_some() {
                    ui.label("Select this capture to open its retained data.");
                } else {
                    ui.add(egui::Label::new("No core file is retained yet. This view shows the recorded capture status; it does not wait for process exit.").wrap());
                }
                crate::evidence::controls(ui, &core.directory);
                return;
            }
            if let Some(core) = self
                .acquired
                .iter()
                .find(|core| Some(&core.directory) == self.selected_directory.as_ref())
            {
                let title =
                    crate::evidence::title(ui, &core.directory, &format!("Run {}", core.run_id));
                crate::theme::section(ui, &title);
                ui.label(crate::app::core_capture_status(core.state));
                ui.add(egui::Label::new(format!("Run {}", core.run_id)).wrap());
                crate::evidence::controls(ui, &core.directory);
                let explanation = if core.file.is_some() {
                    "Select this capture to open its currently recorded data."
                } else if matches!(
                    core.state,
                    antinomie_monitor_core::RunArtifactState::WaitingForRootExit
                        | antinomie_monitor_core::RunArtifactState::InProgress
                ) {
                    "No core file is recorded yet. The capture is waiting for process exit or acquisition; recorded context and memory can be opened when available."
                } else {
                    "This capture retained no core file. Check run history for acquisition details."
                };
                ui.add(egui::Label::new(explanation).wrap());
            } else if self.job.is_some() {
                ui.label("Opening core…");
            } else {
                crate::theme::section(ui, "Process core");
                ui.add(egui::Label::new("Select a core from the list to inspect its threads, memory mappings, disassembly and recovered notes.").wrap());
            }
            return;
        };
        let title = crate::evidence::title(ui, &record.dir, &record.label);
        crate::theme::section(ui, &title);
        ui.horizontal_wrapped(|ui| {
            crate::evidence::controls(ui, &record.dir);
            if ui
                .add_enabled(self.job.is_none(), egui::Button::new("Reveal core file"))
                .clicked()
            {
                let source = record.core.source.clone();
                self.start(move || {
                    reveal(source.parent().unwrap_or(Path::new("/")))
                        .map(|()| Reply::Done("Opened core file directory.".into()))
                });
            }
            if ui
                .add_enabled(self.job.is_none(), egui::Button::new("Export core…"))
                .clicked()
            {
                let source = record.core.source.clone();
                let cancelled = self.cancelled.clone();
                self.start(move || {
                    let Some(destination) = choose_file(true, &cancelled)? else {
                        return Ok(Reply::Done("Export cancelled.".into()));
                    };
                    if destination.exists() {
                        return Err(
                            "Export destination already exists; choose a new filename.".into()
                        );
                    }
                    let mut input = fs::File::open(&source).map_err(|error| error.to_string())?;
                    let mut output = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&destination)
                        .map_err(|error| error.to_string())?;
                    let mut buffer = vec![0; 256 * 1024];
                    loop {
                        if cancelled.load(Ordering::Relaxed) { return Err("Core export cancelled; destination contains only the exported prefix.".into()); }
                        let size = input.read(&mut buffer).map_err(|error|error.to_string())?;
                        if size == 0 { break; }
                        output.write_all(&buffer[..size]).map_err(|error|error.to_string())?;
                    }
                    output.sync_all().map_err(|error| error.to_string())?;
                    Ok(Reply::Done(format!("Exported {}", destination.display())))
                });
            }
        });
        let source_path = record.core.source.display().to_string();
        ui.add(egui::Label::new(&source_path).truncate())
            .on_hover_text(&source_path)
            .context_menu(|ui| {
                if ui.button("Copy core path").clicked() {
                    ui.ctx().copy_text(source_path);
                    ui.close_menu();
                }
            });
        if !record.core.warnings.is_empty() {
            egui::CollapsingHeader::new(format!("Core warnings ({})", record.core.warnings.len()))
                .show(ui, |ui| {
                    for warning in &record.core.warnings {
                        ui.add(
                            egui::Label::new(RichText::new(warning).color(crate::theme::warn()))
                                .wrap(),
                        );
                    }
                });
        }
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Context, "Context");
            ui.selectable_value(&mut self.tab, Tab::Mappings, "Memory mappings");
            ui.selectable_value(&mut self.tab, Tab::Code, "Disassembly");
            ui.selectable_value(&mut self.tab, Tab::Notes, "Recovered notes");
        });
        ui.separator();
        match self.tab {
            Tab::Context => self.context(ui, &record),
            Tab::Mappings => self.mappings(ui, &record),
            Tab::Code => self.disassembly(ui, &record),
            Tab::Notes => {
                egui::ScrollArea::vertical().id_salt("core-notes").show(ui, |ui| {
                    ui.label("Other notes are inventoried below; floating-point/XSAVE payloads are not decoded here.");
                    for (key,value) in &record.core.auxv { ui.monospace(format!("AUXV {key}: 0x{value:x}")); }
                    for note in &record.core.notes { ui.label(note); }
                    for file in &record.core.files { ui.monospace(format!("{:016x}-{:016x} file+0x{:x} {}", file.start, file.end, file.file_offset, file.path)); }
                });
            }
        }
    }
    fn context(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
        egui::ComboBox::from_id_salt("core-thread")
            .selected_text(format!(
                "Thread {}",
                record
                    .core
                    .threads
                    .get(self.thread_index)
                    .map_or(0, |thread| thread.tid)
            ))
            .show_ui(ui, |ui| {
                for (index, thread) in record.core.threads.iter().enumerate() {
                    ui.selectable_value(
                        &mut self.thread_index,
                        index,
                        format!("TID {} · signal {}", thread.tid, thread.signal),
                    );
                }
            });
        let Some(thread) = record.core.threads.get(self.thread_index) else {
            return;
        };
        ui.label(format!(
            "TID {} · parent PID {} · current signal {}",
            thread.tid, thread.parent_pid, thread.signal
        ));
        egui::ScrollArea::both().id_salt("core-registers").show(ui, |ui| {
            egui::Grid::new("core-reg-grid").striped(true).show(ui, |ui| {
                for (name,value) in &thread.registers { ui.monospace(name); ui.monospace(format!("0x{value:016x}"));
                    if ui.small_button("Copy").clicked() { ui.ctx().copy_text(format!("0x{value:x}")); }
                    if (name == "rip" || name == "rsp") && ui.small_button(egui_phosphor::regular::MEMORY).on_hover_text("View memory at this register").clicked() {
                        if let Some(index) = record.core.mappings.iter().position(|mapping| *value >= mapping.start && *value < mapping.end()) {
                            self.mapping_index=index; self.window_offset=(*value-record.core.mappings[index].start)/WINDOW_SIZE*WINDOW_SIZE; self.page=None; self.tab=Tab::Mappings;
                        } else { self.status="Register points to an unmapped address.".into(); }
                    }
                    ui.end_row();
                }
            });
            ui.label("Register values are recovered evidence. Stack unwinding, pointer chains, and debugger execution are not available.");
        });
    }
    fn mappings(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
        let mut requested_page = None;
        egui::SidePanel::left("core_mapping_list")
            .resizable(true)
            .default_width(220.0)
            .width_range(160.0..=360.0)
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                right: 8,
                ..Default::default()
            }))
            .show_inside(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("core-map-list")
                    .show(ui, |ui| {
                        for (index, mapping) in record.core.mappings.iter().enumerate() {
                            let label = format!(
                                "{:x}-{:x} {}\n{} / {} octets captured",
                                mapping.start,
                                mapping.end(),
                                mapping.permissions(),
                                mapping.available_size,
                                mapping.memory_size
                            );
                            if ui
                                .selectable_label(
                                    index == self.mapping_index,
                                    RichText::new(label).monospace(),
                                )
                                .clicked()
                            {
                                self.mapping_index = index;
                                self.window_offset = 0;
                                self.page = None;
                            }
                            for file in record.core.files.iter().filter(|file| {
                                mapping.start >= file.start && mapping.start < file.end
                            }) {
                                ui.small(&file.path);
                            }
                        }
                    });
            });
        egui::CentralPanel::default().frame(egui::Frame::new()).show_inside(ui, |ui| {
            let Some(mapping)=record.core.mappings.get(self.mapping_index) else {ui.label("No PT_LOAD mappings.");return;};
            ui.add(egui::Label::new("?? = unavailable; 00 = captured zero.").wrap())
                .on_hover_text("Unavailable memory can be absent, omitted by the memory filter, or truncated in the saved core.");
            ui.horizontal_wrapped(|ui| {
                if ui.add_enabled(self.window_offset>0,egui::Button::new("Previous span")).clicked() {self.window_offset=self.window_offset.saturating_sub(WINDOW_SIZE);self.page=None;}
                if ui.add_enabled(self.window_offset.saturating_add(WINDOW_SIZE)<mapping.memory_size,egui::Button::new("Next span")).clicked() {self.window_offset=self.window_offset.saturating_add(WINDOW_SIZE);self.page=None;}
            });
            ui.label("Mapping offset (hex)");
            ui.horizontal_wrapped(|ui| {
                let input_width = ui.available_width().min(200.0);
                ui.add(egui::TextEdit::singleline(&mut self.jump).desired_width(input_width));
                if ui.button("Jump").clicked() {
                match parse_address(&self.jump) {Ok(offset) if offset<mapping.memory_size=>{self.window_offset=offset/16*16;self.page=None;},_=>self.status="Offset must lie inside the selected mapping.".into()}
                }
            });
            let span=mapping.memory_size.saturating_sub(self.window_offset).min(WINDOW_SIZE);
            ui.add(egui::Label::new(format!("Offset 0x{:x}–0x{:x} of 0x{:x}",self.window_offset,self.window_offset+span,mapping.memory_size)).wrap())
                .on_hover_text("Scroll this span, advance to another span, or jump to an offset to inspect the entire mapping.");
            let row_count=usize::try_from(span.div_ceil(16)).unwrap_or(0);
            let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
            egui::ScrollArea::both().id_salt(("core-hex",self.mapping_index,self.window_offset)).show_rows(ui,row_height,row_count,|ui,range| {
                for row in range {
                    let address=mapping.start+self.window_offset+row as u64*16;
                    let mut line=format!("{address:016x}  ");let mut ascii=String::new();
                    for column in 0..16 {
                        let Some(at)=address.checked_add(column) else {break;};
                        if at>=mapping.end() {line.push_str("   ");continue;}
                        let value=self.page.as_ref().filter(|(base,data)| at>=*base && at-*base<data.len() as u64).map(|(base,data)|data[(at-*base) as usize]);
                        match value {Some(Some(byte))=>{line.push_str(&format!("{byte:02x} "));ascii.push(if byte.is_ascii_graphic()||byte==b' ' {char::from(byte)} else {'.'});},Some(None)=>{line.push_str("?? ");ascii.push('?');},None=>{line.push_str("·· ");ascii.push(' ');if requested_page.is_none(){requested_page=Some(at/PAGE_SIZE as u64*PAGE_SIZE as u64);}}}
                    }
                    line.push_str(&format!(" {ascii}"));
                    ui.add(egui::Label::new(RichText::new(line).monospace()).extend());
                }
            });
        });
        if let Some(address) = requested_page {
            if self.job.is_none() {
                let core = record.core.clone();
                self.start(move || {
                    let size = (PAGE_SIZE * 2)
                        .min(usize::try_from(u64::MAX - address).unwrap_or(usize::MAX));
                    core.read_virtual(address, size)
                        .map(|data| Reply::Page(address, data))
                        .map_err(|error| error.to_string())
                });
            }
        }
    }
    fn disassembly(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
        ui.label("Decode on demand from captured memory. Decompilation requires an external analysis project and is unavailable here.");
        ui.label("Virtual address (hex)");
        ui.horizontal_wrapped(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.code_address).desired_width(200.0));
            if ui
                .add_enabled(self.job.is_none(), egui::Button::new("Disassemble 4 KiB"))
                .clicked()
            {
                match parse_address(&self.code_address) {
                    Ok(address) => {
                        let core = record.core.clone();
                        let dir = record.dir.clone();
                        self.start(move || {
                            let text = core
                                .disassemble(address, 4096)
                                .map_err(|error| error.to_string())?;
                            fs::write(dir.join("disassembly.txt"), &text)
                                .map_err(|error| error.to_string())?;
                            Ok(Reply::Code(text))
                        });
                    }
                    Err(error) => self.status = error,
                }
            }
        });
        ui.label("Matching symbol binary");
        ui.add(egui::TextEdit::singleline(&mut self.symbol_path).desired_width(f32::INFINITY));
        ui.horizontal_wrapped(|ui| {
            if ui.add_enabled(self.job.is_none(), egui::Button::new("Load symbols for selected mapping")).clicked() {
                let mapping = record.core.mappings.get(self.mapping_index).and_then(|region| {
                    record.core.files.iter().find(|file| region.start >= file.start && region.start < file.end)
                }).cloned();
                if let Some(mapping) = mapping {
                    let path = crate::folders::user_path(&self.symbol_path);
                    let dir = record.dir.clone();
                    self.start(move || {
                        let functions = core_dump::binary_functions(&path, &mapping).map_err(|error| error.to_string())?;
                        let mut output = fs::File::create(dir.join("functions.txt")).map_err(|error|error.to_string())?;
                        writeln!(output, "Supplied binary: {}\nMapped file: {}\nIdentity not independently verified", path.display(), mapping.path).map_err(|error|error.to_string())?;
                        for function in &functions {
                            writeln!(output, "{:016x} {} {}", function.address, function.size, function.name).map_err(|error|error.to_string())?;
                        }
                        output.sync_all().map_err(|error|error.to_string())?;
                        Ok(Reply::Functions(functions))
                    });
                } else {
                    self.status = "Select a file-backed mapping in Memory mappings first; NT_FILE metadata is required for relocation.".into();
                }
            }
        });
        if !self.symbol_status.is_empty() {
            ui.label(&self.symbol_status);
        }
        ui.add(egui::Label::new("Results are saved in the result directory: disassembly.txt, functions.txt and metadata.json.").wrap());
        egui::SidePanel::left("core_function_list")
            .resizable(true)
            .default_width(220.0)
            .width_range(160.0..=360.0)
            .frame(egui::Frame::new().inner_margin(egui::Margin { right: 8, ..Default::default() }))
            .show_inside(ui, |ui| {
                if self.functions.is_empty(){ui.add(egui::Label::new("No function symbols loaded. Use an address, or supply the exact mapped binary; a core alone usually has no symbol table.").wrap());}
                let row_height = ui.text_style_height(&egui::TextStyle::Body) + ui.spacing().item_spacing.y;
                egui::ScrollArea::vertical().id_salt("core-functions").show_rows(ui,row_height,self.functions.len(),|ui,range| {
                    for index in range {let function=&self.functions[index];if ui.selectable_label(false,format!("{:x} {} ({} octets)",function.address,function.name,function.size)).clicked(){self.code_address=format!("{:x}",function.address);}}
                });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new())
            .show_inside(ui, |ui| {
                egui::ScrollArea::both()
                    .id_salt("core-code")
                    .show(ui, |ui| {
                        if self.code.is_empty() {
                            ui.add(
                                egui::Label::new(
                                    "Choose a function or address and click Disassemble.",
                                )
                                .wrap(),
                            );
                        } else {
                            ui.add(
                                egui::Label::new(RichText::new(&self.code).monospace())
                                    .extend()
                                    .selectable(true),
                            );
                        }
                    });
            });
    }
}
fn parse_address(text: &str) -> Result<u64, String> {
    u64::from_str_radix(text.trim().trim_start_matches("0x"), 16)
        .map_err(|error| format!("Invalid hexadecimal address: {error}"))
}
impl Drop for CoreView {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}
fn choose_file(save: bool, cancelled: &AtomicBool) -> Result<Option<PathBuf>, String> {
    let mut command = Command::new("zenity");
    command.args(["--file-selection", "--title=Select process core"]);
    if save {
        command.args(["--save", "--confirm-overwrite"]);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            format!("File picker unavailable ({error}); type the file path instead.")
        })?;
    let status = loop {
        if cancelled.load(Ordering::Relaxed) {
            let kill = child.kill();
            let wait = child.wait();
            return Err(format!(
                "File selection cancelled; cleanup {kill:?}, {wait:?}"
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => {
                let kill = child.kill();
                let wait = child.wait();
                return Err(format!(
                    "File picker wait failed: {error}; cleanup {kill:?}, {wait:?}"
                ));
            }
        }
    };
    let mut output = Vec::new();
    let read = child
        .stdout
        .take()
        .ok_or("file picker output unavailable")?
        .take(8193)
        .read_to_end(&mut output);
    if let Err(error) = read {
        let kill = child.kill();
        let wait = child.wait();
        return Err(format!(
            "File picker read failed: {error}; cleanup {kill:?}, {wait:?}"
        ));
    }
    if output.len() > 8192 {
        let kill = child.kill();
        let wait = child.wait();
        return Err(format!(
            "File picker path exceeds limit; cleanup {kill:?}, {wait:?}"
        ));
    }
    if status.code() == Some(1) {
        return Ok(None);
    }
    if !status.success() {
        return Err(format!("File picker failed: {status}"));
    }
    let text = String::from_utf8(output).map_err(|error| error.to_string())?;
    let text = text.strip_suffix('\n').unwrap_or(&text);
    Ok((!text.is_empty()).then(|| PathBuf::from(text)))
}
fn reveal(path: &Path) -> Result<(), String> {
    let mut child = Command::new("xdg-open")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    let status = child.wait().map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("Directory opener failed: {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::core_dump::{CoreMapping, CoreThread, MappedFile};

    struct Fixture {
        view: CoreView,
        directory: PathBuf,
    }

    #[test]
    fn acquired_catalog_finds_unopened_partial_cores_and_scopes_the_vm() {
        let fixture = Fixture::new();
        for (id, vm_id, state, with_file) in [
            (
                "partial",
                "chosen",
                antinomie_monitor_core::RunArtifactState::Partial,
                true,
            ),
            (
                "waiting",
                "chosen",
                antinomie_monitor_core::RunArtifactState::WaitingForRootExit,
                false,
            ),
            (
                "other",
                "other-vm",
                antinomie_monitor_core::RunArtifactState::Complete,
                true,
            ),
        ] {
            let directory = fixture.directory.join("runs").join(id);
            fs::create_dir_all(directory.join("core")).unwrap();
            let file = directory.join("core/process.elf");
            if with_file {
                fs::write(&file, b"unfinished ELF prefix").unwrap();
            }
            let artifacts = antinomie_monitor_core::RunArtifacts {
                run_id: id.into(),
                vm_id: vm_id.into(),
                boot_id: "boot".into(),
                core_state: state,
                core_dump: with_file.then_some(file),
                ..Default::default()
            };
            fs::write(
                directory.join("artifacts.json"),
                serde_json::to_vec(&artifacts).unwrap(),
            )
            .unwrap();
        }
        let first = catalog(std::slice::from_ref(&fixture.directory), Some("chosen")).unwrap();
        assert!(first.imported.is_empty());
        assert_eq!(first.acquired.len(), 2);
        assert!(first
            .acquired
            .iter()
            .any(|core| core.run_id == "partial" && core.file.is_some()));
        assert!(first
            .acquired
            .iter()
            .any(|core| core.run_id == "waiting" && core.file.is_none()));
        assert!(
            !fixture.directory.join("core-dumps").exists(),
            "discovery must not import or parse incomplete ELF files"
        );
    }

    #[test]
    fn reopening_acquired_core_reuses_its_directory_and_available_prefix() {
        let fixture = Fixture::new();
        let directory = fixture.directory.join("runs/root/core");
        fs::create_dir_all(&directory).unwrap();
        let file = directory.join("process.elf");
        let mut data = vec![0u8; 64 + 56 + 12 + 8 + 336];
        data[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        data[16..18].copy_from_slice(&4u16.to_le_bytes());
        data[18..20].copy_from_slice(&62u16.to_le_bytes());
        data[32..40].copy_from_slice(&64u64.to_le_bytes());
        data[54..56].copy_from_slice(&56u16.to_le_bytes());
        data[56..58].copy_from_slice(&1u16.to_le_bytes());
        data[64..68].copy_from_slice(&4u32.to_le_bytes());
        data[72..80].copy_from_slice(&120u64.to_le_bytes());
        data[96..104].copy_from_slice(&356u64.to_le_bytes());
        data[120..124].copy_from_slice(&5u32.to_le_bytes());
        data[124..128].copy_from_slice(&336u32.to_le_bytes());
        data[128..132].copy_from_slice(&1u32.to_le_bytes());
        data[132..137].copy_from_slice(b"CORE\0");
        data[172..176].copy_from_slice(&77u32.to_le_bytes());
        fs::write(&file, data).unwrap();
        let mut first = acquired_record(&file).unwrap();
        first.label = "Renamed acquisition".into();
        first.tags = "interesting, partial".into();
        first.save().unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap()
            .write_all(&[0])
            .unwrap();
        let second = acquired_record(&file).unwrap();
        assert_eq!(first.dir, directory);
        assert_eq!(second.dir, first.dir);
        assert_eq!(second.core.threads[0].tid, 77);
        assert_eq!(second.label, "Renamed acquisition");
        assert_eq!(second.tags, "interesting, partial");
        assert_eq!(second.core.source_size, first.core.source_size + 1);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);
        assert!(!fixture.directory.join("core-dumps").exists());
        let mut wrong = second;
        wrong.core.source = fixture.directory.join("another-core.elf");
        wrong.save().unwrap();
        assert!(acquired_record(&file)
            .unwrap_err()
            .contains("identity does not match"));
    }
    impl Fixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "antinomie-core-ui-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&directory).unwrap();
            let source = directory.join("synthetic-memory.bin");
            fs::write(&source, [0x90; 4096]).unwrap();
            // Deliberately synthetic domain metadata: parser qualification is
            // tested in monitor-core; these tests qualify view interaction.
            let record = CoreRecord {
                dir: directory.clone(),
                label: "Synthetic process core".into(),
                tags: String::new(),
                core: CoreDump {
                    source,
                    source_size: 4096,
                    threads: [101, 102]
                        .into_iter()
                        .map(|tid| CoreThread {
                            tid,
                            parent_pid: 100,
                            signal: 11,
                            registers: vec![
                                ("rip".into(), 0x400000),
                                ("rsp".into(), 0x400080),
                                ("rax".into(), u64::from(tid)),
                            ],
                        })
                        .collect(),
                    mappings: vec![CoreMapping {
                        start: 0x400000,
                        memory_size: 64 * 1024 * 1024,
                        file_offset: 0,
                        captured_size: 4096,
                        available_size: 4096,
                        flags: 5,
                    }],
                    files: vec![MappedFile {
                        start: 0x400000,
                        end: 0x401000,
                        file_offset: 0,
                        path: "/synthetic/sample".into(),
                    }],
                    auxv: vec![(9, 0x400000)],
                    notes: vec!["Synthetic NT_PRSTATUS / NT_FILE / AUXV evidence".into()],
                    warnings: vec![
                        "Remaining mapping pages were omitted from this synthetic capture".into(),
                    ],
                },
            };
            let mut page = vec![None; PAGE_SIZE * 2];
            page[..4096].fill(Some(0x90));
            let mut view = CoreView::default();
            view.selected = Some(record.clone());
            view.records = vec![record];
            view.code_address = "400000".into();
            view.page = Some((0x400000, page));
            Self { view, directory }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    fn texts(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
        fn collect(shape: &egui::epaint::Shape, result: &mut Vec<(String, egui::Rect)>) {
            match shape {
                egui::epaint::Shape::Text(text) => result.push((
                    text.galley.text().to_owned(),
                    egui::Rect::from_min_size(text.pos, text.galley.size()),
                )),
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        collect(shape, result);
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
        view: &mut CoreView,
        size: egui::Vec2,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        let roots = view.roots.clone();
        let vm_id = view.vm_id.clone();
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events,
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    view.show(
                        ui,
                        &roots,
                        vm_id.as_deref(),
                        false,
                        CoreControls {
                            unavailable: Some("Start a supported VM to dump a process core."),
                            captures: &[],
                            can_cancel: false,
                        },
                    )
                });
            },
        )
    }
    fn settle(ctx: &egui::Context, view: &mut CoreView, size: egui::Vec2) -> egui::FullOutput {
        let mut output = render(ctx, view, size, Vec::new());
        for _ in 0..3 {
            output = render(ctx, view, size, Vec::new());
        }
        output
    }
    fn click(ctx: &egui::Context, view: &mut CoreView, size: egui::Vec2, position: egui::Pos2) {
        for events in [
            vec![egui::Event::PointerMoved(position)],
            vec![egui::Event::PointerButton {
                pos: position,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            }],
            vec![egui::Event::PointerButton {
                pos: position,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        ] {
            render(ctx, view, size, events);
        }
    }

    #[test]
    fn sidebar_selection_shows_unfinished_capture_without_old_core_context() {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        crate::theme::text_size(&ctx, 24.0);
        let size = egui::vec2(800.0, 1000.0);
        let mut fixture = Fixture::new();
        let directory = fixture.directory.join("runs/waiting/core");
        fixture.view.acquired.push(AcquiredCore {
            run_id: "waiting".into(),
            directory: directory.clone(),
            file: None,
            state: antinomie_monitor_core::RunArtifactState::WaitingForRootExit,
        });
        let output = settle(&ctx, &mut fixture.view, size);
        let content = texts(&output);
        let row = content
            .iter()
            .find(|(text, _)| text == "Run waiting")
            .unwrap()
            .1;
        let context = content
            .iter()
            .find(|(text, _)| text == "Context")
            .unwrap()
            .1;
        assert!(
            row.max.x < context.min.x,
            "capture list stays left of analysis"
        );
        assert!(!content.iter().any(|(text, _)| text == "Core file"));
        click(&ctx, &mut fixture.view, size, row.center());
        let output = settle(&ctx, &mut fixture.view, size);
        assert_eq!(fixture.view.selected_directory.as_ref(), Some(&directory));
        assert!(fixture.view.selected.is_none() && fixture.view.job.is_none());
        let content = texts(&output);
        assert!(content
            .iter()
            .any(|(text, _)| text.contains("No core file is recorded yet")));
        assert!(!content.iter().any(|(text, _)| text == "rip"));
        assert!(
            fixture.view.records.len() == 1,
            "waiting selection keeps imported evidence"
        );
    }

    #[test]
    fn unfinished_manual_core_shows_recorded_status_without_stale_context() {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let mut fixture = Fixture::new();
        let directory = fixture.directory.join("core-captures/live");
        fs::create_dir_all(&directory).unwrap();
        fixture.view.select_manual(ProcessCoreCapture {
            format: 1,
            id: "live".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            source_run_id: Some("run".into()),
            restored_from_capture_id: None,
            target: antinomie_monitor_core::GuestProcessIdentity {
                boot_id: "boot".into(),
                task_cookie: 42,
                tgid: 101,
                start_boot_ns: 100,
            },
            directory: directory.clone(),
            file: None,
            state: antinomie_monitor_core::RunArtifactState::InProgress,
            phase: ProcessCorePhase::GuestCapture,
            stored_size: 0,
            guest_size: None,
            sha256: None,
            pause_released: Some(false),
            max_size: 64 * 1024 * 1024,
            timeout_ms: 5000,
            nonce: [1, 2],
            guest_handle: Some(7),
            guest_status: None,
            issue: None,
        });
        let output = settle(&ctx, &mut fixture.view, egui::vec2(1280.0, 900.0));
        let content = texts(&output);
        assert_eq!(fixture.view.selected_directory.as_ref(), Some(&directory));
        assert!(fixture.view.selected.is_none() && fixture.view.job.is_none());
        assert!(content
            .iter()
            .any(|(text, _)| text == "Capture pause has not been released yet"));
        assert!(content
            .iter()
            .any(|(text, _)| text.contains("does not wait for process exit")));
        assert!(!content.iter().any(|(text, _)| text == "rip"));
        assert!(content.iter().any(|(text, _)| text.contains("Dump core")));
        assert_eq!(fixture.view.records.len(), 1);
    }

    #[test]
    fn import_fields_live_in_dialog_and_cancel_preserves_selection() {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        crate::theme::text_size(&ctx, 24.0);
        let size = egui::vec2(800.0, 1000.0);
        let mut fixture = Fixture::new();
        fixture.view.roots = vec![fixture.directory.clone()];
        let original = fixture.view.selected.as_ref().unwrap().dir.clone();
        let output = settle(&ctx, &mut fixture.view, size);
        let content = texts(&output);
        assert!(!content.iter().any(|(text, _)| text == "Core file"));
        let import = content
            .iter()
            .find(|(text, _)| text.contains("Import core…"))
            .unwrap()
            .1
            .center();
        click(&ctx, &mut fixture.view, size, import);
        assert!(fixture.view.import_open);
        let output = settle(&ctx, &mut fixture.view, size);
        let content = texts(&output);
        for label in [
            "Import process core",
            "Core file",
            "Browse…",
            "Recording folder",
            "Import core",
        ] {
            let rect = content
                .iter()
                .find(|(text, _)| text == label)
                .unwrap_or_else(|| panic!("missing {label}"))
                .1;
            assert!(
                rect.min.x >= 0.0 && rect.max.x <= size.x && rect.max.y <= size.y,
                "{label} stays reachable"
            );
        }
        let cancel = content
            .iter()
            .find(|(text, _)| text == "Cancel")
            .unwrap()
            .1
            .center();
        click(&ctx, &mut fixture.view, size, cancel);
        assert!(!fixture.view.import_open && fixture.view.job.is_none());
        assert_eq!(fixture.view.selected.as_ref().unwrap().dir, original);
        assert!(
            fixture.view.code.is_empty(),
            "opening import dialog does not run analysis"
        );
    }

    #[test]
    fn thread_context_and_mapping_controls_render_at_narrow_large_font() {
        for (size, font) in [
            (egui::vec2(1280.0, 900.0), 16.0),
            (egui::vec2(800.0, 1000.0), 24.0),
        ] {
            let ctx = egui::Context::default();
            crate::theme::install(&ctx);
            crate::theme::text_size(&ctx, font);
            let mut fixture = Fixture::new();
            let output = settle(&ctx, &mut fixture.view, size);
            let content = texts(&output);
            assert!(content
                .iter()
                .any(|(text, _)| text.contains("TID 101") && text.contains("signal 11")));
            assert!(content.iter().any(|(text, _)| text == "rip"));
            assert!(content.iter().any(|(text, _)| text == "0x0000000000400000"));
            for label in ["Context", "Memory mappings", "Disassembly"] {
                let (_, rect) = content
                    .iter()
                    .find(|(text, _)| text == label)
                    .unwrap_or_else(|| panic!("missing {label}"));
                assert!(
                    rect.min.x >= 0.0 && rect.max.x <= size.x && rect.max.y <= size.y,
                    "{label} must stay reachable at {size:?}, {font} pt: {rect:?}"
                );
            }
            for (text, rect) in content
                .iter()
                .filter(|(text, _)| text == "Copy" || text == egui_phosphor::regular::MEMORY)
            {
                assert!(
                    rect.max.x <= size.x && rect.max.y <= size.y,
                    "register action {text} stays reachable: {rect:?}"
                );
            }
            assert!(fixture.view.job.is_none());
            fixture.view.thread_index = 1;
            let output = settle(&ctx, &mut fixture.view, size);
            assert!(texts(&output)
                .iter()
                .any(|(text, _)| text.contains("TID 102")));
            fixture.view.tab = Tab::Mappings;
            let output = settle(&ctx, &mut fixture.view, size);
            let content = texts(&output);
            for label in ["Previous span", "Next span", "Jump"] {
                let (_, rect) = content
                    .iter()
                    .find(|(text, _)| text == label)
                    .unwrap_or_else(|| panic!("missing {label}"));
                assert!(
                    rect.max.x <= size.x && rect.max.y <= size.y,
                    "mapping control {label} must stay reachable: {rect:?}"
                );
            }
            assert!(content
                .iter()
                .any(|(text, _)| text.contains("4096 / 67108864 octets captured")));
            assert!(content.iter().any(|(text, _)| text.contains("90 90")));
            let font_id = egui::TextStyle::Monospace.resolve(&ctx.style());
            let row_height = ctx.fonts(|fonts| fonts.row_height(&font_id));
            for (text, rect) in content
                .iter()
                .filter(|(text, _)| text.starts_with("000000000040") && text.contains("90 90"))
            {
                assert!(
                    rect.height() <= row_height + 0.5,
                    "one address must occupy one monospace row at {font} pt: {} high for {text}",
                    rect.height()
                );
            }
            assert!(fixture.view.code.is_empty() && fixture.view.functions.is_empty());
        }
    }

    #[test]
    fn long_disassembly_lines_scroll_horizontally_without_wrapping_at_large_font() {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        crate::theme::text_size(&ctx, 24.0);
        let mut fixture = Fixture::new();
        fixture.view.tab = Tab::Code;
        fixture.view.code = "0000000000400000  mov rax, qword ptr fs:[0x0000000000000028]\n0000000000400009  mov qword ptr [rsp+0x0000000000000010], rax".into();
        let output = settle(&ctx, &mut fixture.view, egui::vec2(800.0, 1000.0));
        let content = texts(&output);
        for label in ["Disassemble 4 KiB", "Load symbols for selected mapping"] {
            let rect = content
                .iter()
                .find(|(text, _)| text == label)
                .unwrap_or_else(|| panic!("missing {label}"))
                .1;
            assert!(
                rect.max.x <= 800.0 && rect.max.y <= 1000.0,
                "{label} stays reachable: {rect:?}"
            );
        }
        let (_, rect) = content
            .iter()
            .find(|(text, _)| text == &fixture.view.code)
            .expect("disassembly text is rendered");
        let font_id = egui::TextStyle::Monospace.resolve(&ctx.style());
        let row_height = ctx.fonts(|fonts| fonts.row_height(&font_id));
        assert!(
            rect.height() <= row_height * 2.0 + 0.5,
            "two instruction addresses must occupy two rows; got {} high",
            rect.height()
        );
        assert!(
            fixture.view.job.is_none(),
            "rendering retained code never starts analysis"
        );
    }

    #[test]
    fn viewing_code_does_not_decode_until_disassemble_is_clicked() {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        let mut fixture = Fixture::new();
        fixture.view.tab = Tab::Code;
        let output = settle(&ctx, &mut fixture.view, size);
        assert!(fixture.view.job.is_none());
        assert!(fixture.view.code.is_empty() && fixture.view.functions.is_empty());
        assert!(!fixture.directory.join("disassembly.txt").exists());
        assert!(!fixture.directory.join("functions.txt").exists());
        let content = texts(&output);
        assert!(content
            .iter()
            .any(|(text, _)| text.contains("No function symbols loaded")));
        let position = content
            .iter()
            .find(|(text, _)| text == "Disassemble 4 KiB")
            .unwrap()
            .1
            .center();
        click(&ctx, &mut fixture.view, size, position);
        assert!(
            fixture.view.job.is_some(),
            "only an explicit decode action starts the worker"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while fixture.view.job.is_some() && std::time::Instant::now() < deadline {
            fixture.view.poll();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            fixture.view.job.is_none(),
            "bounded synthetic disassembly completes"
        );
        assert!(fixture.view.code.contains("nop"));
        assert!(fixture.directory.join("disassembly.txt").is_file());
        assert!(fixture.view.functions.is_empty());
        assert!(!fixture.directory.join("functions.txt").exists());
    }

    #[test]
    #[ignore = "native X11 core-view preview, synthetic metadata, exits automatically"]
    fn native_core_view_fixture() {
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct FixtureApp {
            fixture: Fixture,
            deadline: std::time::Instant,
        }
        impl eframe::App for FixtureApp {
            fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
                egui::CentralPanel::default().show(ctx, |ui| {
                    self.fixture.view.show(
                        ui,
                        &[],
                        None,
                        false,
                        CoreControls {
                            unavailable: Some("Preview"),
                            captures: &[],
                            can_cancel: false,
                        },
                    )
                });
                if std::time::Instant::now() >= self.deadline {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }
        let small = std::env::var_os("ANTINOMIE_CORE_QA_SMALL").is_some();
        let seconds = std::env::var("ANTINOMIE_CORE_QA_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(15)
            .clamp(1, 120);
        let tab = std::env::var("ANTINOMIE_CORE_QA_TAB").unwrap_or_default();
        eframe::run_native(
            "Antinomie Core View QA — synthetic evidence",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default().with_inner_size(if small {
                    [800.0, 900.0]
                } else {
                    [1280.0, 900.0]
                }),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11().with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                crate::theme::install(&cc.egui_ctx);
                crate::theme::text_size(&cc.egui_ctx, if small { 24.0 } else { 16.0 });
                let mut fixture = Fixture::new();
                fixture.view.tab = match tab.as_str() {
                    "mappings" => Tab::Mappings,
                    "code" => Tab::Code,
                    "notes" => Tab::Notes,
                    _ => Tab::Context,
                };
                Ok(Box::new(FixtureApp {
                    fixture,
                    deadline: std::time::Instant::now() + Duration::from_secs(seconds),
                }))
            }),
        )
        .unwrap();
    }
}
