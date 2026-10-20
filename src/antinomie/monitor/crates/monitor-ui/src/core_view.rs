// SPDX-License-Identifier: MIT
//! Process cores stay separate from VM RAM. Metadata, page reads and decoding
//! run in a single bounded background job; rendering never loads a whole core.
use antinomie_monitor_core::core_dump::{self, CoreDump, CoreFunction, CoreMapping, CoreRecord};
use antinomie_monitor_core::{ProcessCoreCapture, ProcessCorePhase};
use eframe::egui::{self, RichText};
use std::{
    fs,
    hash::Hasher,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicI32, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    time::{Duration, Instant},
};

mod catalog;
mod decompile;
mod disassembly;
mod inspect;
mod list;

use self::{catalog::*, decompile::*, inspect::*};

const PAGE_SIZE: usize = 16 * 1024;
const WINDOW_SIZE: u64 = 16 * 1024 * 1024;
const DISASSEMBLY_BYTES: usize = 65536;
const FUNCTION_DISASSEMBLY_LIMIT: u64 = 65536;
enum Reply {
    Open(Box<CoreRecord>, String, Option<CoreFileStamp>),
    Chosen(Option<PathBuf>),
    Page(u64, Vec<Option<u8>>),
    Code(String),
    Decompiled(String),
    Done(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CoreFileStamp {
    device: u64,
    inode: u64,
    file_size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

type CatalogStamp = u64;

struct InspectionReply {
    generation: u64,
    roots: Vec<PathBuf>,
    vm_id: Option<String>,
    initialized: bool,
    selected_stamp: Option<CoreFileStamp>,
    result: Result<Reply, String>,
}

struct SelectedCoreRefresh {
    directory: PathBuf,
    source: PathBuf,
    previous_stamp: Option<CoreFileStamp>,
    stamp: Option<CoreFileStamp>,
    core: Result<Option<CoreDump>, String>,
}

struct SelectedCoreProbe {
    directory: PathBuf,
    source: PathBuf,
    source_size: u64,
    stamp: Option<CoreFileStamp>,
}

struct CatalogReply {
    generation: u64,
    roots: Vec<PathBuf>,
    vm_id: Option<String>,
    catalog: Result<CoreCatalog, String>,
    stamp: Option<CatalogStamp>,
    selected: Option<SelectedCoreRefresh>,
}

#[derive(Default, serde::Serialize)]
struct CoreCatalog {
    imported: Vec<CoreRecord>,
    acquired: Vec<AcquiredCore>,
    manual: Vec<ProcessCoreCapture>,
    issues: Vec<String>,
}

pub(crate) enum CoreAction {
    Dump,
    Cancel(String),
    /// Cancel a run's Core Dump on Exit without stopping the program.
    CancelRun(String),
    /// Delete a saved core, once the user confirms.
    Delete(crate::evidence_delete::Deletion),
}

pub(crate) struct CoreControls<'a> {
    pub unavailable: Option<&'a str>,
    pub captures: &'a [ProcessCoreCapture],
    pub can_cancel: bool,
    /// The running boot: only captures of this boot can still be cancelled.
    pub boot_id: Option<&'a str>,
}

#[derive(Clone, serde::Serialize)]
struct AcquiredCore {
    vm_id: String,
    boot_id: String,
    run_id: String,
    directory: PathBuf,
    file: Option<PathBuf>,
    state: antinomie_monitor_core::RunArtifactState,
    /// The core was deleted: "Deleted", as the run's artifact list words it.
    deleted: Option<&'static str>,
}

impl AcquiredCore {
    /// What the core's state reads as.
    fn status(&self) -> &'static str {
        self.deleted
            .unwrap_or_else(|| crate::app::core_capture_status(self.state))
    }
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
    catalog_generation: u64,
    scope_generation: u64,
    scope_initialized: bool,
    catalog_stamp: Option<CatalogStamp>,
    records: Vec<CoreRecord>,
    acquired: Vec<AcquiredCore>,
    manual: Vec<ProcessCoreCapture>,
    catalog_issues: Vec<String>,
    selected: Option<CoreRecord>,
    selected_stamp: Option<CoreFileStamp>,
    selected_directory: Option<PathBuf>,
    import_open: bool,
    job: Option<Receiver<InspectionReply>>,
    status: String,
    status_notice: Option<(crate::activity::Level, String)>,
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
    symbol_status: String,
    hide_list: bool,
    catalog_job: Option<Receiver<CatalogReply>>,
    function_bodies: Vec<String>,
    code_function: Option<usize>,
    show_decompiled: bool,
    cancelled: Arc<AtomicBool>,
    project_export_active: bool,
    /// Function address chosen by a click, decoded once when no job is running.
    pending_function_decode: Option<u64>,
    /// Address already given to `decode_window`, so later frames do not restart it.
    function_decode_at: Option<u64>,
    /// Pid of the running Ghidra process group leader; 0 when idle.
    ghidra_pid: Arc<AtomicI32>,
    ghidra_cancel: Arc<AtomicBool>,
    decompile_active: bool,
    /// Managed tools directory. Empty keeps the default data-dir fallback.
    tools_dir: PathBuf,
    notes_query: String,
}
impl CoreView {
    fn fail(&mut self, message: String) {
        self.status_notice = Some((crate::activity::Level::Error, message.clone()));
        self.status = message;
    }
    fn warning(&mut self, message: String) {
        self.status_notice = Some((crate::activity::Level::Warn, message.clone()));
        self.status = message;
    }
    fn show_status(&self, ui: &mut egui::Ui) {
        if self.status.is_empty() {
            return;
        }
        if let Some((level, message)) = &self.status_notice {
            if message == &self.status {
                crate::activity::notice(ui, *level, message);
                return;
            }
        }
        ui.add(egui::Label::new(&self.status).wrap());
    }

    pub(crate) fn set_tools_dir(&mut self, dir: PathBuf) {
        self.tools_dir = dir;
    }

    #[cfg(test)]
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
            Ok(opened_reply(record, String::new()))
        });
    }

    fn start(&mut self, work: impl FnOnce() -> Result<Reply, String> + Send + 'static) {
        if self.job.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let generation = self.scope_generation;
        let initialized = self.scope_initialized;
        let roots = self.roots.clone();
        let vm_id = self.vm_id.clone();
        let selected_stamp = self.selected_stamp;
        match std::thread::Builder::new()
            .name("core-inspection".into())
            .spawn(move || {
                if sender
                    .send(InspectionReply {
                        generation,
                        roots,
                        vm_id,
                        initialized,
                        selected_stamp,
                        result: work(),
                    })
                    .is_err()
                {
                    eprintln!("core inspection view closed before job completed");
                }
            }) {
            Ok(_) => self.job = Some(receiver),
            Err(error) => self.fail(error.to_string()),
        }
    }
    fn poll(&mut self) {
        let Some(receiver) = self.job.as_ref() else {
            return;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => InspectionReply {
                generation: self.scope_generation,
                roots: self.roots.clone(),
                vm_id: self.vm_id.clone(),
                initialized: self.scope_initialized,
                selected_stamp: self.selected_stamp,
                result: Err("core inspection worker stopped unexpectedly".into()),
            },
        };
        self.job = None;
        self.decompile_active = false;
        if self.project_export_active {
            self.cancelled.store(false, Ordering::Relaxed);
        }
        self.project_export_active = false;
        if result.generation != self.scope_generation
            || (result.initialized && (result.roots != self.roots || result.vm_id != self.vm_id))
        {
            return;
        }
        // An operation started before the panel's first scope is adopted only
        // when its opened record belongs to that scope's recording roots.
        if !result.initialized && self.scope_initialized {
            if let Ok(Reply::Open(record, _, _)) = &result.result {
                if !self.roots.iter().any(|root| record.dir.starts_with(root)) {
                    return;
                }
            }
        }
        // A byte-page worker can finish after the selected file has grown.
        if matches!(&result.result, Ok(Reply::Page(_, _)))
            && result.selected_stamp != self.selected_stamp
        {
            return;
        }
        match result.result {
            Err(error) => self.fail(error),
            Ok(Reply::Chosen(path)) => {
                if let Some(path) = path {
                    self.source_path = path.display().to_string();
                }
            }
            Ok(Reply::Open(record, code, stamp)) => {
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
                self.selected_stamp = stamp;
                self.import_open = false;
                self.thread_index = 0;
                self.mapping_index = 0;
                self.window_offset = 0;
                self.page = None;
                self.code = code;
                self.functions.clear();
                self.show_decompiled = false;
                self.function_bodies.clear();
                self.code_function = None;
                self.pending_function_decode = None;
                self.function_decode_at = None;
                self.symbol_status.clear();
                self.status = "Core is referenced in place; retain its original file.".into();
                let directory = self.selected.as_ref().map(|record| record.dir.clone());
                if let Some(text) = directory.as_deref().and_then(saved_decompilation) {
                    let (functions, bodies) = parse_ghidra(&text);
                    self.functions = functions;
                    self.function_bodies = bodies;
                    self.code_function = self.functions.first().map(|_| 0);
                    self.show_decompiled = true;
                    self.code = text;
                    self.symbol_status = format!("{} Ghidra functions", self.functions.len());
                }
            }
            Ok(Reply::Page(address, data)) => self.page = Some((address, data)),
            Ok(Reply::Code(code)) => {
                self.code = code;
                self.show_decompiled = false;
                self.status = "Disassembly saved in the result directory.".into();
            }
            Ok(Reply::Decompiled(text)) => {
                let (functions, bodies) = parse_ghidra(&text);
                self.functions = functions;
                self.function_bodies = bodies;
                self.code_function = self.functions.first().map(|_| 0);
                self.show_decompiled = true;
                self.code = text;
                self.symbol_status = format!("{} Ghidra functions", self.functions.len());
                self.status = "Decompilation saved in the result directory.".into();
            }
            Ok(Reply::Done(message)) => self.status = message,
        }
    }

    /// | Argument | Meaning |
    /// |---|---|
    /// | `ui` | Core panel surface |
    /// | `recording_roots` | User-configured durable recording directories |
    /// | `vm_id` | Selected VM identity; filters all retained capture records |
    /// | `active` | Enables bounded background discovery; unfinished metadata refreshes sooner. |
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
        // Invalidate scope before consuming any reply from the previous VM.
        self.set_catalog_scope(recording_roots, vm_id);
        self.poll();
        self.poll_catalog();
        for issue in &self.catalog_issues {
            crate::activity::report(ui.ctx(), crate::activity::Level::Warn, issue);
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
        if let Some(delay) = self.refresh_catalog_if_due(active, Instant::now()) {
            ui.ctx().request_repaint_after(delay);
        }
        if self.job.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(75));
        }
        let mut action = None;
        self.list_toolbar(ui);
        if !self.hide_list {
            egui::SidePanel::left("core_dump_list")
                .resizable(true)
                .default_width(240.0)
                .width_range(180.0..=480.0)
                .frame(egui::Frame::new().inner_margin(egui::Margin {
                    right: 8,
                    ..Default::default()
                }))
                .show_inside(ui, |ui| {
                    action = self.dump_list(
                        ui,
                        controls.unavailable,
                        controls.can_cancel,
                        controls.boot_id,
                    );
                });
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                left: 10,
                ..Default::default()
            }))
            .show_inside(ui, |ui| self.analysis(ui));
        self.import_dialog(ui.ctx());
        action
    }
}

const MAPPING_FIELDS: &[crate::query::FieldSpec<'static>] = &[
    crate::query::FieldSpec::number("memory.start", "Virtual mapping start address"),
    crate::query::FieldSpec::number("memory.end", "Exclusive virtual mapping end address"),
    crate::query::FieldSpec::number("memory.size", "Virtual mapping extent in octets"),
    crate::query::FieldSpec::number(
        "memory.captured_size",
        "Retained available extent in octets",
    ),
    crate::query::FieldSpec::text("memory.permissions", "Recorded ELF mapping permissions"),
    crate::query::FieldSpec::tags(
        "memory.path",
        "Overlapping NT_FILE paths; missing when unrecorded",
    ),
    crate::query::FieldSpec::boolean(
        "memory.available",
        "Some mapping octets are retained; inspect extent for gaps",
    ),
];

const FUNCTION_FIELDS: &[crate::query::FieldSpec<'static>] = &[
    crate::query::FieldSpec::text(
        "function.kind",
        "Original function kind; missing when not retained",
    ),
    crate::query::FieldSpec::text("function.name", "Retained function name"),
    crate::query::FieldSpec::number("function.address", "Original function address"),
    crate::query::FieldSpec::number("function.size", "Recorded function extent in octets"),
];

#[derive(Default)]
struct CoreRowMetrics {
    pid: Option<u64>,
    threads: Option<u64>,
    mappings: Option<u64>,
    size: Option<u64>,
}

const NOTE_FIELDS: &[crate::query::FieldSpec<'static>] = &[
    crate::query::FieldSpec::text("note.kind", "Recovered note kind"),
    crate::query::FieldSpec::text("note.name", "Recovered note name"),
    crate::query::FieldSpec::number(
        "note.thread_id",
        "Recorded thread ID; missing for unscoped notes",
    ),
    crate::query::FieldSpec::text("note.source", "ELF note source"),
    crate::query::FieldSpec::boolean("note.complete", "Recovered note entry is available"),
    crate::query::FieldSpec::text("note.summary", "Recovered value or inventory summary"),
    crate::query::FieldSpec::text("kind", "Recovered note kind"),
    crate::query::FieldSpec::text("name", "Recovered note name"),
    crate::query::FieldSpec::number("thread", "Thread ID; missing for notes without a thread"),
    crate::query::FieldSpec::text("value", "Rendered recovered value"),
    crate::query::FieldSpec::number("value.num", "Numeric AUXV value"),
    crate::query::FieldSpec::text("source", "ELF note source"),
    crate::query::FieldSpec::text("availability", "Captured or unavailable"),
];

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

impl Drop for CoreView {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        self.ghidra_cancel.store(true, Ordering::SeqCst);
        let pid = self.ghidra_pid.swap(0, Ordering::SeqCst);
        if pid > 0 {
            signal_process_group(pid);
            reap_child(pid);
        }
    }
}

#[cfg(test)]
mod tests;
