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

/// Called only by inspection/catalog workers, never by the rendering path.
fn core_file_stamp(path: &Path) -> Option<CoreFileStamp> {
    let metadata = fs::metadata(path).ok()?;
    metadata.is_file().then(|| CoreFileStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        file_size: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

fn opened_reply(record: CoreRecord, code: String) -> Reply {
    let stamp = core_file_stamp(&record.core.source)
        .filter(|stamp| stamp.file_size == record.core.source_size);
    Reply::Open(Box::new(record), code, stamp)
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

fn catalog_stamp(catalog: &CoreCatalog) -> Option<CatalogStamp> {
    // Hash the bounded decoded metadata, not a later filesystem timestamp:
    // a sidecar can be sealed while a catalog worker is reading its old value.
    struct MetadataHash(std::collections::hash_map::DefaultHasher);
    impl Write for MetadataHash {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.write(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut hash = MetadataHash(std::collections::hash_map::DefaultHasher::new());
    serde_json::to_writer(&mut hash, catalog).ok()?;
    Some(hash.0.finish())
}

fn selected_core_refresh(probe: SelectedCoreProbe) -> SelectedCoreRefresh {
    let stamp = core_file_stamp(&probe.source);
    let core = if stamp == probe.stamp
        && stamp.is_some_and(|stamp| stamp.file_size == probe.source_size)
    {
        Ok(None)
    } else if probe.stamp.is_none()
        && stamp.is_some_and(|stamp| stamp.file_size == probe.source_size)
    {
        // A restored view may have no stamp yet. Establish its baseline without
        // inspecting unchanged bytes; ordinary opens carry their worker stamp.
        Ok(None)
    } else {
        CoreDump::open(&probe.source)
            .map(Some)
            .map_err(|error| error.to_string())
    };
    SelectedCoreRefresh {
        directory: probe.directory,
        source: probe.source,
        previous_stamp: probe.stamp,
        stamp: stamp.filter(|stamp| {
            core.as_ref()
                .ok()
                .and_then(|core| core.as_ref())
                .is_none_or(|core| core.source_size == stamp.file_size)
        }),
        core,
    }
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

#[derive(Clone, serde::Serialize)]
struct AcquiredCore {
    vm_id: String,
    boot_id: String,
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
                vm_id: artifacts.vm_id,
                boot_id: artifacts.boot_id,
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
    pub(crate) fn set_tools_dir(&mut self, dir: PathBuf) {
        self.tools_dir = dir;
    }

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
            Err(error) => self.status = error,
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

    fn start_catalog(&mut self) {
        if self.catalog_job.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let generation = self.catalog_generation;
        let roots = self.roots.clone();
        let vm_id = self.vm_id.clone();
        let selected = self.selected.as_ref().map(|record| SelectedCoreProbe {
            directory: record.dir.clone(),
            source: record.core.source.clone(),
            source_size: record.core.source_size,
            stamp: self.selected_stamp,
        });
        self.catalog_checked = Some(Instant::now());
        if std::thread::Builder::new()
            .name("core-catalog".into())
            .spawn(move || {
                let catalog = catalog(&roots, vm_id.as_deref());
                let stamp = catalog.as_ref().ok().and_then(catalog_stamp);
                let selected = selected.map(selected_core_refresh);
                let _ = sender.send(CatalogReply {
                    generation,
                    roots,
                    vm_id,
                    catalog,
                    stamp,
                    selected,
                });
            })
            .is_err()
        {
            self.status = "Could not refresh the core list".into();
            return;
        }
        self.catalog_job = Some(receiver);
    }

    fn poll_catalog(&mut self) {
        let Some(receiver) = self.catalog_job.as_ref() else {
            return;
        };
        let reply = match receiver.try_recv() {
            Ok(reply) => reply,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.catalog_job = None;
                return;
            }
        };
        self.catalog_job = None;
        if reply.generation != self.catalog_generation
            || reply.roots != self.roots
            || reply.vm_id != self.vm_id
        {
            return;
        }
        self.catalog_checked = Some(Instant::now());
        match reply.catalog {
            Ok(catalog) => {
                if reply.stamp.is_none()
                    || self.catalog_stamp != reply.stamp
                    || self.catalog_issues != catalog.issues
                {
                    self.apply_catalog(catalog);
                    self.catalog_stamp = reply.stamp;
                }
            }
            Err(error) => self.status = error,
        }
        if let Some(refresh) = reply.selected {
            self.apply_selected_refresh(refresh);
        }
    }

    fn apply_selected_refresh(&mut self, refresh: SelectedCoreRefresh) {
        let Some(record) = self.selected.as_mut() else {
            return;
        };
        if record.dir != refresh.directory
            || record.core.source != refresh.source
            || self.selected_stamp != refresh.previous_stamp
        {
            return;
        }
        match refresh.core {
            Ok(Some(core)) => {
                let tid = record
                    .core
                    .threads
                    .get(self.thread_index)
                    .map(|thread| thread.tid);
                let mapping = record.core.mappings.get(self.mapping_index).map(|mapping| {
                    (
                        mapping.start,
                        mapping.file_offset,
                        mapping.memory_size,
                        mapping.flags,
                    )
                });
                self.thread_index = tid
                    .and_then(|tid| core.threads.iter().position(|thread| thread.tid == tid))
                    .unwrap_or(0);
                self.mapping_index = mapping
                    .and_then(|identity| {
                        core.mappings.iter().position(|mapping| {
                            (
                                mapping.start,
                                mapping.file_offset,
                                mapping.memory_size,
                                mapping.flags,
                            ) == identity
                        })
                    })
                    .unwrap_or(0);
                if let Some(mapping) = core.mappings.get(self.mapping_index) {
                    self.window_offset = self
                        .window_offset
                        .min(mapping.memory_size.saturating_sub(1) / 16 * 16);
                }
                record.core = core;
                self.selected_stamp = refresh.stamp;
                self.page = None;
            }
            Ok(None) => self.selected_stamp = refresh.stamp,
            Err(error) => self.status = format!("Core metadata refresh: {error}"),
        }
    }

    fn invalidate_catalog(&mut self) {
        self.catalog_generation = self.catalog_generation.wrapping_add(1);
        self.catalog_checked = None;
    }

    fn set_catalog_scope(&mut self, roots: &[PathBuf], vm_id: Option<&str>) {
        if self.roots == roots && self.vm_id.as_deref() == vm_id {
            return;
        }
        let changed_vm = self.scope_initialized && self.vm_id.as_deref() != vm_id;
        if self.scope_initialized {
            self.scope_generation = self.scope_generation.wrapping_add(1);
        }
        self.scope_initialized = true;
        self.invalidate_catalog();
        self.catalog_stamp = None;
        self.acquired.clear();
        self.manual.clear();
        self.records.clear();
        self.catalog_issues.clear();
        self.import_open = false;
        if changed_vm
            || self
                .selected_directory
                .as_ref()
                .is_some_and(|directory| !roots.iter().any(|root| directory.starts_with(root)))
        {
            self.selected = None;
            self.selected_directory = None;
            self.selected_stamp = None;
        }
        self.roots = roots.to_vec();
        self.vm_id = vm_id.map(str::to_owned);
        if self.destination >= self.roots.len() {
            self.destination = 0;
        }
    }

    fn catalog_interval(&self, active: bool) -> Option<Duration> {
        let unfinished = self
            .manual
            .iter()
            .any(|capture| capture.phase != ProcessCorePhase::Finished)
            || self.acquired.iter().any(|capture| {
                matches!(
                    capture.state,
                    antinomie_monitor_core::RunArtifactState::Queued
                        | antinomie_monitor_core::RunArtifactState::WaitingForRootExit
                        | antinomie_monitor_core::RunArtifactState::InProgress
                )
            });
        if unfinished {
            Some(Duration::from_secs(1))
        } else if active {
            Some(Duration::from_secs(5))
        } else {
            None
        }
    }

    fn refresh_catalog_if_due(&mut self, active: bool, now: Instant) -> Option<Duration> {
        let interval = self.catalog_interval(active);
        let due = self.catalog_checked.is_none()
            || interval.is_some_and(|interval| {
                self.catalog_checked
                    .is_some_and(|checked| now.saturating_duration_since(checked) >= interval)
            });
        if due && self.catalog_job.is_none() {
            self.start_catalog();
        }
        if self.catalog_job.is_some() {
            return Some(Duration::from_millis(200));
        }
        interval.map(|interval| {
            interval.saturating_sub(self.catalog_checked.map_or(Duration::ZERO, |checked| {
                now.saturating_duration_since(checked)
            }))
        })
    }

    /// Disk catalog is authoritative inside the recording roots it scanned.
    /// An unfinished capture with no file yet, and any record outside those
    /// roots, stays until a later scan actually covers it.
    fn apply_catalog(&mut self, catalog: CoreCatalog) {
        let covered = |directory: &Path| self.roots.iter().any(|root| directory.starts_with(root));
        let pending_acquired: Vec<_> = self
            .acquired
            .iter()
            .filter(|core| {
                !covered(&core.directory)
                    || (core.file.is_none()
                        && !catalog
                            .acquired
                            .iter()
                            .any(|found| found.directory == core.directory))
            })
            .cloned()
            .collect();
        let pending_manual: Vec<_> = self
            .manual
            .iter()
            .filter(|core| {
                !covered(&core.directory)
                    || (core.file.is_none()
                        && !catalog
                            .manual
                            .iter()
                            .any(|found| found.directory == core.directory))
            })
            .cloned()
            .collect();
        let kept_records: Vec<_> = self
            .records
            .iter()
            .filter(|record| !covered(&record.dir))
            .cloned()
            .collect();
        self.records = catalog.imported;
        self.records.extend(kept_records);
        self.acquired = catalog.acquired;
        self.acquired.extend(pending_acquired);
        self.manual = catalog.manual;
        self.manual.extend(pending_manual);
        self.catalog_issues = catalog.issues;
        self.catalog_checked = Some(Instant::now());
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
                    action = self.dump_list(ui, controls.unavailable, controls.can_cancel);
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

    fn list_toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add(
                    egui::Button::new(egui_phosphor::regular::SIDEBAR_SIMPLE)
                        .frame(false)
                        .selected(!self.hide_list),
                )
                .on_hover_text(if self.hide_list {
                    "Show the core list"
                } else {
                    "Hide the core list"
                })
                .clicked()
            {
                self.hide_list = !self.hide_list;
            }
            let title = self
                .selected
                .as_ref()
                .map(|record| record.label.clone())
                .or_else(|| {
                    self.manual
                        .iter()
                        .find(|core| Some(&core.directory) == self.selected_directory.as_ref())
                        .map(|core| format!("PID {} · {}", core.target.tgid, core.id))
                });
            match title {
                Some(title) => {
                    ui.label(RichText::new(title).strong().color(crate::theme::heading()));
                }
                None => {
                    ui.colored_label(crate::theme::muted(), "No core open");
                }
            }
        });
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
                    self.invalidate_catalog();
                    self.start_catalog();
                    ui.ctx().request_repaint_after(Duration::from_millis(200));
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
            ui.horizontal_wrapped(|ui| {
                ui.spinner();
                ui.label("Working…");
                if self.project_export_active && ui.button("Cancel export").clicked() {
                    self.cancelled.store(true, Ordering::Relaxed);
                }
            });
        }
        let mut acquired_selection = None;
        let mut imported_selection = None;
        let mut file_action: Option<(bool, PathBuf)> = None;
        let mut project_action = None;
        let font_size = egui::TextStyle::Body.resolve(ui.style()).size;
        let mut fields = crate::query::LABEL_FIELDS.to_vec();
        fields.extend(crate::query::CAPTURE_FIELDS);
        fields.extend([
            crate::query::FieldSpec::text("name", "Displayed core name"),
            crate::query::FieldSpec::text("state", "Capture or imported core state"),
            crate::query::FieldSpec::number("pid", "Captured process ID, when retained"),
            crate::query::FieldSpec::number("threads", "Inspected core thread count"),
            crate::query::FieldSpec::number("mappings", "Inspected core mapping count"),
            crate::query::FieldSpec::number("size", "Stored core size in octets, when retained"),
            crate::query::FieldSpec::number("core.thread_count", "Inspected core thread count"),
            crate::query::FieldSpec::boolean(
                "core.partial",
                "Explicit partial acquisition; missing when undetermined",
            ),
            crate::query::FieldSpec::number(
                "core.signal",
                "Signal recorded in an inspected core thread note",
            ),
        ]);
        let tags: Vec<_> = self
            .manual
            .iter()
            .map(|core| &core.directory)
            .chain(self.acquired.iter().map(|core| &core.directory))
            .chain(self.records.iter().map(|record| &record.dir))
            .filter_map(|directory| crate::evidence::annotation(ui, directory))
            .flat_map(|annotation| annotation.tags)
            .collect();
        let filter =
            crate::query::table_filter(ui, "core-history", "Filter core dumps", &fields, &tags);
        let filter_id = ui.id().with(("table-filter", "core-history"));
        let manual_shown: Vec<_> = self
            .manual
            .iter()
            .map(|core| filter.keep_table(&manual_filter_row(ui, core)))
            .collect();
        let acquired_shown: Vec<_> = self
            .acquired
            .iter()
            .map(|core| filter.keep_table(&acquired_filter_row(ui, core)))
            .collect();
        let imported_shown: Vec<_> = self
            .records
            .iter()
            .map(|record| filter.keep_table(&imported_filter_row(ui, record)))
            .collect();
        let matched = manual_shown
            .iter()
            .chain(&acquired_shown)
            .chain(&imported_shown)
            .filter(|shown| **shown)
            .count();
        ui.weak(format!(
            "{matched} / {} cores",
            self.manual.len() + self.acquired.len() + self.records.len()
        ));
        if let Some(directory) = self.selected_directory.as_ref() {
            let visible = self
                .manual
                .iter()
                .zip(&manual_shown)
                .any(|(core, shown)| *shown && &core.directory == directory)
                || self
                    .acquired
                    .iter()
                    .zip(&acquired_shown)
                    .any(|(core, shown)| *shown && &core.directory == directory)
                || self
                    .records
                    .iter()
                    .zip(&imported_shown)
                    .any(|(record, shown)| *shown && &record.dir == directory);
            let known = self.manual.iter().any(|core| &core.directory == directory)
                || self
                    .acquired
                    .iter()
                    .any(|core| &core.directory == directory)
                || self.records.iter().any(|record| &record.dir == directory);
            if known && !visible {
                self.selected = None;
                self.selected_directory = None;
                self.page = None;
            }
        }
        egui::ScrollArea::vertical()
            .id_salt("core_capture_list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                if self.acquired.is_empty() && self.records.is_empty() && self.manual.is_empty() {
                    ui.add_space(8.0);
                    ui.add(egui::Label::new("No core dumps. Dump a live process, enable Core Dump on Exit in Run program, or import a core.").wrap());
                }
                for (index, core) in self.manual.iter().enumerate() {
                    if !manual_shown[index] { continue; }
                    let fallback = format!("PID {} · {}", core.target.tgid, core.id);
                    let title = crate::evidence::title(ui, &core.directory, &fallback);
                    let selected = self.selected_directory.as_ref() == Some(&core.directory);
                    let state = manual_status(core);
                    let color = if core.issue.is_some() { crate::theme::warn() } else { crate::theme::text() };
                    let row = crate::network_view::capture_row(ui, selected, (&title, color), &state, font_size)
                        .on_hover_text(format!("{title}\n{state}\n{}", core.directory.display()));
                    let core_file = core.file.clone();
                    row.context_menu(|ui| {
                        crate::evidence::menu(ui, &core.directory);
                        crate::query::table_row_menu(ui, filter_id, &manual_filter_row(ui, core));
                        core_file_menu(ui, core_file.as_deref(), &mut file_action);
                        core_project_menu(ui, &core.directory, self.job.is_none(), &mut project_action);
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
                for (index, core) in self.acquired.iter().enumerate() {
                    if !acquired_shown[index] { continue; }
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
                    let core_file = core.file.clone();
                    row.context_menu(|ui| {
                        crate::evidence::menu(ui, &core.directory);
                        crate::query::table_row_menu(ui, filter_id, &acquired_filter_row(ui, core));
                        core_file_menu(ui, core_file.as_deref(), &mut file_action);
                        core_project_menu(ui, &core.directory, self.job.is_none(), &mut project_action);
                    });
                    if row.clicked() && self.job.is_none() {
                        acquired_selection = Some((core.directory.clone(), core.file.clone()));
                    }
                }
                if !self.records.is_empty() && !self.acquired.is_empty() {
                    ui.add_space(8.0);
                    crate::theme::section(ui, "Imported cores");
                }
                for (index, record) in self.records.iter().enumerate() {
                    if !imported_shown[index] { continue; }
                    let title = crate::evidence::title(ui, &record.dir, &record.label);
                    let selected = self.selected_directory.as_ref() == Some(&record.dir)
                        || self.selected.as_ref().is_some_and(|current| current.dir == record.dir);
                    let detail = format!("{} threads · {} mappings", record.core.threads.len(), record.core.mappings.len());
                    let row = crate::network_view::capture_row(ui, selected, (&title, crate::theme::text()), &detail, font_size)
                        .on_hover_text(record.core.source.display().to_string());
                    let core_file = record.core.source.clone();
                    row.context_menu(|ui| {
                        crate::evidence::menu(ui, &record.dir);
                        crate::query::table_row_menu(ui, filter_id, &imported_filter_row(ui, record));
                        core_file_menu(ui, Some(&core_file), &mut file_action);
                        core_project_menu(ui, &record.dir, self.job.is_none(), &mut project_action);
                    });
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
                Ok(opened_reply(record, code))
            });
        }
        if let Some((export, path)) = file_action {
            if export {
                self.export_source(path);
            } else {
                let parent = path.parent().unwrap_or(Path::new("/")).to_owned();
                self.start(move || {
                    reveal(&parent).map(|()| Reply::Done("Opened core file directory.".into()))
                });
            }
        }
        if let Some(source) = project_action {
            self.export_project(source);
        }
        action
    }

    fn export_project(&mut self, source: PathBuf) {
        if self.job.is_some() {
            return;
        }
        self.cancelled.store(false, Ordering::Relaxed);
        self.project_export_active = true;
        let cancelled = Arc::clone(&self.cancelled);
        self.start(move || {
            let Some(destination) = choose_path(
                true,
                "Export Ghidra project — choose a new directory path",
                &cancelled,
            )?
            else {
                return Ok(Reply::Done("Ghidra project export cancelled.".into()));
            };
            if cancelled.load(Ordering::Relaxed) {
                return Ok(Reply::Done("Ghidra project export cancelled.".into()));
            }
            antinomie_monitor_core::analysis::copy_project(&source, &destination)?;
            if cancelled.load(Ordering::Relaxed) {
                fs::remove_dir_all(&destination).map_err(|error| {
                    format!("Ghidra export cancelled; partial project cleanup failed: {error}")
                })?;
                return Ok(Reply::Done("Ghidra project export cancelled.".into()));
            }
            Ok(Reply::Done(format!(
                "Exported Ghidra project to {}",
                destination.display()
            )))
        });
        if self.job.is_none() {
            self.project_export_active = false;
        }
    }

    fn export_source(&mut self, source: PathBuf) {
        let cancelled = self.cancelled.clone();
        self.start(move || {
            let Some(destination) = choose_file(true, &cancelled)? else {
                return Ok(Reply::Done("Export cancelled.".into()));
            };
            if destination.exists() {
                return Err("Export destination already exists; choose a new filename.".into());
            }
            let mut input = fs::File::open(&source).map_err(|error| error.to_string())?;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)
                .map_err(|error| error.to_string())?;
            let mut buffer = vec![0; 256 * 1024];
            loop {
                if cancelled.load(Ordering::Relaxed) {
                    return Err(
                        "Core export cancelled; destination contains only the exported prefix."
                            .into(),
                    );
                }
                let size = input.read(&mut buffer).map_err(|error| error.to_string())?;
                if size == 0 {
                    break;
                }
                output
                    .write_all(&buffer[..size])
                    .map_err(|error| error.to_string())?;
            }
            output.sync_all().map_err(|error| error.to_string())?;
            Ok(Reply::Done(format!("Exported {}", destination.display())))
        });
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
                            self.start(move || CoreRecord::import(&path, &root).map(|record| opened_reply(record, String::new())).map_err(|error| error.to_string()));
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
            Tab::Notes => notes_table(ui, &record, &mut self.notes_query),
        }
    }
    fn register_cell(&mut self, ui: &mut egui::Ui, record: &CoreRecord, name: &str, value: u64) {
        let name_color = match name {
            "rip" | "eip" | "pc" => crate::theme::error(),
            "rsp" | "esp" | "rbp" | "ebp" => crate::theme::warn(),
            "rflags" | "eflags" | "flags" => crate::theme::value(crate::theme::ValueKind::Flags),
            _ => crate::theme::value(crate::theme::ValueKind::Name),
        };
        let value_color = if matches!(name, "rflags" | "eflags" | "flags") {
            crate::theme::value(crate::theme::ValueKind::Flags)
        } else {
            crate::theme::value(crate::theme::ValueKind::Pointer)
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new(name).monospace().color(name_color));
            ui.label(
                RichText::new(format!("0x{value:016x}"))
                    .monospace()
                    .color(value_color),
            );
            if ui.small_button("Copy").clicked() {
                ui.ctx().copy_text(format!("0x{value:x}"));
            }
            if (name == "rip" || name == "rsp")
                && ui
                    .small_button(egui_phosphor::regular::MEMORY)
                    .on_hover_text("View memory at this register")
                    .clicked()
            {
                if let Some(index) = record
                    .core
                    .mappings
                    .iter()
                    .position(|mapping| value >= mapping.start && value < mapping.end())
                {
                    self.mapping_index = index;
                    self.window_offset =
                        (value - record.core.mappings[index].start) / WINDOW_SIZE * WINDOW_SIZE;
                    self.page = None;
                    self.tab = Tab::Mappings;
                } else {
                    self.status = "Register points to an unmapped address.".into();
                }
            }
        });
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
            let groups: &[(&str, &[&str])] = &[
                ("Instruction pointer", &["rip", "eip", "pc"]),
                ("Stack and frame", &["rsp", "esp", "rbp", "ebp"]),
                ("Flags", &["rflags", "eflags", "flags"]),
                (
                    "General",
                    &[
                        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
                        "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi",
                    ],
                ),
            ];
            let mut shown = std::collections::BTreeSet::new();
            for (title, names) in groups {
                let present: Vec<_> = names
                    .iter()
                    .filter_map(|name| {
                        thread
                            .registers
                            .iter()
                            .find(|(register, _)| register == name)
                    })
                    .collect();
                if present.is_empty() {
                    continue;
                }
                ui.label(RichText::new(*title).strong().color(crate::theme::heading()));
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 16.0;
                    for (name, value) in present {
                        shown.insert(name.clone());
                        self.register_cell(ui, record, name, *value);
                    }
                });
            }
            let other: Vec<_> = thread
                .registers
                .iter()
                .filter(|(name, _)| !shown.contains(name))
                .collect();
            if !other.is_empty() {
                ui.label(RichText::new("Other").strong().color(crate::theme::heading()));
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 16.0;
                    for (name, value) in other {
                        self.register_cell(ui, record, name, *value);
                    }
                });
            }
            ui.label("Register values are recovered evidence. Stack unwinding, pointer chains, and debugger execution are not available.");
        });
    }
    fn mappings(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
        let mut requested_page = None;
        let filter = crate::query::table_filter(
            ui,
            ("core-mappings", &record.dir),
            "Filter memory mappings",
            MAPPING_FIELDS,
            &[],
        );
        let filter_id = ui
            .id()
            .with(("table-filter", ("core-mappings", &record.dir)));
        let shown: Vec<_> = record
            .core
            .mappings
            .iter()
            .enumerate()
            .filter(|(_, mapping)| filter.keep_table(&mapping_filter_row(&record.core, mapping)))
            .map(|(index, _)| index)
            .collect();
        ui.weak(format!(
            "{} / {} mappings",
            shown.len(),
            record.core.mappings.len()
        ));
        if !shown.contains(&self.mapping_index) {
            self.mapping_index = usize::MAX;
            self.page = None;
            self.window_offset = 0;
        }
        let choices = mapping_choices(&record.core);
        let (selected_label, selected_tip) = choices
            .get(self.mapping_index)
            .map(|(label, tip)| (label.clone(), tip.clone()))
            .unwrap_or_else(|| {
                (
                    "Select a mapping".into(),
                    "Select a retained mapping matching the filter.".into(),
                )
            });
        egui::ComboBox::from_id_salt("core-mapping")
            .width(ui.available_width())
            .selected_text(selected_label)
            .show_ui(ui, |ui| {
                for &index in &shown {
                    let (label, tip) = &choices[index];
                    let row = ui
                        .selectable_value(&mut self.mapping_index, index, label)
                        .on_hover_text(tip);
                    if row.changed() {
                        self.window_offset = 0;
                        self.page = None;
                    }
                    row.context_menu(|ui| {
                        crate::query::table_row_menu(
                            ui,
                            filter_id,
                            &mapping_filter_row(&record.core, &record.core.mappings[index]),
                        )
                    });
                }
            })
            .response
            .on_hover_text(selected_tip);
        let Some(mapping) = record.core.mappings.get(self.mapping_index) else {
            ui.label(if shown.is_empty() {
                "No retained mapping matches this filter."
            } else {
                "Select a mapping to inspect its captured bytes."
            });
            return;
        };
        let wide = ui.available_width() >= 760.0;
        if wide {
            egui::SidePanel::right("core-mapping-info")
                .resizable(true)
                .default_width(280.0)
                .width_range(220.0..=460.0)
                .show_separator_line(true)
                .frame(egui::Frame::new().inner_margin(egui::Margin {
                    left: 12,
                    right: 8,
                    top: 4,
                    bottom: 4,
                }))
                .show_inside(ui, |ui| self.mapping_panel(ui, mapping));
        } else {
            egui::CollapsingHeader::new("Mapping details")
                .default_open(true)
                .show(ui, |ui| self.mapping_panel(ui, mapping));
        }
        let span = mapping
            .memory_size
            .saturating_sub(self.window_offset)
            .min(WINDOW_SIZE);
        ui.add(egui::Label::new(format!("Offset 0x{:x}–0x{:x} of 0x{:x}",self.window_offset,self.window_offset+span,mapping.memory_size)).wrap())
                .on_hover_text("Scroll this span, advance to another span, or jump to an offset to inspect the entire mapping.");
        let row_count = usize::try_from(span.div_ceil(16)).unwrap_or(0);
        let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
        egui::ScrollArea::both()
            .id_salt(("core-hex", self.mapping_index, self.window_offset))
            .show_rows(ui, row_height, row_count, |ui, range| {
                for row in range {
                    let address = mapping.start + self.window_offset + row as u64 * 16;
                    let mut line = format!("{address:016x}  ");
                    let mut ascii = String::new();
                    for column in 0..16 {
                        let Some(at) = address.checked_add(column) else {
                            break;
                        };
                        if at >= mapping.end() {
                            line.push_str("   ");
                            continue;
                        }
                        let value = self
                            .page
                            .as_ref()
                            .filter(|(base, data)| at >= *base && at - *base < data.len() as u64)
                            .map(|(base, data)| data[(at - *base) as usize]);
                        match value {
                            Some(Some(byte)) => {
                                line.push_str(&format!("{byte:02x} "));
                                ascii.push(if byte.is_ascii_graphic() || byte == b' ' {
                                    char::from(byte)
                                } else {
                                    '.'
                                });
                            }
                            Some(None) => {
                                line.push_str("?? ");
                                ascii.push('?');
                            }
                            None => {
                                line.push_str("·· ");
                                ascii.push(' ');
                                if requested_page.is_none() {
                                    requested_page = Some(at / PAGE_SIZE as u64 * PAGE_SIZE as u64);
                                }
                            }
                        }
                    }
                    line.push_str(&format!(" {ascii}"));
                    ui.add(egui::Label::new(RichText::new(line).monospace()).extend());
                }
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
    fn mapping_panel(&mut self, ui: &mut egui::Ui, mapping: &CoreMapping) {
        ui.label(
            RichText::new("Mapping")
                .strong()
                .color(crate::theme::heading()),
        );
        ui.label(format!(
            "{} / {} octets captured",
            mapping.available_size, mapping.memory_size
        ));
        ui.add(egui::Label::new("?? = unavailable; 00 = captured zero.").wrap())
            .on_hover_text(
                "Unavailable memory can be absent, omitted by the memory filter, or truncated in the saved core.",
            );
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(self.window_offset > 0, egui::Button::new("Previous span"))
                .clicked()
            {
                self.window_offset = self.window_offset.saturating_sub(WINDOW_SIZE);
                self.page = None;
            }
            if ui
                .add_enabled(
                    self.window_offset.saturating_add(WINDOW_SIZE) < mapping.memory_size,
                    egui::Button::new("Next span"),
                )
                .clicked()
            {
                self.window_offset = self.window_offset.saturating_add(WINDOW_SIZE);
                self.page = None;
            }
        });
        ui.label("Mapping offset (hex)");
        ui.horizontal_wrapped(|ui| {
            let input_width = ui.available_width().min(160.0);
            ui.add(egui::TextEdit::singleline(&mut self.jump).desired_width(input_width));
            if ui.button("Jump").clicked() {
                match parse_address(&self.jump) {
                    Ok(offset) if offset < mapping.memory_size => {
                        self.window_offset = offset / 16 * 16;
                        self.page = None;
                    }
                    _ => self.status = "Offset must lie inside the selected mapping.".into(),
                }
            }
        });
    }

    fn disassembly(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
        let mut filtered_without_selection = false;
        egui::SidePanel::left("core_function_list")
            .resizable(true)
            .default_width(220.0)
            .width_range(160.0..=420.0)
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                right: 8,
                ..Default::default()
            }))
            .show_inside(ui, |ui| {
                let filter = crate::query::table_filter(
                    ui,
                    ("core-function-filter", &record.dir),
                    "Filter functions",
                    FUNCTION_FIELDS,
                    &[],
                );
                let filter_id = ui
                    .id()
                    .with(("table-filter", ("core-function-filter", &record.dir)));
                let shown: Vec<_> = self
                    .functions
                    .iter()
                    .enumerate()
                    .filter(|(_, function)| filter.keep_table(&function_filter_row(function)))
                    .map(|(index, _)| index)
                    .collect();
                ui.weak(format!(
                    "{} / {} functions",
                    shown.len(),
                    self.functions.len()
                ));
                if self
                    .code_function
                    .is_some_and(|index| !shown.contains(&index))
                {
                    self.code_function = None;
                    self.pending_function_decode = None;
                    self.status = "The selected function is hidden by this filter.".into();
                }
                filtered_without_selection =
                    shown.len() != self.functions.len() && self.code_function.is_none();
                if ui.button("Export functions").clicked() {
                    match export_saved_functions(&record.dir) {
                        Ok(path) => {
                            self.status = format!("Exported functions to {}", path.display());
                        }
                        Err(error) => self.status = error,
                    }
                }
                if self.functions.is_empty() {
                    ui.add(egui::Label::new("No functions indexed").wrap());
                }
                let row_height = ui.text_style_height(&egui::TextStyle::Body) * 4.0
                    + ui.spacing().item_spacing.y * 2.0;
                egui::ScrollArea::vertical()
                    .id_salt("core-functions")
                    .show_rows(ui, row_height, shown.len(), |ui, range| {
                        for slot in range {
                            let index = shown[slot];
                            let function = &self.functions[index];
                            let label = format!(
                                "symbol {}\naddress {:x}\nmodule not recorded\n{} octets",
                                function.name, function.address, function.size
                            );
                            let response =
                                ui.selectable_label(self.code_function == Some(index), label);
                            response.context_menu(|ui| {
                                crate::query::table_row_menu(
                                    ui,
                                    filter_id,
                                    &function_filter_row(function),
                                )
                            });
                            if response.clicked() {
                                let address = function.address;
                                self.code_function = Some(index);
                                self.code_address = format!("{address:x}");
                                if !self.show_decompiled {
                                    self.pending_function_decode = Some(address);
                                }
                            }
                        }
                    });
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(crate::theme::terminal())
                    .inner_margin(egui::Margin {
                        left: 10,
                        ..Default::default()
                    }),
            )
            .show_inside(ui, |ui| {
                if filtered_without_selection {
                    ui.label("Select a function matching the filter to inspect its code.");
                    return;
                }
                self.follow_function_decode(record);
                let idle = self.code.is_empty() && !self.show_decompiled;
                if idle {
                    ui.vertical_centered(|ui| {
                        ui.add_space((ui.available_height() * 0.28).max(12.0));
                        ui.label("Disassemble or decompile this core on demand.");
                        if self.job.is_some() {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(if self.status.is_empty() {
                                    "Disassembling…"
                                } else {
                                    self.status.as_str()
                                });
                            });
                        } else if !self.status.is_empty() {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&self.status).color(crate::theme::warn()),
                                )
                                .wrap(),
                            );
                        }
                        if ui
                            .add_enabled(
                                self.job.is_none(),
                                egui::Button::new(self.disassemble_label()),
                            )
                            .clicked()
                        {
                            self.decode_window(record);
                        }
                        self.ghidra_button(ui, record);
                    });
                    return;
                }
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            self.job.is_none(),
                            egui::Button::new(self.disassemble_label()),
                        )
                        .clicked()
                    {
                        self.decode_window(record);
                    }
                    self.ghidra_button(ui, record);
                });
                if !self.symbol_status.is_empty() {
                    ui.label(&self.symbol_status);
                }
                if self.show_decompiled {
                    let body = self
                        .code_function
                        .and_then(|index| self.function_bodies.get(index))
                        .map(String::as_str)
                        .unwrap_or("Select a function.");
                    paint_source(ui, body);
                } else {
                    let lines = self.asm_lines();
                    if lines.is_empty() && self.code_function.is_some() {
                        ui.label(
                            RichText::new("This function is outside the decoded window.").weak(),
                        );
                    } else {
                        let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
                        egui::ScrollArea::both()
                            .id_salt("core-code")
                            .auto_shrink([false, false])
                            .show_rows(ui, row_height, lines.len(), |ui, range| {
                                for index in range {
                                    paint_asm(ui, lines[index]);
                                }
                            });
                    }
                }
            });
    }

    fn asm_lines(&self) -> Vec<&str> {
        let range = self.code_function.and_then(|index| {
            self.functions.get(index).map(|function| {
                (
                    function.address,
                    function.address.saturating_add(function.size.max(1)),
                )
            })
        });
        let lines: Vec<&str> = self.code.lines().filter(|line| !line.is_empty()).collect();
        let Some((start, end)) = range else {
            return lines;
        };
        lines
            .into_iter()
            .filter(|line| {
                let address = line.split_whitespace().next().unwrap_or("");
                u64::from_str_radix(address, 16)
                    .is_ok_and(|address| address >= start && address < end)
            })
            .collect()
    }

    /// Start one disassembly window for a function the user just selected.
    fn follow_function_decode(&mut self, record: &CoreRecord) {
        let Some(address) = self.pending_function_decode else {
            return;
        };
        if self.function_decode_at == Some(address) {
            self.pending_function_decode = None;
            return;
        }
        if self.show_decompiled || self.job.is_some() {
            return;
        }
        let selected = self
            .code_function
            .and_then(|index| self.functions.get(index))
            .map(|function| function.address);
        if selected != Some(address) {
            return;
        }
        if !self.code.is_empty() && !self.asm_lines().is_empty() {
            self.pending_function_decode = None;
            return;
        }
        self.function_decode_at = Some(address);
        self.pending_function_decode = None;
        self.code_address = format!("{address:x}");
        self.decode_window(record);
    }

    fn ghidra_button(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
        if self.decompile_active {
            if ui.button("Cancel").clicked() {
                self.cancel_decompile();
            }
            return;
        }
        if ui
            .add_enabled(
                self.job.is_none(),
                egui::Button::new("Decompile with Ghidra"),
            )
            .clicked()
        {
            self.decompile_core(record);
        }
    }

    fn cancel_decompile(&mut self) {
        self.ghidra_cancel.store(true, Ordering::SeqCst);
        let pid = self.ghidra_pid.swap(0, Ordering::SeqCst);
        if pid > 0 {
            signal_process_group(pid);
            reap_child(pid);
        }
        self.decompile_active = false;
        self.status = DECOMPILE_CANCELLED.into();
    }

    /// Address and octet count for the next disassembly request.
    /// A selected function with a positive size starts at `function.address`
    /// for `min(function.size, 65536)` octets, even when `code_address` is stale.
    /// Otherwise the request is 65536 octets at `code_address`. `disassemble`
    /// stops at the first missing byte and caps the decode at 64 KiB.
    fn disassembly_request(&mut self, core: &CoreDump) -> Result<(u64, usize), String> {
        if let Some(function) = self
            .code_function
            .and_then(|index| self.functions.get(index))
            .filter(|function| function.size > 0)
        {
            if !captured_byte(core, function.address) {
                return Err(format!(
                    "Function {:x} has no captured bytes at its start.",
                    function.address
                ));
            }
            let octets = function.size.min(FUNCTION_DISASSEMBLY_LIMIT);
            let size = usize::try_from(octets)
                .map_err(|_| "function disassembly window does not fit".to_owned())?;
            self.code_address = format!("{:x}", function.address);
            return Ok((function.address, size));
        }
        let address = captured_code_origin(core, &self.code_address)?;
        self.code_address = format!("{address:x}");
        Ok((address, DISASSEMBLY_BYTES))
    }

    fn disassemble_label(&self) -> String {
        self.code_function
            .and_then(|index| self.functions.get(index))
            .filter(|function| function.size > 0)
            .map(|function| {
                let octets = function.size.min(FUNCTION_DISASSEMBLY_LIMIT);
                format!("Disassemble function ({octets} octets)")
            })
            .unwrap_or_else(|| "Disassemble captured code".to_owned())
    }

    fn decode_window(&mut self, record: &CoreRecord) {
        match self.disassembly_request(&record.core) {
            Ok((address, size)) => {
                self.status = format!("Disassembling 0x{address:x} ({size} octets)…");
                let core = record.core.clone();
                let dir = record.dir.clone();
                self.start(move || {
                    let text = core
                        .disassemble(address, size)
                        .map_err(|error| error.to_string())?;
                    fs::write(dir.join("disassembly.txt"), &text)
                        .map_err(|error| error.to_string())?;
                    Ok(Reply::Code(text))
                });
            }
            Err(error) => self.status = error,
        }
    }

    fn decompile_core(&mut self, record: &CoreRecord) {
        if self.job.is_some() {
            return;
        }
        if let Err(error) = write_ghidra_mappings(&record.dir, &record.core.mappings) {
            self.status = error;
            return;
        }
        self.ghidra_cancel.store(false, Ordering::SeqCst);
        let source = record.core.source.clone();
        let dir = record.dir.clone();
        let tools_dir = self.tools_dir.clone();
        let pid = Arc::clone(&self.ghidra_pid);
        let cancel = Arc::clone(&self.ghidra_cancel);
        self.decompile_active = true;
        self.start(move || {
            ghidra_decompile(&source, &dir, &tools_dir, &pid, &cancel).map(Reply::Decompiled)
        });
        if self.job.is_none() {
            self.decompile_active = false;
        }
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

fn mapping_filter_row(
    core: &CoreDump,
    mapping: &CoreMapping,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue as V;
    let paths: Vec<_> = core
        .files
        .iter()
        .filter(|file| {
            file.start < mapping.end() && mapping.start < file.end && !file.path.is_empty()
        })
        .map(|file| file.path.clone())
        .collect();
    vec![
        ("memory.start", V::Number(i128::from(mapping.start))),
        ("memory.end", V::Number(i128::from(mapping.end()))),
        ("memory.size", V::Number(i128::from(mapping.memory_size))),
        (
            "memory.captured_size",
            V::Number(i128::from(mapping.available_size)),
        ),
        ("memory.permissions", V::Text(mapping.permissions())),
        (
            "memory.path",
            if paths.is_empty() {
                V::Missing
            } else {
                V::List(paths)
            },
        ),
        ("memory.available", V::Bool(mapping.available_size > 0)),
    ]
}

const FUNCTION_FIELDS: &[crate::query::FieldSpec<'static>] = &[
    crate::query::FieldSpec::text(
        "function.kind",
        "Original function kind; missing when not retained",
    ),
    crate::query::FieldSpec::text("function.name", "Retained function name"),
    crate::query::FieldSpec::number("function.address", "Original function address"),
    crate::query::FieldSpec::number("function.size", "Recorded function extent in octets"),
];

fn function_filter_row(function: &CoreFunction) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue as V;
    vec![
        ("function.name", V::Text(function.name.clone())),
        ("function.address", V::Number(i128::from(function.address))),
        ("function.size", V::Number(i128::from(function.size))),
    ]
}

fn mapping_name(core: &CoreDump, mapping: &CoreMapping) -> String {
    let mut paths = Vec::new();
    for file in &core.files {
        let path = file.path.trim();
        if path.is_empty() {
            continue;
        }
        if file.start < mapping.end()
            && mapping.start < file.end
            && !paths.iter().any(|existing| existing == path)
        {
            paths.push(path.to_owned());
        }
    }
    match paths.as_slice() {
        [] => "unknown".into(),
        [one] => one.clone(),
        [first, rest @ ..] => format!("{first} (+{} file extents)", rest.len()),
    }
}

fn mapping_choices(core: &CoreDump) -> Vec<(String, String)> {
    let names: Vec<String> = core
        .mappings
        .iter()
        .map(|mapping| mapping_name(core, mapping))
        .collect();
    core.mappings
        .iter()
        .zip(names)
        .map(|(mapping, name)| {
            let permissions = mapping.permissions();
            let shown = if name == "unknown" || name.starts_with("unknown ") {
                "unknown".to_owned()
            } else if name.ends_with(" file extents)") {
                name.clone()
            } else {
                Path::new(&name)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(&name)
                    .to_owned()
            };
            let label = format!(
                "mmap {:x}-{:x} {permissions} [{shown}]",
                mapping.start,
                mapping.end()
            );
            let label = ellipsize(&label, 96);
            let tip = if shown == "unknown" {
                format!("{name}\nNo NT_FILE name overlaps this mapping.")
            } else {
                name
            };
            (label, tip)
        })
        .collect()
}

fn ellipsize(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let keep = limit.saturating_sub(1);
    let end = text
        .char_indices()
        .nth(keep)
        .map(|(index, _)| index)
        .unwrap_or(text.len());
    format!("{}…", &text[..end])
}

/// A typed address is used only when a captured byte exists there.
/// Otherwise the instruction pointer is used when it is captured, then the
/// first executable mapping that actually contains captured bytes.
fn captured_code_origin(core: &CoreDump, typed: &str) -> Result<u64, String> {
    if let Ok(address) = parse_address(typed) {
        if captured_byte(core, address) {
            return Ok(address);
        }
    }
    if let Some(thread) = core.threads.first() {
        for name in ["rip", "eip", "pc"] {
            if let Some(address) = thread.register(name) {
                if captured_byte(core, address) {
                    return Ok(address);
                }
            }
        }
    }
    core.mappings
        .iter()
        .find(|mapping| mapping.flags & 1 != 0 && mapping.available_size > 0)
        .map(|mapping| mapping.start)
        .ok_or_else(|| {
            "No captured executable bytes. This core has no executable mapping with captured data."
                .to_owned()
        })
}

fn captured_byte(core: &CoreDump, address: u64) -> bool {
    core.mappings.iter().any(|mapping| {
        let available = mapping.available_size.min(mapping.memory_size);
        let end = mapping.start.saturating_add(available);
        address >= mapping.start && address < end
    })
}

fn core_file_menu(ui: &mut egui::Ui, file: Option<&Path>, action: &mut Option<(bool, PathBuf)>) {
    let Some(file) = file else { return };
    if ui.button("Open core file directory").clicked() {
        *action = Some((false, file.to_owned()));
        ui.close_menu();
    }
    if ui.button("Export core…").clicked() {
        *action = Some((true, file.to_owned()));
        ui.close_menu();
    }
}

fn core_project_menu(
    ui: &mut egui::Ui,
    directory: &Path,
    enabled: bool,
    action: &mut Option<PathBuf>,
) {
    let source = directory.join("ghidra-project");
    if source.join("antinomie.gpr").is_file()
        && source.join("antinomie.rep").is_dir()
        && ui
            .add_enabled(enabled, egui::Button::new("Export Ghidra project…"))
            .clicked()
    {
        *action = Some(source);
        ui.close_menu();
    }
}

fn manual_filter_row(
    ui: &egui::Ui,
    core: &antinomie_monitor_core::ProcessCoreCapture,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue as V;
    let mut row = core_history_row(
        ui,
        &core.directory,
        &core.id,
        &format!("PID {} · {}", core.target.tgid, core.id),
        &manual_status(core),
        CoreRowMetrics {
            pid: Some(u64::from(core.target.tgid)),
            size: Some(core.stored_size),
            ..Default::default()
        },
    );
    row.extend([
        ("vm.id", V::Text(core.vm_id.clone())),
        ("boot.id", V::Text(core.boot_id.clone())),
        (
            "run.id",
            core.source_run_id
                .as_ref()
                .map_or(V::Missing, |id| V::Text(id.clone())),
        ),
        (
            "entry.complete",
            V::Bool(core.state == antinomie_monitor_core::RunArtifactState::Complete),
        ),
        (
            "capture.complete",
            V::Bool(core.state == antinomie_monitor_core::RunArtifactState::Complete),
        ),
        (
            "capture.run_id",
            core.source_run_id
                .as_ref()
                .map_or(V::Missing, |id| V::Text(id.clone())),
        ),
        (
            "capture.expected_size",
            core.guest_size
                .map_or(V::Missing, |size| V::Number(i128::from(size))),
        ),
        (
            "core.partial",
            match core.state {
                antinomie_monitor_core::RunArtifactState::Complete => V::Bool(false),
                antinomie_monitor_core::RunArtifactState::Partial => V::Bool(true),
                _ => V::Missing,
            },
        ),
    ]);
    row
}
fn acquired_filter_row(
    ui: &egui::Ui,
    core: &AcquiredCore,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue as V;
    let mut row = core_history_row(
        ui,
        &core.directory,
        &core.run_id,
        &format!("Run {}", core.run_id),
        crate::app::core_capture_status(core.state),
        CoreRowMetrics::default(),
    );
    row.extend([
        ("vm.id", V::Text(core.vm_id.clone())),
        ("boot.id", V::Text(core.boot_id.clone())),
        ("run.id", V::Text(core.run_id.clone())),
        (
            "entry.complete",
            V::Bool(core.state == antinomie_monitor_core::RunArtifactState::Complete),
        ),
        (
            "capture.complete",
            V::Bool(core.state == antinomie_monitor_core::RunArtifactState::Complete),
        ),
        ("capture.run_id", V::Text(core.run_id.clone())),
        (
            "core.partial",
            match core.state {
                antinomie_monitor_core::RunArtifactState::Complete => V::Bool(false),
                antinomie_monitor_core::RunArtifactState::Partial => V::Bool(true),
                _ => V::Missing,
            },
        ),
    ]);
    row
}
fn imported_filter_row(
    ui: &egui::Ui,
    record: &CoreRecord,
) -> Vec<(&'static str, crate::query::RowValue)> {
    let mut row = core_history_row(
        ui,
        &record.dir,
        &record.dir.display().to_string(),
        &record.label,
        "imported",
        CoreRowMetrics {
            threads: Some(record.core.threads.len() as u64),
            mappings: Some(record.core.mappings.len() as u64),
            size: Some(record.core.source_size),
            ..Default::default()
        },
    );
    row.push((
        "core.signal",
        record
            .core
            .threads
            .first()
            .map_or(crate::query::RowValue::Missing, |thread| {
                crate::query::RowValue::Number(i128::from(thread.signal))
            }),
    ));
    row
}

#[derive(Default)]
struct CoreRowMetrics {
    pid: Option<u64>,
    threads: Option<u64>,
    mappings: Option<u64>,
    size: Option<u64>,
}

fn core_history_row(
    ui: &egui::Ui,
    directory: &Path,
    id: &str,
    fallback: &str,
    state: &str,
    metrics: CoreRowMetrics,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue;
    let CoreRowMetrics {
        pid,
        threads,
        mappings,
        size,
    } = metrics;
    let annotation = crate::evidence::annotation(ui, directory);
    let mut row = crate::query::label_row(
        id,
        annotation.as_ref().map_or("", |value| &value.name),
        &directory.display().to_string(),
        annotation
            .as_ref()
            .map_or(&[], |value| value.tags.as_slice()),
    );
    row.extend([
        ("capture.kind", RowValue::Text("core".into())),
        ("capture.state", RowValue::Text(state.into())),
        (
            "capture.size",
            size.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "core.thread_count",
            threads.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        ("entry.kind", RowValue::Text("core".into())),
        ("entry.state", RowValue::Text(state.into())),
        (
            "entry.size",
            size.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "name",
            RowValue::Text(
                annotation
                    .as_ref()
                    .filter(|value| !value.name.is_empty())
                    .map_or_else(|| fallback.into(), |value| value.name.clone()),
            ),
        ),
        ("state", RowValue::Text(state.into())),
        (
            "pid",
            pid.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "threads",
            threads.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "mappings",
            mappings.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "size",
            size.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
    ]);
    row
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

fn notes_table(ui: &mut egui::Ui, record: &CoreRecord, query: &mut String) {
    use egui_extras::{Column, TableBuilder};
    const EM_DASH: &str = "—";
    ui.label(
        "Other notes are inventoried below; floating-point/XSAVE payloads are not decoded here.",
    );
    crate::query::filter_edit(
        ui,
        query,
        "Filter recovered notes",
        ui.available_width(),
        crate::query::FilterScope::Table(NOTE_FIELDS),
    );
    let filter = crate::query::applied_table(ui, query, NOTE_FIELDS, ("core-notes", &record.dir));
    if crate::query::compile_table(query, NOTE_FIELDS)
        .error
        .is_none()
    {
        crate::query::remember_valid_filter(ui, query);
    }
    #[derive(Clone)]
    struct NoteRow {
        kind: &'static str,
        name: String,
        thread: &'static str,
        value: String,
        source: &'static str,
        availability: &'static str,
        number: Option<u64>,
    }
    let mut rows = Vec::new();
    for (key, value) in &record.core.auxv {
        rows.push(NoteRow {
            kind: "AUXV",
            name: key.to_string(),
            thread: EM_DASH,
            value: format!("0x{value:x}"),
            source: "NT_AUXV",
            availability: "captured",
            number: Some(*value),
        });
    }
    for note in &record.core.notes {
        rows.push(NoteRow {
            kind: "Note",
            name: note.clone(),
            thread: EM_DASH,
            value: EM_DASH.to_string(),
            source: "core note",
            availability: "captured",
            number: None,
        });
    }
    for file in &record.core.files {
        rows.push(NoteRow {
            kind: "File",
            name: file.path.clone(),
            thread: EM_DASH,
            value: format!(
                "{:016x}-{:016x} file+0x{:x}",
                file.start, file.end, file.file_offset
            ),
            source: "NT_FILE",
            availability: "captured",
            number: None,
        });
    }
    let total = rows.len();
    impl NoteRow {
        fn values(&self) -> Vec<(&'static str, crate::query::RowValue)> {
            let row = self;
            use crate::query::RowValue;
            vec![
                ("note.kind", RowValue::Text(row.kind.into())),
                ("note.name", RowValue::Text(row.name.clone())),
                ("note.thread_id", RowValue::Missing),
                ("note.source", RowValue::Text(row.source.into())),
                (
                    "note.complete",
                    RowValue::Bool(row.availability == "captured"),
                ),
                (
                    "note.summary",
                    RowValue::Text(if row.value == EM_DASH {
                        row.name.clone()
                    } else {
                        row.value.clone()
                    }),
                ),
                ("kind", RowValue::Text(row.kind.into())),
                ("name", RowValue::Text(row.name.clone())),
                ("thread", RowValue::Missing),
                (
                    "value",
                    if row.value == EM_DASH {
                        RowValue::Missing
                    } else {
                        RowValue::Text(row.value.clone())
                    },
                ),
                (
                    "value.num",
                    row.number.map_or(RowValue::Missing, |value| {
                        RowValue::Number(i128::from(value))
                    }),
                ),
                ("source", RowValue::Text(row.source.into())),
                ("availability", RowValue::Text(row.availability.into())),
            ]
        }
    }
    rows.retain(|row| filter.keep_table(&row.values()));
    let row_count = rows.len();
    ui.weak(format!("{row_count} / {total} notes"));
    let selection_id = ui.id().with(("core-note-detail", &record.dir));
    if ui
        .data(|data| data.get_temp::<NoteRow>(selection_id))
        .is_some_and(|selected| !filter.keep_table(&selected.values()))
    {
        ui.data_mut(|data| data.remove::<NoteRow>(selection_id));
    }

    let selected_detail = ui.data(|data| data.get_temp::<NoteRow>(selection_id));
    let detail_height = if selected_detail.is_some() {
        160.0
    } else {
        0.0
    };
    let header_height =
        ui.text_style_height(&egui::TextStyle::Body).max(20.0) + ui.spacing().item_spacing.y;
    let table_height = (ui.available_height() - detail_height - header_height).max(80.0);
    TableBuilder::new(ui)
        .max_scroll_height(table_height)
        .striped(true)
        .sense(egui::Sense::click())
        .column(Column::auto().at_least(64.0))
        .column(Column::remainder().at_least(120.0))
        .column(Column::auto().at_least(64.0))
        .column(Column::remainder().at_least(160.0))
        .column(Column::auto().at_least(80.0))
        .column(Column::auto().at_least(88.0))
        .header(20.0, |mut header| {
            for title in ["Kind", "Name", "Thread", "Value", "Source", "Availability"] {
                header.col(|ui| {
                    ui.strong(title);
                });
            }
        })
        .body(|body| {
            body.rows(18.0, row_count, |mut row| {
                let note = &rows[row.index()];
                for text in [
                    note.kind,
                    note.name.as_str(),
                    note.thread,
                    note.value.as_str(),
                    note.source,
                    note.availability,
                ] {
                    row.col(|ui| {
                        ui.add(egui::Label::new(text).truncate())
                            .on_hover_text(text);
                    });
                }
                if row.response().clicked() {
                    row.response().request_focus();
                    row.response().ctx.data_mut(|data| {
                        data.insert_temp(selection_id, note.clone());
                    });
                }
                row.response().context_menu(|ui| {
                    crate::query::value_menu(
                        ui,
                        "name",
                        &crate::query::RowValue::Text(note.name.clone()),
                        query,
                    );
                    ui.menu_button("Filter by field", |ui| {
                        for (field, value) in note.values() {
                            ui.menu_button(field, |ui| {
                                crate::query::value_menu(ui, field, &value, query)
                            });
                        }
                    });
                    if ui.button("Copy complete note").clicked() {
                        ui.ctx().copy_text(format!(
                            "{}\t{}\t{}\t{}\t{}\t{}",
                            note.kind,
                            note.name,
                            note.thread,
                            note.value,
                            note.source,
                            note.availability
                        ));
                        ui.close_menu();
                    }
                });
            });
        });
    if let Some(note) = ui.data(|data| data.get_temp::<NoteRow>(selection_id)) {
        let detail = format!(
            "{} · {} · {}\n{}",
            note.kind, note.name, note.source, note.value
        );
        egui::CollapsingHeader::new("Selected note")
            .default_open(true)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt(("core-note-detail-scroll", &record.dir))
                    .max_height(128.0)
                    .show(ui, |ui| {
                        ui.set_max_width((ui.clip_rect().right() - ui.max_rect().left()).max(80.0));
                        ui.add(egui::Label::new(detail).selectable(true).wrap());
                    });
            });
    }
}

fn paint_asm(ui: &mut egui::Ui, line: &str) {
    let (address, rest) = line.split_once("  ").unwrap_or(("", line));
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        if !address.is_empty() {
            ui.label(
                RichText::new(address)
                    .monospace()
                    .color(crate::theme::value(crate::theme::ValueKind::Pointer)),
            );
        }
        let mut parts = rest.splitn(2, char::is_whitespace);
        let mnemonic = parts.next().unwrap_or("");
        let operands = parts.next().unwrap_or("").trim_start();
        let mnemonic_color = if mnemonic.starts_with('j') || mnemonic == "call" || mnemonic == "ret"
        {
            crate::theme::warn()
        } else {
            crate::theme::value(crate::theme::ValueKind::Name)
        };
        ui.label(RichText::new(mnemonic).monospace().color(mnemonic_color));
        ui.label(
            RichText::new(operands)
                .monospace()
                .color(crate::theme::text()),
        );
    });
}

fn paint_source(ui: &mut egui::Ui, body: &str) {
    egui::ScrollArea::both()
        .id_salt("core-decomp")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for line in body.lines() {
                let mut job = egui::text::LayoutJob::default();
                for word in line.split_inclusive(|character: char| {
                    !character.is_ascii_alphanumeric() && character != '_'
                }) {
                    let color = if matches!(
                        word,
                        "if "
                            | "else "
                            | "return "
                            | "while "
                            | "for "
                            | "int "
                            | "void "
                            | "char "
                            | "long "
                    ) {
                        crate::theme::error()
                    } else if word
                        .chars()
                        .next()
                        .is_some_and(|character| character.is_ascii_digit())
                    {
                        crate::theme::warn()
                    } else {
                        crate::theme::text()
                    };
                    job.append(
                        word,
                        0.0,
                        egui::TextFormat {
                            font_id: egui::TextStyle::Monospace.resolve(ui.style()),
                            color,
                            ..Default::default()
                        },
                    );
                }
                ui.add(egui::Label::new(job).extend());
            }
        });
}

/// Load `decompiled.txt` from this record's directory only when a function marker is present.
fn saved_decompilation(dir: &Path) -> Option<String> {
    let path = dir.join("decompiled.txt");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() => {}
        _ => return None,
    }
    let text = fs::read_to_string(&path).ok()?;
    text.lines()
        .any(|line| line.starts_with("@@ANTINOMIE-FUNCTION"))
        .then_some(text)
}

fn export_saved_functions(dir: &Path) -> Result<PathBuf, String> {
    let source = dir.join("decompiled.txt");
    let text = fs::read_to_string(&source).map_err(|error| error.to_string())?;
    if crate::analysis::index_ghidra_markers(&text).is_empty() {
        return Err("this result has no saved Ghidra function markers".into());
    }
    let exported = crate::analysis::export_ghidra_text(&text);
    let destination = dir.join("function-export.txt");
    fs::write(&destination, exported).map_err(|error| error.to_string())?;
    Ok(destination)
}

fn parse_ghidra(text: &str) -> (Vec<CoreFunction>, Vec<String>) {
    let mut functions = Vec::new();
    let mut bodies = Vec::new();
    let mut current = String::new();
    let mut open = false;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("@@ANTINOMIE-FUNCTION\t") {
            if open {
                bodies.push(std::mem::take(&mut current));
            }
            open = true;
            let mut parts = rest.split('\t');
            let address = parts
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let size = parts
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let name = parts.next().unwrap_or("FUN").to_string();
            functions.push(CoreFunction {
                address,
                size,
                name,
            });
        } else if open && !line.starts_with("@@ANTINOMIE-") {
            current.push_str(line);
            current.push('\n');
        }
    }
    if open {
        bodies.push(current);
    }
    (functions, bodies)
}

/// Record each mapping's declared and captured extents. Holes stay absent;
/// this file is not a zero-padded image of `memory_size`.
fn write_ghidra_mappings(dir: &Path, mappings: &[CoreMapping]) -> Result<(), String> {
    let mut text = String::new();
    for mapping in mappings {
        text.push_str(&format!(
            "{:x} {} {} {} {}\n",
            mapping.start,
            mapping.memory_size,
            mapping.captured_size,
            mapping.available_size,
            mapping.permissions()
        ));
    }
    fs::write(dir.join("ghidra-mappings.txt"), text).map_err(|error| error.to_string())
}

fn ghidra_decompile(
    core: &Path,
    dir: &Path,
    tools_dir: &Path,
    _pid_slot: &AtomicI32,
    cancel: &AtomicBool,
) -> Result<String, String> {
    // The analysis job owns analyzeHeadless. This thread only starts that job
    // and watches cancel. A mappings file is not passed and is not a result.
    match antinomie_monitor_core::decompile_captured_core(core, dir, tools_dir, cancel) {
        Err(error) if error == "cancelled" || cancel.load(Ordering::SeqCst) => {
            Err(DECOMPILE_CANCELLED.into())
        }
        other => other,
    }
}

#[cfg(test)]
fn accept_ghidra_export(
    success: bool,
    export: &Path,
    previous_modified: Option<std::time::SystemTime>,
) -> Result<String, String> {
    if !success {
        return Err("Ghidra decompilation failed; an existing export is not a result.".to_string());
    }
    let metadata =
        fs::metadata(export).map_err(|_| "Ghidra produced no decompilation.".to_string())?;
    if let Some(previous) = previous_modified {
        let modified = metadata
            .modified()
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        if modified <= previous {
            return Err(
                "Ghidra produced no decompilation for this run; refusing an older export."
                    .to_string(),
            );
        }
    }
    fs::read_to_string(export).map_err(|error| format!("Ghidra produced no decompilation. {error}"))
}

const DECOMPILE_CANCELLED: &str = "The decompile was cancelled.";

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

fn signal_process_group(pid: i32) {
    if pid > 0 {
        unsafe {
            kill(-pid, 9);
        }
    }
}

fn reap_child(pid: i32) {
    if pid <= 0 {
        return;
    }
    let mut status = 0;
    loop {
        let result = unsafe { waitpid(pid, &mut status, 0) };
        if result >= 0 {
            return;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(4) {
            return;
        }
    }
}

fn parse_address(text: &str) -> Result<u64, String> {
    u64::from_str_radix(text.trim().trim_start_matches("0x"), 16)
        .map_err(|error| format!("Invalid hexadecimal address: {error}"))
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
fn choose_file(save: bool, cancelled: &AtomicBool) -> Result<Option<PathBuf>, String> {
    choose_path(save, "Select process core", cancelled)
}
fn choose_path(save: bool, title: &str, cancelled: &AtomicBool) -> Result<Option<PathBuf>, String> {
    let mut command = Command::new("zenity");
    command.args(["--file-selection", "--title", title]);
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

    fn wait_catalog(view: &mut CoreView) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while view.catalog_job.is_some() {
            view.poll_catalog();
            assert!(Instant::now() < deadline, "catalog worker did not finish");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn timed_refresh(view: &mut CoreView, active: bool) {
        let now = view.catalog_checked.unwrap_or_else(Instant::now) + Duration::from_secs(5);
        view.refresh_catalog_if_due(active, now);
        assert!(
            view.catalog_job.is_some(),
            "a due refresh starts without clicking Refresh"
        );
        wait_catalog(view);
    }

    fn growing_elf(path: &Path) -> usize {
        // Two real PRSTATUS notes and two PT_LOAD mappings; the second load is
        // advertised as 32 octets but initially only its first 16 are retained.
        let note_offset = 64 + 3 * 56;
        let payload_offset = note_offset + 2 * 356;
        let mut data = vec![0u8; payload_offset + 32];
        data[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        data[16..18].copy_from_slice(&4u16.to_le_bytes());
        data[18..20].copy_from_slice(&62u16.to_le_bytes());
        data[32..40].copy_from_slice(&64u64.to_le_bytes());
        data[54..56].copy_from_slice(&56u16.to_le_bytes());
        data[56..58].copy_from_slice(&3u16.to_le_bytes());
        data[64..68].copy_from_slice(&4u32.to_le_bytes());
        data[72..80].copy_from_slice(&(note_offset as u64).to_le_bytes());
        data[96..104].copy_from_slice(&712u64.to_le_bytes());
        for index in 0..2 {
            let header = 120 + index * 56;
            data[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
            data[header + 4..header + 8].copy_from_slice(&5u32.to_le_bytes());
            data[header + 8..header + 16]
                .copy_from_slice(&((payload_offset + index * 16) as u64).to_le_bytes());
            data[header + 16..header + 24]
                .copy_from_slice(&(0x400000u64 + index as u64 * 0x1000).to_le_bytes());
            data[header + 32..header + 40]
                .copy_from_slice(&(if index == 0 { 16u64 } else { 32u64 }).to_le_bytes());
            data[header + 40..header + 48].copy_from_slice(&4096u64.to_le_bytes());
            let note = note_offset + index * 356;
            data[note..note + 4].copy_from_slice(&5u32.to_le_bytes());
            data[note + 4..note + 8].copy_from_slice(&336u32.to_le_bytes());
            data[note + 8..note + 12].copy_from_slice(&1u32.to_le_bytes());
            data[note + 12..note + 17].copy_from_slice(b"CORE\0");
            data[note + 52..note + 56].copy_from_slice(&(77u32 + index as u32).to_le_bytes());
        }
        fs::write(path, &data).unwrap();
        data.len()
    }

    #[test]
    fn live_catalog_tracks_real_capture_lifecycle_without_resetting_selection() {
        use antinomie_monitor_core::RunArtifactState as State;
        let mut fixture = Fixture::new();
        let roots = vec![fixture.directory.clone()];
        fixture.view.set_catalog_scope(&roots, Some("chosen"));
        let selected = fixture.directory.join("runs/live/core");
        fs::create_dir_all(&selected).unwrap();
        fixture.view.selected = None;
        fixture.view.selected_directory = Some(selected.clone());
        fixture.view.code = "saved code".into();
        fixture.view.notes_query = "pid == 123".into();
        fixture.view.hide_list = true;
        for state in [
            State::WaitingForRootExit,
            State::InProgress,
            State::Complete,
        ] {
            let artifacts = antinomie_monitor_core::RunArtifacts {
                vm_id: "chosen".into(),
                boot_id: "boot".into(),
                run_id: "live".into(),
                core_state: state,
                core_dump: (state != State::WaitingForRootExit)
                    .then(|| selected.join("process.elf")),
                ..Default::default()
            };
            fs::write(
                selected.parent().unwrap().join("artifacts.json"),
                serde_json::to_vec(&artifacts).unwrap(),
            )
            .unwrap();
            // Deliberately not an ELF: catalog discovery must never parse it.
            if state != State::WaitingForRootExit {
                fs::write(selected.join("process.elf"), b"unfinished prefix").unwrap();
            }
            timed_refresh(&mut fixture.view, true);
            assert_eq!(fixture.view.acquired[0].state, state);
            assert_eq!(fixture.view.selected_directory.as_ref(), Some(&selected));
            assert!(fixture.view.selected.is_none() && fixture.view.job.is_none());
            assert_eq!(fixture.view.code, "saved code");
            assert_eq!(fixture.view.notes_query, "pid == 123");
            assert!(fixture.view.hide_list);
        }
        assert!(fixture.view.catalog_issues.is_empty());
        assert_eq!(fixture.view.catalog_interval(false), None);
        assert_eq!(
            fixture.view.catalog_interval(true),
            Some(Duration::from_secs(5))
        );
        assert!(!selected.join("metadata.json").exists());
    }

    #[test]
    fn live_manual_metadata_refresh_keeps_loaded_inspection_and_filters() {
        use antinomie_monitor_core::RunArtifactState as State;
        let mut fixture = Fixture::new();
        fixture
            .view
            .set_catalog_scope(&[fixture.directory.clone()], Some("chosen"));
        fixture.view.selected_directory = Some(fixture.directory.clone());
        fixture.view.thread_index = 1;
        fixture.view.code = "saved analysis".into();
        fixture.view.notes_query = "NT_FILE".into();
        let directory = fixture.directory.join("core-captures/manual");
        fs::create_dir_all(&directory).unwrap();
        let mut capture = ProcessCoreCapture {
            format: 1,
            id: "manual".into(),
            vm_id: "chosen".into(),
            boot_id: "boot".into(),
            source_run_id: None,
            restored_from_capture_id: None,
            target: antinomie_monitor_core::GuestProcessIdentity {
                boot_id: "boot".into(),
                task_cookie: 42,
                tgid: 123,
                start_boot_ns: 1,
            },
            directory: directory.clone(),
            file: None,
            state: State::WaitingForRootExit,
            phase: ProcessCorePhase::Admission,
            stored_size: 0,
            guest_size: None,
            sha256: None,
            pause_released: None,
            max_size: 1024 * 1024,
            timeout_ms: 5000,
            nonce: [1, 2],
            guest_handle: None,
            guest_status: None,
            issue: None,
        };
        for (phase, state) in [
            (ProcessCorePhase::Admission, State::WaitingForRootExit),
            (ProcessCorePhase::Transfer, State::InProgress),
            (ProcessCorePhase::Finished, State::Complete),
        ] {
            capture.phase = phase;
            capture.state = state;
            if phase == ProcessCorePhase::Finished {
                capture.file = Some(directory.join("process.elf"));
                capture.stored_size = 64;
                capture.guest_size = Some(64);
                capture.sha256 = Some("0".repeat(64));
                capture.pause_released = Some(true);
                fs::write(directory.join("process.elf"), [0; 64]).unwrap();
            }
            fs::write(
                directory.join("core.json"),
                serde_json::to_vec(&capture).unwrap(),
            )
            .unwrap();
            timed_refresh(&mut fixture.view, true);
            assert_eq!(fixture.view.manual[0].phase, phase);
            assert_eq!(fixture.view.manual[0].state, state);
            assert_eq!(
                fixture.view.selected_directory.as_ref(),
                Some(&fixture.directory)
            );
            assert_eq!(
                fixture.view.selected.as_ref().unwrap().core.threads[fixture.view.thread_index].tid,
                102
            );
            assert!(fixture.view.page.is_some());
            assert_eq!(fixture.view.code, "saved analysis");
            assert_eq!(fixture.view.notes_query, "NT_FILE");
            assert!(fixture.view.job.is_none());
        }
        assert!(fixture.view.catalog_issues.is_empty());
        assert_eq!(fixture.view.catalog_interval(false), None);
    }

    #[test]
    fn initial_open_is_adopted_but_old_prefix_page_is_rejected() {
        let mut fixture = Fixture::new();
        let record = fixture.view.selected.as_ref().unwrap().clone();
        fixture
            .view
            .start(move || Ok(opened_reply(record, String::new())));
        fixture
            .view
            .set_catalog_scope(&[fixture.directory.clone()], Some("chosen"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while fixture.view.job.is_some() {
            fixture.view.poll();
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            fixture.view.selected.as_ref().unwrap().core.threads[0].tid,
            101
        );
        let (release, wait) = mpsc::sync_channel(1);
        fixture.view.start(move || {
            wait.recv().unwrap();
            Ok(Reply::Page(0x400000, vec![Some(0x90)]))
        });
        fixture.view.selected_stamp = None;
        release.send(()).unwrap();
        while fixture.view.job.is_some() {
            fixture.view.poll();
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            fixture.view.page.is_none(),
            "old prefix page cannot undo metadata invalidation"
        );
    }

    #[test]
    fn growing_selected_core_refreshes_prefix_and_preserves_loaded_view() {
        let mut fixture = Fixture::new();
        fixture
            .view
            .set_catalog_scope(&[fixture.directory.clone()], Some("chosen"));
        let file = fixture.directory.join("growing.elf");
        let initial_size = growing_elf(&file);
        let mut record = fixture.view.selected.take().unwrap();
        record.core = CoreDump::open(&file).unwrap();
        fixture.view.selected_stamp = core_file_stamp(&file);
        fixture.view.selected_directory = Some(record.dir.clone());
        fixture.view.selected = Some(record);
        fixture.view.thread_index = 1;
        fixture.view.mapping_index = 1;
        fixture.view.window_offset = 16;
        fixture.view.code = "retained disassembly".into();
        fixture.view.code_address = "401010".into();
        fixture.view.notes_query = "tid == 78".into();
        fixture.view.tab = Tab::Code;
        fixture.view.hide_list = true;
        timed_refresh(&mut fixture.view, true);
        let catalog_stamp = fixture.view.catalog_stamp;
        assert!(
            fixture.view.page.is_some(),
            "unchanged source preserves cached page"
        );
        fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap()
            .write_all(&[0x90; 16])
            .unwrap();
        timed_refresh(&mut fixture.view, true);
        let core = &fixture.view.selected.as_ref().unwrap().core;
        assert_eq!(core.source_size, initial_size as u64 + 16);
        assert_eq!(core.threads[fixture.view.thread_index].tid, 78);
        assert_eq!(core.mappings[fixture.view.mapping_index].start, 0x401000);
        assert_eq!(core.mappings[1].available_size, 32);
        assert_eq!(fixture.view.window_offset, 16);
        assert_eq!(fixture.view.code, "retained disassembly");
        assert_eq!(fixture.view.code_address, "401010");
        assert_eq!(fixture.view.notes_query, "tid == 78");
        assert!(fixture.view.tab == Tab::Code && fixture.view.hide_list);
        assert_eq!(
            fixture.view.catalog_stamp, catalog_stamp,
            "source refresh works with unchanged catalog metadata"
        );
        assert!(fixture.view.page.is_none() && fixture.view.job.is_none());
        // Malformed changed prefixes retain the last valid view and retry later.
        fs::write(&file, b"invalid ELF").unwrap();
        timed_refresh(&mut fixture.view, true);
        assert_eq!(
            fixture.view.selected.as_ref().unwrap().core.source_size,
            initial_size as u64 + 16
        );
        assert!(fixture.view.status.starts_with("Core metadata refresh:"));
    }

    #[test]
    fn parsed_size_mismatch_remains_dirty_even_with_equal_file_stamp() {
        let fixture = Fixture::new();
        let file = fixture.directory.join("growing.elf");
        growing_elf(&file);
        let record = acquired_record(&file).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap()
            .write_all(&[0; 16])
            .unwrap();
        let current = core_file_stamp(&file);
        assert!(matches!(
            opened_reply(record.clone(), String::new()),
            Reply::Open(_, _, None)
        ));
        let refresh = selected_core_refresh(SelectedCoreProbe {
            directory: record.dir,
            source: file,
            source_size: record.core.source_size,
            stamp: current,
        });
        assert_eq!(
            refresh.core.unwrap().unwrap().source_size,
            current.unwrap().file_size
        );
    }

    #[test]
    fn late_catalog_reply_is_rejected_for_vm_and_roots_and_current_refresh_is_queued() {
        let mut fixture = Fixture::new();
        let original_roots = vec![fixture.directory.clone()];
        for (roots, vm) in [
            (original_roots.clone(), "other-vm"),
            (vec![fixture.directory.join("other-root")], "chosen"),
        ] {
            fixture
                .view
                .set_catalog_scope(&original_roots, Some("chosen"));
            let (sender, receiver) = mpsc::sync_channel(1);
            let stale = CatalogReply {
                generation: fixture.view.catalog_generation,
                roots: original_roots.clone(),
                vm_id: Some("chosen".into()),
                catalog: Ok(CoreCatalog {
                    acquired: vec![AcquiredCore {
                        vm_id: "chosen".into(),
                        boot_id: "boot".into(),
                        run_id: "stale".into(),
                        directory: fixture.directory.join("old"),
                        file: None,
                        state: antinomie_monitor_core::RunArtifactState::WaitingForRootExit,
                    }],
                    ..Default::default()
                }),
                stamp: Some(123),
                selected: None,
            };
            fixture.view.catalog_job = Some(receiver);
            fixture.view.set_catalog_scope(&roots, Some(vm));
            fixture.view.refresh_catalog_if_due(true, Instant::now());
            sender.send(stale).unwrap();
            fixture.view.poll_catalog();
            assert!(fixture.view.acquired.is_empty());
            assert!(fixture.view.catalog_checked.is_none());
            fixture.view.refresh_catalog_if_due(true, Instant::now());
            wait_catalog(&mut fixture.view);
            assert!(fixture.view.acquired.is_empty());
        }
    }

    #[test]
    fn previous_vm_inspection_finishes_files_without_applying_open_code_or_decompiled() {
        let mut fixture = Fixture::new();
        let roots = vec![fixture.directory.clone()];
        for reply in [
            opened_reply(
                fixture.view.selected.as_ref().unwrap().clone(),
                "old open".into(),
            ),
            Reply::Code("old code".into()),
            Reply::Decompiled("old decompilation".into()),
        ] {
            fixture.view.set_catalog_scope(&roots, Some("previous"));
            let output = fixture.directory.join("completed-worker-output");
            let worker_output = output.clone();
            let (release, wait) = mpsc::sync_channel(1);
            fixture.view.start(move || {
                wait.recv().unwrap();
                fs::write(worker_output, b"retained old operation output").unwrap();
                Ok(reply)
            });
            fixture.view.set_catalog_scope(&roots, Some("current"));
            fixture.view.code = "current selection".into();
            release.send(()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while fixture.view.job.is_some() {
                fixture.view.poll();
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(fs::read(&output).unwrap(), b"retained old operation output");
            assert!(fixture.view.selected.is_none());
            assert_eq!(fixture.view.code, "current selection");
            assert!(fixture.view.functions.is_empty());
        }
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
            vm_id: "fixture-vm".into(),
            boot_id: "fixture-boot".into(),
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
        for label in ["Disassemble captured code", "Decompile with Ghidra"] {
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
        let font_id = egui::TextStyle::Monospace.resolve(&ctx.style());
        let row_height = ctx.fonts(|fonts| fonts.row_height(&font_id));
        let instruction_rows: Vec<_> = content
            .iter()
            .filter(|(text, _)| text.starts_with("000000000040000"))
            .collect();
        assert!(
            instruction_rows.len() >= 2,
            "both instruction addresses are rendered"
        );
        for (text, rect) in &instruction_rows {
            assert!(
                rect.height() <= row_height + 0.5,
                "one instruction occupies one row; got {} high for {text}",
                rect.height()
            );
        }
        assert!(
            fixture.view.job.is_none(),
            "rendering retained code never starts analysis"
        );
    }

    #[test]
    fn long_decompiled_lines_scroll_horizontally_at_large_font() {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        crate::theme::text_size(&ctx, 24.0);
        let mut fixture = Fixture::new();
        fixture.view.tab = Tab::Code;
        fixture.view.show_decompiled = true;
        fixture.view.code_function = Some(0);
        fixture.view.functions.push(CoreFunction {
            address: 0x400000,
            size: 16,
            name: "FUN_00400000".into(),
        });
        let line = "return CONCAT44((int)(in_RAX >> 0x20), (int)uVar3) & 0x7fffffffffffffff;";
        fixture.view.function_bodies.push(line.into());
        fixture.view.code = line.into();
        let output = settle(&ctx, &mut fixture.view, egui::vec2(800.0, 900.0));
        let content = texts(&output);
        let (_, rect) = content
            .iter()
            .find(|(text, _)| text == line)
            .expect("retained decompiled line is rendered");
        let font_id = egui::TextStyle::Monospace.resolve(&ctx.style());
        let row_height = ctx.fonts(|fonts| fonts.row_height(&font_id));
        assert!(
            rect.height() <= row_height + 0.5,
            "decompiled line stays one visual row: {rect:?}"
        );
        assert!(
            rect.max.x > 800.0,
            "long line extends beyond the viewport for horizontal scrolling: {rect:?}"
        );
        assert!(
            fixture.view.job.is_none(),
            "viewing saved decompilation starts no job"
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
            .any(|(text, _)| text.contains("No functions indexed")));
        let position = content
            .iter()
            .find(|(text, _)| text == "Disassemble captured code")
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
        let shown = texts(&settle(&ctx, &mut fixture.view, size));
        assert!(shown.iter().any(|(text, _)| text.contains("nop")));
        assert!(shown
            .iter()
            .all(|(text, _)| !text.contains("Function index is")
                && !text.contains("It is not an original source symbol")
                && !text.contains("It is not a complete list of the core")));
    }

    #[test]
    fn disassemble_uses_captured_executable_bytes_when_rip_is_absent() {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        let mut fixture = Fixture::new();
        fixture.view.tab = Tab::Code;
        fixture.view.code_address.clear();
        fixture.view.selected.as_mut().unwrap().core.threads[0].registers[0].1 = 0x1;
        let output = settle(&ctx, &mut fixture.view, size);
        let position = texts(&output)
            .iter()
            .find(|(text, _)| text == "Disassemble captured code")
            .unwrap()
            .1
            .center();
        click(&ctx, &mut fixture.view, size, position);
        assert!(fixture.view.job.is_some());
        assert!(fixture.view.status.contains("Disassembling 0x400000"));
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while fixture.view.job.is_some() && std::time::Instant::now() < deadline {
            fixture.view.poll();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(fixture.view.code.contains("nop"), "{}", fixture.view.status);
        assert_eq!(fixture.view.code_address, "400000");
    }

    #[test]
    fn mapping_choices_use_recovered_names_and_mark_unknown_duplicates() {
        let fixture = Fixture::new();
        let core = &fixture.view.selected.as_ref().unwrap().core;
        let choices = mapping_choices(core);
        assert!(
            choices[0].0.starts_with("mmap 400000-") && choices[0].0.contains("r-x [sample]"),
            "{}",
            choices[0].0
        );
        assert!(choices[0].1.contains("/synthetic/sample"));
        let mut unnamed = core.clone();
        unnamed.files.clear();
        assert!(
            mapping_choices(&unnamed)[0].0.contains("r-x [unknown]"),
            "{}",
            mapping_choices(&unnamed)[0].0
        );
        assert!(mapping_choices(&unnamed)[0].1.contains("No NT_FILE name"));
        let mut duplicated = core.clone();
        duplicated.mappings.push(CoreMapping {
            start: 0x500000,
            memory_size: 0x1000,
            file_offset: 0,
            captured_size: 16,
            available_size: 16,
            flags: 5,
        });
        duplicated
            .files
            .push(antinomie_monitor_core::core_dump::MappedFile {
                start: 0x500000,
                end: 0x501000,
                file_offset: 0,
                path: "/synthetic/sample".into(),
            });
        let choices = mapping_choices(&duplicated);
        assert!(choices[0].0.contains("400000-"), "{}", choices[0].0);
        assert!(choices[1].0.contains("500000-"), "{}", choices[1].0);
        assert!(choices
            .iter()
            .all(|(label, tip)| label.contains("[sample]") && tip == "/synthetic/sample"));
        let mut ambiguous = core.clone();
        let mut overlapping = ambiguous.files[0].clone();
        overlapping.path = "/other/module".into();
        ambiguous.files.push(overlapping);
        let choices = mapping_choices(&ambiguous);
        assert!(choices[0]
            .0
            .contains("[/synthetic/sample (+1 file extents)]"));
        assert!(choices[0].1.contains("/synthetic/sample"));
        assert_eq!(captured_code_origin(&unnamed, ""), Ok(0x400000));
        unnamed.mappings[0].flags = 4;
        unnamed.threads[0].registers.clear();
        assert!(captured_code_origin(&unnamed, "").is_err());
    }

    #[test]
    fn mapping_filter_clears_hidden_hexdump_and_preserves_missing_paths() {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let mut fixture = Fixture::new();
        let record = fixture.view.selected.as_ref().unwrap().clone();
        for (draft, index) in [
            (
                "memory.permissions == \"r-x\" && memory.available == true",
                0,
            ),
            ("memory.permissions == \"rw-\"", usize::MAX),
        ] {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let id = ui
                        .id()
                        .with(("table-filter", ("core-mappings", &record.dir)));
                    ui.data_mut(|data| data.insert_temp(id, draft.to_owned()));
                    fixture.view.mappings(ui, &record);
                });
            });
            assert_eq!(fixture.view.mapping_index, index);
        }
        assert!(fixture.view.page.is_none());
        let mut unknown = record.core.clone();
        unknown.files.clear();
        assert!(crate::query::compile_table(
            "missing(memory.path) && memory.start == 4194304 && memory.captured_size == 4096",
            MAPPING_FIELDS
        )
        .keep_table(&mapping_filter_row(&unknown, &unknown.mappings[0])));
        let mut unavailable = unknown.mappings[0].clone();
        unavailable.available_size = 0;
        assert!(crate::query::compile_table(
            "memory.available == false && memory.captured_size == 0",
            MAPPING_FIELDS
        )
        .keep_table(&mapping_filter_row(&unknown, &unavailable)));
        let function = CoreFunction {
            name: "FUN_fffffffffffffffe".into(),
            address: u64::MAX - 1,
            size: 0,
        };
        assert!(crate::query::compile_table("function.address == 0xfffffffffffffffe && function.size == 0 && missing(function.kind)", FUNCTION_FIELDS).keep_table(&function_filter_row(&function)));
    }

    #[test]
    fn ghidra_mappings_record_sparse_extent_without_zero_fill() {
        let directory = std::env::temp_dir().join(format!(
            "antinomie-ghidra-mappings-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let _cleanup = RemoveDir(&directory);
        let mapping = CoreMapping {
            start: 0x400000,
            memory_size: 64 * 1024 * 1024,
            file_offset: 0,
            captured_size: 8192,
            available_size: 4096,
            flags: 5,
        };
        assert!(mapping.available_size < mapping.memory_size);
        write_ghidra_mappings(&directory, std::slice::from_ref(&mapping)).unwrap();
        let path = directory.join("ghidra-mappings.txt");
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text, "400000 67108864 8192 4096 r-x\n");
        assert!(
            fs::metadata(&path).unwrap().len() < mapping.memory_size,
            "ghidra-mappings.txt records extents and does not pad holes with zero bytes"
        );
    }

    #[test]
    fn failed_status_must_not_accept_an_old_export() {
        let directory = std::env::temp_dir().join(format!(
            "antinomie-ghidra-export-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let _cleanup = RemoveDir(&directory);
        let export = directory.join("decompiled.txt");
        let body = "@@ANTINOMIE-FUNCTION\t64\t1\told\nvoid old(void) {}\n";
        fs::write(&export, body).unwrap();
        let previous = fs::metadata(&export).unwrap().modified().ok();
        let error = accept_ghidra_export(false, &export, previous)
            .expect_err("failed status must not accept an old export");
        assert!(
            !error.contains("void old") && !error.contains("@@ANTINOMIE-FUNCTION"),
            "{error}"
        );
        assert_eq!(fs::read_to_string(&export).unwrap(), body);
    }

    struct RemoveDir<'a>(&'a Path);

    impl Drop for RemoveDir<'_> {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.0);
        }
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

    #[test]
    #[ignore = "native X11; opens a genuine process core and waits for a Disassemble click"]
    fn native_genuine_core_disassemble() {
        use winit::platform::x11::EventLoopBuilderExtX11;
        let source = PathBuf::from(
            std::env::var("ANTINOMIE_GENUINE_CORE")
                .expect("Set ANTINOMIE_GENUINE_CORE to a retained native process ELF core"),
        );
        assert!(
            source.is_file(),
            "genuine core missing: {}",
            source.display()
        );
        let existing = std::env::var_os("ANTINOMIE_CORE_QA_RECORD_DIR").map(PathBuf::from);
        let (root, record) = if let Some(directory) = existing {
            let root = directory
                .parent()
                .and_then(Path::parent)
                .expect("QA record is nested under a core-dumps catalog")
                .to_owned();
            assert_eq!(
                directory.parent().and_then(Path::file_name),
                Some(std::ffi::OsStr::new("core-dumps"))
            );
            let record = core_dump::list_records(std::slice::from_ref(&root))
                .expect("list existing owned QA records")
                .into_iter()
                .find(|record| record.dir == directory)
                .expect("requested QA record is in its catalog");
            assert_eq!(record.core.source, fs::canonicalize(&source).unwrap());
            (root, record)
        } else {
            let root = std::env::temp_dir().join(format!(
                "antinomie-native-core-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&root).unwrap();
            let record =
                CoreRecord::import(&source, &root).expect("import genuine core by reference");
            (root, record)
        };
        let status_path = PathBuf::from("/tmp/antinomie-genuine-core-status");
        struct App {
            view: CoreView,
            root: PathBuf,
            deadline: Instant,
            status_path: PathBuf,
        }
        impl eframe::App for App {
            fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let _ = self.view.show(
                        ui,
                        std::slice::from_ref(&self.root),
                        Some("qa"),
                        false,
                        CoreControls {
                            unavailable: Some("Preview does not capture a live process"),
                            captures: &[],
                            can_cancel: false,
                        },
                    );
                });
                crate::evidence::dialogs(ctx);
                let code_lines = self
                    .view
                    .code
                    .lines()
                    .filter(|line| !line.is_empty())
                    .count();
                let _ = fs::write(
                    &self.status_path,
                    format!(
                        "status={}\ncode_lines={code_lines}\njob={}\n",
                        self.view.status.replace('\n', " "),
                        self.view.job.is_some()
                    ),
                );
                if Instant::now() >= self.deadline {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }
        let small = std::env::var_os("ANTINOMIE_CORE_QA_SMALL").is_some();
        let font = std::env::var("ANTINOMIE_CORE_QA_FONT")
            .ok()
            .and_then(|value| value.parse::<f32>().ok())
            .unwrap_or(if small { 24.0 } else { 16.0 });
        let seconds = std::env::var("ANTINOMIE_CORE_QA_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(90)
            .clamp(1, 180);
        let tab = std::env::var("ANTINOMIE_CORE_QA_TAB").unwrap_or_else(|_| "code".into());
        eframe::run_native(
            "Antinomie Genuine Core",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size(if small {
                        [800.0, 900.0]
                    } else {
                        [1280.0, 900.0]
                    })
                    .with_position([40.0, 40.0]),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11().with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                crate::theme::install(&cc.egui_ctx);
                crate::theme::text_size(&cc.egui_ctx, font);
                let mut view = CoreView::default();
                view.selected_directory = Some(record.dir.clone());
                view.tab = match tab.as_str() {
                    "mappings" => Tab::Mappings,
                    "notes" => Tab::Notes,
                    "context" => Tab::Context,
                    _ => Tab::Code,
                };
                view.records.push(record.clone());
                view.open(&record.core.source);
                Ok(Box::new(App {
                    view,
                    root,
                    deadline: Instant::now() + Duration::from_secs(seconds),
                    status_path,
                }))
            }),
        )
        .unwrap();
    }
}
