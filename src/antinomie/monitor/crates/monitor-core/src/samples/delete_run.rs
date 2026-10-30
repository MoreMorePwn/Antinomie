// SPDX-License-Identifier: GPL-3.0-only
//! Deleting a run of a library sample.
//!
//! The analyst chooses, per artefact, to keep it or delete it. Kept files
//! move into the library (`artefacts/<sha256>`, a move, no copy unless the
//! two folders are on different disks). The run's folder is then removed and
//! the sample's custody log records what happened to each artefact. The
//! run's record (its summary with the environment, the Triage digest, the
//! static reports) is copied into the library first, so the sample keeps its
//! runs, rollups and reports.
//!
//! What is removed is limited on purpose. Only the run's own folder is
//! removed, found by its id inside the VM's recording (`runs/<id>` or
//! `boots/<boot>/runs/<id>`), never through a symbolic link, and only when
//! its `run.json` names this VM, this run and this sample. Files a run owns
//! but that live elsewhere in the recording (the exit memory dump, the
//! network captures) are never deleted here: they can be kept (moved into
//! the library) or left where they are, and a capture another run also names
//! always stays. Nothing outside the VM's recording folders is touched.
use super::{
    custody::CustodyEvent,
    kept::{self, ArtifactKind, Fate, NewArtifact, SavedKind, short_hash},
    library::Library,
};
use crate::{BackendOptions, RunArtifacts, RunSummary};
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

/// Largest top-level file of a run copied into its record.
const RECORD_FILE_LIMIT: u64 = 4 << 20;
/// Most bytes of static reports copied into a run's record.
const RECORD_ANALYSIS_LIMIT: u64 = 256 << 20;

/// Where an artefact is, and so what can be done with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// In the run's folder: Keep or Delete.
    InFolder,
    /// Elsewhere in the VM's recording and owned by this run alone: Keep
    /// (move it into the library) or Leave it where it is.
    Outside,
    /// Stays with the VM: a snapshot, or a capture other runs also name.
    WithVm,
    /// Goes into the sample record with the run's record.
    InRecord,
}

/// One artefact of the run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanItem {
    /// Identifies the row: `<kind>/<name>`.
    pub key: String,
    pub kind: ArtifactKind,
    pub name: String,
    /// Where it is now (empty for a snapshot).
    pub path: PathBuf,
    /// Its SHA-256; empty when it has none or could not be read.
    pub hash: String,
    pub size: u64,
    pub context: String,
    pub because: String,
    pub place: Place,
}

impl PlanItem {
    /// "Core dump 9c41e2a0".
    pub fn title(&self) -> String {
        format!("{} {}", self.kind.label(), short_hash(&self.hash))
    }

    /// Whether the analyst chooses for this row.
    pub fn choosable(&self) -> bool {
        matches!(self.place, Place::InFolder | Place::Outside)
    }
}

/// What deleting a run would do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunPlan {
    pub sha256: String,
    pub vm_id: String,
    pub run_id: String,
    /// The run's folders: `(recording folder, run folder)`.
    pub folders: Vec<(PathBuf, PathBuf)>,
    pub items: Vec<PlanItem>,
}

/// What a deletion did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Deleted {
    pub kept: usize,
    pub deleted: usize,
    /// Bytes of the files deleted.
    pub freed: u64,
    /// Where the run's record is now.
    pub record: PathBuf,
}

/// An id that is one plain path component.
fn safe_component(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && !text.starts_with('.')
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
}

/// A recording folder's run folders with this id, each checked: a real
/// folder (not a link) that lies inside the recording.
fn run_folders(
    options: &BackendOptions,
    vm_id: &str,
    run_id: &str,
) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    if !safe_component(run_id) || !safe_component(vm_id) {
        return Err("the run or VM identity is not a plain name".into());
    }
    let locations = crate::locations::locations(options, vm_id)?;
    let mut found = Vec::new();
    for directory in locations.recording_directories {
        let Ok(root) = fs::canonicalize(&directory) else {
            continue;
        };
        let mut candidates = vec![root.join("runs").join(run_id)];
        if let Ok(boots) = fs::read_dir(root.join("boots")) {
            for boot in boots.flatten() {
                candidates.push(boot.path().join("runs").join(run_id));
            }
        }
        for candidate in candidates {
            if !is_real_dir(&candidate) {
                continue;
            }
            // A link in the path to the folder would lead the canonical name
            // away from the recording.
            let Ok(canonical) = fs::canonicalize(&candidate) else {
                continue;
            };
            if canonical != candidate || !canonical.starts_with(&root) {
                continue;
            }
            found.push((root.clone(), canonical));
        }
    }
    if found.is_empty() {
        return Err("the run's folder was not found in the VM's recording".into());
    }
    Ok(found)
}

fn read_summary(dir: &Path) -> Result<RunSummary, String> {
    let path = dir.join("run.json");
    let meta = fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.file_type().is_file() || meta.len() > (1 << 20) {
        return Err(format!("{} is not a run record", path.display()));
    }
    let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// The recording folder's other runs' `artifacts.json` paths named, for the
/// exclusivity check: every path any run but this one names.
fn named_by_others(root: &Path, run_id: &str) -> BTreeSet<PathBuf> {
    let mut run_dirs = vec![root.join("runs")];
    if let Ok(boots) = fs::read_dir(root.join("boots")) {
        run_dirs.extend(boots.flatten().map(|boot| boot.path().join("runs")));
    }
    let mut named = BTreeSet::new();
    for run_dir in run_dirs {
        for entry in fs::read_dir(&run_dir).into_iter().flatten().flatten() {
            if entry.file_name().to_string_lossy() == run_id {
                continue;
            }
            if let Ok(Some(artifacts)) = RunArtifacts::load(&entry.path()) {
                named.extend(artifacts.network_captures);
                named.extend(artifacts.memory_dump);
                named.extend(artifacts.core_dump);
            }
        }
    }
    named
}

/// Whether `path` is one of the places the recorder writes a run-owned
/// memory dump or network capture to, inside `root`, and not a link.
fn recorder_place(root: &Path, path: &Path) -> Option<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return None;
    }
    let meta = fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    let relative = canonical.strip_prefix(root).ok()?;
    let parts: Vec<_> = relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    let ok = match parts.as_slice() {
        [memory, _] => memory == "memory" && meta.is_dir(),
        [boots, _, network, file] => {
            boots == "boots" && network == "network" && file.ends_with(".pcap") && meta.is_file()
        }
        [boots, _, file] => boots == "boots" && file == "network.pcap" && meta.is_file(),
        _ => false,
    };
    ok.then_some(canonical)
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
}

/// Work out what deleting the run would do, reading hashes of its files.
pub fn plan(
    options: &BackendOptions,
    sha256: &str,
    vm_id: &str,
    run_id: &str,
) -> Result<RunPlan, String> {
    let sha256 = sha256.to_ascii_lowercase();
    let folders = run_folders(options, vm_id, run_id)?;
    let library = Library::open(&options.data_dir)?;
    let mut items = Vec::new();
    let mut seen_names = BTreeSet::new();
    let mut summary = None;
    for (root, dir) in &folders {
        let found = read_summary(dir)?;
        if found.id != run_id || found.vm_id != vm_id {
            return Err("the run's record does not name this run".into());
        }
        if found
            .request
            .sample
            .as_ref()
            .is_none_or(|sample| !sample.sha256.eq_ignore_ascii_case(&sha256))
        {
            return Err("the run is not a run of this sample".into());
        }
        let others = named_by_others(root, run_id);
        let hash_of = |path: &Path| library.artifact_hash(path).unwrap_or_default();
        let mut push = |item: PlanItem| {
            if seen_names.insert(item.key.clone()) {
                items.push(item);
            }
        };
        if let Ok(Some(artifacts)) = RunArtifacts::load(dir) {
            if let (Some(core), false) = (&artifacts.core_dump, artifacts.core_deleted) {
                let inside = fs::symlink_metadata(core).is_ok_and(|m| !m.file_type().is_symlink())
                    && fs::canonicalize(core).is_ok_and(|c| c.starts_with(dir));
                if fs::symlink_metadata(core).is_ok() {
                    push(PlanItem {
                        key: format!("core/{}", name_of(core)),
                        kind: ArtifactKind::Core,
                        name: name_of(core),
                        path: core.clone(),
                        hash: if inside { hash_of(core) } else { String::new() },
                        size: crate::evidence_delete::measure(core).bytes,
                        context: String::new(),
                        because: "Core dump on exit".into(),
                        place: if inside {
                            Place::InFolder
                        } else {
                            Place::WithVm
                        },
                    });
                }
            }
            if let Some((memory, place)) = artifacts
                .memory_dump
                .as_ref()
                .and_then(|memory| Some((memory, recorder_place(root, memory)?)))
            {
                {
                    let shared = others.contains(memory) || others.contains(&place);
                    push(PlanItem {
                        key: format!("memory/{}", name_of(&place)),
                        kind: ArtifactKind::Memory,
                        name: name_of(&place),
                        hash: hash_of(&place),
                        size: crate::evidence_delete::measure(&place).bytes,
                        path: place,
                        context: String::new(),
                        because: "Memory dump on exit".into(),
                        place: if shared {
                            Place::WithVm
                        } else {
                            Place::Outside
                        },
                    });
                }
            }
            for capture in &artifacts.network_captures {
                if let Some(place) = recorder_place(root, capture) {
                    let shared = others.contains(capture) || others.contains(&place);
                    push(PlanItem {
                        key: format!("capture/{}", name_of(&place)),
                        kind: ArtifactKind::Capture,
                        name: name_of(&place),
                        hash: hash_of(&place),
                        size: crate::evidence_delete::measure(&place).bytes,
                        path: place,
                        context: String::new(),
                        because: "Network capture".into(),
                        place: if shared {
                            Place::WithVm
                        } else {
                            Place::Outside
                        },
                    });
                }
            }
        }
        for saved in kept::saved_items(dir) {
            let kind = saved.artifact_kind();
            let key = format!("{}/{}", kind.as_str(), saved.name);
            if saved.kind == SavedKind::Snapshot {
                push(PlanItem {
                    key,
                    kind,
                    name: saved.name.clone(),
                    path: PathBuf::new(),
                    hash: saved.sha256.clone(),
                    size: saved.size,
                    context: saved.context.clone(),
                    because: saved.because(),
                    place: Place::WithVm,
                });
                continue;
            }
            let Some(path) = saved.file_in(dir) else {
                continue;
            };
            let inside = fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_file())
                && fs::canonicalize(&path).is_ok_and(|c| c.starts_with(dir));
            if inside {
                push(PlanItem {
                    key,
                    kind,
                    name: saved.name.clone(),
                    hash: hash_of(&path),
                    size: crate::evidence_delete::measure(&path).bytes,
                    path,
                    context: saved.context.clone(),
                    because: saved.because(),
                    place: Place::InFolder,
                });
            }
        }
        if let Some(report) = &found.analysis {
            let analysis = dir.join("analysis");
            if is_real_dir(&analysis) {
                push(PlanItem {
                    key: format!("static/{}", report.id),
                    kind: ArtifactKind::Static,
                    name: report.id.clone(),
                    path: analysis,
                    hash: String::new(),
                    size: 0,
                    context: String::new(),
                    because: "Static Analysis › Analyze".into(),
                    place: Place::InRecord,
                });
            }
        }
        summary.get_or_insert(found);
    }
    summary.ok_or_else(|| "the run's record was not found".to_owned())?;
    Ok(RunPlan {
        sha256,
        vm_id: vm_id.to_owned(),
        run_id: run_id.to_owned(),
        folders,
        items,
    })
}

/// Move `source` to `destination`; across disks, copy it, compare the hash
/// and only then remove the source.
fn move_into(source: &Path, destination: &Path, hash: &str) -> Result<(), String> {
    match fs::rename(source, destination) {
        Ok(()) => return Ok(()),
        Err(error) if error.raw_os_error() != Some(18) => {
            return Err(format!("{}: {error}", source.display()));
        }
        Err(_) => {}
    }
    let partial = destination.with_extension("part");
    let _ = fs::remove_dir_all(&partial).or_else(|_| fs::remove_file(&partial));
    copy_tree(source, &partial)?;
    if kept::artifact_sha256(&partial).as_deref() != Some(hash) {
        let _ = fs::remove_dir_all(&partial).or_else(|_| fs::remove_file(&partial));
        return Err(format!(
            "{}: the copy did not match; nothing was removed",
            source.display()
        ));
    }
    fs::rename(&partial, destination).map_err(|e| e.to_string())?;
    fs::remove_dir_all(source)
        .or_else(|_| fs::remove_file(source))
        .map_err(|e| format!("{}: {e}", source.display()))
}

/// Copy a file or a folder of plain files; links are skipped.
fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(from).map_err(|e| format!("{}: {e}", from.display()))?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_dir() {
        crate::storage::private_dir(to).map_err(|e| format!("{}: {e}", to.display()))?;
        for entry in fs::read_dir(from)
            .map_err(|e| format!("{}: {e}", from.display()))?
            .flatten()
        {
            copy_tree(&entry.path(), &to.join(entry.file_name()))?;
        }
        Ok(())
    } else {
        fs::copy(from, to)
            .map(|_| ())
            .map_err(|e| format!("{}: {e}", from.display()))
    }
}

/// Put one artefact into the library; returns where it is.
fn keep_item(library: &Library, item: &PlanItem) -> Result<PathBuf, String> {
    if item.hash.len() != 64 {
        return Err(format!(
            "{} cannot be read, so it cannot be kept",
            item.title()
        ));
    }
    let folder = library.artifacts_dir();
    crate::storage::private_dir(&folder).map_err(|e| format!("{}: {e}", folder.display()))?;
    let destination = folder.join(&item.hash);
    if fs::symlink_metadata(&destination).is_ok() {
        // The same bytes are already kept: the copy in the run is a repeat.
        if kept::artifact_sha256(&destination).as_deref() != Some(item.hash.as_str()) {
            return Err(format!(
                "{} is already there with other contents",
                destination.display()
            ));
        }
        fs::remove_dir_all(&item.path)
            .or_else(|_| fs::remove_file(&item.path))
            .map_err(|e| format!("{}: {e}", item.path.display()))?;
    } else {
        move_into(&item.path, &destination, &item.hash)?;
    }
    Ok(destination)
}

/// Copy the run's record into the library: its top-level files and its
/// static reports (never the plain copy of the specimen).
fn retain_record(library: &Library, plan: &RunPlan) -> Result<PathBuf, String> {
    let record = library
        .record_dir()
        .join(&plan.sha256)
        .join(&plan.vm_id)
        .join(&plan.run_id);
    crate::storage::private_dir(&record).map_err(|e| format!("{}: {e}", record.display()))?;
    let mut budget = RECORD_ANALYSIS_LIMIT;
    for (_, dir) in &plan.folders {
        for entry in fs::read_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .flatten()
        {
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            let name = entry.file_name();
            // An artifact is kept or deleted as chosen, never copied here.
            let artifact = plan.items.iter().any(|item| item.path == entry.path());
            if meta.file_type().is_file() && meta.len() <= RECORD_FILE_LIMIT && !artifact {
                fs::copy(entry.path(), record.join(&name))
                    .map_err(|e| format!("{}: {e}", entry.path().display()))?;
            } else if meta.is_dir() && name == "analysis" {
                copy_reports(&entry.path(), &record.join("analysis"), &mut budget)?;
            }
        }
    }
    if let Some((_, run_directory)) = plan.folders.first() {
        save_process_tree(&record, run_directory);
    }
    Ok(record)
}

/// The record's copy of the run's process tree, so the Runs tab still shows
/// what the run did after its recording is deleted.
pub const PROCESS_TREE_FILE: &str = "process-tree.json";

/// The tree and its issues, as [`save_process_tree`] left them in a record.
pub type SavedTree = (Vec<crate::capture_processes::CaptureProcess>, Vec<String>);

/// Read the process tree a record kept.
pub fn saved_process_tree(record: &Path) -> Option<SavedTree> {
    let path = record.join(PROCESS_TREE_FILE);
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.file_type().is_file() || meta.len() > RECORD_FILE_LIMIT {
        return None;
    }
    serde_json::from_slice(&fs::read(&path).ok()?).ok()
}

/// Write the tree of the run whose record was just copied into `record` from
/// the run's own folder (best effort: a recording that cannot be read has no
/// tree to keep).
fn save_process_tree(record: &Path, run_directory: &Path) {
    let Ok(run) = read_summary(record) else {
        return;
    };
    let source = crate::recording::Recording {
        directory: run_directory.to_path_buf(),
        manifest: serde_json::Value::Null,
        events: Vec::new(),
    };
    let cancel = std::sync::atomic::AtomicBool::new(false);
    if let Ok(tree) = source.process_tree_cancellable(run.pid, &run.request.path, &cancel) {
        let _ = crate::storage::atomic_json(&record.join(PROCESS_TREE_FILE), &tree);
    }
}

fn copy_reports(from: &Path, to: &Path, budget: &mut u64) -> Result<(), String> {
    crate::storage::private_dir(to).map_err(|e| format!("{}: {e}", to.display()))?;
    for entry in fs::read_dir(from)
        .map_err(|e| format!("{}: {e}", from.display()))?
        .flatten()
    {
        let Ok(meta) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let name = entry.file_name();
        if meta.file_type().is_symlink() || name == "specimen" {
            continue;
        }
        if meta.is_dir() {
            copy_reports(&entry.path(), &to.join(&name), budget)?;
        } else if meta.is_file() && meta.len() <= *budget {
            *budget -= meta.len();
            fs::copy(entry.path(), to.join(&name))
                .map_err(|e| format!("{}: {e}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// Delete the run described by `plan` (made just before): the artefacts in
/// `keep` are kept, the rest of the run's own files are deleted. `live` says
/// the run is still running, which refuses the deletion.
pub fn delete(
    options: &BackendOptions,
    plan_before: &RunPlan,
    keep: &BTreeSet<String>,
    vm_name: &str,
    live: bool,
) -> Result<Deleted, String> {
    if live {
        return Err("the run is still running; stop it first".into());
    }
    // Plan again: what is on disk now decides, not what the dialog showed.
    let plan = self::plan(
        options,
        &plan_before.sha256,
        &plan_before.vm_id,
        &plan_before.run_id,
    )?;
    let library = Library::open(&options.data_dir)?;
    let now = super::library::now_ms();
    let mut done = Deleted::default();
    let mut notes = Vec::new();
    let record_row = |item: &PlanItem, fate: Fate, stored: PathBuf| NewArtifact {
        kind: item.kind,
        vm_id: plan.vm_id.clone(),
        run_id: plan.run_id.clone(),
        name: item.name.clone(),
        hash: item.hash.clone(),
        size: item.size,
        fate,
        stored,
        because: item.because.clone(),
        context: item.context.clone(),
    };
    // The run's record first: if it cannot be saved, nothing is lost.
    done.record = retain_record(&library, &plan)?;
    for item in &plan.items {
        let wanted = keep.contains(&item.key);
        let (fate, stored) = match item.place {
            Place::WithVm => (Fate::WithVm, PathBuf::new()),
            Place::InRecord => (Fate::InRecord, done.record.join("analysis")),
            Place::InFolder | Place::Outside if wanted => {
                let stored = keep_item(&library, item)?;
                done.kept += 1;
                (Fate::Kept, stored)
            }
            Place::InFolder => {
                done.deleted += 1;
                done.freed += item.size;
                (Fate::Deleted, PathBuf::new())
            }
            Place::Outside => (Fate::WithVm, PathBuf::new()),
        };
        library.record_artifact(&plan.sha256, &record_row(item, fate, stored), now)?;
        match fate {
            Fate::Kept => notes.push(format!("kept {}", item.title().to_lowercase())),
            Fate::Deleted => notes.push(format!("deleted {}", item.title().to_lowercase())),
            Fate::WithVm | Fate::InRecord => {}
        }
    }
    for (root, dir) in &plan.folders {
        remove_run_folder(root, dir, &plan.run_id)?;
    }
    let detail = if notes.is_empty() {
        "no artefacts".to_owned()
    } else {
        notes.join(", ")
    };
    library.record_event(
        &plan.sha256,
        "analyst",
        CustodyEvent::RunDeleted {
            vm: vm_name.to_owned(),
            run: plan.run_id.clone(),
            detail,
        },
    )?;
    Ok(done)
}

/// Remove one run folder, after checking again that it is the run's own.
fn remove_run_folder(root: &Path, dir: &Path, run_id: &str) -> Result<(), String> {
    let meta = fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let canonical = fs::canonicalize(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let parent_ok = dir
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "runs");
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || canonical != dir
        || !canonical.starts_with(root)
        || canonical == root
        || !parent_ok
        || dir.file_name().is_none_or(|name| name != run_id)
    {
        return Err(format!("{} is not the run's folder", dir.display()));
    }
    fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

impl Library {
    /// Where the records of deleted runs are kept.
    pub fn record_dir(&self) -> PathBuf {
        self.root.join("runs")
    }

    /// The runs of a sample whose folder was deleted through the app, as
    /// their records in the library read. `directory` is the record's folder.
    pub fn retained_runs(&self, sha256: &str) -> Result<Vec<RunSummary>, String> {
        let sha256 = sha256.to_ascii_lowercase();
        let mut found = Vec::new();
        for seen in self.runs_of(&sha256)? {
            if !safe_component(&seen.vm_id) || !safe_component(&seen.run_id) {
                continue;
            }
            let dir = self
                .record_dir()
                .join(&sha256)
                .join(&seen.vm_id)
                .join(&seen.run_id);
            if !dir.join("run.json").is_file() {
                continue;
            }
            if let Ok(mut run) = read_summary(&dir) {
                run.directory = dir;
                found.push(run);
            }
        }
        Ok(found)
    }
}
