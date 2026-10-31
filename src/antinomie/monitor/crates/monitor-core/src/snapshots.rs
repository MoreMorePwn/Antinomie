// SPDX-License-Identifier: GPL-3.0-only
//! Durable external qcow2 checkpoints. Saved layers are immutable dependencies.
use crate::{
    api::{
        BackendOptions, SnapshotRequest, VmCheckpoint, VmConfig, VmSnapshotConsistency,
        VmSnapshotMode, VmSnapshotTree,
    },
    storage::{atomic_json, private_dir, read_json, sha256_uncached, unique_id, vm_dir},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) mod run_layer;

const MAX_NODES: usize = 256;
const MAX_CHAIN: usize = 64;
const MAX_METADATA_SIZE: u64 = 4 * 1024 * 1024;
const MANIFEST: &str = "snapshots.json";
const JOURNAL: &str = "snapshot-operation.json";

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    checkpoint: VmCheckpoint,
    disk: PathBuf,
    memory: Option<PathBuf>,
    memory_sha256: Option<String>,
    compatibility: Option<String>,
    host_checkpoint: Option<Value>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Manifest {
    schema: u32,
    vm_id: String,
    active_disk: PathBuf,
    active_parent_id: Option<String>,
    nodes: Vec<Record>,
    recovery_note: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
enum Operation {
    Take,
    Restore,
}
#[derive(Clone, Serialize, Deserialize)]
struct Journal {
    operation: Operation,
    id: String,
    previous_disk: PathBuf,
    next_disk: PathBuf,
}

/// A durable intent to freeze the current layer and select a writable child.
pub(crate) struct PreparedTake {
    pub id: String,
    pub frozen_disk: PathBuf,
    pub active_disk: PathBuf,
    pub memory_path: Option<PathBuf>,
    record: Record,
}
/// A validated restore candidate. The previous working disk remains intact.
pub(crate) struct PreparedRestore {
    pub id: String,
    pub mode: VmSnapshotMode,
    pub active_disk: PathBuf,
    pub memory_path: Option<PathBuf>,
    pub compatibility: Option<String>,
}

fn regular(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("snapshot artifact {}: {e}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err("snapshot artifacts must be regular files".into());
    }
    Ok(metadata)
}
fn owned(directory: &Path, relative: &Path) -> Result<PathBuf, String> {
    let path = owned_path(directory, relative)?;
    regular(&path)?;
    Ok(path)
}
fn owned_path(directory: &Path, relative: &Path) -> Result<PathBuf, String> {
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("invalid snapshot artifact path".into());
    }
    if relative != Path::new("disk.qcow2")
        && (relative.components().count() != 2 || !relative.starts_with("snapshots"))
    {
        return Err("snapshot artifact is outside its owned directory".into());
    }
    let path = directory.join(relative);
    if fs::canonicalize(path.parent().ok_or("snapshot path has no parent")?)
        .map_err(|e| e.to_string())?
        != fs::canonicalize(directory.join(if relative == Path::new("disk.qcow2") {
            ""
        } else {
            "snapshots"
        }))
        .map_err(|e| e.to_string())?
    {
        return Err("snapshot artifact parent is invalid".into());
    }
    if relative.starts_with("snapshots")
        && fs::symlink_metadata(directory.join("snapshots"))
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
    {
        return Err("snapshot directory cannot be a symbolic link".into());
    }
    Ok(path)
}
fn bounded_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    if regular(path)?.len() > MAX_METADATA_SIZE {
        return Err("snapshot metadata exceeds limit".into());
    }
    read_json(path)
}
fn load(directory: &Path, vm: &VmConfig) -> Result<Manifest, String> {
    let path = directory.join(MANIFEST);
    if !path.try_exists().map_err(|e| e.to_string())? {
        regular(&directory.join("disk.qcow2"))?;
        return Ok(Manifest {
            schema: 1,
            vm_id: vm.id.clone(),
            active_disk: "disk.qcow2".into(),
            active_parent_id: None,
            nodes: Vec::new(),
            recovery_note: None,
        });
    }
    let manifest: Manifest = bounded_json(&path)?;
    if manifest.schema != 1 || manifest.vm_id != vm.id || manifest.nodes.len() > MAX_NODES {
        return Err("unsupported snapshot manifest or VM identity".into());
    }
    owned(directory, &manifest.active_disk)?;
    let mut ids = BTreeSet::new();
    let mut disks = BTreeSet::new();
    disks.insert(manifest.active_disk.clone());
    for node in &manifest.nodes {
        if node.checkpoint.id.is_empty()
            || node.checkpoint.id.len() > 128
            || !ids.insert(node.checkpoint.id.as_str())
            || !disks.insert(node.disk.clone())
            || node.checkpoint.config.id != vm.id
        {
            return Err("duplicate or invalid snapshot identity/layer".into());
        }
        owned(directory, &node.disk)?;
        if let Some(memory) = &node.memory {
            owned_path(directory, memory)?;
        }
        if (node.checkpoint.mode == VmSnapshotMode::Full) != node.memory.is_some() {
            return Err("snapshot mode/artifacts disagree".into());
        }
    }
    for node in &manifest.nodes {
        let mut seen = BTreeSet::new();
        let mut current = Some(node.checkpoint.id.as_str());
        while let Some(id) = current {
            if !seen.insert(id) {
                return Err("snapshot parent cycle".into());
            }
            let parent = manifest
                .nodes
                .iter()
                .find(|node| node.checkpoint.id == id)
                .ok_or("snapshot parent is missing")?;
            current = parent.checkpoint.parent_id.as_deref();
        }
    }
    if manifest
        .active_parent_id
        .as_ref()
        .is_some_and(|id| !ids.contains(id.as_str()))
    {
        return Err("active snapshot parent is missing".into());
    }
    Ok(manifest)
}
fn save(directory: &Path, manifest: &Manifest) -> Result<(), String> {
    if serde_json::to_vec_pretty(manifest)
        .map_err(|e| e.to_string())?
        .len() as u64
        > MAX_METADATA_SIZE
    {
        return Err("snapshot metadata exceeds limit; operation journal retained".into());
    }
    atomic_json(&directory.join(MANIFEST), manifest)
}
fn pending(directory: &Path) -> Result<(), String> {
    if directory
        .join(JOURNAL)
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        Err("snapshot operation needs stopped-VM recovery before another operation".into())
    } else {
        Ok(())
    }
}
fn sync_directory(directory: &Path) -> Result<(), String> {
    File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("snapshot directory durability: {e}"))
}
fn remove_journal(directory: &Path) -> Result<(), String> {
    fs::remove_file(directory.join(JOURNAL))
        .map_err(|e| format!("snapshot journal cleanup: {e}"))?;
    sync_directory(directory)
}
fn make_child(
    options: &BackendOptions,
    directory: &Path,
    backing: &Path,
) -> Result<PathBuf, String> {
    let backing = fs::canonicalize(backing).map_err(|e| format!("snapshot backing path: {e}"))?;
    let output = Command::new(&options.qemu_img)
        .args([
            "info",
            "-U",
            "-f",
            "qcow2",
            "--backing-chain",
            "--output=json",
        ])
        .arg(&backing)
        .output()
        .map_err(|e| format!("snapshot chain preflight: {e}"))?;
    if !output.status.success() || output.stdout.len() as u64 > MAX_METADATA_SIZE {
        return Err(format!(
            "snapshot chain preflight: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let chain: Vec<Value> = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    if chain.len() >= MAX_CHAIN {
        return Err(
            "snapshot backing chain limit reached; create an independent duplicate first".into(),
        );
    }
    let folder = directory.join("snapshots");
    if folder.try_exists().map_err(|e| e.to_string())?
        && !fs::symlink_metadata(&folder)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_dir()
    {
        return Err("snapshot directory must be an owned directory".into());
    }
    private_dir(&folder).map_err(|e| e.to_string())?;
    let relative = PathBuf::from(format!("snapshots/{}.qcow2", unique_id()));
    let path = directory.join(&relative);
    if path.try_exists().map_err(|e| e.to_string())? {
        return Err("snapshot artifact already exists".into());
    }
    let output = Command::new(&options.qemu_img)
        .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
        .arg(&backing)
        .arg(&path)
        .output()
        .map_err(|e| format!("snapshot child creation: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "snapshot child creation: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    File::open(&path)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    sync_directory(&folder)?;
    sync_directory(directory)?;
    Ok(relative)
}
fn label(name: &str) -> Result<(), String> {
    if name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        Err("snapshot name must contain 1–128 bytes without control characters".into())
    } else {
        Ok(())
    }
}

pub(crate) fn active_disk(options: &BackendOptions, vm: &VmConfig) -> Result<PathBuf, String> {
    let directory = vm_dir(options, &vm.id)?;
    pending(&directory)?;
    let manifest = load(&directory, vm)?;
    owned(&directory, &manifest.active_disk)
}
/// A saved checkpoint's frozen disk layer.
pub(crate) struct CheckpointDisk {
    pub path: PathBuf,
    pub name: String,
    /// The checkpoint the layer belongs to.
    pub id: String,
    pub parent_id: Option<String>,
}
/// The frozen layer of the saved, not deleted, checkpoint `id`: an immutable
/// qcow2 whose backing chain reaches the base. Like [`active_disk`] it
/// refuses while a snapshot operation is unfinished.
pub(crate) fn checkpoint_disk(
    options: &BackendOptions,
    vm: &VmConfig,
    id: &str,
) -> Result<CheckpointDisk, String> {
    let directory = vm_dir(options, &vm.id)?;
    pending(&directory)?;
    let manifest = load(&directory, vm)?;
    let record = manifest
        .nodes
        .iter()
        .find(|node| node.checkpoint.id == id)
        .ok_or("the checkpoint does not exist")?;
    if record.checkpoint.deleted {
        return Err("the checkpoint was deleted".into());
    }
    Ok(CheckpointDisk {
        path: owned(&directory, &record.disk)?,
        name: record.checkpoint.name.clone(),
        id: record.checkpoint.id.clone(),
        parent_id: record.checkpoint.parent_id.clone(),
    })
}
pub(crate) fn recovery_required(options: &BackendOptions, vm: &VmConfig) -> Result<bool, String> {
    vm_dir(options, &vm.id)?
        .join(JOURNAL)
        .try_exists()
        .map_err(|error| format!("snapshot operation journal: {error}"))
}
/// How a checkpoint's recorded profile compares with the VM's current one.
pub(crate) fn profile_of(
    recorded: Option<&crate::stealth::StealthProfile>,
    current: &crate::stealth::StealthProfile,
) -> crate::api::SnapshotProfile {
    match recorded {
        None => crate::api::SnapshotProfile::Unknown,
        Some(recorded) if recorded == current => crate::api::SnapshotProfile::Same,
        Some(recorded) => crate::api::SnapshotProfile::Other {
            machine: recorded.machine_name(),
        },
    }
}
pub(crate) fn list(options: &BackendOptions, vm: &VmConfig) -> Result<VmSnapshotTree, String> {
    let directory = vm_dir(options, &vm.id)?;
    let manifest = load(&directory, vm)?;
    Ok(VmSnapshotTree {
        vm_id: vm.id.clone(),
        nodes: manifest
            .nodes
            .into_iter()
            .map(|mut record| {
                if let Some(memory) = &record.memory
                    && !regular(&directory.join(memory)).is_ok_and(|metadata| metadata.len() == record.checkpoint.memory_size)
                {
                    record.checkpoint.compatible = false;
                    record.checkpoint.compatibility_note = Some("Saved memory artifact is unavailable or changed; reboot from the disk checkpoint".into());
                }
                record.checkpoint.profile = profile_of(record.checkpoint.stealth.as_ref(), &vm.stealth);
                record.checkpoint
            })
            .collect(),
        active_parent_id: manifest.active_parent_id,
        recovery_note: if directory.join(JOURNAL).exists() {
            Some("unfinished operation requires stopped-VM recovery".into())
        } else {
            manifest.recovery_note
        },
        ..VmSnapshotTree::default()
    })
}
pub(crate) fn compatibility(
    options: &BackendOptions,
    vm: &VmConfig,
    id: &str,
) -> Result<Option<String>, String> {
    let directory = vm_dir(options, &vm.id)?;
    let manifest = load(&directory, vm)?;
    Ok(manifest
        .nodes
        .iter()
        .find(|node| node.checkpoint.id == id && !node.checkpoint.deleted)
        .ok_or("snapshot is missing or deleted")?
        .compatibility
        .clone())
}
/// One manifest read for graph compatibility checks; avoids per-node reparsing.
pub(crate) fn compatibilities(
    options: &BackendOptions,
    vm: &VmConfig,
) -> Result<std::collections::BTreeMap<String, Option<String>>, String> {
    let directory = vm_dir(options, &vm.id)?;
    let manifest = load(&directory, vm)?;
    Ok(manifest
        .nodes
        .into_iter()
        .filter(|record| !record.checkpoint.deleted)
        .map(|record| (record.checkpoint.id, record.compatibility))
        .collect())
}
pub(crate) fn host_checkpoint(
    options: &BackendOptions,
    vm: &VmConfig,
    id: &str,
) -> Result<Option<Value>, String> {
    let directory = vm_dir(options, &vm.id)?;
    let manifest = load(&directory, vm)?;
    Ok(manifest
        .nodes
        .iter()
        .find(|node| node.checkpoint.id == id && !node.checkpoint.deleted)
        .ok_or("snapshot is missing or deleted")?
        .host_checkpoint
        .clone())
}
pub(crate) fn prepare_take(
    options: &BackendOptions,
    vm: &VmConfig,
    request: &SnapshotRequest,
    consistency: VmSnapshotConsistency,
) -> Result<PreparedTake, String> {
    label(&request.name)?;
    if request.description.len() > 4096 {
        return Err("snapshot description exceeds 4096 bytes".into());
    }
    if request.mode == VmSnapshotMode::Full && consistency != VmSnapshotConsistency::Paused {
        return Err("full snapshots require paused guest state".into());
    }
    let directory = vm_dir(options, &vm.id)?;
    run_layer::settle_stopped(options, &vm.id)?;
    pending(&directory)?;
    let manifest = load(&directory, vm)?;
    if manifest.nodes.len() == MAX_NODES {
        return Err(
            "snapshot metadata limit reached; preserved checkpoints cannot be overwritten".into(),
        );
    }
    let frozen_disk = owned(&directory, &manifest.active_disk)?;
    let active_disk = make_child(options, &directory, &frozen_disk)?;
    let id = unique_id();
    let memory = (request.mode == VmSnapshotMode::Full)
        .then(|| PathBuf::from(format!("snapshots/{id}.state")));
    let record = Record {
        checkpoint: VmCheckpoint {
            id: id.clone(),
            parent_id: manifest.active_parent_id,
            name: request.name.clone(),
            description: request.description.clone(),
            created_unix_ms: u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_millis(),
            )
            .map_err(|e| e.to_string())?,
            mode: request.mode,
            consistency,
            config: vm.clone(),
            disk_size: regular(&frozen_disk)?.blocks().saturating_mul(512),
            memory_size: 0,
            compatible: true,
            compatibility_note: None,
            deleted: false,
            stealth: Some(vm.stealth.clone()),
            profile: crate::api::SnapshotProfile::Same,
        },
        disk: manifest.active_disk.clone(),
        memory: memory.clone(),
        memory_sha256: None,
        compatibility: None,
        host_checkpoint: None,
    };
    atomic_json(
        &directory.join(JOURNAL),
        &Journal {
            operation: Operation::Take,
            id: id.clone(),
            previous_disk: manifest.active_disk,
            next_disk: active_disk.clone(),
        },
    )?;
    Ok(PreparedTake {
        id,
        frozen_disk,
        active_disk: directory.join(active_disk),
        memory_path: memory.map(|path| directory.join(path)),
        record,
    })
}
pub(crate) fn commit_take(
    options: &BackendOptions,
    vm: &VmConfig,
    mut prepared: PreparedTake,
    compatibility: Option<String>,
    host_checkpoint: Option<Value>,
) -> Result<VmCheckpoint, String> {
    let directory = vm_dir(options, &vm.id)?;
    let journal: Journal = bounded_json(&directory.join(JOURNAL))?;
    if journal.operation != Operation::Take
        || journal.id != prepared.id
        || directory.join(&journal.next_disk) != prepared.active_disk
    {
        return Err("snapshot take journal mismatch".into());
    }
    let mut manifest = load(&directory, vm)?;
    if manifest.active_disk != journal.previous_disk {
        return Err("snapshot active disk changed during take".into());
    }
    File::open(&prepared.frozen_disk)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    if let Some(path) = &prepared.memory_path {
        let meta = regular(path)?;
        if meta.len() == 0 || compatibility.is_none() || host_checkpoint.is_none() {
            return Err("full snapshot state/context is incomplete".into());
        }
        File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        prepared.record.memory_sha256 = Some(
            sha256_uncached(File::open(path).map_err(|e| e.to_string())?)?
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        );
        prepared.record.checkpoint.memory_size = meta.len();
        sync_directory(path.parent().ok_or("memory artifact has no parent")?)?;
    }
    prepared.record.compatibility = compatibility;
    prepared.record.host_checkpoint = host_checkpoint;
    prepared.record.checkpoint.disk_size =
        regular(&prepared.frozen_disk)?.blocks().saturating_mul(512);
    let checkpoint = prepared.record.checkpoint.clone();
    manifest.nodes.push(prepared.record);
    manifest.active_disk = journal.next_disk;
    manifest.active_parent_id = Some(prepared.id);
    manifest.recovery_note = None;
    save(&directory, &manifest)?;
    remove_journal(&directory)?;
    Ok(checkpoint)
}
/// Called only after the owning QEMU has stopped. Interrupted takes select their
/// child whether or not the pivot happened; both preserve all prior disk writes.
pub(crate) fn recover_pending(options: &BackendOptions, vm: &VmConfig) -> Result<(), String> {
    let directory = vm_dir(options, &vm.id)?;
    if !directory
        .join(JOURNAL)
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        return Ok(());
    }
    let journal: Journal = bounded_json(&directory.join(JOURNAL))?;
    owned(&directory, &journal.previous_disk)?;
    owned(&directory, &journal.next_disk)?;
    let mut manifest = load(&directory, vm)?;
    if manifest.active_disk != journal.previous_disk && manifest.active_disk != journal.next_disk {
        return Err(
            "snapshot recovery active disk differs from journal; artifacts retained".into(),
        );
    }
    if journal.operation == Operation::Take {
        manifest.active_disk = journal.next_disk;
    }
    manifest.recovery_note = Some("interrupted snapshot operation recovered; disk writes retained; incomplete checkpoints were not published".into());
    save(&directory, &manifest)?;
    remove_journal(&directory)
}
pub(crate) fn prepare_restore(
    options: &BackendOptions,
    vm: &VmConfig,
    id: &str,
    boot_from_disk: bool,
) -> Result<PreparedRestore, String> {
    preflight_restore(options, vm, id, boot_from_disk)?;
    let directory = vm_dir(options, &vm.id)?;
    pending(&directory)?;
    let manifest = load(&directory, vm)?;
    let record = manifest
        .nodes
        .iter()
        .find(|node| node.checkpoint.id == id && !node.checkpoint.deleted)
        .ok_or("snapshot is missing or deleted")?;
    let memory_path = if boot_from_disk {
        None
    } else {
        record
            .memory
            .as_ref()
            .map(|path| owned(&directory, path))
            .transpose()?
    };
    if let Some(path) = &memory_path {
        let hash = sha256_uncached(File::open(path).map_err(|e| e.to_string())?)?;
        let actual = hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if record.memory_sha256.as_deref() != Some(actual.as_str())
            || regular(path)?.len() != record.checkpoint.memory_size
        {
            return Err("saved memory state checksum/size differs; current VM retained".into());
        }
    }
    let active_disk = make_child(options, &directory, &owned(&directory, &record.disk)?)?;
    atomic_json(
        &directory.join(JOURNAL),
        &Journal {
            operation: Operation::Restore,
            id: id.into(),
            previous_disk: manifest.active_disk,
            next_disk: active_disk.clone(),
        },
    )?;
    Ok(PreparedRestore {
        id: id.into(),
        mode: if memory_path.is_some() {
            VmSnapshotMode::Full
        } else {
            VmSnapshotMode::Disk
        },
        active_disk: directory.join(active_disk),
        memory_path,
        compatibility: record.compatibility.clone(),
    })
}
/// Finish the stopped boot's automatic layer, then validate the restore target
/// before saving or replacing the current working state.
pub(crate) fn preflight_restore(
    options: &BackendOptions,
    vm: &VmConfig,
    id: &str,
    boot_from_disk: bool,
) -> Result<(), String> {
    let directory = vm_dir(options, &vm.id)?;
    run_layer::settle_stopped(options, &vm.id)?;
    pending(&directory)?;
    let manifest = load(&directory, vm)?;
    let record = manifest
        .nodes
        .iter()
        .find(|node| node.checkpoint.id == id && !node.checkpoint.deleted)
        .ok_or("snapshot is missing or deleted")?;
    let bundle: crate::storage::Bundle = bounded_json(&directory.join("bundle.json"))?;
    bundle.verify_installed()?;
    validate_disk(
        options,
        vm,
        &owned(&directory, &record.disk)?,
        bundle.vm_disk(),
    )?;
    if !boot_from_disk && record.checkpoint.mode == VmSnapshotMode::Full {
        let path = owned(
            &directory,
            record
                .memory
                .as_deref()
                .ok_or("full snapshot memory artifact is missing")?,
        )?;
        if record.compatibility.is_none() || record.host_checkpoint.is_none() {
            return Err("full snapshot host recovery context is missing".into());
        }
        let hash = sha256_uncached(File::open(&path).map_err(|e| e.to_string())?)?;
        let actual = hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if record.memory_sha256.as_deref() != Some(actual.as_str())
            || regular(&path)?.len() != record.checkpoint.memory_size
        {
            return Err("saved memory state checksum/size differs; current VM retained".into());
        }
    }
    Ok(())
}
pub(crate) fn commit_restore(
    options: &BackendOptions,
    vm: &VmConfig,
    prepared: &PreparedRestore,
) -> Result<(), String> {
    let directory = vm_dir(options, &vm.id)?;
    let journal: Journal = bounded_json(&directory.join(JOURNAL))?;
    if journal.operation != Operation::Restore
        || journal.id != prepared.id
        || directory.join(&journal.next_disk) != prepared.active_disk
    {
        return Err("snapshot restore journal mismatch".into());
    }
    let mut manifest = load(&directory, vm)?;
    if manifest.active_disk != journal.previous_disk {
        return Err("snapshot active disk changed during restore".into());
    }
    owned(&directory, &journal.next_disk)?;
    manifest.active_disk = journal.next_disk;
    manifest.active_parent_id = Some(prepared.id.clone());
    manifest.recovery_note = None;
    save(&directory, &manifest)?;
    remove_journal(&directory)
}
pub(crate) fn cancel_restore(
    options: &BackendOptions,
    vm: &VmConfig,
    prepared: &PreparedRestore,
) -> Result<(), String> {
    let directory = vm_dir(options, &vm.id)?;
    let journal: Journal = bounded_json(&directory.join(JOURNAL))?;
    if journal.operation != Operation::Restore || journal.id != prepared.id {
        return Err("snapshot restore journal mismatch".into());
    }
    if load(&directory, vm)?.active_disk != journal.previous_disk {
        return Err("restore is already published; cancel cannot rewind current state".into());
    }
    // Preserve the candidate too: failed incoming migration may have useful evidence.
    remove_journal(&directory)
}
pub(crate) fn rename(
    options: &BackendOptions,
    vm: &VmConfig,
    id: &str,
    name: &str,
) -> Result<(), String> {
    label(name)?;
    let directory = vm_dir(options, &vm.id)?;
    run_layer::settle_stopped(options, &vm.id)?;
    pending(&directory)?;
    let mut manifest = load(&directory, vm)?;
    manifest
        .nodes
        .iter_mut()
        .find(|node| node.checkpoint.id == id && !node.checkpoint.deleted)
        .ok_or("snapshot is missing or deleted")?
        .checkpoint
        .name = name.into();
    save(&directory, &manifest)
}
pub(crate) fn logical_delete(
    options: &BackendOptions,
    vm: &VmConfig,
    id: &str,
) -> Result<(), String> {
    let directory = vm_dir(options, &vm.id)?;
    run_layer::settle_stopped(options, &vm.id)?;
    pending(&directory)?;
    let mut manifest = load(&directory, vm)?;
    manifest
        .nodes
        .iter_mut()
        .find(|node| node.checkpoint.id == id && !node.checkpoint.deleted)
        .ok_or("snapshot is missing or deleted")?
        .checkpoint
        .deleted = true;
    save(&directory, &manifest)
}
pub(crate) fn managed(directory: &Path) -> bool {
    directory.join(MANIFEST).exists() || directory.join(JOURNAL).exists()
}

/// Extra artifacts for confirmed whole-VM deletion. Dependencies are VM-owned;
/// deleting an entire tree never removes its separate pinned installed base.
pub(crate) fn deletion_paths(
    options: &BackendOptions,
    vm: &VmConfig,
    base: &Path,
) -> Result<Vec<PathBuf>, String> {
    let directory = vm_dir(options, &vm.id)?;
    if !managed(&directory) {
        return Ok(Vec::new());
    }
    run_layer::settle_stopped(options, &vm.id)?;
    pending(&directory)?;
    load(&directory, vm)?;
    validate_active(options, vm, base)?;
    let manifest = directory.join(MANIFEST);
    regular(&manifest)?;
    let folder = directory.join("snapshots");
    if !fs::symlink_metadata(&folder)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_dir()
    {
        return Err("snapshot deletion requires an owned directory".into());
    }
    let mut count = 0usize;
    for entry in fs::read_dir(&folder).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        count += 1;
        if count > 4096 {
            return Err("snapshot artifact deletion count exceeds limit; files retained".into());
        }
        let path = entry.path();
        regular(&path)?;
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or("invalid snapshot artifact name")?;
        if stem.is_empty()
            || stem.len() > 128
            || !stem
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
            || !matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("qcow2" | "state")
            )
        {
            return Err("unrecognized file in snapshot directory; files retained".into());
        }
    }
    Ok(vec![manifest, folder])
}

/// Verifies every backing against the pinned base and VM-owned immutable layers.
pub(crate) fn validate_active(
    options: &BackendOptions,
    vm: &VmConfig,
    base: &Path,
) -> Result<(), String> {
    validate_disk(options, vm, &active_disk(options, vm)?, base)
}
pub(crate) fn validate_disk(
    options: &BackendOptions,
    vm: &VmConfig,
    disk: &Path,
    base: &Path,
) -> Result<(), String> {
    let directory = vm_dir(options, &vm.id)?;
    let output = Command::new(&options.qemu_img)
        .args([
            "info",
            "-U",
            "-f",
            "qcow2",
            "--backing-chain",
            "--output=json",
        ])
        .arg(disk)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "snapshot backing validation: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if output.stdout.len() > MAX_METADATA_SIZE as usize {
        return Err("snapshot chain metadata exceeds limit".into());
    }
    let chain: Vec<Value> = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    if chain.is_empty() || chain.len() > MAX_CHAIN {
        return Err("snapshot chain exceeds supported depth of 64 layers".into());
    }
    let base = fs::canonicalize(base).map_err(|e| e.to_string())?;
    let canonical_directory = fs::canonicalize(&directory).map_err(|e| e.to_string())?;
    let mut seen = BTreeSet::new();
    for (index, image) in chain.iter().enumerate() {
        if image.get("format").and_then(Value::as_str) != Some("qcow2") {
            return Err("snapshot backing chain must use qcow2".into());
        }
        let filename = Path::new(
            image
                .get("filename")
                .and_then(Value::as_str)
                .ok_or("snapshot chain filename is missing")?,
        );
        regular(filename)?;
        let actual = fs::canonicalize(filename).map_err(|e| e.to_string())?;
        if !seen.insert(actual.clone()) {
            return Err("snapshot backing cycle".into());
        }
        if index + 1 == chain.len() {
            if actual != base
                && actual
                    != fs::canonicalize(directory.join("disk.qcow2")).map_err(|e| e.to_string())?
            {
                return Err("snapshot backing differs from pinned installed base".into());
            }
        } else {
            let relative = actual
                .strip_prefix(&canonical_directory)
                .map_err(|_| "snapshot backing is outside its VM")?;
            owned(&directory, relative)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) struct Fixture {
        pub(super) root: PathBuf,
        pub(super) options: BackendOptions,
        pub(super) vm: VmConfig,
        pub(super) directory: PathBuf,
        pub(super) base: PathBuf,
    }
    impl Fixture {
        pub(super) fn new() -> Self {
            let root = std::env::temp_dir().join(format!("ant-snapshot-{}", unique_id()));
            let options = BackendOptions {
                data_dir: root.clone(),
                ..BackendOptions::default()
            };
            let mut vm = VmConfig {
                id: "fixture".into(),
                name: "Fixture".into(),
                ..VmConfig::default()
            };
            let directory = root.join("fixture");
            private_dir(&directory).unwrap();
            let base = root.join("base.qcow2");
            Self::command("qemu-img", &["create", "-f", "qcow2"], &base, Some("4M"));
            let kernel = root.join("kernel");
            fs::write(&kernel, b"synthetic kernel").unwrap();
            let bundle = crate::storage::Bundle {
                arch: Default::default(),
                kernel,
                base_disk: base,
                initrd: None,
                kernel_append: String::new(),
                kernel_version: "6.12.94".into(),
                schema_id: 1,
                base_identity: None,
                guest: None,
                fixed_display: false,
                build_provenance: None,
                antinomie_revision: None,
                antinomie_source: None,
                symbols: None,
                stealth_support: Vec::new(),
                built_with: None,
                min_app_version: None,
                name: None,
                uefi: Default::default(),
            }
            .install(&options)
            .unwrap();
            let base = bundle.base_disk.clone();
            vm.base_identity = bundle.base_identity.clone();
            atomic_json(&directory.join("bundle.json"), &bundle).unwrap();
            atomic_json(&directory.join("config.json"), &vm).unwrap();
            let output = Command::new("qemu-img")
                .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
                .arg(&base)
                .arg(directory.join("disk.qcow2"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            Self {
                root,
                options,
                vm,
                directory,
                base,
            }
        }
        pub(super) fn command(program: &str, args: &[&str], path: &Path, trailing: Option<&str>) {
            let mut command = Command::new(program);
            command.args(args).arg(path);
            if let Some(value) = trailing {
                command.arg(value);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        pub(super) fn write(&self, value: u8) {
            let path = active_disk(&self.options, &self.vm).unwrap();
            Self::command(
                "qemu-io",
                &["-f", "qcow2", "-c", &format!("write -P {value} 0 4096")],
                &path,
                None,
            );
        }
        pub(super) fn read(&self, disk: &Path, value: u8) {
            Self::command(
                "qemu-io",
                &[
                    "-r",
                    "-f",
                    "qcow2",
                    "-c",
                    &format!("read -P {value} 0 4096"),
                ],
                disk,
                None,
            );
        }
        pub(super) fn take(&self, name: &str) -> VmCheckpoint {
            let request = SnapshotRequest {
                name: name.into(),
                description: String::new(),
                mode: VmSnapshotMode::Disk,
            };
            let prepared = prepare_take(
                &self.options,
                &self.vm,
                &request,
                VmSnapshotConsistency::Stopped,
            )
            .unwrap();
            commit_take(&self.options, &self.vm, prepared, None, None).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn branches_restore_exact_disk_data_and_retain_deleted_ancestors() {
        let fixture = Fixture::new();
        fixture.write(17);
        let a = fixture.take("A");
        fixture.write(34);
        let b = fixture.take("B");
        let restore = prepare_restore(&fixture.options, &fixture.vm, &a.id, true).unwrap();
        commit_restore(&fixture.options, &fixture.vm, &restore).unwrap();
        fixture.read(&active_disk(&fixture.options, &fixture.vm).unwrap(), 17);
        fixture.write(51);
        let c = fixture.take("C");
        assert_eq!(b.parent_id.as_deref(), Some(a.id.as_str()));
        assert_eq!(c.parent_id.as_deref(), Some(a.id.as_str()));
        logical_delete(&fixture.options, &fixture.vm, &a.id).unwrap();
        assert!(prepare_restore(&fixture.options, &fixture.vm, &a.id, true).is_err());
        let restore = prepare_restore(&fixture.options, &fixture.vm, &b.id, true).unwrap();
        commit_restore(&fixture.options, &fixture.vm, &restore).unwrap();
        fixture.read(&active_disk(&fixture.options, &fixture.vm).unwrap(), 34);
        validate_active(&fixture.options, &fixture.vm, &fixture.base).unwrap();
        rename(&fixture.options, &fixture.vm, &b.id, "Renamed B").unwrap();
        assert_eq!(list(&fixture.options, &fixture.vm).unwrap().nodes.len(), 3);
    }
    #[test]
    fn a_snapshot_records_its_stealth_profile_and_lists_how_it_compares() {
        use crate::api::SnapshotProfile;
        use crate::stealth::{StealthPreset, StealthProfile};
        let mut fixture = Fixture::new();
        // Taken as a realistic desktop.
        fixture.vm.stealth =
            StealthProfile::realistic(StealthPreset::RealisticDesktop, "GenuineIntel");
        let taken = fixture.take("As desktop");
        assert_eq!(taken.stealth.as_ref(), Some(&fixture.vm.stealth));
        let nodes = |fixture: &Fixture| list(&fixture.options, &fixture.vm).unwrap().nodes;
        assert_eq!(nodes(&fixture)[0].profile, SnapshotProfile::Same);
        // The same machine with other serials is another profile.
        let mut other = fixture.vm.clone();
        other.stealth.identity.rerandomize();
        let machine = fixture.vm.stealth.machine_name();
        assert_eq!(
            list(&fixture.options, &other).unwrap().nodes[0].profile,
            SnapshotProfile::Other {
                machine: machine.clone()
            }
        );
        // So is Transparent, which names itself plainly.
        other.stealth = StealthProfile::transparent();
        assert_eq!(
            list(&fixture.options, &other).unwrap().nodes[0].profile,
            SnapshotProfile::Other { machine }
        );
        fixture.vm.stealth = StealthProfile::transparent();
        assert!(matches!(
            nodes(&fixture)[0].profile,
            SnapshotProfile::Other { .. }
        ));
        // A snapshot saved before profiles were recorded has none to compare.
        let directory = vm_dir(&fixture.options, &fixture.vm.id).unwrap();
        let mut manifest: Manifest = read_json(&directory.join(MANIFEST)).unwrap();
        manifest.nodes[0].checkpoint.stealth = None;
        atomic_json(&directory.join(MANIFEST), &manifest).unwrap();
        assert_eq!(nodes(&fixture)[0].profile, SnapshotProfile::Unknown);
        let text = fs::read_to_string(directory.join(MANIFEST)).unwrap();
        // And the field itself is optional on disk.
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(
            value["nodes"][0]["checkpoint"].get("profile").is_none(),
            "the comparison is never saved"
        );
        value["nodes"][0]["checkpoint"]
            .as_object_mut()
            .unwrap()
            .remove("stealth");
        let old: Manifest = serde_json::from_value(value).unwrap();
        assert!(old.nodes[0].checkpoint.stealth.is_none());
    }
    #[test]
    fn interrupted_take_before_or_after_pivot_preserves_all_disk_writes() {
        for pivoted in [false, true] {
            let fixture = Fixture::new();
            fixture.write(17);
            let prepared = prepare_take(
                &fixture.options,
                &fixture.vm,
                &SnapshotRequest {
                    name: "Interrupted".into(),
                    description: String::new(),
                    mode: VmSnapshotMode::Disk,
                },
                VmSnapshotConsistency::Stopped,
            )
            .unwrap();
            let writable = if pivoted {
                &prepared.active_disk
            } else {
                &prepared.frozen_disk
            };
            Fixture::command(
                "qemu-io",
                &["-f", "qcow2", "-c", "write -P 85 0 4096"],
                writable,
                None,
            );
            assert!(active_disk(&fixture.options, &fixture.vm).is_err());
            recover_pending(&fixture.options, &fixture.vm).unwrap();
            fixture.read(&active_disk(&fixture.options, &fixture.vm).unwrap(), 85);
            assert!(
                list(&fixture.options, &fixture.vm)
                    .unwrap()
                    .nodes
                    .is_empty()
            );
        }
    }
    #[test]
    fn failed_publication_recovers_child_without_publishing_checkpoint() {
        let fixture = Fixture::new();
        fixture.write(17);
        let prepared = prepare_take(
            &fixture.options,
            &fixture.vm,
            &SnapshotRequest {
                name: "Fails".into(),
                description: String::new(),
                mode: VmSnapshotMode::Disk,
            },
            VmSnapshotConsistency::Stopped,
        )
        .unwrap();
        crate::storage::fail_next_json_rename(&fixture.directory.join(MANIFEST));
        assert!(commit_take(&fixture.options, &fixture.vm, prepared, None, None).is_err());
        recover_pending(&fixture.options, &fixture.vm).unwrap();
        fixture.read(&active_disk(&fixture.options, &fixture.vm).unwrap(), 17);
        assert!(
            list(&fixture.options, &fixture.vm)
                .unwrap()
                .nodes
                .is_empty()
        );
    }
    #[test]
    fn published_checkpoint_survives_uncertain_directory_durability() {
        let fixture = Fixture::new();
        let prepared = prepare_take(
            &fixture.options,
            &fixture.vm,
            &SnapshotRequest {
                name: "Published".into(),
                description: String::new(),
                mode: VmSnapshotMode::Disk,
            },
            VmSnapshotConsistency::Stopped,
        )
        .unwrap();
        crate::storage::fail_next_directory_sync(&fixture.directory.join(MANIFEST));
        assert!(commit_take(&fixture.options, &fixture.vm, prepared, None, None).is_err());
        recover_pending(&fixture.options, &fixture.vm).unwrap();
        assert_eq!(list(&fixture.options, &fixture.vm).unwrap().nodes.len(), 1);
        validate_active(&fixture.options, &fixture.vm, &fixture.base).unwrap();
    }
    #[test]
    fn restore_cancel_preserves_future_and_committed_restore_cannot_be_cancelled() {
        let fixture = Fixture::new();
        fixture.write(17);
        let a = fixture.take("A");
        fixture.write(34);
        let future = active_disk(&fixture.options, &fixture.vm).unwrap();
        let restore = prepare_restore(&fixture.options, &fixture.vm, &a.id, true).unwrap();
        cancel_restore(&fixture.options, &fixture.vm, &restore).unwrap();
        fixture.read(&future, 34);
        assert_eq!(active_disk(&fixture.options, &fixture.vm).unwrap(), future);
        let restore = prepare_restore(&fixture.options, &fixture.vm, &a.id, true).unwrap();
        commit_restore(&fixture.options, &fixture.vm, &restore).unwrap();
        assert!(cancel_restore(&fixture.options, &fixture.vm, &restore).is_err());
        fixture.read(&future, 34);
    }
    #[test]
    fn tampered_memory_digest_and_invalid_artifact_paths_fail_before_restore() {
        let fixture = Fixture::new();
        let prepared = prepare_take(
            &fixture.options,
            &fixture.vm,
            &SnapshotRequest {
                name: "Full".into(),
                description: String::new(),
                mode: VmSnapshotMode::Full,
            },
            VmSnapshotConsistency::Paused,
        )
        .unwrap();
        let memory = prepared.memory_path.clone().unwrap();
        fs::write(&memory, b"saved state").unwrap();
        let node = commit_take(
            &fixture.options,
            &fixture.vm,
            prepared,
            Some("fingerprint".into()),
            Some(serde_json::json!({"runs":[]})),
        )
        .unwrap();
        fs::write(&memory, b"wrong state").unwrap();
        assert!(preflight_restore(&fixture.options, &fixture.vm, &node.id, false).is_err());
        assert!(!fixture.directory.join(JOURNAL).exists());
        let mut manifest = load(&fixture.directory, &fixture.vm).unwrap();
        manifest.nodes[0].disk = "../base.qcow2".into();
        save(&fixture.directory, &manifest).unwrap();
        assert!(list(&fixture.options, &fixture.vm).is_err());
    }
    #[test]
    fn parent_cycles_and_oversized_metadata_are_rejected() {
        let fixture = Fixture::new();
        let a = fixture.take("A");
        let mut manifest = load(&fixture.directory, &fixture.vm).unwrap();
        manifest.nodes[0].checkpoint.parent_id = Some(a.id);
        save(&fixture.directory, &manifest).unwrap();
        assert!(list(&fixture.options, &fixture.vm).is_err());
        manifest.nodes[0].checkpoint.parent_id = None;
        manifest.nodes[0].host_checkpoint =
            Some(Value::String("x".repeat(MAX_METADATA_SIZE as usize)));
        assert!(save(&fixture.directory, &manifest).is_err());
    }
    #[test]
    fn restore_rejects_foreign_backing_before_creating_a_journal() {
        let fixture = Fixture::new();
        let node = fixture.take("A");
        let foreign = fixture.root.join("foreign.qcow2");
        Fixture::command("qemu-img", &["create", "-f", "qcow2"], &foreign, Some("4M"));
        let output = Command::new("qemu-img")
            .args(["rebase", "-u", "-f", "qcow2", "-F", "qcow2", "-b"])
            .arg(&foreign)
            .arg(fixture.directory.join("disk.qcow2"))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(preflight_restore(&fixture.options, &fixture.vm, &node.id, true).is_err());
        assert!(!fixture.directory.join(JOURNAL).exists());
    }
    #[test]
    fn maximum_chain_depth_is_rejected_before_artifact_or_journal_creation() {
        let fixture = Fixture::new();
        let folder = fixture.directory.join("snapshots");
        private_dir(&folder).unwrap();
        let mut backing = fixture.directory.join("disk.qcow2");
        for index in 0..MAX_CHAIN - 2 {
            let path = folder.join(format!("depth-{index}.qcow2"));
            let output = Command::new("qemu-img")
                .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
                .arg(&backing)
                .arg(&path)
                .output()
                .unwrap();
            assert!(output.status.success());
            backing = path;
        }
        let count = fs::read_dir(&folder).unwrap().count();
        assert!(make_child(&fixture.options, &fixture.directory, &backing).is_err());
        assert_eq!(fs::read_dir(&folder).unwrap().count(), count);
        assert!(!fixture.directory.join(JOURNAL).exists());
    }
    #[test]
    fn whole_vm_deletion_removes_owned_snapshot_tree_but_preserves_base_and_unknown_files() {
        let fixture = Fixture::new();
        fixture.take("A");
        fixture.take("B");
        let user_file = fixture.directory.join("snapshots/user-note.txt");
        fs::write(&user_file, b"keep").unwrap();
        assert!(crate::storage::delete_vm(&fixture.options, &fixture.vm.id).is_err());
        assert_eq!(fs::read(&user_file).unwrap(), b"keep");
        assert!(fixture.directory.join("config.json").exists());
        fs::remove_file(user_file).unwrap();
        crate::storage::fail_next_directory_sync(&fixture.directory.join("config.json"));
        assert!(crate::storage::delete_vm(&fixture.options, &fixture.vm.id).is_err());
        assert!(fixture.directory.join("config.json").exists());
        assert!(fixture.directory.join("snapshots").exists());
        assert_eq!(list(&fixture.options, &fixture.vm).unwrap().nodes.len(), 2);
        assert!(
            crate::locations::registered_vms(&fixture.options)
                .unwrap()
                .iter()
                .any(|vm| vm.id == fixture.vm.id)
        );
        crate::storage::delete_vm(&fixture.options, &fixture.vm.id).unwrap();
        assert!(!fixture.directory.join("snapshots").exists());
        assert!(!fixture.directory.join(MANIFEST).exists());
        assert!(!fixture.directory.join("disk.qcow2").exists());
        assert!(fixture.base.exists());
    }
    #[test]
    fn missing_memory_allows_disk_reboot_and_does_not_block_descendant_restore() {
        let fixture = Fixture::new();
        fixture.write(17);
        let prepared = prepare_take(
            &fixture.options,
            &fixture.vm,
            &SnapshotRequest {
                name: "Full".into(),
                description: String::new(),
                mode: VmSnapshotMode::Full,
            },
            VmSnapshotConsistency::Paused,
        )
        .unwrap();
        let memory = prepared.memory_path.clone().unwrap();
        fs::write(&memory, b"saved state").unwrap();
        let full = commit_take(
            &fixture.options,
            &fixture.vm,
            prepared,
            Some("fingerprint".into()),
            Some(serde_json::json!({"runs":[]})),
        )
        .unwrap();
        fixture.write(34);
        let descendant = fixture.take("Disk descendant");
        fs::remove_file(memory).unwrap();
        let tree = list(&fixture.options, &fixture.vm).unwrap();
        assert!(
            !tree
                .nodes
                .iter()
                .find(|node| node.id == full.id)
                .unwrap()
                .compatible
        );
        assert!(preflight_restore(&fixture.options, &fixture.vm, &full.id, false).is_err());
        let restore = prepare_restore(&fixture.options, &fixture.vm, &full.id, true).unwrap();
        commit_restore(&fixture.options, &fixture.vm, &restore).unwrap();
        fixture.read(&active_disk(&fixture.options, &fixture.vm).unwrap(), 17);
        let restore = prepare_restore(&fixture.options, &fixture.vm, &descendant.id, true).unwrap();
        commit_restore(&fixture.options, &fixture.vm, &restore).unwrap();
        fixture.read(&active_disk(&fixture.options, &fixture.vm).unwrap(), 34);
    }
}
