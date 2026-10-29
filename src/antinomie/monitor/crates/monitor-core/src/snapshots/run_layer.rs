// SPDX-License-Identifier: GPL-3.0-only
//! The automatic layer of a run: how the disk a boot started from is kept
//! readable while the boot overwrites it, without copying anything at start.
//!
//! At every VM start the layer QEMU would write ("sealed", `A`) gets a fresh
//! empty child (`B`, a file under `snapshots/`) that becomes the active disk,
//! so everything the boot writes lands in `B` and `A` stays exactly as the
//! boot found it. It costs one `qemu-img create`: no data is copied. When the
//! boot is over (QEMU stopped, the recording saved) the earlier bytes of the
//! files the run changed are copied from `A` into the recording
//! ([`crate::file_before_store`]) and then `B` is committed down into `A`
//! (`qemu-img commit`) and removed, so the chain is what it was before the
//! start: at most one extra layer, and only while the boot runs.
//!
//! Choices, recorded because the Snapshots view and the take/restore code
//! share the manifest:
//!
//! * The layer is **not** a checkpoint. It is never a manifest node, so the
//!   Snapshots view (which lists nodes) never shows it, and a user snapshot is
//!   never merged: only `B`, a layer the app made and no node refers to, is
//!   committed, and only into `A`, its own backing file.
//! * The manifest's `active_disk` points at `B` while the boot runs, so a
//!   snapshot taken during the run freezes `B` (its backing `A` is then an
//!   ordinary lower layer) exactly as it froze the overlay before. When the
//!   boot ended with a snapshot taken or restored, `B` belongs to the user's
//!   chain and nothing is merged: the record is dropped and the chain keeps
//!   its one extra layer.
//! * `run-layer.json` in the VM folder says what is pending, and the folder's
//!   `run-layer.lock` serialises the finalizers. A crash or kill leaves the
//!   record: the next start or the next launch of the app finishes the job
//!   ([`finalize`]) before it uses the disk, copying if it still can.
//! * A VM that had no `snapshots.json` gets it deleted again after the merge,
//!   so it is not "managed" afterwards (reset and delete work as before).
use super::*;
use std::{os::unix::fs::OpenOptionsExt, sync::Mutex};

const RECORD: &str = "run-layer.json";
const LOCK: &str = "run-layer.lock";

/// VMs whose boot in this process has not ended.
static LIVE: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// The pending automatic layer of a VM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub format: u32,
    pub vm_id: String,
    pub boot_id: String,
    /// The boot's folder in the recording (where the earlier bytes go).
    pub boot_dir: PathBuf,
    /// `A`, relative to the VM folder.
    pub sealed: PathBuf,
    /// `B`, relative to the VM folder.
    pub top: PathBuf,
    /// The VM had no snapshot manifest before this boot.
    pub manifest_absent: bool,
}

/// What became of a pending layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `B` was committed into `A` and removed.
    Merged,
    /// A snapshot was taken or restored during the boot, so `B` is part of
    /// the user's chain and stays.
    KeptInChain,
    /// `B` was already gone from the chain (an earlier finalize was cut
    /// short after switching back); the record is dropped.
    Cleaned,
}

impl Record {
    fn path(directory: &Path) -> PathBuf {
        directory.join(RECORD)
    }
    pub fn load(directory: &Path) -> Option<Self> {
        let file = File::open(Self::path(directory)).ok()?;
        serde_json::from_reader(std::io::Read::take(file, 1 << 20))
            .ok()
            .filter(|record: &Self| record.format == 1)
    }
}

/// The pending record of `vm_id`, if there is one.
pub(crate) fn pending_record(options: &BackendOptions, vm_id: &str) -> Option<Record> {
    Record::load(&vm_dir(options, vm_id).ok()?)
}

/// Whether a boot of `vm_id` is running in this process.
pub(crate) fn live(vm_id: &str) -> bool {
    LIVE.lock().is_ok_and(|live| live.contains(vm_id))
}

fn lock(directory: &Path) -> Result<File, String> {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(directory.join(LOCK))
        .map_err(|e| format!("run layer lock: {e}"))?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |_| "the previous run's disk is still being finished; try again in a moment".to_owned(),
    )?;
    Ok(file)
}

fn config(vm_id: &str) -> VmConfig {
    VmConfig {
        id: vm_id.to_owned(),
        ..VmConfig::default()
    }
}

/// Seal the active layer and make a fresh empty one the active disk, just
/// before the boot `boot_id` (recorded in `boot_dir`) starts QEMU. A record
/// left by an earlier boot is finished first.
pub(crate) fn begin(
    options: &BackendOptions,
    vm: &VmConfig,
    boot_dir: &Path,
    boot_id: &str,
) -> Result<(), String> {
    let directory = vm_dir(options, &vm.id)?;
    pending(&directory)?;
    let _lock = lock(&directory)?;
    if let Some(old) = Record::load(&directory) {
        // No boot of this process is running (the worker starts one VM at a
        // time and only calls this for a start), so the record is an earlier
        // boot's.
        if let Ok(mut live) = LIVE.lock() {
            live.remove(&vm.id);
        }
        settle(options, &directory, &old)?;
    }
    let mut manifest = load(&directory, vm)?;
    let manifest_absent = !directory
        .join(MANIFEST)
        .try_exists()
        .map_err(|e| e.to_string())?;
    let sealed = manifest.active_disk.clone();
    let top = make_child(options, &directory, &owned(&directory, &sealed)?)?;
    atomic_json(
        &Record::path(&directory),
        &Record {
            format: 1,
            vm_id: vm.id.clone(),
            boot_id: boot_id.to_owned(),
            boot_dir: boot_dir.to_path_buf(),
            sealed,
            top: top.clone(),
            manifest_absent,
        },
    )?;
    manifest.active_disk = top;
    save(&directory, &manifest)?;
    if let Ok(mut live) = LIVE.lock() {
        live.insert(vm.id.clone());
    }
    Ok(())
}

/// The boot of `vm_id` is over in this process (QEMU stopped).
pub(crate) fn ended(vm_id: &str) {
    if let Ok(mut live) = LIVE.lock() {
        live.remove(vm_id);
    }
}

/// Refuse while a pending layer would be disturbed (resize, delete).
pub(crate) fn ensure_idle(options: &BackendOptions, vm_id: &str) -> Result<(), String> {
    if pending_record(options, vm_id).is_some() {
        Err("the previous run's disk is still being finished; try again in a moment".into())
    } else {
        Ok(())
    }
}

/// VMs whose automatic layer is to be finished once the recording is saved.
static DUE: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
/// VMs with a finalize at work in this process.
static BUSY: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
static SCANNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether a layer is waiting to be finished or being finished right now.
pub(crate) fn working() -> bool {
    DUE.lock().is_ok_and(|due| !due.is_empty()) || BUSY.lock().is_ok_and(|busy| !busy.is_empty())
}

/// The VM's boot ended: its layer is finished at the next [`finalize_due`].
pub(crate) fn mark_due(vm_id: &str) {
    if let Ok(mut due) = DUE.lock() {
        due.insert(vm_id.to_owned());
    }
}

/// Start the finalize of every due VM in a thread of its own (the copy can
/// take a while). The first call of a process also finds layers an earlier
/// process left behind (a crash or kill) among `vms`.
pub(crate) fn finalize_due(options: &BackendOptions, vms: &[String]) {
    if !vms.is_empty() && !SCANNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        for vm in vms {
            if pending_record(options, vm).is_some() {
                mark_due(vm);
            }
        }
    }
    let due: Vec<String> = match DUE.lock() {
        Ok(mut due) => std::mem::take(&mut *due).into_iter().collect(),
        Err(_) => return,
    };
    for vm in due {
        let Ok(mut busy) = BUSY.lock() else { continue };
        if !busy.insert(vm.clone()) {
            mark_due(&vm);
            continue;
        }
        drop(busy);
        let options = options.clone();
        std::thread::spawn(move || {
            let result = finalize(&options, &vm);
            if let Ok(mut busy) = BUSY.lock() {
                busy.remove(&vm);
            }
            // A start that is running or a finalize at work elsewhere is
            // tried again; any other failure leaves the record for the next
            // start to finish.
            if matches!(&result, Err(why) if why.contains("still being finished")) {
                mark_due(&vm);
            }
        });
    }
}

/// Finish the automatic layer a stopped VM still has pending, waiting for a
/// finalize already at work, before a snapshot operation reads or changes the
/// manifest: the finalize switches the active disk back and deletes the layer,
/// and an operation that had loaded the manifest before would freeze or restore
/// a file that is gone a moment later. Does nothing while a boot of the VM runs
/// (a snapshot taken during the boot is the user's and keeps the layer) or when
/// nothing is pending.
pub(crate) fn settle_stopped(options: &BackendOptions, vm_id: &str) -> Result<(), String> {
    let deadline = std::time::Instant::now() + SETTLE_WAIT;
    loop {
        if pending_record(options, vm_id).is_none() || live(vm_id) {
            return Ok(());
        }
        match finalize(options, vm_id) {
            Ok(_) => return Ok(()),
            Err(why) if why.contains("still being finished") => {
                if std::time::Instant::now() >= deadline {
                    return Err(why);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(why) => return Err(why),
        }
    }
}

/// How long a snapshot operation waits for the previous run's layer.
const SETTLE_WAIT: std::time::Duration = std::time::Duration::from_secs(300);

/// Copy the earlier bytes (when a program is set up for it) and merge the layer
/// down. Does nothing when no record is pending. Refuses while a boot of the
/// VM runs in this process or another finalize is at work.
pub(crate) fn finalize(options: &BackendOptions, vm_id: &str) -> Result<Option<Outcome>, String> {
    let directory = vm_dir(options, vm_id)?;
    if Record::load(&directory).is_none() {
        return Ok(None);
    }
    if live(vm_id) {
        return Err("the VM is running".into());
    }
    let _lock = lock(&directory)?;
    let Some(record) = Record::load(&directory) else {
        return Ok(None);
    };
    settle(options, &directory, &record).map(Some)
}

fn settle(options: &BackendOptions, directory: &Path, record: &Record) -> Result<Outcome, String> {
    // The earlier bytes first: they are read from `A`, which the merge changes.
    if let Err(why) = crate::file_before_store::copy_for(record) {
        crate::file_before_store::note_not_copied(&record.boot_dir, &record.boot_id, &why);
    }
    let sealed = owned(directory, &record.sealed)?;
    let top_path = owned_path(directory, &record.top)?;
    let mut manifest = load(directory, &config(&record.vm_id))?;
    let top_exists = top_path.try_exists().map_err(|e| e.to_string())?;
    let referenced = manifest
        .nodes
        .iter()
        .any(|node| node.disk == record.top || node.disk == record.sealed);
    let outcome = if manifest.active_disk == record.sealed || !top_exists {
        // Switched back before (a cut-short finalize): only the file is left.
        if manifest.active_disk == record.top {
            manifest.active_disk = record.sealed.clone();
            save(directory, &manifest)?;
        }
        if top_exists && !referenced {
            let _ = fs::remove_file(&top_path);
        }
        Outcome::Cleaned
    } else if manifest.active_disk == record.top && !referenced {
        let backing = backing_of(options, &top_path)?;
        if fs::canonicalize(&backing).map_err(|e| e.to_string())?
            != fs::canonicalize(&sealed).map_err(|e| e.to_string())?
        {
            return Err(
                "the automatic layer's backing file is not the sealed layer; left as it is".into(),
            );
        }
        commit(options, &top_path)?;
        manifest.active_disk = record.sealed.clone();
        if record.manifest_absent && manifest.nodes.is_empty() && !directory.join(JOURNAL).exists()
        {
            let _ = fs::remove_file(directory.join(MANIFEST));
        } else {
            save(directory, &manifest)?;
        }
        fs::remove_file(&top_path).map_err(|e| format!("automatic layer cleanup: {e}"))?;
        let _ = fs::remove_dir(directory.join("snapshots"));
        Outcome::Merged
    } else {
        Outcome::KeptInChain
    };
    fs::remove_file(Record::path(directory)).map_err(|e| format!("run layer record: {e}"))?;
    sync_directory(directory)?;
    Ok(outcome)
}

fn backing_of(options: &BackendOptions, layer: &Path) -> Result<PathBuf, String> {
    let output = Command::new(&options.qemu_img)
        .args(["info", "-U", "-f", "qcow2", "--output=json"])
        .arg(layer)
        .output()
        .map_err(|e| format!("run layer info: {e}"))?;
    if !output.status.success() || output.stdout.len() as u64 > MAX_METADATA_SIZE {
        return Err(format!(
            "run layer info: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let info: Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    info.get("full-backing-filename")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| "the automatic layer has no backing file".into())
}

/// Write `layer` into its backing file. Safe to repeat after a cut-short run.
fn commit(options: &BackendOptions, layer: &Path) -> Result<(), String> {
    let output = Command::new(&options.qemu_img)
        .args(["commit", "-q", "-f", "qcow2", "-d"])
        .arg(layer)
        .output()
        .map_err(|e| format!("run layer commit: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "run layer commit: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
