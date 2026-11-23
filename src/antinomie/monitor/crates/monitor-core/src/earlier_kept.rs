// SPDX-License-Identifier: GPL-3.0-only
//! Letting a VM go before the earlier bytes of its boot are copied
//! (ANT-T0612).
//!
//! The copy of the earlier bytes ([`crate::file_before_store`]) reads the
//! sealed layer `A` of the boot's automatic layer ([`crate::snapshots`]), so
//! it had to run before `A` was merged, and the VM waited for it. The copy is
//! a scan of the boot's whole recording by Triage: about 14 minutes for a
//! 2 GiB recording, all of it with the VM held. A lane VM's `A` is the small
//! overlay a restore laid on the clean snapshot, so it is kept aside instead:
//!
//! 1. [`keep`] copies `A` into `<boot>/file-before-start/layer.qcow2` with its
//!    size and modification time, and writes `pending.json` beside it;
//! 2. the layer is merged and its record removed: the VM is free;
//! 3. [`finish`] runs the copy, which reads the kept layer in place of `A`
//!    (`disk-start.json` is read through [`substitute`]), then removes the
//!    folder.
//!
//! An `A` larger than [`KEEP_LIMIT`] (a VM whose own disk is `A`) is not
//! kept aside: its copy runs before the merge, as before. A boot whose start
//! was not frozen has no layer to keep and its copy waits all the same.
//! [`finish`] holds the folder's lock while it works, so a reader (the
//! service's Triage item) tells a copy at work ([`at_work`]) from one a
//! stopped process left, and runs that one itself.
use crate::disk_start::{DiskStart, Layer, Start};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// The folder in a boot's recording.
pub const DIR: &str = "file-before-start";
const MARKER: &str = "pending.json";
const LAYER: &str = "layer.qcow2";
const LOCK: &str = "lock";
/// The largest sealed layer kept aside.
pub const KEEP_LIMIT: u64 = 256 << 20;

/// `pending.json`: a copy that is still to be made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub format: u32,
    pub boot_id: String,
    /// `A` as `disk-start.json` names it; `None` when nothing was kept (the
    /// start was not frozen, or `A` had changed already).
    pub original: Option<PathBuf>,
    /// Host Unix ms the VM was let go.
    pub kept_ms: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn folder(boot_dir: &Path) -> PathBuf {
    boot_dir.join(DIR)
}

/// The copy still to be made for the boot in `boot_dir`, if any.
pub fn pending(boot_dir: &Path) -> Option<Pending> {
    let text = fs::read(folder(boot_dir).join(MARKER)).ok()?;
    serde_json::from_slice(&text)
        .ok()
        .filter(|pending: &Pending| pending.format == 1)
}

fn mtime_of(layer: &Layer) -> SystemTime {
    let nanos = u64::try_from(layer.mtime_ns.max(0)).unwrap_or(u64::MAX);
    UNIX_EPOCH + Duration::from_nanos(nanos)
}

/// Keep `sealed` (the boot's `A`) aside so the copy can run after the merge.
/// `Err` says why it cannot: the copy then runs before the merge.
pub(crate) fn keep(boot_dir: &Path, boot_id: &str, sealed: &Path) -> Result<(), String> {
    let start = DiskStart::load_as_saved(boot_dir).map(|start| start.start);
    let original = match start {
        Some(Start::Frozen(frozen)) => {
            let top = frozen
                .layers
                .first()
                .ok_or("the starting disk has no layer")?;
            let sealed = fs::canonicalize(sealed).map_err(|e| format!("the sealed layer: {e}"))?;
            if top.path != sealed {
                return Err("the starting disk is not the sealed layer".into());
            }
            if frozen.verify().is_err() {
                // The copy could not read it anyway: nothing to keep.
                None
            } else if top.size > KEEP_LIMIT {
                return Err(format!(
                    "the sealed layer is {} MiB, over {} MiB",
                    top.size >> 20,
                    KEEP_LIMIT >> 20
                ));
            } else {
                copy_layer(boot_dir, top)?;
                Some(top.path.clone())
            }
        }
        _ => None,
    };
    let dir = folder(boot_dir);
    crate::storage::private_dir(&dir).map_err(|e| e.to_string())?;
    crate::storage::atomic_json(
        &dir.join(MARKER),
        &Pending {
            format: 1,
            boot_id: boot_id.to_owned(),
            original,
            kept_ms: now_ms(),
        },
    )
}

/// `A` into the folder, with its size and modification time, so the
/// starting disk's own check ([`crate::disk_start::Frozen::verify`]) holds.
fn copy_layer(boot_dir: &Path, layer: &Layer) -> Result<(), String> {
    let dir = folder(boot_dir);
    crate::storage::private_dir(&dir).map_err(|e| e.to_string())?;
    let target = dir.join(LAYER);
    let temp = dir.join(format!(".{LAYER}.tmp"));
    let copied = (|| {
        fs::copy(&layer.path, &temp).map_err(|e| format!("keeping the sealed layer: {e}"))?;
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        file.set_modified(mtime_of(layer))
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temp, &target).map_err(|e| e.to_string())?;
        let kept = Layer::of(&target)?;
        if kept.size != layer.size || kept.mtime_ns != layer.mtime_ns {
            return Err("the kept layer does not match the sealed layer".to_owned());
        }
        Ok(())
    })();
    if copied.is_err() {
        let _ = fs::remove_file(&temp);
        let _ = fs::remove_file(&target);
    }
    copied
}

/// `start` as the boot in `boot_dir` reads it while its copy is pending:
/// the kept layer in place of `A`.
pub(crate) fn substitute(boot_dir: &Path, start: &mut DiskStart) {
    let Some(Pending {
        original: Some(original),
        ..
    }) = pending(boot_dir)
    else {
        return;
    };
    let Start::Frozen(frozen) = &mut start.start else {
        return;
    };
    if let Some(top) = frozen.layers.first_mut()
        && top.path == original
    {
        top.path = folder(boot_dir).join(LAYER);
    }
}

fn open_lock(boot_dir: &Path) -> Option<fs::File> {
    fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(folder(boot_dir).join(LOCK))
        .ok()
}

/// Whether a copy of the boot in `boot_dir` is at work in some process.
pub fn at_work(boot_dir: &Path) -> bool {
    let Ok(file) = fs::File::open(folder(boot_dir).join(LOCK)) else {
        return false;
    };
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockShared) {
        Ok(()) => {
            crate::data_owner::unlock(&file);
            false
        }
        Err(rustix::io::Errno::WOULDBLOCK) => true,
        Err(_) => false,
    }
}

/// What [`finish`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finished {
    /// No copy was pending.
    Nothing,
    /// The copy was made (or failed, and the boot's recording says why).
    Copied,
    /// Another process or thread is making it.
    Busy,
}

/// Make the pending copy of the boot in `boot_dir`, then drop the kept
/// layer. A copy that fails says so in the boot's recording, like one made
/// before the merge.
pub fn finish(boot_dir: &Path) -> Finished {
    let Some(pending) = pending(boot_dir) else {
        return Finished::Nothing;
    };
    let Some(file) = open_lock(boot_dir) else {
        return Finished::Busy;
    };
    if rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err() {
        return Finished::Busy;
    }
    let _held = crate::data_owner::HeldFlock::new(file);
    // Read again under the lock: a finish that just ended removed it.
    if self::pending(boot_dir).is_none() {
        return Finished::Nothing;
    }
    if let Err(why) = crate::file_before_store::copy_boot(boot_dir, &pending.boot_id) {
        crate::file_before_store::note_not_copied(boot_dir, &pending.boot_id, &why);
    }
    let dir = folder(boot_dir);
    // The marker first: a kept layer without it is only a stray file.
    let _ = fs::remove_file(dir.join(MARKER));
    let _ = fs::remove_file(dir.join(LAYER));
    let _ = fs::remove_file(dir.join(LOCK));
    let _ = fs::remove_dir(&dir);
    Finished::Copied
}

/// Boots whose copy runs on a thread of this process.
static COPYING: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

/// Make the copy on a thread of its own ([`finish`]).
pub(crate) fn spawn_finish(boot_dir: PathBuf) {
    if let Ok(mut copying) = COPYING.lock()
        && !copying.insert(boot_dir.clone())
    {
        return;
    }
    std::thread::spawn(move || {
        finish(&boot_dir);
        if let Ok(mut copying) = COPYING.lock() {
            copying.remove(&boot_dir);
        }
    });
}

/// Whether a copy runs on a thread of this process.
pub(crate) fn copying() -> bool {
    COPYING.lock().is_ok_and(|copying| !copying.is_empty())
}

#[cfg(test)]
mod tests;
