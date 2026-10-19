// SPDX-License-Identifier: MIT
//! Saved disk dumps: a standalone sparse `root.ext4` in
//! `<recording dir>/disks/<id>/` and the `dump.json` sidecar that names it.
//!
//! `dump.json` is written last, after the image is complete and renamed from
//! its `.part` name, so a folder without it is a leftover of a cancelled or
//! crashed job and never listed ([`sweep_partial`] removes it). Imported raw
//! images stay where they are; their folder holds only the sidecar and
//! whatever is extracted from them.
use super::{
    DISKS_DIR, DiskSourceKind, DiskSourceRecord, EXTRACTED_DIR, Ext4State, IMAGE_FILE,
    SCRATCH_PREFIX, SUPERBLOCK_OFFSET, read_state, unix_ms,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

/// The sidecar of a dump folder.
pub const SUMMARY_FILE: &str = "dump.json";
/// Name of an image while it is being written.
pub const PART_FILE: &str = "root.ext4.part";
/// Largest `dump.json` read.
const SUMMARY_LIMIT: u64 = 1024 * 1024;
/// Read size of the hashing pass.
const HASH_CHUNK: usize = 1024 * 1024;

/// Which kind of image a folder holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskImageFormat {
    /// A raw ext4 filesystem image (the VM's whole disk).
    #[default]
    RawExt4,
    /// A format a later version wrote; this one cannot open it.
    #[serde(other)]
    Unsupported,
}

/// One saved disk dump (sidecar `dump.json`), the analogue of `MemoryDump`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DiskDump {
    pub id: String,
    pub vm_id: String,
    pub vm_name: String,
    pub imported: bool,
    /// The image: its name in the dump folder, or (imported) its path.
    pub file: PathBuf,
    pub format: DiskImageFormat,
    pub fs_state: Ext4State,
    pub started_ms: u64,
    /// `None` for a record that was never completed.
    pub finished_ms: Option<u64>,
    /// The disk's virtual size: the image's length.
    pub logical_size: u64,
    /// What the sparse image occupies (`st_blocks * 512`).
    pub allocated_size: Option<u64>,
    /// SHA-256 of the full logical content, as `sha256sum root.ext4` gives.
    pub sha256: Option<String>,
    pub source: DiskSourceRecord,
    /// The guest system the VM ran, as the bundle names it.
    pub system: String,
    pub error: Option<String>,
    /// The dump folder (not saved).
    #[serde(skip)]
    pub dir: PathBuf,
}

impl DiskDump {
    /// The image on disk. A dump's own file is a plain name in its folder;
    /// anything else in the sidecar is reduced to its last component.
    pub fn path(&self) -> PathBuf {
        if self.imported {
            self.file.clone()
        } else {
            let name = self.file.file_name().unwrap_or(IMAGE_FILE.as_ref());
            self.dir.join(name)
        }
    }

    pub fn complete(&self) -> bool {
        self.finished_ms.is_some() && self.error.is_none()
    }

    /// The image is gone (an imported file that moved).
    pub fn missing(&self) -> bool {
        self.complete() && !self.path().is_file()
    }

    /// The image can be opened by this version.
    pub fn browsable(&self) -> bool {
        self.complete() && self.format == DiskImageFormat::RawExt4 && !self.missing()
    }

    /// Where files extracted from this dump go: inside its own folder.
    pub fn extract_dir(&self) -> PathBuf {
        self.dir.join(EXTRACTED_DIR)
    }

    pub fn save(&self) -> Result<(), String> {
        crate::storage::atomic_json(&self.dir.join(SUMMARY_FILE), self)?;
        File::open(&self.dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("{}: {error}", self.dir.display()))
    }
}

/// Every dump in these recording directories, newest first.
pub fn list(recording_dirs: &[PathBuf]) -> Vec<DiskDump> {
    let mut dumps: Vec<DiskDump> = recording_dirs
        .iter()
        .flat_map(|root| {
            fs::read_dir(root.join(DISKS_DIR))
                .into_iter()
                .flatten()
                .flatten()
        })
        .filter_map(|entry| {
            let dir = entry.path();
            let name = entry.file_name();
            let name = name.to_str()?;
            if name.starts_with('.') || name == EXTRACTED_DIR || !entry.file_type().ok()?.is_dir() {
                return None;
            }
            let file = File::open(dir.join(SUMMARY_FILE)).ok()?;
            let mut text = Vec::new();
            file.take(SUMMARY_LIMIT + 1).read_to_end(&mut text).ok()?;
            if text.len() as u64 > SUMMARY_LIMIT {
                return None;
            }
            let mut dump: DiskDump = serde_json::from_slice(&text).ok()?;
            dump.dir = dir;
            Some(dump)
        })
        .collect();
    dumps.sort_by(|a, b| b.started_ms.cmp(&a.started_ms).then(b.id.cmp(&a.id)));
    dumps.dedup_by(|a, b| a.dir == b.dir);
    dumps
}

/// Delete a dump's folder with its extractions. An imported file is left
/// alone. Guarded: the folder must be a direct child of a `disks/` folder
/// that holds a `dump.json`. The sidecar goes first, so a deletion cut short
/// never leaves a listed dump with a missing image.
pub fn delete(dump: &DiskDump) -> Result<(), String> {
    remove_dump_dir(&dump.dir)
}

pub(crate) fn remove_dump_dir(dir: &Path) -> Result<(), String> {
    let named = dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| !name.starts_with('.') && name != EXTRACTED_DIR);
    let in_disks = dir
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == DISKS_DIR);
    let metadata =
        fs::symlink_metadata(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    if !named
        || !in_disks
        || !metadata.is_dir()
        || !fs::symlink_metadata(dir.join(SUMMARY_FILE)).is_ok_and(|summary| summary.is_file())
    {
        return Err("not a disk dump folder".into());
    }
    fs::remove_file(dir.join(SUMMARY_FILE))
        .map_err(|error| format!("{}: {error}", dir.join(SUMMARY_FILE).display()))?;
    fs::remove_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))
}

/// Remove what a cancelled or crashed dump left: folders of `disks_dir`
/// without a `dump.json` that hold nothing but a (partial) image, and
/// `.part` files inside finished dumps. Scratch folders (views) and the
/// extraction folder are not touched. Returns how many folders were removed.
pub fn sweep_partial(disks_dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(disks_dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(SCRATCH_PREFIX)
            || name.starts_with('.')
            || name == EXTRACTED_DIR
            || !entry.file_type().is_ok_and(|kind| kind.is_dir())
        {
            continue;
        }
        if path.join(SUMMARY_FILE).is_file() {
            let _ = fs::remove_file(path.join(PART_FILE));
            continue;
        }
        // Only what a dump job writes; anything else is somebody's folder.
        let ours = fs::read_dir(&path).is_ok_and(|mut files| {
            files.all(|file| {
                file.is_ok_and(|file| {
                    file.file_name() == PART_FILE || file.file_name() == IMAGE_FILE
                })
            })
        });
        if ours && fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// SHA-256 of a file's full logical content, in 1 MiB reads. Holes read as
/// zeros, so this is what `sha256sum` prints. `progress(done, total)` is
/// called between reads; the pass stops with "cancelled" when `cancel` is set.
pub fn sha256_file(
    path: &Path,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let total = file.metadata().map_err(|error| error.to_string())?.len();
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_CHUNK];
    let mut done = 0u64;
    progress(0, total);
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        done += count as u64;
        progress(done, total);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// The most of an image's superblock the import checks read.
const IMPORT_MIN_SIZE: u64 = SUPERBLOCK_OFFSET + 1024;
/// `EXT4_FEATURE_INCOMPAT_64BIT`: the block count has a high half.
const INCOMPAT_64BIT: u32 = 0x80;

/// Check that `image` is a raw ext2/3/4 image that is not cut short: the
/// superblock magic, a sane block size, and a file at least as long as the
/// filesystem it describes. Returns its state and length. qcow2 and
/// partitioned disks are named as such.
pub fn validate_raw_ext4(image: &Path) -> Result<(Ext4State, u64), String> {
    let mut file = File::open(image).map_err(|error| format!("{}: {error}", image.display()))?;
    let length = file.metadata().map_err(|error| error.to_string())?.len();
    let mut head = [0u8; 512];
    let count = file.read(&mut head).map_err(|error| error.to_string())?;
    if head[..count].starts_with(b"QFI\xfb") {
        return Err(
            "this is a qcow2 image; importing qcow2 is not available yet, only raw ext4 images"
                .into(),
        );
    }
    if length < IMPORT_MIN_SIZE {
        return Err("the file is too small to hold an ext4 filesystem".into());
    }
    let state = read_state(image).map_err(|error| {
        if count == 512 && head[510] == 0x55 && head[511] == 0xAA {
            "this looks like a partitioned disk; only a raw ext4 image of one filesystem can be imported"
                .to_string()
        } else {
            error
        }
    })?;
    let mut superblock = [0u8; 1024];
    file.seek(SeekFrom::Start(SUPERBLOCK_OFFSET))
        .and_then(|_| file.read_exact(&mut superblock))
        .map_err(|error| error.to_string())?;
    let word = |offset: usize| {
        u32::from_le_bytes([
            superblock[offset],
            superblock[offset + 1],
            superblock[offset + 2],
            superblock[offset + 3],
        ])
    };
    let log_block_size = word(0x18);
    if log_block_size > 6 {
        return Err("the filesystem declares an invalid block size".into());
    }
    let mut blocks = u64::from(word(0x04));
    if word(0x60) & INCOMPAT_64BIT != 0 {
        blocks |= u64::from(word(0x150)) << 32;
    }
    if blocks == 0 {
        return Err("the filesystem declares no blocks".into());
    }
    let needed = blocks.saturating_mul(1024u64 << log_block_size);
    if length < needed {
        return Err(format!(
            "the image is cut short: the filesystem needs {needed} bytes and the file has {length}"
        ));
    }
    Ok((state, length))
}

/// Import a raw ext4 image made elsewhere. The file stays where it is; the
/// recording directory gets a folder with the sidecar. The image is read only
/// for its superblock here; its content is parsed in the sandboxed reader.
pub fn import(
    recording_dir: &Path,
    vm_id: &str,
    vm_name: &str,
    path: &Path,
) -> Result<DiskDump, String> {
    let path = fs::canonicalize(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = fs::metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let (fs_state, length) = validate_raw_ext4(&path)?;
    let now = unix_ms();
    let id = crate::storage::unique_id();
    let disks = recording_dir.join(DISKS_DIR);
    let dir = disks.join(&id);
    crate::storage::private_dir(&disks)
        .and_then(|()| crate::storage::private_dir(&dir))
        .map_err(|error| format!("{}: {error}", dir.display()))?;
    let dump = DiskDump {
        id,
        vm_id: vm_id.into(),
        vm_name: vm_name.into(),
        imported: true,
        file: path,
        format: DiskImageFormat::RawExt4,
        fs_state,
        started_ms: now,
        finished_ms: Some(now),
        logical_size: length,
        allocated_size: Some(metadata.blocks().saturating_mul(512)),
        source: DiskSourceRecord {
            kind: DiskSourceKind::Imported,
            ..DiskSourceRecord::default()
        },
        system: "Imported raw ext4 image".into(),
        dir,
        ..DiskDump::default()
    };
    if let Err(error) = dump.save() {
        let _ = fs::remove_dir_all(&dump.dir);
        return Err(error);
    }
    Ok(dump)
}

#[cfg(test)]
mod tests;
