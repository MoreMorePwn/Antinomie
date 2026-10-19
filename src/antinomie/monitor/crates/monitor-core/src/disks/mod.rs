// SPDX-License-Identifier: MIT
//! The Disks tab's backend: a read-only view of a VM's current disk while the
//! VM is off, and the sandboxed reader that browses it.
//!
//! The VM's qcow2 chain is flattened by `qemu-img convert` into a sparse raw
//! ext4 image under `<recording dir>/disks/.scratch-<id>/root.ext4` (a
//! *scratch* image: temporary, never listed, swept at start). The reader
//! ([`reader`]) only ever opens that plain file, inside a bubblewrap sandbox.
//! A disk job ([`job`]) holds a lease on the VM's image while `qemu-img` reads
//! the chain; the backend refuses every command that would change the chain
//! meanwhile, and closes the view when the chain changes or the VM starts.
//!
//! Phase 1 builds the view. Dumps (`disks/<id>/dump.json`), checkpoint sources,
//! imports and partition carving are later phases: [`DiskJobPurpose`] and
//! [`DiskSourceKind`] are the seams they extend.
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub mod extract;
pub mod job;
pub mod measure;
pub mod reader;

/// Folder of a recording directory that holds disk views and (later) dumps.
pub const DISKS_DIR: &str = "disks";
/// File name of a flattened raw ext4 image.
pub const IMAGE_FILE: &str = "root.ext4";
/// Name prefix of the temporary folder of one view.
pub const SCRATCH_PREFIX: &str = ".scratch-";
/// Folder of `disks/` that keeps files extracted from a view.
pub const EXTRACTED_DIR: &str = "extracted";

/// Offset of the ext4 superblock in the image.
const SUPERBLOCK_OFFSET: u64 = 1024;
/// `s_magic` and `s_state` inside the superblock.
const MAGIC_OFFSET: u64 = SUPERBLOCK_OFFSET + 0x38;
const STATE_OFFSET: u64 = SUPERBLOCK_OFFSET + 0x3A;
const EXT4_MAGIC: u16 = 0xEF53;
/// `EXT4_VALID_FS`: the filesystem was unmounted cleanly.
const EXT4_VALID_FS: u16 = 1;

/// A size in 1024-based units: `1.9 GiB`, `812 MiB`, `640 B`.
pub fn format_size(size: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if size < 1024 {
        return format!("{size} B");
    }
    let mut value = size as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub(crate) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// ext4 superblock state of an image (`s_state & EXT4_VALID_FS`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ext4State {
    #[default]
    Unknown,
    /// The guest shut down cleanly: the image is its exact final state.
    Clean,
    /// The guest was forced off: committed journal transactions are applied
    /// while reading, writes still in the guest's memory are not on disk.
    NotClean,
}

impl Ext4State {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "state unknown",
            Self::Clean => "clean",
            Self::NotClean => "not cleanly unmounted",
        }
    }

    /// What the state means for what the tree shows.
    pub fn explanation(self) -> &'static str {
        match self {
            Self::Unknown => "The filesystem state could not be read.",
            Self::Clean => "The guest shut down cleanly; this is the exact final filesystem state.",
            Self::NotClean => {
                "Not cleanly unmounted: the guest was forced off. Committed journal \
                 transactions are applied while reading; writes still in the guest's \
                 memory at power-off are not on disk."
            }
        }
    }
}

/// Read the superblock state of a raw image; an error when it is not ext2/3/4.
pub fn read_state(image: &Path) -> Result<Ext4State, String> {
    let mut file = File::open(image).map_err(|error| format!("{}: {error}", image.display()))?;
    let mut word = [0u8; 2];
    file.seek(SeekFrom::Start(MAGIC_OFFSET))
        .and_then(|_| file.read_exact(&mut word))
        .map_err(|_| "the image is too small to hold an ext4 filesystem".to_string())?;
    if u16::from_le_bytes(word) != EXT4_MAGIC {
        return Err(
            "the disk does not hold an ext2/3/4 filesystem at its start (unsupported filesystem or \
             partitioned disk)"
                .into(),
        );
    }
    file.seek(SeekFrom::Start(STATE_OFFSET))
        .and_then(|_| file.read_exact(&mut word))
        .map_err(|error| error.to_string())?;
    Ok(if u16::from_le_bytes(word) & EXT4_VALID_FS != 0 {
        Ext4State::Clean
    } else {
        Ext4State::NotClean
    })
}

/// Which disk state a view or (later) a dump was read from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DiskSourceKind {
    /// The VM's current disk, VM off.
    #[default]
    Current,
    // Phase 3: Checkpoint { id, name } (a saved snapshot's frozen layer).
}

/// One layer of the chain an image was read from (top first, base last).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DiskLayerRef {
    pub filename: String,
    pub size: u64,
    pub modified_ms: u64,
}

/// Where an image came from: identity only, never a path the UI opens.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DiskSourceRecord {
    pub kind: DiskSourceKind,
    /// Manifest-relative: `disk.qcow2` or `snapshots/<id>.qcow2`.
    pub active_layer: String,
    pub active_parent_id: Option<String>,
    pub layers: Vec<DiskLayerRef>,
}

/// The open "Current disk (VM off)" view, published in the snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CurrentDiskView {
    pub vm_id: String,
    /// Names the view: its scratch folder and its extraction folder.
    pub view_id: String,
    /// `<recording dir>/disks/.scratch-<view_id>/root.ext4`.
    pub image: PathBuf,
    /// `<recording dir>/disks/extracted/<view_id>`: kept when the view closes.
    pub extract_dir: PathBuf,
    pub taken_ms: u64,
    pub source: DiskSourceRecord,
    pub fs_state: Ext4State,
    pub logical_size: u64,
    pub allocated_size: u64,
}

/// What measuring found; shown before Open.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiskMeasure {
    pub vm_id: String,
    pub source: DiskSourceRecord,
    pub logical_size: u64,
    /// `qemu-img map` data sum: an upper bound of the image's allocation.
    pub allocated_estimate: u64,
    /// Space available under `<recording dir>/disks`.
    pub free_space: u64,
    pub sparse_supported: bool,
    pub measured_ms: u64,
    /// The directory the view is written to.
    pub directory: PathBuf,
    pub error: Option<String>,
}

impl DiskMeasure {
    /// Free space the image needs: the estimate, or the full logical size on
    /// a filesystem that cannot hold holes, plus a margin.
    pub fn needed_space(&self) -> u64 {
        let need = if self.sparse_supported {
            self.allocated_estimate
        } else {
            self.logical_size
        };
        need.saturating_add(SPACE_MARGIN)
    }

    /// The reason Open must be refused for lack of space.
    pub fn space_error(&self) -> Option<String> {
        (self.free_space < self.needed_space()).then(|| {
            format!(
                "the current disk needs about {} of free space under {}; {} is available{}",
                format_size(self.needed_space()),
                self.directory.display(),
                format_size(self.free_space),
                if self.sparse_supported {
                    ""
                } else {
                    " (that folder's filesystem cannot hold sparse files, so the image takes its full size)"
                },
            )
        })
    }
}

/// Free space left over after an image (the memory dump preflight's margin).
pub(crate) const SPACE_MARGIN: u64 = 64 * 1024 * 1024;

/// What a disk job does. Dumps and "keep as dump" are Phase 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskJobPurpose {
    /// `qemu-img map`: the allocation estimate.
    Measure,
    /// Flatten the chain into a scratch image and open it.
    View,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DiskJobStage {
    Measuring,
    Converting { percent: f32 },
    Finalizing,
}

/// The single active disk job (the analogue of `memory::DumpProgress`).
#[derive(Clone, Debug, PartialEq)]
pub struct DiskJobProgress {
    pub vm_id: String,
    pub purpose: DiskJobPurpose,
    pub stage: DiskJobStage,
    /// Estimated allocated size of the image being written.
    pub estimate: u64,
    pub started_ms: u64,
}

/// `<recording dir>/disks`.
pub fn disks_dir(recording_dir: &Path) -> PathBuf {
    recording_dir.join(DISKS_DIR)
}

/// The folder of one view's scratch image.
pub fn scratch_dir(disks_dir: &Path, view_id: &str) -> PathBuf {
    disks_dir.join(format!("{SCRATCH_PREFIX}{view_id}"))
}

/// Remove every scratch folder of `disks_dir` (leftovers of a crash or of a
/// view whose app exited), except `keep`. Returns how many were removed.
pub fn sweep_scratch(disks_dir: &Path, keep: Option<&Path>) -> usize {
    let Ok(entries) = fs::read_dir(disks_dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let scratch = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(SCRATCH_PREFIX));
        let directory = entry.file_type().is_ok_and(|kind| kind.is_dir());
        if scratch && directory && keep != Some(path.as_path()) && fs::remove_dir_all(&path).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// Delete one view's scratch image, never anything outside a scratch folder.
/// Its extraction folder is removed too when nothing was extracted into it;
/// extracted files are host evidence and stay.
pub fn remove_scratch(view: &CurrentDiskView) {
    let folder = view.image.parent();
    if let Some(folder) = folder
        && folder
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(SCRATCH_PREFIX))
    {
        let _ = fs::remove_dir_all(folder);
        // `remove_dir` only removes an empty folder.
        if view.extract_dir.file_name().is_some() {
            let _ = fs::remove_dir(&view.extract_dir);
            if let Some(parent) = view.extract_dir.parent() {
                let _ = fs::remove_dir(parent);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod fixture;
#[cfg(test)]
mod tests;
