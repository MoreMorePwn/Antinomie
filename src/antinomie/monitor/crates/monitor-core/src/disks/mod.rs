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
//! A view can be kept: **Dump disk** flattens the chain straight into
//! `disks/<id>/root.ext4`, and **Keep as dump** promotes an open view's scratch
//! folder by rename. A dump is a standalone image with a `dump.json` sidecar
//! ([`dump`]), listed newest first and browsable while the VM runs; raw ext4
//! images made elsewhere can be imported, and a dump exported as a sparse raw
//! or qcow2 file ([`export`]). Checkpoint sources, partition carving and
//! qcow2 import are a later phase: [`DiskSourceKind`] is the seam.
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub mod dump;
pub mod export;
pub mod extract;
pub mod job;
pub mod measure;
pub mod partition;
pub mod reader;
pub(crate) mod sandbox;

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

/// Which disk state a view or a dump was read from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DiskSourceKind {
    /// The VM's current disk, VM off.
    #[default]
    Current,
    /// A raw ext4 image made elsewhere (or a qcow2 converted in the sandbox).
    Imported,
    /// A saved checkpoint's frozen layer.
    Checkpoint { id: String, name: String },
    /// The installed base image the VM's disk was created from.
    Base,
}

impl DiskSourceKind {
    /// "Current disk", "Disk at before-run", "Base image", "Imported image".
    pub fn label(&self) -> String {
        match self {
            Self::Current => "Current disk".into(),
            Self::Imported => "Imported image".into(),
            Self::Checkpoint { name, .. } => format!("Disk at {name}"),
            Self::Base => "Base image".into(),
        }
    }

    /// The request that reads this source again, when it is one.
    pub fn spec(&self) -> Option<DiskSourceSpec> {
        match self {
            Self::Current => Some(DiskSourceSpec::Current),
            Self::Checkpoint { id, .. } => Some(DiskSourceSpec::Checkpoint(id.clone())),
            Self::Base => Some(DiskSourceSpec::Base),
            Self::Imported => None,
        }
    }
}

/// What to read: the VM's current disk, the installed base it was created
/// from, or the frozen layer of a saved (not deleted) checkpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum DiskSourceSpec {
    #[default]
    Current,
    Base,
    Checkpoint(String),
}

/// One layer of the chain an image was read from (top first, base last).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DiskLayerRef {
    pub filename: String,
    pub size: u64,
    pub modified_ms: u64,
    /// SHA-256 of the layer file, when the per-layer digest setting was on.
    pub sha256: Option<String>,
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
    /// The partition of the disk the image was carved from; `None` for a
    /// whole-disk filesystem.
    pub partition: Option<partition::Partition>,
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
    /// The dump this view was kept as; the view then reads the dump's image.
    pub kept_as: Option<String>,
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
    /// The recording quota figure: the most a single dump may allocate. A
    /// view is not bounded by it.
    pub quota: u64,
    pub error: Option<String>,
    /// The disk's partition table; `None` for a whole-disk filesystem.
    pub partitions: Option<partition::PartitionTable>,
    /// Why the table could not be read (the disk is then treated as one
    /// filesystem and fails to open if it is not).
    pub partition_error: Option<String>,
    /// The partition the estimate and the image are for.
    pub partition: Option<u32>,
}

impl DiskMeasure {
    /// The chosen partition, if the disk has a table.
    pub fn selected(&self) -> Option<&partition::Partition> {
        self.partitions
            .as_ref()
            .zip(self.partition)
            .and_then(|(table, index)| table.get(index))
    }

    /// The size of the image that will be written: the partition, or the disk.
    pub fn image_size(&self) -> u64 {
        self.selected()
            .map_or(self.logical_size, |partition| partition.length)
    }

    /// Why this measurement cannot be opened or dumped as a filesystem: the
    /// disk has a partition table and the chosen partition (or the lack of
    /// one) is not an ext2/3/4 filesystem.
    pub fn unsupported(&self) -> Option<String> {
        let table = self.partitions.as_ref()?;
        match self.selected() {
            None if table.partitions.is_empty() => {
                Some("the partition table lists no partitions".into())
            }
            None => Some(
                "unsupported filesystem: no ext2/3/4 partition on this disk; pick a partition \
                 to save it to the host"
                    .into(),
            ),
            Some(partition) if partition.fs != partition::PartitionFs::Ext4 => Some(format!(
                "unsupported filesystem: partition {} ({}) does not hold ext2/3/4",
                partition.index, partition.kind
            )),
            Some(_) => None,
        }
    }

    /// Free space the image needs: the estimate, or the full logical size on
    /// a filesystem that cannot hold holes, plus a margin.
    pub fn needed_space(&self) -> u64 {
        let need = if self.sparse_supported {
            self.allocated_estimate
        } else {
            self.image_size()
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

impl DiskMeasure {
    /// The reason a dump is refused: its estimated allocation is over the
    /// recording quota (a per-dump ceiling). Views are not bounded by it.
    pub fn quota_error(&self) -> Option<String> {
        quota_error(self.allocated_estimate, self.quota)
    }
}

/// The refusal of a dump of about `size` bytes under the quota `ceiling`.
pub fn quota_error(size: u64, ceiling: u64) -> Option<String> {
    (ceiling > 0 && size > ceiling).then(|| {
        format!(
            "a disk dump of about {} exceeds the recording quota of {}; raise the quota in \
             Settings to dump this disk",
            format_size(size),
            format_size(ceiling)
        )
    })
}

/// Free space left over after an image (the memory dump preflight's margin).
pub(crate) const SPACE_MARGIN: u64 = 64 * 1024 * 1024;

/// What a disk job does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskJobPurpose {
    /// `qemu-img map`: the allocation estimate and the partition table.
    Measure,
    /// Flatten the chain into a scratch image and open it.
    View,
    /// Flatten the chain into a new dump.
    Dump,
    /// Promote the open view's scratch image to a dump.
    Keep,
    /// Flatten a source into a second scratch image to compare the open
    /// entry against.
    Reference,
    /// Save one partition of a disk to a file chosen on the host.
    Carve,
    /// Convert an imported qcow2 inside the sandbox into a dump.
    Import,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DiskJobStage {
    Measuring,
    Converting {
        percent: f32,
    },
    /// SHA-256 of the image (and, if asked, of the chain's layers).
    Hashing {
        done: u64,
        total: u64,
    },
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
