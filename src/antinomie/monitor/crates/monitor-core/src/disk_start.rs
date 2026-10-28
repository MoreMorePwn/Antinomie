// SPDX-License-Identifier: GPL-3.0-only
//! The disk a boot started from, remembered so a run's earlier file bytes can
//! be read from it later.
//!
//! A VM's disk is a writable qcow2 overlay over frozen layers (checkpoints)
//! and the installed base. While a boot runs, the overlay changes, so the
//! state a run started from can be read back only from layers that were
//! already frozen at the start. At every boot start the app therefore writes
//! `disk-start.json` into the boot's folder:
//!
//! * the overlay was empty (a new or reset VM, or a restore, which always
//!   lays a new empty overlay on the checkpoint's frozen layer): the layers
//!   below it, top first, each with its size and modification time, are the
//!   starting disk ([`Start::Frozen`]);
//! * the overlay already held changes from earlier boots: the starting state
//!   is in a file the boot is about to write, so it cannot be read back
//!   ([`Start::Changed`]);
//! * the chain could not be read ([`Start::Unknown`]).
//!
//! Nothing is copied into the recording. The layers are read in place, only
//! when a file's earlier bytes are asked for, and only if every layer is
//! still the file it was at the start ([`Frozen::verify`]); a base that was
//! deleted, refreshed or rewritten, or a checkpoint that was deleted, makes
//! the earlier bytes unavailable, and the window says so.
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
};

/// The record's name in a boot's folder.
pub const FILE: &str = "disk-start.json";
/// Layers followed at most (the snapshot code allows 64).
const CHAIN_LIMIT: usize = 64;
/// Largest L1 table read to decide whether an overlay is empty.
const L1_LIMIT: u64 = 16 * 1024 * 1024;
const MAGIC: u32 = 0x5146_49fb;
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;

/// One frozen layer as it was at the start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Layer {
    pub path: PathBuf,
    pub size: u64,
    pub mtime_ns: i128,
}

impl Layer {
    fn of(path: &Path) -> Result<Self, String> {
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            size: meta.len(),
            mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
        })
    }
}

/// The layers a boot started from, top first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frozen {
    pub layers: Vec<Layer>,
}

impl Frozen {
    /// Whether every layer is still the file it was, or why not.
    pub fn verify(&self) -> Result<(), String> {
        for layer in &self.layers {
            let now = Layer::of(&layer.path).map_err(|_| {
                format!(
                    "{} is gone (a deleted base or checkpoint)",
                    layer.path.display()
                )
            })?;
            if now != *layer {
                return Err(format!(
                    "{} changed after the run started",
                    layer.path.display()
                ));
            }
        }
        Ok(())
    }

    /// The layers' paths, top first.
    pub fn paths(&self) -> Vec<PathBuf> {
        self.layers.iter().map(|layer| layer.path.clone()).collect()
    }
}

/// What is known of the disk a boot started from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Start {
    Frozen(Frozen),
    /// The VM's overlay already held changes: the starting state is not kept.
    Changed,
    Unknown(String),
}

/// How the boot came to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Via {
    /// A normal start.
    Start,
    /// A snapshot restore, which replaces the disk of a running timeline.
    Restore,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskStart {
    pub format: u32,
    pub boot_id: String,
    pub via: Via,
    pub start: Start,
}

fn be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(data[at..at + 4].try_into().unwrap_or_default())
}
fn be64(data: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(data[at..at + 8].try_into().unwrap_or_default())
}

struct Header {
    backing: Option<PathBuf>,
    l1_size: u64,
    l1_offset: u64,
}

/// The parts of a qcow2 header that name its backing file and L1 table.
fn header(path: &Path) -> Result<Header, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut head = [0u8; 48];
    file.read_exact_at(&mut head, 0)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if be32(&head, 0) != MAGIC {
        return Err(format!("{} is not a qcow2 image", path.display()));
    }
    let (offset, size) = (be64(&head, 8), u64::from(be32(&head, 16)));
    let backing = if offset == 0 {
        None
    } else {
        if size == 0 || size > 1023 {
            return Err(format!("{}: backing name out of range", path.display()));
        }
        let mut name = vec![0u8; size as usize];
        file.read_exact_at(&mut name, offset)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let name = String::from_utf8(name).map_err(|_| "backing name is not text".to_owned())?;
        let name = Path::new(&name);
        Some(if name.is_absolute() {
            name.to_path_buf()
        } else {
            path.parent().unwrap_or(Path::new(".")).join(name)
        })
    };
    Ok(Header {
        backing,
        l1_size: u64::from(be32(&head, 36)),
        l1_offset: be64(&head, 40),
    })
}

/// Whether the overlay at `path` has no allocated cluster of its own.
fn overlay_is_empty(path: &Path, head: &Header) -> Result<bool, String> {
    let bytes = head.l1_size * 8;
    if bytes > L1_LIMIT {
        return Err("qcow2 L1 table out of range".into());
    }
    let file = File::open(path).map_err(|e| e.to_string())?;
    let mut raw = vec![0u8; bytes as usize];
    file.read_exact_at(&mut raw, head.l1_offset)
        .map_err(|e| e.to_string())?;
    Ok(raw
        .as_chunks::<8>()
        .0
        .iter()
        .all(|entry| u64::from_be_bytes(*entry) & OFFSET_MASK == 0))
}

impl DiskStart {
    /// What the disk looks like just before a boot on `active` starts (the
    /// VM's writable overlay, not yet opened by QEMU).
    pub fn capture(active: &Path, boot_id: &str, via: Via) -> Self {
        let start = Self::inspect(active).unwrap_or_else(Start::Unknown);
        Self {
            format: 1,
            boot_id: boot_id.to_owned(),
            via,
            start,
        }
    }

    fn inspect(active: &Path) -> Result<Start, String> {
        let top = header(active)?;
        let Some(first) = top.backing.clone() else {
            return Err("the VM's disk has no base below it".into());
        };
        if !overlay_is_empty(active, &top)? {
            return Ok(Start::Changed);
        }
        let mut layers = Vec::new();
        let mut next = Some(first);
        while let Some(path) = next {
            if layers.len() >= CHAIN_LIMIT {
                return Err("the disk chain is too long".into());
            }
            let path =
                std::fs::canonicalize(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            next = header(&path)?.backing;
            layers.push(Layer::of(&path)?);
        }
        Ok(Start::Frozen(Frozen { layers }))
    }

    /// Save the record in the boot's folder.
    pub fn save(&self, boot_dir: &Path) -> Result<(), String> {
        crate::storage::atomic_json(&boot_dir.join(FILE), self)
    }

    /// The record in `boot_dir`, if the boot has one.
    pub fn load(boot_dir: &Path) -> Option<Self> {
        let path = boot_dir.join(FILE);
        let mut text = String::new();
        File::open(path)
            .ok()?
            .take(1 << 20)
            .read_to_string(&mut text)
            .ok()?;
        serde_json::from_str(&text)
            .ok()
            .filter(|s: &Self| s.format == 1)
    }

    /// The record of the boot `boot_id` that recorded the run segment in
    /// `directory`: `<rec>/boots/<boot_id>/`, where `<rec>` holds the run's
    /// folder (`<rec>/runs/<id>` or `<rec>/boots/<boot>/runs/<id>`). Falls
    /// back to the nearest ancestor of `directory` that holds a record.
    pub fn of_segment(directory: &Path, boot_id: &str) -> Option<Self> {
        let runs = directory.parent().filter(|runs| runs.ends_with("runs"));
        let above = runs.and_then(Path::parent);
        let root = above.and_then(|above| match above.parent() {
            Some(boots) if boots.ends_with("boots") => boots.parent(),
            _ => Some(above),
        });
        let safe = !boot_id.is_empty() && !boot_id.contains(['/', '\\']) && boot_id != "..";
        root.filter(|_| safe)
            .and_then(|root| Self::load(&root.join("boots").join(boot_id)))
            .or_else(|| Self::find(directory))
    }

    /// The record in the nearest ancestor of `directory` (within five
    /// levels) that holds one.
    pub fn find(directory: &Path) -> Option<Self> {
        directory.ancestors().take(5).find_map(Self::load)
    }
}

#[cfg(test)]
mod tests;
