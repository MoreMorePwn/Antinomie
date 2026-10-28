// SPDX-License-Identifier: GPL-3.0-only
//! The earlier bytes of the files a boot changed, kept in the boot's
//! recording.
//!
//! File activity 2 reads a file's earlier bytes from the disk the boot started
//! from. That disk can change or go away (a refreshed base, a deleted
//! checkpoint) and a plain restart of a used VM never had a readable one. So
//! when the boot is over the app copies, from the sealed layer
//! ([`crate::snapshots`]' automatic layer), only the files the trace says the
//! boot changed into `<boot>/file-before/`, within caps, before the sealed layer
//! is merged. The recording then reads on its own.
//!
//! Layout: `index.json` ([`Index`]) and one blob per copied file. Every file
//! asked about gets an entry, so the window can say what became of it:
//!
//! | [`Status`] | Meaning |
//! | --- | --- |
//! | `Created` | The run created the file: it started empty. |
//! | `Copied` | The whole earlier content is in a blob (SHA-256 kept). |
//! | `NotCopied` | Over the per-file or per-run cap, or over the 1 GiB limit: size, and SHA-256 where it was taken, only. Not captured. |
//! | `Elsewhere` | Not on the disk (tmpfs, another mount, another file under that name). |
//! | `Unavailable` | The disk could not be read; says why. |
//!
//! The caps default to those of File activity 1 and are set in Settings ›
//! Advanced ([`set_limits`]). The copy is not counted against the capture
//! quota; the per-run cap bounds it.
use crate::{
    file_before::{Before, DiskFile, StartDisk},
    file_writes::Limits,
    kernel_notes::FileKey,
    storage::atomic_json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// The folder in a boot's recording.
pub const DIR: &str = "file-before";
const INDEX: &str = "index.json";
/// Read from the disk in pieces of this size.
const CHUNK: u64 = 4 << 20;

static PER_FILE: AtomicU64 = AtomicU64::new(crate::file_writes::DEFAULT_PER_FILE);
static PER_RUN: AtomicU64 = AtomicU64::new(crate::file_writes::DEFAULT_PER_RUN);

/// The caps the next copy follows (Settings).
pub fn set_limits(limits: Limits) {
    PER_FILE.store(limits.per_file, Ordering::Relaxed);
    PER_RUN.store(limits.per_run, Ordering::Relaxed);
}

/// The caps in force now.
pub fn limits() -> Limits {
    Limits {
        per_file: PER_FILE.load(Ordering::Relaxed),
        per_run: PER_RUN.load(Ordering::Relaxed),
    }
}

/// A file's identity, as the guest recorded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    pub dev: u64,
    pub ino: u64,
    pub generation: u32,
}

impl From<FileKey> for Key {
    fn from(key: FileKey) -> Self {
        Self {
            dev: key.dev,
            ino: key.ino,
            generation: key.generation,
        }
    }
}

/// What became of one file's earlier bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    /// The run created the file: it started empty.
    Created,
    Copied,
    NotCopied(String),
    Elsewhere(String),
    Unavailable(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    pub names: Vec<String>,
    pub key: Option<Key>,
    /// The inode was checked against the disk.
    pub exact: bool,
    pub size: u64,
    pub sha256: Option<String>,
    pub status: Status,
    /// The blob's file name in the folder.
    pub blob: Option<String>,
}

impl Entry {
    fn has_name(&self, path: &str) -> bool {
        self.path == path || self.names.iter().any(|name| name == path)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    pub format: u32,
    pub boot_id: String,
    /// Every changed file the boot's runs touched was asked about.
    pub complete: bool,
    /// Why the copy is incomplete, or a remark.
    pub note: Option<String>,
    pub per_file: u64,
    pub per_run: u64,
    pub copied_bytes: u64,
    pub files: Vec<Entry>,
}

impl Index {
    fn new(boot_id: &str, limits: Limits) -> Self {
        Self {
            format: 1,
            boot_id: boot_id.to_owned(),
            complete: false,
            note: None,
            per_file: limits.per_file,
            per_run: limits.per_run,
            copied_bytes: 0,
            files: Vec::new(),
        }
    }

    pub fn load(boot_dir: &Path) -> Option<Self> {
        let mut text = String::new();
        File::open(boot_dir.join(DIR).join(INDEX))
            .ok()?
            .take(64 << 20)
            .read_to_string(&mut text)
            .ok()?;
        serde_json::from_str(&text)
            .ok()
            .filter(|index: &Self| index.format == 1)
    }

    fn save(&self, boot_dir: &Path) -> Result<(), String> {
        let dir = boot_dir.join(DIR);
        crate::storage::private_dir(&dir).map_err(|e| e.to_string())?;
        atomic_json(&dir.join(INDEX), self)
    }

    /// The entry for a file reached by `path`, unless the guest identity
    /// says the entry is another file.
    pub fn entry(&self, path: &str, key: Option<FileKey>) -> Option<&Entry> {
        let key = key.map(Key::from);
        self.files.iter().find(|entry| {
            entry.has_name(path)
                && match (entry.key, key) {
                    (Some(a), Some(b)) => a == b,
                    _ => true,
                }
        })
    }
}

/// A finished boot whose earlier bytes are to be copied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub vm_id: String,
    pub boot_id: String,
    /// The boot's folder in the recording.
    pub boot_dir: PathBuf,
}

/// The flag that makes the app run the copy for one boot and exit, like the
/// other worker programs (`--disk-reader`): the trace is read by the UI
/// crate's file index, so the copy is its work, in a process of its own.
pub const COPY_FLAG: &str = "--copy-earlier-bytes";
/// Longest the copy of one boot may take.
const COPY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// The program serving [`COPY_FLAG`]: `ANTINOMIE_COPIER` (test harnesses), or
/// this program when it is the app.
fn copier_executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("ANTINOMIE_COPIER") {
        return Some(path.into());
    }
    let exe = std::env::current_exe().ok()?;
    (exe.file_name()? == "antinomie-monitor").then_some(exe)
}

/// Serve [`COPY_FLAG`] in this process, if it was asked for: `copy` reads the
/// boot's runs and adds the earlier bytes of the files they changed to the
/// boot's recording (see [`Writer`]). Returns the exit code.
pub fn worker_main_if_requested(copy: impl FnOnce(&Job) -> Result<(), String>) -> Option<i32> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_none_or(|arg| arg != COPY_FLAG) {
        return None;
    }
    let result = (|| {
        let [_, _, boot_dir, boot_id, per_file, per_run] = args.as_slice() else {
            return Err("usage: --copy-earlier-bytes BOOT_DIR BOOT_ID PER_FILE PER_RUN".to_owned());
        };
        let number = |value: &std::ffi::OsString| {
            value
                .to_str()
                .and_then(|text| text.parse::<u64>().ok())
                .ok_or_else(|| "invalid cap".to_owned())
        };
        set_limits(Limits {
            per_file: number(per_file)?,
            per_run: number(per_run)?,
        });
        copy(&Job {
            vm_id: String::new(),
            boot_id: boot_id.to_string_lossy().into_owned(),
            boot_dir: PathBuf::from(boot_dir),
        })
    })();
    Some(match result {
        Ok(()) => 0,
        Err(why) => {
            eprintln!("{why}");
            1
        }
    })
}

/// Run the copy for `record`'s boot in a process of its own. Fails (and the
/// boot's recording says so) when there is no program to run or it fails.
pub(crate) fn copy_for(record: &crate::snapshots::run_layer::Record) -> Result<(), String> {
    let exe = copier_executable().ok_or("no program is set up to copy the earlier bytes")?;
    let limits = limits();
    let mut child = std::process::Command::new(exe)
        .arg(COPY_FLAG)
        .arg(&record.boot_dir)
        .arg(&record.boot_id)
        .arg(limits.per_file.to_string())
        .arg(limits.per_run.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("copy program: {e}"))?;
    let deadline = std::time::Instant::now() + COPY_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => return Err(format!("the copy program failed ({status})")),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("the copy took too long and was stopped".into());
            }
            Err(e) => return Err(format!("copy program: {e}")),
        }
    }
}

/// The copy did not happen: say so in the boot's recording (unless an
/// earlier, complete copy is there).
pub(crate) fn note_not_copied(boot_dir: &Path, boot_id: &str, why: &str) {
    let mut index = Index::load(boot_dir).unwrap_or_else(|| Index::new(boot_id, limits()));
    if index.complete && why.is_empty() {
        return;
    }
    index.complete = false;
    index.note = Some(format!("earlier bytes not (fully) copied: {why}"));
    let _ = index.save(boot_dir);
}

/// Adds files to a boot's folder.
pub struct Writer {
    boot_dir: PathBuf,
    index: Index,
    limits: Limits,
    unsaved: usize,
}

/// Reads a file of the starting disk to its end in pieces.
fn pieces(
    disk: &StartDisk,
    path: &str,
    size: u64,
    mut each: impl FnMut(&[u8]) -> Result<(), String>,
) -> Result<(), String> {
    let mut at = 0;
    while at < size {
        let want = (size - at).min(CHUNK);
        let bytes = disk.read(path, at, want)?;
        if bytes.is_empty() {
            return Err("the file is shorter on the disk than its inode says".into());
        }
        each(&bytes)?;
        at += bytes.len() as u64;
    }
    Ok(())
}

fn hex(digest: impl AsRef<[u8]>) -> String {
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Writer {
    /// Add to the folder of `boot_dir`, keeping what an earlier pass wrote.
    pub fn open(boot_dir: &Path, boot_id: &str, limits: Limits) -> Self {
        let index = Index::load(boot_dir)
            .filter(|index| index.boot_id == boot_id)
            .unwrap_or_else(|| Index::new(boot_id, limits));
        Self {
            boot_dir: boot_dir.to_path_buf(),
            index,
            limits,
            unsaved: 0,
        }
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Whether a file reached by `path` already has an entry.
    pub fn has(&self, path: &str, key: Option<FileKey>) -> bool {
        self.index.entry(path, key).is_some()
    }

    /// Record what is known of a changed file's earlier bytes, copying them
    /// from `file` (the sealed disk) when they fit the caps.
    pub fn record(
        &mut self,
        path: &str,
        names: &[String],
        key: Option<FileKey>,
        before: &Before,
        file: Option<&DiskFile>,
    ) {
        if matches!(before, Before::Recorded { .. } | Before::NotCopied { .. })
            || self.has(path, key)
        {
            return;
        }
        let mut entry = Entry {
            path: path.to_owned(),
            names: names.to_vec(),
            key: key.map(Key::from),
            exact: false,
            size: 0,
            sha256: None,
            status: Status::Copied,
            blob: None,
        };
        match before {
            Before::OnDisk { size, exact } => {
                entry.size = *size;
                entry.exact = *exact;
                match file {
                    Some(file) => self.copy(&mut entry, &file.disk, &file.path),
                    None => entry.status = Status::Unavailable("no disk to read from".into()),
                }
            }
            Before::TooLarge(size) => {
                entry.size = *size;
                entry.status = Status::NotCopied(format!(
                    "the file is over the {} limit on the starting disk",
                    crate::byte_size::file_size(crate::file_before::SIZE_CAP)
                ));
            }
            Before::Elsewhere(why) => entry.status = Status::Elsewhere(why.clone()),
            Before::Unavailable(why) => entry.status = Status::Unavailable(why.clone()),
            Before::Created => entry.status = Status::Created,
            Before::Recorded { .. } | Before::NotCopied { .. } => return,
        }
        self.index.files.push(entry);
        self.unsaved += 1;
        if self.unsaved >= 32 {
            let _ = self.index.save(&self.boot_dir);
            self.unsaved = 0;
        }
    }

    fn copy(&mut self, entry: &mut Entry, disk: &StartDisk, path: &str) {
        let size = entry.size;
        let fits = size <= self.limits.per_file
            && self.index.copied_bytes.saturating_add(size) <= self.limits.per_run;
        if !fits {
            let (why, which) = if size > self.limits.per_file {
                ("per-file", self.limits.per_file)
            } else {
                ("per-run", self.limits.per_run)
            };
            // Size and hash only: the content is not kept.
            let mut hasher = Sha256::new();
            let hashed = pieces(disk, path, size, |bytes| {
                hasher.update(bytes);
                Ok(())
            });
            entry.sha256 = hashed.ok().map(|()| hex(hasher.finalize()));
            entry.status = Status::NotCopied(format!(
                "not captured: over the {why} cap of {} (size and SHA-256 kept)",
                crate::byte_size::file_size(which)
            ));
            return;
        }
        let dir = self.boot_dir.join(DIR);
        let blob = format!("{:06}", self.index.files.len());
        let written = crate::storage::private_dir(&dir)
            .map_err(|e| e.to_string())
            .and_then(|()| File::create(dir.join(&blob)).map_err(|e| e.to_string()))
            .and_then(|mut out| {
                let mut hasher = Sha256::new();
                pieces(disk, path, size, |bytes| {
                    hasher.update(bytes);
                    out.write_all(bytes).map_err(|e| e.to_string())
                })?;
                out.sync_all().map_err(|e| e.to_string())?;
                Ok(hex(hasher.finalize()))
            });
        match written {
            Ok(sha) => {
                entry.sha256 = Some(sha);
                entry.blob = Some(blob);
                self.index.copied_bytes += size;
            }
            Err(why) => {
                let _ = std::fs::remove_file(dir.join(&blob));
                entry.status = Status::Unavailable(format!("the copy failed: {why}"));
            }
        }
    }

    /// Save the index; `complete` says every changed file was asked about.
    pub fn finish(&mut self, complete: bool, note: Option<String>) -> Result<(), String> {
        self.index.complete = complete;
        self.index.note = note;
        self.index.per_file = self.limits.per_file;
        self.index.per_run = self.limits.per_run;
        self.index.save(&self.boot_dir)
    }
}

/// A boot's folder read back: the earlier bytes as the recording kept them.
#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    pub index: Index,
}

impl Store {
    pub fn open(boot_dir: &Path) -> Option<Self> {
        Some(Self {
            dir: boot_dir.join(DIR),
            index: Index::load(boot_dir)?,
        })
    }

    /// What the recording holds of the file reached by `path`.
    pub fn find(&self, path: &str, key: Option<FileKey>) -> Option<Before> {
        let entry = self.index.entry(path, key)?;
        Some(match &entry.status {
            Status::Created => Before::Created,
            Status::Copied => Before::Recorded {
                size: entry.size,
                exact: entry.exact,
            },
            Status::NotCopied(why) => Before::NotCopied {
                size: entry.size,
                sha256: entry.sha256.clone(),
                why: why.clone(),
            },
            Status::Elsewhere(why) => Before::Elsewhere(why.clone()),
            Status::Unavailable(why) => Before::Unavailable(why.clone()),
        })
    }

    /// `len` bytes of a copied file from `offset`; fewer at its end.
    pub fn read(&self, path: &str, offset: u64, len: u64) -> Result<Vec<u8>, String> {
        let entry = self
            .index
            .files
            .iter()
            .find(|entry| entry.has_name(path) && entry.status == Status::Copied)
            .ok_or("the recording holds no copy of this file")?;
        let blob = entry.blob.as_deref().ok_or("the copy has no blob")?;
        if blob.contains(['/', '\\']) || blob == ".." {
            return Err("invalid blob name".into());
        }
        let file = File::open(self.dir.join(blob)).map_err(|e| e.to_string())?;
        let end = offset.saturating_add(len).min(entry.size);
        let want = end.saturating_sub(offset);
        let mut out = vec![0u8; usize::try_from(want).map_err(|e| e.to_string())?];
        std::os::unix::fs::FileExt::read_exact_at(&file, &mut out, offset)
            .map_err(|e| e.to_string())?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
