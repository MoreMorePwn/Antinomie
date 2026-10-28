// SPDX-License-Identifier: GPL-3.0-only
//! The bytes a file held before the run touched it, read from the disk the
//! run started from.
//!
//! The trace records what a run wrote, not what it overwrote. For a file that
//! existed when the run started, the earlier bytes are on the starting disk
//! ([`crate::disk_start`]): the frozen layers under the VM's overlay. They are
//! read in place, on demand, by the sandboxed disk reader (a qcow2 chain, no
//! mount, nothing run), never copied into the recording.
//!
//! What this can and cannot say:
//!
//! * A file the run created starts empty ([`Before::Created`]); its earlier
//!   bytes are its own earlier writes.
//! * A file is matched on the starting disk by path, and when the trace
//!   named its inode (device, inode number, generation) the inode is read
//!   raw from the disk and must agree (type, size, owner, time, generation),
//!   so a name another file took over, or a reused inode number, is not
//!   mistaken for the file ([`Before::Elsewhere`]).
//! * Files that are not on the disk are not here: tmpfs (`/dev/shm`, `/run`,
//!   `/tmp` where it is a RAM disk), other mounts, and anything in a RAM
//!   snapshot. They show as [`Before::Elsewhere`].
//! * Files over [`SIZE_CAP`] are not offered ([`Before::TooLarge`]).
//! * If the starting disk is gone or was not recorded ([`Before::Unavailable`])
//!   the window says why.
use crate::disk_start::{DiskStart, Frozen, Start, Via};
use crate::disks::reader::{
    DiskAnswer, DiskRequest, LocationMatch, RANGE_LIMIT, ReadError, Reader,
};
use crate::kernel_notes::FileKey;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Largest file whose earlier bytes are offered.
pub const SIZE_CAP: u64 = 1 << 30;

/// What is known of a file's bytes at the start of the run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Before {
    /// The run created the file: it started empty.
    Created,
    /// On the starting disk with this size. `exact` is true when the inode
    /// the run saw was checked against the disk; false when only the path
    /// was (the guest recorded no inode).
    OnDisk { size: u64, exact: bool },
    /// The starting disk does not hold this file (tmpfs, another mount, a
    /// name another file took over); says why.
    Elsewhere(String),
    /// On the disk, but larger than [`SIZE_CAP`].
    TooLarge(u64),
    /// The starting disk cannot be read; says why.
    Unavailable(String),
}

/// An open starting disk. The reader worker starts with the first request
/// and ends when this is dropped.
pub struct StartDisk {
    layers: Vec<PathBuf>,
    executable: Option<PathBuf>,
    reader: Mutex<Option<(Reader, PathBuf)>>,
}

impl std::fmt::Debug for StartDisk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "StartDisk({:?})", self.layers)
    }
}

impl StartDisk {
    /// The starting disk of `start`, when it is recorded and every layer is
    /// still as it was. `executable` is the program that serves
    /// `--disk-reader` (`None`: this one).
    pub fn open(start: &DiskStart, executable: Option<PathBuf>) -> Result<Arc<Self>, String> {
        let frozen: &Frozen = match &start.start {
            Start::Frozen(frozen) => frozen,
            Start::Changed => {
                return Err(
                    "the VM's disk already held changes from earlier boots when the run \
                            started, and that state was not kept (start from a new or reset VM, \
                            or restore a checkpoint, to keep it)"
                        .into(),
                );
            }
            Start::Unknown(why) => {
                return Err(format!("the starting disk was not recorded: {why}"));
            }
        };
        frozen.verify()?;
        Ok(Arc::new(Self {
            layers: frozen.paths(),
            executable,
            reader: Mutex::new(None),
        }))
    }

    fn with_reader<T>(
        &self,
        use_reader: impl FnOnce(&mut Reader, &Path) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut held = self.reader.lock().map_err(|_| "disk reader".to_owned())?;
        if held.is_none() {
            let scratch = std::env::temp_dir().join(format!(
                "antinomie-before-{}-{}",
                std::process::id(),
                crate::storage::unique_id()
            ));
            let reader = match &self.executable {
                Some(executable) => {
                    Reader::with_executable_and_chain(executable.clone(), &self.layers, &scratch)?
                }
                None => Reader::open_chain(&self.layers, &scratch)?,
            };
            *held = Some((reader, scratch));
        }
        let (reader, scratch) = held.as_mut().expect("opened above");
        let scratch = scratch.clone();
        use_reader(reader, &scratch)
    }

    /// Whether `path` (with the inode the trace named, if it did) is on the
    /// starting disk.
    pub fn find(&self, path: &str, key: Option<FileKey>) -> Before {
        let located = self.with_reader(|reader, _| {
            reader.request(DiskRequest::Locate {
                path: path.to_owned(),
                ino: key.map(|key| key.ino),
                generation: key.map(|key| key.generation),
            })
        });
        match located {
            Err(why) => Before::Unavailable(why),
            Ok(Err(ReadError::NotFound)) => Before::Elsewhere(
                "the path is not on the starting disk (a file the run created, or on tmpfs or \
                 another mount)"
                    .into(),
            ),
            Ok(Err(error)) => Before::Unavailable(error.to_string()),
            Ok(Ok(DiskAnswer::Located(location))) => match location.matched {
                LocationMatch::Different(why) => Before::Elsewhere(why),
                _ if location.size > SIZE_CAP => Before::TooLarge(location.size),
                matched => Before::OnDisk {
                    size: location.size,
                    exact: matched == LocationMatch::Inode,
                },
            },
            Ok(Ok(other)) => Before::Unavailable(format!("unexpected answer {other:?}")),
        }
    }

    /// `len` bytes of the file at `path` from `offset` on the starting disk.
    /// Fewer come back at the end of the file.
    pub fn read(&self, path: &str, offset: u64, len: u64) -> Result<Vec<u8>, String> {
        let len = len.min(RANGE_LIMIT);
        self.with_reader(|reader, scratch| {
            let answer = reader.request(DiskRequest::ReadRange {
                path: path.to_owned(),
                offset,
                len,
            })?;
            match answer {
                Ok(DiskAnswer::Ranged(_)) => {
                    let out = scratch.join(reader.last_request_id().to_string());
                    let bytes = std::fs::read(&out).map_err(|error| error.to_string());
                    let _ = std::fs::remove_file(&out);
                    bytes
                }
                Ok(other) => Err(format!("unexpected answer {other:?}")),
                Err(error) => Err(error.to_string()),
            }
        })
    }
}

impl Drop for StartDisk {
    fn drop(&mut self) {
        if let Some((_, scratch)) = self.reader.get_mut().ok().and_then(Option::take) {
            let _ = std::fs::remove_dir_all(scratch);
        }
    }
}

/// What one file of a run needs to find its earlier bytes.
pub struct Wanted<'a> {
    /// The name the file was first reached by, and other names it had.
    pub path: &'a str,
    pub names: &'a [String],
    /// The inode the trace named, if it did.
    pub key: Option<FileKey>,
    /// The run created the file.
    pub created: bool,
    /// The first and last recording segment of the run that touched it.
    pub first_segment: usize,
    pub last_segment: usize,
}

/// Finds the starting disk of each recording segment of a run and what it
/// holds of each file.
///
/// A segment that has its own record started a boot; one without it is a
/// transport reconnect of the boot before, on the same disk. A snapshot
/// restore replaces the disk under a running timeline, so a file the run
/// used both before and after one has no single starting disk and gets no
/// earlier bytes.
pub struct Resolver {
    /// Per segment: its own record, if it has one.
    own: Vec<Option<DiskStart>>,
    /// Per segment: the index of the segment whose record applies.
    effective: Vec<Option<usize>>,
    executable: Option<PathBuf>,
    disks: std::collections::BTreeMap<usize, Result<Arc<StartDisk>, String>>,
}

impl Resolver {
    /// `segments`: each segment's run folder and the boot that recorded it,
    /// oldest first.
    pub fn new(segments: &[(PathBuf, String)], executable: Option<PathBuf>) -> Self {
        let own: Vec<_> = segments
            .iter()
            .map(|(dir, boot)| DiskStart::of_segment(dir, boot))
            .collect();
        let mut effective = Vec::new();
        let mut current = None;
        for (index, start) in own.iter().enumerate() {
            if start.is_some() {
                current = Some(index);
            }
            effective.push(current);
        }
        Self {
            own,
            effective,
            executable,
            disks: Default::default(),
        }
    }

    /// The earlier bytes of one file and where to read them from.
    pub fn resolve(&mut self, wanted: &Wanted<'_>) -> (Before, Option<DiskFile>) {
        if wanted.created {
            return (Before::Created, None);
        }
        let last = wanted.last_segment.min(self.own.len().saturating_sub(1));
        let first = wanted.first_segment.min(last);
        if self
            .own
            .get(first + 1..=last)
            .into_iter()
            .flatten()
            .any(|start| {
                start
                    .as_ref()
                    .is_some_and(|start| start.via == Via::Restore)
            })
        {
            return (
                Before::Unavailable(
                    "a snapshot restore replaced the disk while the run was using this file".into(),
                ),
                None,
            );
        }
        let Some(source) = self.effective.get(first).copied().flatten() else {
            return (
                Before::Unavailable(
                    "the run's starting disk was not recorded (a recording from before the app                      kept it, or a boot that could not save it)"
                        .into(),
                ),
                None,
            );
        };
        let executable = self.executable.clone();
        let own = &self.own;
        let disk = self.disks.entry(source).or_insert_with(|| {
            let start = own[source].as_ref().expect("effective names a record");
            StartDisk::open(start, executable)
        });
        let disk = match disk {
            Ok(disk) => Arc::clone(disk),
            Err(why) => return (Before::Unavailable(why.clone()), None),
        };
        let mut first_answer = None;
        for path in std::iter::once(wanted.path).chain(wanted.names.iter().map(String::as_str)) {
            if !path.starts_with('/') {
                continue;
            }
            let found = disk.find(path, wanted.key);
            let on_disk = matches!(found, Before::OnDisk { .. } | Before::TooLarge(_));
            let file = DiskFile {
                disk: Arc::clone(&disk),
                path: path.into(),
            };
            if on_disk {
                return (found, Some(file));
            }
            first_answer.get_or_insert(found);
        }
        (
            first_answer.unwrap_or_else(|| {
                Before::Elsewhere("the file has no path the starting disk could be asked".into())
            }),
            None,
        )
    }
}

/// One file on a starting disk: where [`crate::file_writes::Source::Disk`]
/// reads from.
#[derive(Clone, Debug)]
pub struct DiskFile {
    pub disk: Arc<StartDisk>,
    pub path: Arc<str>,
}

impl PartialEq for DiskFile {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.disk, &other.disk) && self.path == other.path
    }
}
impl Eq for DiskFile {}

#[cfg(test)]
mod tests;
