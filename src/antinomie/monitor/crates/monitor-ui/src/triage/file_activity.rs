// SPDX-License-Identifier: GPL-3.0-only
//! The history of every file a run touched, for the File activity window.
//!
//! The index is fed by [`super::files::FileIndex`] with each file call and
//! keeps what the calls themselves say: which process did what, in order, with the offset, length and captured
//! bytes of every read and write. Nothing is inferred: a file's content before
//! the run is known only from what the run read, and a write whose bytes the
//! kernel did not capture has an offset and a length and no content.
use super::file_category::{Category, Hit};
use super::files::result_label;
use super::*;
use antinomie_monitor_core::file_writes::{Budget, Captured, Limits, Tally, Writes};
use antinomie_monitor_core::kernel_notes::{FileHash, FileId, FileKey};
use std::collections::BTreeMap;

mod graph;
mod window;

pub(super) use window::{Window, CALLS_TABLE, FILE_TABLE};

#[cfg(test)]
pub(super) mod tests;

/// Files kept; the rest are counted.
const FILES_MAX: usize = 4096;
/// Events kept per file; the rest are counted.
const EVENTS_PER_FILE: usize = 512;
/// Events kept for the whole run.
const EVENTS_MAX: usize = 100_000;
/// Octets of a transfer kept as its content preview.
pub(super) const CONTENT_HEAD: usize = 64;
/// Names a file was seen under, besides its first.
const NAMES_MAX: usize = 16;
/// Names followed to the file they lead to.
const NAMES_TRACKED: usize = 65536;

/// What a call did to the file, the stage of its story.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Open,
    Create,
    Read,
    Write,
    Resize,
    Rename,
    Link,
    Delete,
    Exec,
    Attributes,
    Map,
    Probe,
    Other,
}

impl Kind {
    pub(super) fn verb(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Create => "create",
            Self::Read => "read",
            Self::Write => "write",
            Self::Resize => "resize",
            Self::Rename => "rename",
            Self::Link => "link",
            Self::Delete => "delete",
            Self::Exec => "execute",
            Self::Attributes => "attributes",
            Self::Map => "map",
            Self::Probe => "probe",
            Self::Other => "other",
        }
    }

    /// Whether the call changes the file or its name.
    pub(super) fn changes(self) -> bool {
        matches!(
            self,
            Self::Create
                | Self::Write
                | Self::Resize
                | Self::Rename
                | Self::Link
                | Self::Delete
                | Self::Attributes
        )
    }
}

/// One call on the file.
#[derive(Clone, Debug)]
pub(super) struct Event {
    pub time: u64,
    pub key: trace::InvocationKey,
    /// Index into [`Activity::processes`].
    pub process: u32,
    pub kind: Kind,
    /// The call as the tables name it (`openat`, `pwrite64`, `write (io_uring)`).
    pub operation: String,
    /// `None` for a call with no recorded exit.
    pub success: Option<bool>,
    pub result: String,
    /// Where in the file a read or write was, when the descriptor's position
    /// was known.
    pub offset: Option<u64>,
    /// Octets transferred (the call's result).
    pub len: Option<u64>,
    /// The first octets of the transfer, as far as the kernel captured them.
    pub content: Vec<u8>,
    /// The call moved more octets than it captured.
    pub content_gap: bool,
    /// A write that went past the end of the file as far as it was known.
    pub extends: bool,
    /// The kernel worker system that carried the call (`io_uring`, `AIO`);
    /// such a call has no syscall of its own.
    pub via: Option<&'static str>,
    /// The new name of a rename or link.
    pub other_path: Option<String>,
    /// A short remark ("1 link remains").
    pub note: String,
}

/// A run of consecutive octets whose value the run changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ByteRun {
    pub offset: u64,
    /// `None` is an octet the run did not capture.
    pub before: Vec<Option<u8>>,
    pub after: Vec<Option<u8>>,
}

/// A hash the guest took of the file.
#[derive(Clone, Debug)]
pub(super) struct HashNote {
    pub time: u64,
    /// "closed after write", "before delete" or "exec image".
    pub moment: &'static str,
    pub sha256: Option<String>,
    /// The file changed while the guest read it, so the digest may not match.
    pub changed: bool,
    /// Why there is no usable digest.
    pub skipped: Option<String>,
}

/// What the change reconstruction knows of the file's contents.
#[derive(Clone, Debug, Default)]
pub(super) struct Contents {
    pub original_size: Option<u64>,
    pub final_size: Option<u64>,
    pub differing: usize,
    pub runs: Vec<ByteRun>,
    /// Why the above is not the whole story.
    pub gaps: Vec<&'static str>,
    pub hash: Option<FileHash>,
}

/// Everything the run did to one file.
#[derive(Clone, Debug)]
pub(super) struct FileActivity {
    pub path: String,
    pub path_known: bool,
    /// Other names the file was reached by (renames, links, descriptors).
    pub names: Vec<String>,
    pub identity: Option<FileKey>,
    pub events: Vec<Event>,
    /// Events past the per-file bound.
    pub omitted: u64,
    pub first_ns: u64,
    pub last_ns: u64,
    /// Every call used one of descriptors 0 to 2.
    pub standard_io: bool,
    pub created: bool,
    pub deleted: bool,
    /// The kernel refused every call.
    pub failed_only: bool,
    pub contents: Contents,
    /// Every hash the guest took of the file, in order: the run's evidence
    /// that its bytes changed even where no write payload exists.
    pub hashes: Vec<HashNote>,
    /// The ranges the run wrote, kept within the budget or marked not
    /// captured; unlike `events` they are not bounded by the event cap.
    pub writes: Writes,
}

impl FileActivity {
    /// The file lies in a library directory (the Hide library toggle).
    pub(super) fn library(&self) -> bool {
        file_visibility::library_path(&self.path)
    }

    /// Whether any call changed the file or its name and succeeded.
    pub(super) fn changed(&self) -> bool {
        self.events
            .iter()
            .any(|event| event.kind.changes() && event.success != Some(false))
    }

    /// "3 writes, 1 read, deleted": the stages in order of first appearance.
    pub(super) fn summary(&self) -> String {
        let mut counts: Vec<(Kind, usize)> = Vec::new();
        for event in &self.events {
            match counts.iter_mut().find(|(kind, _)| *kind == event.kind) {
                Some((_, count)) => *count += 1,
                None => counts.push((event.kind, 1)),
            }
        }
        counts
            .into_iter()
            .map(|(kind, count)| {
                if count == 1 {
                    kind.verb().to_owned()
                } else {
                    format!("{} {count}×", kind.verb())
                }
            })
            .collect::<Vec<_>>()
            .join(" → ")
    }
}

/// The run's file activity.
#[derive(Clone, Debug, Default)]
pub(super) struct Activity {
    /// In order of the first call on each file.
    pub files: Vec<FileActivity>,
    /// Process id and image of whoever made the calls.
    pub processes: Vec<(u32, Option<String>)>,
    pub omitted_files: u64,
    pub omitted_events: u64,
    /// Written bytes kept and skipped by the whole run, and the caps.
    pub written: Tally,
    pub limits: Limits,
}

impl Activity {
    pub(super) fn process_label(&self, index: u32) -> String {
        match self.processes.get(index as usize) {
            Some((pid, Some(image))) => format!("{pid} {image}"),
            Some((pid, None)) => pid.to_string(),
            None => "unknown process".into(),
        }
    }
}

/// What the file index tells the activity of one file call.
pub(super) struct Record<'a> {
    /// The name the call reached the file by, or the unavailable-path mark.
    pub path: &'a str,
    pub path_known: bool,
    /// Task and descriptor, to tell nameless files apart.
    pub cookie: u64,
    pub fd: Option<u64>,
    /// The file the guest identified, once a call named it.
    pub identity: Option<FileId>,
    pub call: &'a InvocationSummary,
    pub event: &'a EventSummary,
    pub image: Option<&'a str>,
    pub hits: &'a [Hit],
    pub transfer: Option<Transfer>,
    /// The new name of a rename or link.
    pub new_name: Option<String>,
}

/// A read or write, as far as the host can place it.
pub(super) struct Transfer {
    pub write: bool,
    pub offset: Option<u64>,
    pub len: u64,
    pub content: Vec<u8>,
    pub gap: bool,
    pub extends: bool,
    /// The stretches of a write's payload the kernel captured.
    pub stretches: Vec<Captured>,
}

/// Collects [`Record`]s into an [`Activity`]. A file is its identity where the
/// guest recorded one, so its names join; where it did not, a name is a file
/// until a rename or link gives the same file another.
#[derive(Default)]
pub(super) struct Builder {
    files: BTreeMap<String, FileActivity>,
    /// The file each name leads to now.
    current: BTreeMap<String, String>,
    processes: Vec<(u32, Option<String>)>,
    events: usize,
    omitted_files: u64,
    omitted_events: u64,
    budget: Budget,
}

fn kind_of(hits: &[Hit], name: &str, transfer: Option<&Transfer>) -> Kind {
    let has = |category| hits.iter().any(|hit| hit.category == category);
    if has(Category::Deleted) {
        Kind::Delete
    } else if has(Category::Renamed) {
        Kind::Rename
    } else if has(Category::Linked) {
        Kind::Link
    } else if has(Category::Created) {
        Kind::Create
    } else if has(Category::Opened) && OPEN_NAMES.contains(&name) {
        Kind::Open
    } else if has(Category::Executed) {
        Kind::Exec
    } else if transfer.is_some_and(|transfer| transfer.write) || has(Category::Written) {
        Kind::Write
    } else if has(Category::Truncated) {
        Kind::Resize
    } else if transfer.is_some() || has(Category::Read) {
        Kind::Read
    } else if has(Category::Permissions) || has(Category::Timestamps) || has(Category::Xattrs) {
        Kind::Attributes
    } else if has(Category::Mapped) {
        Kind::Map
    } else if has(Category::Opened) {
        Kind::Open
    } else if has(Category::Probed) {
        Kind::Probe
    } else {
        Kind::Other
    }
}

impl Builder {
    /// The caps on the write content kept (set before the first call).
    pub(super) fn set_limits(&mut self, limits: Limits) {
        self.budget = Budget::new(limits);
    }

    fn process(&mut self, pid: u32, image: Option<&str>) -> u32 {
        let key = (pid, image.map(str::to_owned));
        if let Some(index) = self.processes.iter().position(|known| *known == key) {
            return index as u32;
        }
        self.processes.push(key);
        (self.processes.len() - 1) as u32
    }

    /// The key of the file a record is about. Identity first; else the file
    /// the name leads to now; else the name; a call with no name is keyed by
    /// the task and descriptor.
    fn key(&mut self, record: &Record<'_>) -> String {
        if let Some(id) = &record.identity {
            let key = format!("id:{}:{}:{}", id.key.dev, id.key.ino, id.key.generation);
            if record.path_known && self.current.len() < NAMES_TRACKED {
                self.current.insert(record.path.to_owned(), key.clone());
            }
            return key;
        }
        if record.path_known {
            return self
                .current
                .get(record.path)
                .cloned()
                .unwrap_or_else(|| record.path.to_owned());
        }
        format!(
            "\u{0}{}:{}",
            record.cookie,
            record.fd.map_or("?".to_owned(), |fd| fd.to_string())
        )
    }

    pub(super) fn record(&mut self, record: Record<'_>) {
        let key = self.key(&record);
        let Record {
            path,
            path_known,
            fd,
            identity,
            call,
            event,
            image,
            hits,
            transfer,
            new_name,
            ..
        } = record;
        let links_left = identity.map(|id| if id.directory { 0 } else { id.nlink });
        let identity = identity.map(|id| id.key);
        let path = if path_known {
            path.to_owned()
        } else {
            fd.and_then(crate::values::standard_fd_name)
                .map(str::to_owned)
                .or_else(|| fd.map(|fd| format!("fd {fd}")))
                .unwrap_or_else(|| "fd unavailable".into())
        };
        let group = key.as_str();
        if !self.files.contains_key(group) && self.files.len() >= FILES_MAX {
            self.omitted_files += 1;
            return;
        }
        let kind = kind_of(hits, &event.syscall_name, transfer.as_ref());
        // Past the bounds a call only sets what the file is known to have been.
        let capped = self.events >= EVENTS_MAX
            || self
                .files
                .get(group)
                .is_some_and(|file| file.events.len() >= EVENTS_PER_FILE);
        let process = if capped {
            0
        } else {
            self.process(event.pid, image)
        };
        let outcome = file_category::outcome(call);
        let success = match outcome {
            file_category::Outcome::Succeeded => Some(true),
            file_category::Outcome::Failed(_) => Some(false),
            file_category::Outcome::NoExit => None,
        };
        let result = if capped {
            String::new()
        } else {
            result_label(call.exit.as_ref().and_then(|exit| exit.result))
        };
        let mut note = String::new();
        if kind == Kind::Delete && success == Some(true) {
            note = match links_left {
                Some(0) => "last name removed".into(),
                Some(1) => "1 link remains".into(),
                Some(left) => format!("{left} links remain"),
                None => "links left unknown".into(),
            };
        }
        let file = self
            .files
            .entry(key.clone())
            .or_insert_with(|| FileActivity {
                path: path.clone(),
                path_known,
                names: Vec::new(),
                identity,
                events: Vec::new(),
                omitted: 0,
                first_ns: event.timestamp_ns,
                last_ns: event.timestamp_ns,
                standard_io: true,
                created: false,
                deleted: false,
                failed_only: true,
                contents: Contents::default(),
                hashes: Vec::new(),
                writes: Writes::default(),
            });
        if !file.path_known && path_known {
            file.path = path.clone();
            file.path_known = true;
        }
        file.identity = file.identity.or(identity);
        // The file under another name it was reached by.
        for name in new_name.iter().chain((path != file.path).then_some(&path)) {
            if *name != file.path && !file.names.contains(name) && file.names.len() < NAMES_MAX {
                file.names.push(name.clone());
            }
        }
        file.standard_io &= fd.is_some_and(|fd| fd <= 2);
        file.failed_only &= success == Some(false);
        file.first_ns = file.first_ns.min(event.timestamp_ns);
        file.last_ns = file.last_ns.max(event.timestamp_ns);
        if success != Some(false) {
            file.created |= kind == Kind::Create;
            file.deleted |= kind == Kind::Delete && links_left.is_none_or(|left| left == 0);
            // A file made again after it was deleted is a new life.
            if kind == Kind::Create {
                file.deleted = false;
            }
        }
        // Write content is kept per file whatever the event bounds say: a
        // file written in small blocks has more writes than events.
        let transfer = transfer.map(|mut t| {
            if t.write && success != Some(false) {
                file.writes.add(
                    &mut self.budget,
                    t.offset,
                    t.len,
                    std::mem::take(&mut t.stretches),
                );
            }
            t
        });
        if capped {
            file.omitted += 1;
            self.omitted_events += 1;
            return;
        }
        self.events += 1;
        let (offset, len, content, content_gap, extends) = match transfer {
            Some(t) => (t.offset, Some(t.len), t.content, t.gap, t.extends),
            None => (None, None, Vec::new(), false, false),
        };
        let renamed = kind == Kind::Rename && success != Some(false);
        let linked = kind == Kind::Link && success != Some(false);
        let removed = kind == Kind::Delete && success != Some(false);
        file.events.push(Event {
            time: event.timestamp_ns,
            key: trace::key(call),
            process,
            kind,
            operation: file_events::operation_label(call, event),
            success,
            result,
            offset,
            len,
            content,
            content_gap,
            extends,
            via: async_files::via(call),
            other_path: new_name.clone(),
            note,
        });
        // The names lead to files as the call left them.
        if path_known && (renamed || removed) {
            self.current.remove(&path);
        }
        if let Some(name) = new_name.filter(|_| renamed || linked) {
            if self.current.len() < NAMES_TRACKED {
                self.current.insert(name, key);
            }
        }
    }

    /// A hash the guest took of the file `identity`, or else the one at `path`.
    pub(super) fn hash(
        &mut self,
        identity: Option<FileKey>,
        path: Option<&str>,
        time: u64,
        moment: &'static str,
        hash: &FileHash,
    ) {
        let key = identity
            .map(|id| format!("id:{}:{}:{}", id.dev, id.ino, id.generation))
            .or_else(|| {
                path.map(|path| self.current.get(path).cloned().unwrap_or(path.to_owned()))
            });
        let Some(file) = key.and_then(|key| self.files.get_mut(&key)) else {
            return;
        };
        if file.hashes.len() < NAMES_MAX {
            file.hashes.push(HashNote {
                time,
                moment,
                sha256: hash.sha256_hex(),
                changed: hash.changed,
                skipped: hash.skipped(),
            });
        }
    }

    /// The files in order of first call. `contents` gives what the change
    /// reconstruction knows of a file.
    pub(super) fn finish(
        self,
        mut contents: impl FnMut(&FileActivity) -> Option<Contents>,
    ) -> Activity {
        let mut files: Vec<_> = self
            .files
            .into_values()
            .map(|mut file| {
                if let Some(known) = contents(&file) {
                    file.contents = known;
                }
                file
            })
            .collect();
        files.sort_by_key(|file| (file.first_ns, file.path.clone()));
        Activity {
            files,
            processes: self.processes,
            omitted_files: self.omitted_files,
            omitted_events: self.omitted_events,
            written: self.budget.run,
            limits: self.budget.limits,
        }
    }
}
