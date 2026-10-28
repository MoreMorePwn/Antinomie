// SPDX-License-Identifier: GPL-3.0-only
//! What a run wrote into each file, kept within a budget.
//!
//! The syscall trace already holds every captured write payload in the run's
//! object store (deduplicated by hash there). This module is the index over
//! it: for each file, the byte ranges the run wrote, each either **kept**
//! (the bytes can be read back, from the object store or from an inline copy)
//! or **not captured**, with the reason. Nothing is zero-filled and nothing is
//! dropped without a trace: a range that does not fit the budget is recorded
//! as not captured, and the totals say how many bytes were kept and skipped.
//!
//! Policy (decided with the user, 2026-10-28): when a cap is reached the
//! *first* writes are kept (headers, droppers), later ranges are recorded as
//! not captured. The guest's hash at the last close still covers the final
//! state of the file.
//!
//! | Name | Role |
//! | --- | --- |
//! | [`Limits`] | Per-file and per-run byte caps (Settings) |
//! | [`Budget`] | The run's running account against the caps |
//! | [`Writes`] | One file's write extents in the order applied, and its tally |
//! | [`Extent`] | A range of the file with its [`Piece`]: kept bytes or a [`Gap`] |
//! | [`Writes::layout`] | The extents with later writes laid over earlier ones |
//! | [`Writes::read`] | The exact bytes of a fully kept range |
//!
//! The extent model is what the later file-reconstruction work builds on: a
//! byte map assigns each file offset one of unknown (no extent), kept
//! (written), or one of the [`Gap`] reasons (not captured).
use crate::api::FieldSummary;
use crate::recording;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

/// Default cap on the bytes kept for one file.
pub const DEFAULT_PER_FILE: u64 = 64 << 20;
/// Default cap on the bytes kept for the whole run.
pub const DEFAULT_PER_RUN: u64 = 1 << 30;
/// Extents listed for one file; further writes are only counted.
pub const EXTENTS_PER_FILE: usize = 65_536;
/// Most captured bytes read from the object store in one call.
const READ_CHUNK: u64 = 65_536;

/// The caps, in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub per_file: u64,
    pub per_run: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_file: DEFAULT_PER_FILE,
            per_run: DEFAULT_PER_RUN,
        }
    }
}

/// Where kept bytes can be read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A copy held with the extent (a short capture the recording kept inline).
    Inline(Vec<u8>),
    /// A range of a file on the run's starting disk, read on demand.
    Disk {
        file: crate::file_before::DiskFile,
        /// Where in the file the range starts.
        at: u64,
    },
    /// A range of a captured field in the run's object store.
    Object {
        /// The recording directory the field belongs to.
        recording: Arc<PathBuf>,
        /// The field's saved object name.
        raw: Arc<PathBuf>,
        /// Where in the field the range starts.
        at: u64,
    },
}

impl Source {
    /// The part of this source that starts `skip` bytes in.
    fn tail(&self, skip: u64) -> Source {
        match self {
            Source::Inline(bytes) => {
                Source::Inline(bytes[usize::try_from(skip).unwrap_or(usize::MAX)..].to_vec())
            }
            Source::Object { recording, raw, at } => Source::Object {
                recording: recording.clone(),
                raw: raw.clone(),
                at: at + skip,
            },
            Source::Disk { file, at } => Source::Disk {
                file: file.clone(),
                at: at + skip,
            },
        }
    }

    /// The first `len` bytes of this source.
    fn head(&self, len: u64) -> Source {
        match self {
            Source::Inline(bytes) => {
                Source::Inline(bytes[..usize::try_from(len).unwrap_or(usize::MAX)].to_vec())
            }
            other => other.clone(),
        }
    }

    /// `len` bytes from `skip` in, `len` at most [`READ_CHUNK`].
    fn read(&self, skip: u64, len: u64) -> Result<Vec<u8>, ReadError> {
        match self {
            Source::Inline(bytes) => usize::try_from(skip)
                .ok()
                .and_then(|from| bytes.get(from..from.checked_add(usize::try_from(len).ok()?)?))
                .map(<[u8]>::to_vec)
                .ok_or(ReadError::Unreadable),
            Source::Disk { file, at } => file
                .disk
                .read(&file.path, at + skip, len)
                .ok()
                .filter(|bytes| bytes.len() as u64 == len)
                .ok_or(ReadError::Unreadable),
            Source::Object { recording, raw, at } => {
                let start = at + skip;
                let field = FieldSummary {
                    arg: None,
                    object_id: 0,
                    key: String::new(),
                    layout: String::new(),
                    logical_len: None,
                    captured_len: start + len,
                    status: None,
                    capture_error: 0,
                    complete: true,
                    preview: Vec::new(),
                    raw_path: Some(raw.as_ref().clone()),
                    ranges: vec![(start, len)],
                    recapture: None,
                    encoding: None,
                };
                recording::read_captured_range(
                    recording,
                    &field,
                    start,
                    usize::try_from(len).map_err(|_| ReadError::Unreadable)?,
                )
                .map_err(|_| ReadError::Unreadable)
            }
        }
    }
}

/// Why a written range has no bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gap {
    /// The kernel did not capture these bytes of the call.
    NotRecorded,
    /// The file's cap was reached.
    FileCap,
    /// The run's cap was reached.
    RunCap,
}

impl Gap {
    pub fn label(self) -> &'static str {
        match self {
            Gap::NotRecorded => "not recorded by the kernel",
            Gap::FileCap => "past the per-file cap",
            Gap::RunCap => "past the per-run cap",
        }
    }
}

/// The content of one range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    Kept(Source),
    /// What the file held at the start of the run, read from the starting
    /// disk; the run's writes lie over it.
    Before(Source),
    NotCaptured(Gap),
}

/// A range of the file the run wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extent {
    pub offset: u64,
    pub len: u64,
    pub piece: Piece,
}

impl Extent {
    fn end(&self) -> u64 {
        self.offset + self.len
    }

    /// The part of this extent in `[from, to)`.
    fn cut(&self, from: u64, to: u64) -> Extent {
        let (from, to) = (from.max(self.offset), to.min(self.end()));
        let piece = match &self.piece {
            Piece::Kept(source) => Piece::Kept(source.tail(from - self.offset).head(to - from)),
            Piece::Before(source) => Piece::Before(source.tail(from - self.offset).head(to - from)),
            gap => gap.clone(),
        };
        Extent {
            offset: from,
            len: to - from,
            piece,
        }
    }
}

/// Bytes counted, by what became of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub kept: u64,
    pub file_cap: u64,
    pub run_cap: u64,
    pub not_recorded: u64,
    /// Written at an offset the host could not place (append, shared
    /// descriptor): counted, never listed.
    pub offset_unknown: u64,
    /// Written after the file's list of extents was full.
    pub unlisted: u64,
}

impl Tally {
    /// Bytes written and not kept, for whatever reason.
    pub fn skipped(&self) -> u64 {
        self.file_cap + self.run_cap + self.not_recorded + self.offset_unknown + self.unlisted
    }

    fn add(&mut self, other: &Tally) {
        self.kept += other.kept;
        self.file_cap += other.file_cap;
        self.run_cap += other.run_cap;
        self.not_recorded += other.not_recorded;
        self.offset_unknown += other.offset_unknown;
        self.unlisted += other.unlisted;
    }
}

/// The run's account against the caps.
#[derive(Clone, Debug, Default)]
pub struct Budget {
    pub limits: Limits,
    /// Everything the run's files together kept or skipped.
    pub run: Tally,
}

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            run: Tally::default(),
        }
    }
}

/// What a file held when the run started: `size` bytes readable from `source`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Before {
    pub size: u64,
    pub source: Source,
}

/// Why a range could not be read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// Some byte of the range was never captured; the offset is the first.
    NotCaptured(u64),
    /// Some byte of the range was never written by the run (unknown).
    Unknown(u64),
    /// A kept range could not be read from the object store.
    Unreadable,
}

/// One captured stretch of a write call: `len` bytes from `rel` into the
/// call's payload.
pub struct Captured {
    pub rel: u64,
    pub len: u64,
    pub source: Source,
}

/// One file's write extents, in the order the run wrote them: the order the
/// file system applied them when the guest numbered the writes (revision 18's
/// write order), otherwise the order of the calls.
#[derive(Clone, Debug, Default)]
pub struct Writes {
    extents: Vec<Extent>,
    /// The write order of each extent's call, alongside `extents`.
    orders: Vec<Option<u64>>,
    pub tally: Tally,
}

impl Writes {
    /// The extents as written, earlier first; they may overlap.
    pub fn extents(&self) -> &[Extent] {
        &self.extents
    }

    /// Account for one write call of `len` bytes at `offset` (`None` when the
    /// host could not place it). `captured` lists the stretches the kernel
    /// captured, ascending and not overlapping; the rest of the call is not
    /// recorded. The head of each stretch is kept while the caps allow.
    pub fn add(
        &mut self,
        budget: &mut Budget,
        offset: Option<u64>,
        len: u64,
        captured: Vec<Captured>,
    ) {
        self.add_ordered(budget, offset, len, captured, None);
    }

    /// [`Self::add`] for a write the guest numbered: a write that reaches the
    /// host after one the file system applied later (two writers raced) goes
    /// under it, before the first numbered extent with a higher number. An
    /// unnumbered extent is never passed.
    pub fn add_ordered(
        &mut self,
        budget: &mut Budget,
        offset: Option<u64>,
        len: u64,
        captured: Vec<Captured>,
        order: Option<u64>,
    ) {
        let mut tally = Tally::default();
        let Some(offset) = offset.filter(|_| len > 0) else {
            tally.offset_unknown = len;
            self.finish(budget, &tally);
            return;
        };
        let mut cursor = 0u64;
        let mut pieces: Vec<Extent> = Vec::new();
        let push = |rel: u64, len: u64, piece: Piece, pieces: &mut Vec<Extent>| {
            if len > 0 {
                pieces.push(Extent {
                    offset: offset.saturating_add(rel),
                    len,
                    piece,
                });
            }
        };
        for stretch in captured {
            let rel = stretch.rel.max(cursor);
            let end = stretch.rel.saturating_add(stretch.len).min(len);
            if rel >= end {
                continue;
            }
            let skip = rel - stretch.rel;
            push(
                cursor,
                rel - cursor,
                Piece::NotCaptured(Gap::NotRecorded),
                &mut pieces,
            );
            tally.not_recorded += rel - cursor;
            let want = end - rel;
            let file_left = budget
                .limits
                .per_file
                .saturating_sub(self.tally.kept + tally.kept);
            let run_left = budget
                .limits
                .per_run
                .saturating_sub(budget.run.kept + tally.kept);
            let keep = want.min(file_left).min(run_left);
            if keep > 0 {
                push(
                    rel,
                    keep,
                    Piece::Kept(stretch.source.tail(skip).head(keep)),
                    &mut pieces,
                );
                tally.kept += keep;
            }
            if keep < want {
                let (gap, counter) = if file_left <= run_left {
                    (Gap::FileCap, &mut tally.file_cap)
                } else {
                    (Gap::RunCap, &mut tally.run_cap)
                };
                *counter += want - keep;
                push(
                    rel + keep,
                    want - keep,
                    Piece::NotCaptured(gap),
                    &mut pieces,
                );
            }
            cursor = end;
        }
        push(
            cursor,
            len - cursor,
            Piece::NotCaptured(Gap::NotRecorded),
            &mut pieces,
        );
        tally.not_recorded += len - cursor;
        if self.extents.len() + pieces.len() > EXTENTS_PER_FILE {
            // The list is full: the bytes are still accounted for, but as
            // not kept, so the totals stay true to what can be read back.
            tally.unlisted += tally.kept + tally.file_cap + tally.run_cap;
            tally.kept = 0;
            tally.file_cap = 0;
            tally.run_cap = 0;
        } else {
            let mut at = self.extents.len();
            if let Some(order) = order {
                while at > 0 && self.orders[at - 1].is_some_and(|later| later > order) {
                    at -= 1;
                }
            }
            let count = pieces.len();
            self.extents.splice(at..at, pieces);
            self.orders
                .splice(at..at, std::iter::repeat_n(order, count));
        }
        self.finish(budget, &tally);
    }

    fn finish(&mut self, budget: &mut Budget, tally: &Tally) {
        self.tally.add(tally);
        budget.run.add(tally);
    }

    /// The extents with later writes laid over earlier ones: ascending,
    /// not overlapping. Offsets no extent covers are unknown.
    pub fn layout(&self) -> Vec<Extent> {
        self.layout_over(None)
    }

    /// [`Self::layout`] over what the file held when the run started: the
    /// bytes no write covers are the earlier ones ([`Piece::Before`]), up to
    /// its size.
    pub fn layout_over(&self, before: Option<&Before>) -> Vec<Extent> {
        let mut laid: BTreeMap<u64, Extent> = BTreeMap::new();
        let earlier = before
            .filter(|before| before.size > 0)
            .map(|before| Extent {
                offset: 0,
                len: before.size,
                piece: Piece::Before(before.source.clone()),
            });
        for extent in earlier.iter().chain(&self.extents) {
            let (from, to) = (extent.offset, extent.end());
            let touching: Vec<u64> = laid
                .range(..to)
                .rev()
                .take_while(|(_, old)| old.end() > from)
                .map(|(start, _)| *start)
                .collect();
            for start in touching {
                let old = laid.remove(&start).expect("listed");
                if old.offset < from {
                    laid.insert(old.offset, old.cut(old.offset, from));
                }
                if old.end() > to {
                    laid.insert(to, old.cut(to, old.end()));
                }
            }
            laid.insert(from, extent.clone());
        }
        laid.into_values().collect()
    }

    /// The bytes `[offset, offset + len)` as the run wrote them, or the first
    /// reason they cannot be given. Never fills a gap.
    pub fn read(&self, offset: u64, len: u64) -> Result<Vec<u8>, ReadError> {
        self.read_over(None, offset, len)
    }

    /// [`Self::read`] with the file's earlier bytes under the writes.
    pub fn read_over(
        &self,
        before: Option<&Before>,
        offset: u64,
        len: u64,
    ) -> Result<Vec<u8>, ReadError> {
        let end = offset.checked_add(len).ok_or(ReadError::Unknown(offset))?;
        let mut out = Vec::with_capacity(usize::try_from(len).unwrap_or(0).min(1 << 26));
        let mut at = offset;
        for extent in self.layout_over(before) {
            if extent.end() <= at {
                continue;
            }
            if extent.offset > at {
                return Err(ReadError::Unknown(at));
            }
            if at >= end {
                break;
            }
            let (Piece::Kept(source) | Piece::Before(source)) = &extent.piece else {
                return Err(ReadError::NotCaptured(at));
            };
            let stop = extent.end().min(end);
            let mut from = at - extent.offset;
            let mut left = stop - at;
            while left > 0 {
                let step = left.min(READ_CHUNK);
                out.extend(source.read(from, step)?);
                from += step;
                left -= step;
            }
            at = stop;
            if at >= end {
                break;
            }
        }
        if at < end {
            return Err(ReadError::Unknown(at));
        }
        Ok(out)
    }
}

/// Where a recording's objects are, for callers that build [`Source`]s.
pub fn object_source(recording: &Arc<PathBuf>, raw: &Arc<PathBuf>, at: u64) -> Source {
    Source::Object {
        recording: recording.clone(),
        raw: raw.clone(),
        at,
    }
}

#[cfg(test)]
mod tests;
