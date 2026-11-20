// SPDX-License-Identifier: GPL-3.0-only
//! A matching page of the invocation list and its totals, as separate reads.
//!
//! A page seeks to its cursor in the packet index and stops after the calls
//! it shows, so its cost follows the page, not the recording. The totals walk
//! every call once; callers run them off the interactive path and keep the
//! answer for the same recording, filter and indexed length.
use super::call_reader::{ASYNC_PARTIAL, CallReader};
use super::*;

/// The prefix of a raw archive a read covered. An append-only archive that
/// grew has another length; a replaced one has another identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveStamp {
    pub identity: String,
    pub length: u64,
}

/// One page of matching calls, without totals.
///
/// | Field | Meaning |
/// | --- | --- |
/// | `page` | At most the requested number of matching calls and the cursor of the next one |
/// | `stamp` | The indexed prefix the page was read from |
pub struct MatchingPage {
    pub page: InvocationPage,
    pub stamp: ArchiveStamp,
}

/// Matching calls over the indexed prefix.
///
/// | Field | Meaning |
/// | --- | --- |
/// | `total` | Calls accepted by the predicate, including those before any cursor |
/// | `source_total` | Reconstructed saved calls of the selected process before the predicate |
/// | `stamp` | The indexed prefix that was counted |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchTotals {
    pub total: u64,
    pub source_total: u64,
    pub stamp: ArchiveStamp,
}

/// Most bytes of previews one page carries.
const PAGE_PREVIEW_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn indexed_boundary(connection: &rusqlite::Connection) -> Result<u64, RecordingError> {
    let boundary: i64 =
        connection.query_row("SELECT length FROM indexed LIMIT 1", [], |row| row.get(0))?;
    u64::try_from(boundary).map_err(|_| RecordingError::Limit("negative indexed boundary"))
}

/// Calls read per statement of a long walk.
const CALL_BATCH: i64 = 4096;

/// The calls of the indexed prefix in raw-file order, read in batches of
/// [`CALL_BATCH`]. Each batch is a statement of its own, so a walk over a
/// million calls (the window's count, a filter that matches little) holds the
/// index only while one batch is read, and a builder of the index commits
/// between two batches instead of waiting for the walk's end (ANT-T0575).
pub(super) struct CallRows {
    /// The first offset the next batch may start at.
    from: i64,
    boundary: i64,
    pid: Option<u32>,
    identity: String,
    batch: std::collections::VecDeque<(Vec<u8>, u64)>,
    done: bool,
}

impl CallRows {
    pub(super) fn new(
        from: u64,
        boundary: u64,
        pid: Option<u32>,
        identity: &str,
    ) -> Result<Self, RecordingError> {
        let offset = |value: u64| {
            i64::try_from(value).map_err(|_| RecordingError::Limit("cursor too large"))
        };
        Ok(Self {
            from: offset(from)?,
            boundary: offset(boundary)?,
            pid,
            identity: identity.to_owned(),
            batch: Default::default(),
            done: false,
        })
    }

    /// The next call's key and first offset, or `None` after the last one.
    pub(super) fn next(
        &mut self,
        connection: &rusqlite::Connection,
        cancel: &AtomicBool,
    ) -> Result<Option<(Vec<u8>, u64)>, RecordingError> {
        if self.batch.is_empty() && !self.done {
            let batch = retry_index_busy(cancel, || self.read(connection))?;
            self.done = (batch.len() as i64) < CALL_BATCH;
            if let Some((_, last)) = batch.last() {
                self.from = *last as i64 + 1;
            }
            self.batch = batch.into();
        }
        Ok(self.batch.pop_front())
    }

    fn read(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Vec<(Vec<u8>, u64)>, RecordingError> {
        // The rows below the boundary are still the ones counted from: an
        // index another build of the app started again has not got back to them.
        let (identity, length): (String, i64) =
            connection.query_row("SELECT identity,length FROM indexed LIMIT 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
        if identity != self.identity || length < self.boundary {
            return Err(RecordingError::Limit(
                "the archive index was rebuilt while being read; open it again",
            ));
        }
        let mut statement = connection.prepare_cached(
            "SELECT key,first_offset FROM invocations WHERE first_offset>=?1 AND first_offset<?2 \
             AND (?3 IS NULL OR pid=?3) ORDER BY first_offset LIMIT ?4",
        )?;
        let rows = statement.query_map(
            rusqlite::params![self.from, self.boundary, self.pid, CALL_BATCH],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let mut batch = Vec::new();
        for row in rows {
            let (key, first_offset) = row?;
            let first_offset = u64::try_from(first_offset)
                .map_err(|_| RecordingError::Limit("negative cached invocation offset"))?;
            batch.push((key, first_offset));
        }
        Ok(batch)
    }
}

impl Recording {
    /// Read one page of matching calls, starting at the raw cursor `offset`.
    ///
    /// | Argument | Meaning |
    /// | --- | --- |
    /// | `offset` | Inclusive raw-file cursor returned by a previous page |
    /// | `limit` | Maximum returned calls, in `1..=256` |
    /// | `pid` | Optional guest process/thread-group predicate |
    /// | `cancel` | Cooperative cancellation, checked while indexing and reading packets |
    /// | `keep` | Predicate on the same bounded summaries ordinary archive pages show |
    ///
    /// Only the calls from the cursor to the end of the page are read; a
    /// predicate that rejects most calls reads more, and `cancel` stops it.
    pub fn matching_page_cancellable(
        &self,
        offset: u64,
        limit: usize,
        pid: Option<u32>,
        cancel: &AtomicBool,
        keep: impl FnMut(&InvocationSummary) -> bool,
    ) -> Result<MatchingPage, RecordingError> {
        self.matching_page_within(offset, limit, pid, cancel, keep, PAGE_PREVIEW_BYTES)
    }

    /// [`Self::matching_page_cancellable`] with `budget` bytes of previews.
    pub(super) fn matching_page_within(
        &self,
        offset: u64,
        limit: usize,
        pid: Option<u32>,
        cancel: &AtomicBool,
        keep: impl FnMut(&InvocationSummary) -> bool,
        budget: usize,
    ) -> Result<MatchingPage, RecordingError> {
        self.matching_range_within(offset, 0, limit, pid, cancel, keep, budget)
    }

    /// Seek by matching-call rank after a known raw cursor, without retaining
    /// the skipped calls. Used for direct page jumps and virtual table windows.
    ///
    /// | Argument | Meaning |
    /// | --- | --- |
    /// | `offset` | Inclusive raw cursor; zero starts at the recording beginning |
    /// | `skip` | Matching calls to skip after that cursor |
    /// | `limit` | Window size, 1 through 256; independent of the UI page size |
    /// | `pid` | Optional guest process predicate |
    /// | `cancel` | Cooperative read cancellation |
    /// | `keep` | Filter applied before counting the skipped calls |
    ///
    /// Returns a bounded matching window and the next raw cursor.
    pub fn matching_range_cancellable(
        &self,
        offset: u64,
        skip: u64,
        limit: usize,
        pid: Option<u32>,
        cancel: &AtomicBool,
        keep: impl FnMut(&InvocationSummary) -> bool,
    ) -> Result<MatchingPage, RecordingError> {
        self.matching_range_within(offset, skip, limit, pid, cancel, keep, PAGE_PREVIEW_BYTES)
    }

    #[allow(clippy::too_many_arguments)]
    fn matching_range_within(
        &self,
        offset: u64,
        mut skip: u64,
        limit: usize,
        pid: Option<u32>,
        cancel: &AtomicBool,
        mut keep: impl FnMut(&InvocationSummary) -> bool,
        budget: usize,
    ) -> Result<MatchingPage, RecordingError> {
        if cancel.load(Ordering::Relaxed) {
            return Err(RecordingError::Limit("archive read cancelled"));
        }
        if !(1..=256).contains(&limit) {
            return Err(RecordingError::Limit("page size must be 1..256"));
        }
        let path = self.directory.join("telemetry.raw");
        let (connection, identity) = archive_index(&self.directory, cancel)?;
        let boundary = indexed_boundary(&connection)?;
        if offset > raw_identity(&path)?.1 {
            return Err(RecordingError::Limit("cursor beyond raw archive"));
        }
        let mut reader =
            CallReader::open(&self.directory, &connection, boundary, self.guest_arch())?;
        let mut calls = CallRows::new(offset, boundary, pid, &identity)?;
        let mut invocations = Vec::with_capacity(limit);
        let mut next_offset = None;
        let mut page_preview_size = 0_usize;
        while let Some((key, first_offset)) = calls.next(&connection, cancel)? {
            if cancel.load(Ordering::Relaxed) {
                return Err(RecordingError::Limit("archive read cancelled"));
            }
            let Some(invocation) = reader.call(&key, cancel)? else {
                continue;
            };
            if !keep(&invocation) {
                continue;
            }
            if skip > 0 {
                skip -= 1;
                continue;
            }
            if invocations.len() == limit {
                next_offset = Some(first_offset);
                break;
            }
            let size = invocation
                .entry
                .iter()
                .chain(invocation.exit.iter())
                .chain(&invocation.async_events)
                .chain(invocation.task_exit.iter())
                .fold(0_usize, |size, event| {
                    size.saturating_add(event_preview_size(event))
                });
            // A page holds at most `budget` bytes of previews: a call that
            // would pass it starts the next page (a call alone is bounded far
            // below it), so io_uring submissions each carrying hundreds of
            // observed payloads are shown a few at a time.
            if page_preview_size.saturating_add(size) > budget {
                if invocations.is_empty() {
                    return Err(RecordingError::Limit(
                        "archive page previews exceed 64 MiB; raw records retained",
                    ));
                }
                next_offset = Some(first_offset);
                break;
            }
            page_preview_size += size;
            invocations.push(invocation);
        }
        let mut issues = reader.take_issues();
        if invocations.iter().any(|call| call.async_omitted() > 0) {
            push_issue(&mut issues, ASYNC_PARTIAL.into());
        }
        let (after_identity, after_size) = raw_identity(&path)?;
        if after_identity != identity || after_size < boundary {
            return Err(RecordingError::Limit(
                "raw archive was replaced or shrunk while being read; open it again",
            ));
        }
        Ok(MatchingPage {
            page: InvocationPage {
                invocations,
                next_offset,
                issues,
            },
            stamp: ArchiveStamp {
                identity,
                length: boundary,
            },
        })
    }

    /// Count the calls `keep` accepts over the whole indexed prefix. Walks
    /// every call once; run it apart from page reads and keep its answer.
    pub fn matching_totals_cancellable(
        &self,
        pid: Option<u32>,
        cancel: &AtomicBool,
        mut keep: impl FnMut(&InvocationSummary) -> bool,
    ) -> Result<MatchTotals, RecordingError> {
        if cancel.load(Ordering::Relaxed) {
            return Err(RecordingError::Limit("archive read cancelled"));
        }
        let path = self.directory.join("telemetry.raw");
        let (connection, identity) = archive_index(&self.directory, cancel)?;
        let boundary = indexed_boundary(&connection)?;
        let mut reader =
            CallReader::open(&self.directory, &connection, boundary, self.guest_arch())?;
        let mut calls = CallRows::new(0, boundary, pid, &identity)?;
        let (mut total, mut source_total) = (0_u64, 0_u64);
        while let Some((key, _)) = calls.next(&connection, cancel)? {
            if cancel.load(Ordering::Relaxed) {
                return Err(RecordingError::Limit("archive read cancelled"));
            }
            let Some(invocation) = reader.call(&key, cancel)? else {
                continue;
            };
            source_total = source_total
                .checked_add(1)
                .ok_or(RecordingError::Limit("invocation count overflow"))?;
            if keep(&invocation) {
                total = total
                    .checked_add(1)
                    .ok_or(RecordingError::Limit("matching invocation count overflow"))?;
            }
        }
        let (after_identity, after_size) = raw_identity(&path)?;
        if after_identity != identity || after_size < boundary {
            return Err(RecordingError::Limit(
                "raw archive was replaced or shrunk while being read; open it again",
            ));
        }
        Ok(MatchTotals {
            total,
            source_total,
            stamp: ArchiveStamp {
                identity,
                length: boundary,
            },
        })
    }
}
