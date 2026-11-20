// SPDX-License-Identifier: GPL-3.0-only
//! Sharing the cached packet index between its readers and its builder
//! (ANT-T0575).
//!
//! The index is an SQLite file with a rollback journal, so a commit needs the
//! file to itself: while any reader is inside a statement, the committer holds
//! the PENDING lock and every new reader is turned away. Two rules keep one
//! side from starving the other:
//!
//! - an open of an index that is already current takes no write reservation
//!   (even an empty write transaction needs that exclusive lock to commit);
//!   it is checked in a read transaction, see [`current_index`];
//! - a long walk reads the calls in batches ([`super::matching::CallRows`]),
//!   so a builder commits between two batches instead of after the walk.
//!
//! A read that still meets a lock retries ([`retry_index_busy`]) and, after a
//! moment, tells the thread's waiter ([`with_index_wait`]) so a progress line
//! can say it is waiting rather than freeze.
use super::*;
use std::time::{Duration, Instant};

/// How long a read waits on a lock before its statement fails and is retried.
/// A builder's commit is short; the build's own 50 ms keeps its reservation
/// from blocking for long when another builder has it.
pub(super) const READ_BUSY: Duration = Duration::from_secs(2);

/// How long a read meets locks before its waiter is told.
const WAIT_REPORTED_AFTER: Duration = Duration::from_millis(500);

/// Told `true` when a read on this thread has waited on the index for a while,
/// `false` when it got in.
type IndexWait = Box<dyn Fn(bool)>;

thread_local! {
    static INDEX_WAIT: std::cell::RefCell<Option<IndexWait>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `read`; while a read of an archive index on this thread waits for
/// another reader or builder of the index, `report(true)` is called, and
/// `report(false)` once it gets in.
pub fn with_index_wait<R>(report: impl Fn(bool) + 'static, read: impl FnOnce() -> R) -> R {
    let previous = INDEX_WAIT.with(|slot| slot.borrow_mut().replace(Box::new(report)));
    let result = read();
    INDEX_WAIT.with(|slot| *slot.borrow_mut() = previous);
    result
}

fn report_wait(waiting: bool) {
    INDEX_WAIT.with(|slot| {
        if let Some(report) = slot.borrow().as_ref() {
            report(waiting);
        }
    });
}

fn busy(error: &RecordingError) -> bool {
    matches!(
        error,
        RecordingError::Index(error) if matches!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        )
    )
}

pub(super) fn retry_index_busy<T>(
    cancel: &AtomicBool,
    mut read: impl FnMut() -> Result<T, RecordingError>,
) -> Result<T, RecordingError> {
    let mut since: Option<Instant> = None;
    let mut reported = false;
    let result = loop {
        if cancel.load(Ordering::Relaxed) {
            break Err(RecordingError::Limit("archive read cancelled"));
        }
        match read() {
            // Index builds and queries share this cache. Only lock contention
            // is transient; retain real I/O, corruption and quota failures.
            Err(error) if busy(&error) => {
                let since = *since.get_or_insert_with(Instant::now);
                if !reported && since.elapsed() >= WAIT_REPORTED_AFTER {
                    reported = true;
                    report_wait(true);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            result => break result,
        }
    };
    if reported {
        report_wait(false);
    }
    result
}

/// The point an index can be resumed from for the archive `identity` of
/// `length` bytes, or `None` when it is to be built again: another archive,
/// another layout, a cursor past the end, or an index an older build wrote.
pub(super) fn resume_point(
    connection: &rusqlite::Connection,
    identity: &str,
    length: u64,
) -> Result<Option<u64>, RecordingError> {
    // An index written before the `writer` stamp existed has no such column.
    let stamped: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('indexed') WHERE name='writer'",
        [],
        |row| row.get(0),
    )?;
    if stamped == 0 {
        return Ok(None);
    }
    let cached: Option<(String, i64, Option<i64>)> = connection
        .query_row(
            "SELECT identity,length,writer FROM indexed LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    // An older build resumes any index without looking at its layout and
    // appends rows of its own kind; it also rewrites the cursor row without
    // the writer stamp, so such an index is rebuilt.
    Ok(cached
        .filter(|(cached, indexed, writer)| {
            cached == identity
                && *indexed as u64 <= length
                && version == INDEX_VERSION
                && *writer == Some(INDEX_VERSION)
        })
        .map(|(_, indexed, _)| indexed as u64))
}

/// Whether the secondary indexes a finished build creates are there.
pub(super) fn finished_build(connection: &rusqlite::Connection) -> Result<bool, RecordingError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN \
         ('invocation_order','invocation_process','packet_events')",
        [],
        |row| row.get(0),
    )?;
    Ok(count == 3)
}

/// Whether a whole packet starts at `start` and ends within `length`: the
/// index has something to add. A recording that ends inside a packet (one
/// cut off while being written) has none after its last whole packet.
fn packet_after(
    directory: &Path,
    raw: &Path,
    start: u64,
    length: u64,
) -> Result<bool, RecordingError> {
    let mut reader = BufReader::new(archive_io::open_regular(directory, raw)?);
    reader.seek(SeekFrom::Start(start))?;
    match next_packet(&mut reader) {
        Ok(Some(_)) => Ok(reader.stream_position()? <= length),
        Ok(None) => Ok(false),
        Err(RecordingError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// The archive's identity when the index already holds every whole packet of
/// it, read in a read transaction: no write reservation, so an open of a
/// current index never waits for the readers of it. `None` when the index
/// is to be built, extended or rebuilt.
pub(super) fn current_index(
    connection: &mut rusqlite::Connection,
    directory: &Path,
    raw: &Path,
) -> Result<Option<String>, RecordingError> {
    let transaction = connection.transaction()?;
    let (identity, length) = raw_identity(raw)?;
    let Some(start) = resume_point(&transaction, &identity, length)? else {
        return Ok(None);
    };
    let current = start == length
        || (finished_build(&transaction)? && !packet_after(directory, raw, start, length)?);
    // Read only: dropping it ends the read transaction.
    drop(transaction);
    Ok(current.then_some(identity))
}
