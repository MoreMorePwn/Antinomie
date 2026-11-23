// SPDX-License-Identifier: GPL-3.0-only
//! What a recording that is still being written changed since an earlier read
//! (ANT-T0602). Triage refreshes a live run from a snapshot of its scan: the
//! calls before the snapshot must read back exactly as they did. A call is read
//! from the packets of its key below the indexed boundary, so a call whose key
//! gained no packet at or after the earlier boundary reads back the same.
use super::*;

/// The index of a recording now, and the calls that gained records since an
/// earlier boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Growth {
    /// The raw file as a file (device and inode): another file is another recording.
    pub identity: String,
    /// Bytes of the raw file the index holds.
    pub boundary: u64,
    /// The first record of the earliest call that began before the earlier
    /// boundary and gained a record at or after it; `None` when none did.
    pub earliest_changed: Option<u64>,
    /// Tasks (stream, task cookie) whose observations attributed to the task
    /// itself (call id 0: an SQPOLL ring's requests) gained records.
    pub attributed: std::collections::BTreeSet<(u64, u64)>,
}

impl Recording {
    /// The index's identity and boundary now, after adding what was appended.
    pub fn indexed_extent(&self, cancel: &AtomicBool) -> Result<(String, u64), RecordingError> {
        retry_index_busy(cancel, || {
            let (connection, identity) = archive_index(&self.directory, cancel)?;
            Ok((identity, matching::indexed_boundary(&connection)?))
        })
    }

    /// The raw offset of the first record of call `key`; `None` when the
    /// index has no such call.
    pub fn call_offset(
        &self,
        key: (u64, u64, u64),
        cancel: &AtomicBool,
    ) -> Result<Option<u64>, RecordingError> {
        retry_index_busy(cancel, || {
            let (connection, _) = archive_index(&self.directory, cancel)?;
            let offset: Option<i64> = connection
                .query_row(
                    "SELECT first_offset FROM invocations WHERE key=?1",
                    [key_blob(key)],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(offset.and_then(|offset| u64::try_from(offset).ok()))
        })
    }

    /// What gained records at or after raw offset `since` (an earlier
    /// [`Self::indexed_extent`] boundary of the same file).
    pub fn growth_since(&self, since: u64, cancel: &AtomicBool) -> Result<Growth, RecordingError> {
        retry_index_busy(cancel, || {
            let (connection, identity) = archive_index(&self.directory, cancel)?;
            let boundary = matching::indexed_boundary(&connection)?;
            let mut growth = Growth {
                identity,
                boundary,
                ..Growth::default()
            };
            let since =
                i64::try_from(since).map_err(|_| RecordingError::Limit("cursor too large"))?;
            let Some(first) = first_packet_at(&connection, since)? else {
                return Ok(growth);
            };
            let mut keys =
                connection.prepare("SELECT DISTINCT key FROM packets WHERE rowid>=?1")?;
            let mut call =
                connection.prepare("SELECT first_offset FROM invocations WHERE key=?1")?;
            let mut rows = keys.query([first])?;
            while let Some(row) = rows.next()? {
                if cancel.load(Ordering::Relaxed) {
                    return Err(RecordingError::Limit("archive read cancelled"));
                }
                let key: Vec<u8> = row.get(0)?;
                if key.len() == 24 && key[16..] == [0; 8] {
                    let word = |at: usize| {
                        u64::from_le_bytes(key[at..at + 8].try_into().unwrap_or_default())
                    };
                    growth.attributed.insert((word(0), word(8)));
                    continue;
                }
                let offset: Option<i64> = call.query_row([&key], |row| row.get(0)).optional()?;
                if let Some(offset) = offset.filter(|offset| *offset < since) {
                    let offset = offset as u64;
                    growth.earliest_changed = Some(
                        growth
                            .earliest_changed
                            .map_or(offset, |earliest| earliest.min(offset)),
                    );
                }
            }
            Ok(growth)
        })
    }
}

/// The row id of the first indexed packet at or after raw offset `since`.
/// The index adds packets in file order (a build and each extension read the
/// file forward from its cursor), so offsets grow with the row id and a
/// binary search over row ids finds it without reading the table.
fn first_packet_at(
    connection: &rusqlite::Connection,
    since: i64,
) -> Result<Option<i64>, RecordingError> {
    let mut at = connection
        .prepare("SELECT rowid, offset FROM packets WHERE rowid>=?1 ORDER BY rowid LIMIT 1")?;
    let mut packet = |rowid: i64| -> Result<Option<(i64, i64)>, RecordingError> {
        Ok(at
            .query_row([rowid], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?)
    };
    let last: Option<i64> =
        connection.query_row("SELECT MAX(rowid) FROM packets", [], |row| row.get(0))?;
    let Some(last) = last else {
        return Ok(None);
    };
    match packet(last)? {
        Some((_, offset)) if offset >= since => {}
        _ => return Ok(None),
    }
    // `best` is the first such row at or after `high`; the search narrows
    // [low, high) to the rows before it.
    let (mut low, mut high, mut best) = (0i64, last, last);
    while low < high {
        let middle = low + (high - low) / 2;
        match packet(middle)? {
            Some((rowid, offset)) if offset >= since => {
                best = best.min(rowid);
                high = middle;
            }
            Some((rowid, _)) => low = rowid + 1,
            None => break,
        }
    }
    Ok(Some(best))
}
