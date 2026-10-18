//! A matching page of the invocation list and its totals, as separate reads.
//!
//! A page seeks to its cursor in the packet index and stops after the calls
//! it shows, so its cost follows the page, not the recording. The totals walk
//! every call once; callers run them off the interactive path and keep the
//! answer for the same recording, filter and indexed length.
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

/// Assembles one indexed call at a time from its packets.
struct CallReader<'a> {
    objects: PathBuf,
    reader: BufReader<File>,
    packets: rusqlite::Statement<'a>,
    boundary: u64,
    issues: Vec<String>,
}

impl<'a> CallReader<'a> {
    fn open(
        directory: &Path,
        connection: &'a rusqlite::Connection,
        boundary: u64,
    ) -> Result<Self, RecordingError> {
        let objects = directory.join("objects");
        // One check of the objects directory for the whole read.
        Assembler::open_archive(objects.clone())
            .map_err(|_| RecordingError::Limit("cannot open archived objects"))?;
        let file = archive_io::open_regular(directory, &directory.join("telemetry.raw"))?;
        Ok(Self {
            objects,
            // Packets are read at scattered offsets: a small buffer.
            reader: BufReader::with_capacity(1024, file),
            packets: connection
                .prepare("SELECT offset FROM packets WHERE key=?1 AND offset<?2 ORDER BY offset")?,
            boundary,
            issues: Vec::new(),
        })
    }

    /// The call under `key` as the ordinary archive page shows it; `None`
    /// when its packets pair into no call (lifecycle-only observations).
    fn call(
        &mut self,
        key: &[u8],
        cancel: &AtomicBool,
    ) -> Result<Option<InvocationSummary>, RecordingError> {
        let mut assembler = Assembler::archive_checked(self.objects.clone());
        let mut latest = std::collections::BTreeMap::new();
        let mut preview_size = 0_usize;
        let offsets = self
            .packets
            .query_map(rusqlite::params![key, self.boundary as i64], |row| {
                row.get::<_, i64>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for packet_offset in offsets {
            if cancel.load(Ordering::Relaxed) {
                return Err(RecordingError::Limit("archive read cancelled"));
            }
            let packet_offset = u64::try_from(packet_offset)
                .map_err(|_| RecordingError::Limit("negative cached packet offset"))?;
            self.reader.seek(SeekFrom::Start(packet_offset))?;
            let (_, packet) = next_packet(&mut self.reader)?
                .ok_or(RecordingError::Limit("indexed packet is missing"))?;
            if self.reader.stream_position()? > self.boundary {
                return Err(RecordingError::Limit(
                    "indexed packet exceeds retained boundary",
                ));
            }
            if invocation_key(&packet).map(key_blob).as_deref() != Some(key) {
                return Err(RecordingError::Limit("indexed packet identity changed"));
            }
            match assembler.ingest(&packet) {
                Ok(Some(event)) => {
                    let event_key = (
                        event.phase,
                        if event.phase == 3 { event.event_seq } else { 0 },
                    );
                    let event_size = event_preview_size(&event);
                    let previous = latest.insert(event_key, event);
                    preview_size = preview_size
                        .saturating_sub(previous.as_ref().map_or(0, event_preview_size))
                        .saturating_add(event_size);
                    if latest.len() > 2048 {
                        // Preserve entry/exit and task-exit evidence; ordinary
                        // async summaries retain their existing bounded preview.
                        let remove = latest
                            .iter()
                            .rev()
                            .find(|(key, event)| {
                                key.0 == 3
                                    && !event
                                        .fields
                                        .iter()
                                        .any(|field| field.key == "lifecycle.task_exit")
                            })
                            .map(|(key, _)| *key)
                            .or_else(|| latest.keys().next().copied());
                        if let Some(remove) = remove
                            && let Some(removed) = latest.remove(&remove)
                        {
                            preview_size =
                                preview_size.saturating_sub(event_preview_size(&removed));
                        }
                        let omitted =
                            "additional archive event previews omitted; raw records retained";
                        if self.issues.len() < 32
                            && !self.issues.iter().any(|issue| issue == omitted)
                        {
                            self.issues.push(omitted.into());
                        }
                    }
                    if preview_size > 32 * 1024 * 1024 {
                        return Err(RecordingError::Limit(
                            "archive invocation previews exceed 32 MiB; raw records retained",
                        ));
                    }
                }
                Ok(None) => {}
                Err(error) if self.issues.len() < 32 => self.issues.push(error.to_string()),
                Err(_) => {}
            }
        }
        let events: Vec<_> = latest.into_values().collect();
        Ok(pair_events(&events).into_iter().next())
    }
}

fn indexed_boundary(connection: &rusqlite::Connection) -> Result<u64, RecordingError> {
    let boundary: i64 =
        connection.query_row("SELECT length FROM indexed LIMIT 1", [], |row| row.get(0))?;
    u64::try_from(boundary).map_err(|_| RecordingError::Limit("negative indexed boundary"))
}

fn call_rows(connection: &rusqlite::Connection) -> Result<rusqlite::Statement<'_>, RecordingError> {
    Ok(connection.prepare(
        "SELECT key,first_offset FROM invocations WHERE first_offset>=?1 AND first_offset<?2 \
         AND (?3 IS NULL OR pid=?3) ORDER BY first_offset",
    )?)
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
        mut keep: impl FnMut(&InvocationSummary) -> bool,
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
        let mut reader = CallReader::open(&self.directory, &connection, boundary)?;
        let mut query = call_rows(&connection)?;
        let mut rows = query.query(rusqlite::params![
            i64::try_from(offset).map_err(|_| RecordingError::Limit("cursor too large"))?,
            boundary as i64,
            pid
        ])?;
        let mut invocations = Vec::with_capacity(limit);
        let mut next_offset = None;
        let mut page_preview_size = 0_usize;
        while let Some(row) = rows.next()? {
            if cancel.load(Ordering::Relaxed) {
                return Err(RecordingError::Limit("archive read cancelled"));
            }
            let key: Vec<u8> = row.get(0)?;
            let first_offset = u64::try_from(row.get::<_, i64>(1)?)
                .map_err(|_| RecordingError::Limit("negative cached invocation offset"))?;
            let Some(invocation) = reader.call(&key, cancel)? else {
                continue;
            };
            if !keep(&invocation) {
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
            page_preview_size = page_preview_size.saturating_add(size);
            if page_preview_size > 64 * 1024 * 1024 {
                return Err(RecordingError::Limit(
                    "archive page previews exceed 64 MiB; raw records retained",
                ));
            }
            invocations.push(invocation);
        }
        let issues = std::mem::take(&mut reader.issues);
        drop(rows);
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
        let mut reader = CallReader::open(&self.directory, &connection, boundary)?;
        let mut query = call_rows(&connection)?;
        let mut rows = query.query(rusqlite::params![0_i64, boundary as i64, pid])?;
        let (mut total, mut source_total) = (0_u64, 0_u64);
        while let Some(row) = rows.next()? {
            if cancel.load(Ordering::Relaxed) {
                return Err(RecordingError::Limit("archive read cancelled"));
            }
            let key: Vec<u8> = row.get(0)?;
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
        drop(rows);
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
