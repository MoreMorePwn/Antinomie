// SPDX-License-Identifier: MIT
//! Assembles the saved evidence of one call from the packet index.
//!
//! A call's entry, exit and task end are always read. Its async observations
//! are read in event order, a bounded window at a time: the first
//! [`ASYNC_PREVIEW_LIMIT`] for the call's preview, any later window for
//! [`Recording::async_page_cancellable`]. Reads follow the index, so a call
//! with thousands of completions costs its window, not its packet count.
use super::*;
use std::collections::BTreeMap;

/// Page diagnostic for calls whose async observations are only previewed.
pub(super) const ASYNC_PARTIAL: &str = "some calls list only the first 256 of their saved async observations; browse the rest, raw records retained";

/// Most task-end records read for one call. A task ends once; the bound
/// keeps a damaged recording from growing a preview.
const TASK_EXITS: usize = 4;
/// Largest preview of one call; larger means the evidence is too big to show.
const CALL_PREVIEW_BYTES: usize = 32 * 1024 * 1024;

/// The latest summary of each event read so far, with its preview size.
pub(super) struct Preview {
    assembler: Assembler,
    /// By phase and, for observations, event sequence.
    pub(super) latest: BTreeMap<(u8, u64), EventSummary>,
    size: usize,
}

impl Preview {
    pub(super) fn new(objects: PathBuf) -> Self {
        Self {
            assembler: Assembler::archive_checked(objects),
            latest: BTreeMap::new(),
            size: 0,
        }
    }

    fn put(&mut self, event: EventSummary) -> Result<(), RecordingError> {
        let key = (
            event.phase,
            if event.phase == 3 { event.event_seq } else { 0 },
        );
        let added = event_preview_size(&event);
        let previous = self.latest.insert(key, event);
        self.size = self
            .size
            .saturating_sub(previous.as_ref().map_or(0, event_preview_size))
            .saturating_add(added);
        if self.size > CALL_PREVIEW_BYTES {
            return Err(RecordingError::Limit(
                "archive invocation previews exceed 32 MiB; raw records retained",
            ));
        }
        Ok(())
    }
}

/// The index lookups of a call. Statements are prepared once per read.
struct Queries<'a> {
    /// Entry and exit packets, by offset.
    ends: rusqlite::Statement<'a>,
    /// Sequences of the records that end the task.
    exits: rusqlite::Statement<'a>,
    /// The packets of one observation.
    event: rusqlite::Statement<'a>,
    /// Packets of async observations from a sequence on, in event order.
    window: rusqlite::Statement<'a>,
    /// Distinct async observations of a call.
    saved: rusqlite::Statement<'a>,
}

/// The raw archive and the objects it was recorded with.
struct Source {
    objects: PathBuf,
    reader: BufReader<File>,
    boundary: u64,
    issues: Vec<String>,
}

impl Source {
    /// Assemble the packet at `offset`, which must belong to `key`.
    fn ingest(
        &mut self,
        key: &[u8],
        offset: i64,
        preview: &mut Preview,
    ) -> Result<(), RecordingError> {
        let offset = u64::try_from(offset)
            .map_err(|_| RecordingError::Limit("negative cached packet offset"))?;
        self.reader.seek(SeekFrom::Start(offset))?;
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
        match preview.assembler.ingest(&packet) {
            Ok(Some(event)) => preview.put(event)?,
            Ok(None) => {}
            Err(error) => push_issue(&mut self.issues, error.to_string()),
        }
        Ok(())
    }
}

/// Assembles one indexed call at a time from its packets.
pub(super) struct CallReader<'a> {
    queries: Queries<'a>,
    source: Source,
}

/// The async observations a window read and where the next one starts.
pub(super) struct Window {
    /// Index form of the next observation's sequence; `None` at the end.
    pub(super) next: Option<i64>,
    /// Observations read.
    pub(super) seen: usize,
}

const NOT_LIFECYCLE: &str =
    "NOT EXISTS (SELECT 1 FROM lifecycle l WHERE l.key=p.key AND l.seq=p.seq)";

impl<'a> CallReader<'a> {
    pub(super) fn open(
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
            queries: Queries {
                ends: connection.prepare(
                    "SELECT offset FROM packets WHERE key=?1 AND phase<3 AND offset<?2 \
                     ORDER BY offset",
                )?,
                exits: connection.prepare(&format!(
                    "SELECT seq FROM lifecycle WHERE key=?1 AND task_exit=1 \
                     ORDER BY seq LIMIT {TASK_EXITS}"
                ))?,
                event: connection.prepare(
                    "SELECT offset FROM packets WHERE key=?1 AND phase=3 AND seq=?2 \
                     AND offset<?3 ORDER BY offset",
                )?,
                window: connection.prepare(&format!(
                    "SELECT seq,offset FROM packets p WHERE key=?1 AND phase=3 AND seq>=?2 \
                     AND offset<?3 AND {NOT_LIFECYCLE} ORDER BY seq,offset"
                ))?,
                saved: connection.prepare(&format!(
                    "SELECT COUNT(DISTINCT seq) FROM packets p WHERE key=?1 AND phase=3 \
                     AND offset<?2 AND {NOT_LIFECYCLE}"
                ))?,
            },
            source: Source {
                objects,
                // Packets are read at scattered offsets: a small buffer.
                reader: BufReader::with_capacity(1024, file),
                boundary,
                issues: Vec::new(),
            },
        })
    }

    /// Diagnostics from the reads so far.
    pub(super) fn take_issues(&mut self) -> Vec<String> {
        std::mem::take(&mut self.source.issues)
    }

    pub(super) fn preview(&self) -> Preview {
        Preview::new(self.source.objects.clone())
    }

    /// Read at most `limit` async observations of `key` from sequence `from`
    /// (index form) on, in event order. Cancellation is checked per packet.
    pub(super) fn window(
        &mut self,
        key: &[u8],
        from: i64,
        limit: usize,
        preview: &mut Preview,
        cancel: &AtomicBool,
    ) -> Result<Window, RecordingError> {
        let mut rows =
            self.queries
                .window
                .query(rusqlite::params![key, from, self.source.boundary as i64])?;
        let mut window = Window {
            next: None,
            seen: 0,
        };
        let mut current = None;
        while let Some(row) = rows.next()? {
            if cancel.load(Ordering::Relaxed) {
                return Err(RecordingError::Limit("archive read cancelled"));
            }
            let (seq, offset): (i64, i64) = (row.get(0)?, row.get(1)?);
            if current != Some(seq) {
                if window.seen == limit {
                    window.next = Some(seq);
                    break;
                }
                window.seen += 1;
                current = Some(seq);
            }
            self.source.ingest(key, offset, preview)?;
        }
        Ok(window)
    }

    /// Distinct async observations the index holds for `key`.
    pub(super) fn saved(&mut self, key: &[u8]) -> Result<u64, RecordingError> {
        let count: i64 = self
            .queries
            .saved
            .query_row(rusqlite::params![key, self.source.boundary as i64], |row| {
                row.get(0)
            })?;
        u64::try_from(count).map_err(|_| RecordingError::Limit("negative observation count"))
    }

    /// The call under `key` as the ordinary archive page shows it; `None`
    /// when its packets pair into no call (lifecycle-only observations).
    ///
    /// Entry, exit and the task end are always read, wherever they fall among
    /// the call's records. The async preview is the first
    /// [`ASYNC_PREVIEW_LIMIT`] observations; the call says how many more were
    /// saved.
    pub(super) fn call(
        &mut self,
        key: &[u8],
        cancel: &AtomicBool,
    ) -> Result<Option<InvocationSummary>, RecordingError> {
        let mut preview = self.preview();
        let boundary = self.source.boundary as i64;
        let mut rows = self.queries.ends.query(rusqlite::params![key, boundary])?;
        while let Some(row) = rows.next()? {
            if cancel.load(Ordering::Relaxed) {
                return Err(RecordingError::Limit("archive read cancelled"));
            }
            self.source.ingest(key, row.get(0)?, &mut preview)?;
        }
        drop(rows);
        let exits = self
            .queries
            .exits
            .query_map([key], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for seq in exits {
            let mut rows = self
                .queries
                .event
                .query(rusqlite::params![key, seq, boundary])?;
            while let Some(row) = rows.next()? {
                if cancel.load(Ordering::Relaxed) {
                    return Err(RecordingError::Limit("archive read cancelled"));
                }
                self.source.ingest(key, row.get(0)?, &mut preview)?;
            }
        }
        let window = self.window(key, i64::MIN, ASYNC_PREVIEW_LIMIT, &mut preview, cancel)?;
        // A window that ran out of observations has seen every saved one.
        let saved = match window.next {
            Some(_) => self.saved(key)?,
            None => window.seen as u64,
        };
        let events: Vec<_> = preview.latest.into_values().collect();
        let Some(mut call) = pair_events(&events).into_iter().next() else {
            return Ok(None);
        };
        // Pairing leaves out records that are not async observations; they
        // were read but are not part of the count.
        let unpaired = (window.seen as u64).saturating_sub(call.async_events.len() as u64);
        call.async_saved = saved.saturating_sub(unpaired);
        Ok(Some(call))
    }
}
