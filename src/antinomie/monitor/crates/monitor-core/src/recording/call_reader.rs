// SPDX-License-Identifier: GPL-3.0-only
//! Assembles the saved evidence of one call from the packet index.
//!
//! A call's entry, exit, task end and kernel notes are always read. Its async observations
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
/// Most lifecycle records read for a key that has no call (a launch).
const LIFECYCLE_EVENTS: usize = 64;
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
    pub(super) fn new(objects: PathBuf, arch: crate::api::GuestArch) -> Self {
        let mut assembler = Assembler::archive_checked(objects);
        assembler.set_arch(arch);
        Self {
            assembler,
            latest: BTreeMap::new(),
            size: 0,
        }
    }

    fn key_of(phase: u8, event_seq: u64) -> (u8, u64) {
        (phase, if phase == 3 { event_seq } else { 0 })
    }

    /// Take out the summary kept for the event `packet` belongs to, so the
    /// assembler can extend its own list in place: while a copy is kept, every
    /// packet of an event with thousands of fields would copy them all.
    fn take(&mut self, packet: &[u8]) -> Option<((u8, u64), EventSummary)> {
        let (header, _) = parser::parse_packet(packet).ok()?;
        let key = Self::key_of(header.phase, header.event_seq);
        let event = self.latest.remove(&key)?;
        self.size = self.size.saturating_sub(event_preview_size(&event));
        Some((key, event))
    }

    /// Keep what [`Self::take`] took out when the packet gave no newer one.
    fn restore(&mut self, taken: Option<((u8, u64), EventSummary)>) {
        if let Some((key, event)) = taken {
            self.size = self.size.saturating_add(event_preview_size(&event));
            self.latest.insert(key, event);
        }
    }

    fn put(&mut self, event: EventSummary) -> Result<(), RecordingError> {
        let key = Self::key_of(event.phase, event.event_seq);
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
    /// Sequences of the credential and hash records.
    notes: rusqlite::Statement<'a>,
    /// Sequences of every lifecycle record, for a key with no call.
    lifecycle: rusqlite::Statement<'a>,
    /// The packets of one observation.
    event: rusqlite::Statement<'a>,
    /// Packets of async observations from a sequence on, in event order.
    window: rusqlite::Statement<'a>,
    /// Distinct async observations of a call.
    saved: rusqlite::Statement<'a>,
}

/// Bytes of the raw archive read at once. A walk reads calls in archive
/// order, so most packets are in a window an earlier one loaded.
const WINDOW_SIZE: usize = 256 * 1024;
/// Windows kept: a call's exit or async records may lie far past its entry
/// (a call that blocked), and one window would be read again for every call
/// after it, back and forth (ANT-T0612: the copies were a fifth of a scan).
const WINDOWS: usize = 4;

/// The raw archive and the objects it was recorded with.
struct Source {
    objects: PathBuf,
    /// The guest's architecture: the records' calls are its ids.
    arch: crate::api::GuestArch,
    file: File,
    /// Archive bytes from each window's start, each read with one
    /// positioned read; the most recently used last.
    windows: Vec<(u64, Vec<u8>)>,
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
        let prefix = self.bytes(offset, 4)?;
        let size = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
        if !(128..=262112).contains(&size) {
            return Err(RecordingError::Limit("invalid raw packet length"));
        }
        let packet = self.bytes(offset + 4, size)?;
        if invocation_key(packet).map(key_blob).as_deref() != Some(key) {
            return Err(RecordingError::Limit("indexed packet identity changed"));
        }
        let packet = packet.to_vec();
        let taken = preview.take(&packet);
        match preview.assembler.ingest(&packet) {
            Ok(Some(event)) => preview.put(event)?,
            Ok(None) => preview.restore(taken),
            Err(error) => {
                preview.restore(taken);
                push_issue(&mut self.issues, error.to_string());
            }
        }
        Ok(())
    }

    /// `len` archive bytes at `offset`, all inside the indexed boundary.
    fn bytes(&mut self, offset: u64, len: usize) -> Result<&[u8], RecordingError> {
        let end = offset
            .checked_add(len as u64)
            .ok_or(RecordingError::Limit("raw packet extent overflows"))?;
        if end > self.boundary {
            return Err(if offset >= self.boundary {
                RecordingError::Limit("indexed packet is missing")
            } else {
                RecordingError::Limit("indexed packet exceeds retained boundary")
            });
        }
        let held = self
            .windows
            .iter()
            .position(|(start, bytes)| offset >= *start && end <= *start + bytes.len() as u64);
        let at = match held {
            Some(at) => at,
            None => {
                use std::os::unix::fs::FileExt;
                let want = (self.boundary - offset).min(WINDOW_SIZE.max(len) as u64) as usize;
                let mut bytes = if self.windows.len() >= WINDOWS {
                    self.windows.remove(0).1
                } else {
                    Vec::new()
                };
                bytes.resize(want, 0);
                self.file.read_exact_at(&mut bytes, offset)?;
                self.windows.push((offset, bytes));
                self.windows.len() - 1
            }
        };
        let last = self.windows.len() - 1;
        if at != last {
            let window = self.windows.remove(at);
            self.windows.push(window);
        }
        let (start, bytes) = &self.windows[last];
        let from = (offset - start) as usize;
        Ok(&bytes[from..from + len])
    }
}

/// Assembles one indexed call at a time from its packets.
pub(super) struct CallReader<'a> {
    connection: &'a rusqlite::Connection,
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

/// A read transaction that ends when it goes out of scope, when the
/// connection was not in one already.
struct ReadTransaction<'a>(Option<&'a rusqlite::Connection>);

impl<'a> ReadTransaction<'a> {
    fn begin(connection: &'a rusqlite::Connection) -> Self {
        // Cached statements: a walk begins one per call, and parsing the
        // text each time was a share of its cost of its own.
        let begun = connection.is_autocommit()
            && connection
                .prepare_cached("BEGIN DEFERRED")
                .and_then(|mut begin| begin.execute([]))
                .is_ok();
        Self(begun.then_some(connection))
    }
}

impl Drop for ReadTransaction<'_> {
    fn drop(&mut self) {
        if let Some(connection) = self.0 {
            // A read transaction has nothing to keep; its end only lets go.
            let _ = connection
                .prepare_cached("ROLLBACK")
                .and_then(|mut rollback| rollback.execute([]));
        }
    }
}

const NOT_LIFECYCLE: &str =
    "NOT EXISTS (SELECT 1 FROM lifecycle l WHERE l.key=p.key AND l.seq=p.seq)";

impl<'a> CallReader<'a> {
    pub(super) fn open(
        directory: &Path,
        connection: &'a rusqlite::Connection,
        boundary: u64,
        arch: crate::api::GuestArch,
    ) -> Result<Self, RecordingError> {
        let objects = directory.join("objects");
        // The packed objects' index is checked once in this page.
        crate::object_pack::next_read_epoch();
        // One check of the objects directory for the whole read.
        Assembler::open_archive(objects.clone())
            .map_err(|_| RecordingError::Limit("cannot open archived objects"))?;
        let file = archive_io::open_regular(directory, &directory.join("telemetry.raw"))?;
        Ok(Self {
            connection,
            queries: Queries {
                ends: connection.prepare(
                    "SELECT offset FROM packets WHERE key=?1 AND phase<3 AND offset<?2 \
                     ORDER BY offset",
                )?,
                exits: connection.prepare(&format!(
                    "SELECT seq FROM lifecycle WHERE key=?1 AND task_exit=1 \
                     ORDER BY seq LIMIT {TASK_EXITS}"
                ))?,
                notes: connection.prepare(&format!(
                    "SELECT seq FROM lifecycle WHERE key=?1 AND task_exit=2 \
                     ORDER BY seq LIMIT {}",
                    crate::kernel_notes::NOTES_PER_CALL
                ))?,
                lifecycle: connection.prepare(&format!(
                    "SELECT seq FROM lifecycle WHERE key=?1 ORDER BY seq LIMIT {LIFECYCLE_EVENTS}"
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
                arch,
                file,
                windows: Vec::new(),
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
        Preview::new(self.source.objects.clone(), self.source.arch)
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

    /// The lifecycle records under `key` (at most [`LIFECYCLE_EVENTS`]), in
    /// event order: for a key no call owns, such as a run's launch.
    pub(super) fn lifecycle(
        &mut self,
        key: &[u8],
        cancel: &AtomicBool,
    ) -> Result<Vec<EventSummary>, RecordingError> {
        let mut preview = self.preview();
        let boundary = self.source.boundary as i64;
        let sequences = self
            .queries
            .lifecycle
            .query_map([key], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for seq in sequences {
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
        Ok(preview
            .latest
            .into_values()
            .filter(|event| event.phase == 3)
            .collect())
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
        // One read transaction for the call's lookups: each statement of its
        // own took the file's lock, checked it for a journal and read its
        // change counter again, a few times for every call of a walk
        // (ANT-T0588). The transaction ends with the call, so a builder of
        // the index waits for no more than one call.
        let _read = ReadTransaction::begin(self.connection);
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
        let mut exits = self
            .queries
            .exits
            .query_map([key], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        exits.extend(
            self.queries
                .notes
                .query_map([key], |row| row.get::<_, i64>(0))?
                .collect::<Result<Vec<_>, _>>()?,
        );
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
