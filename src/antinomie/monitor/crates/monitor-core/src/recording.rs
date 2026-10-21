//! Reopen finalized captures and inspect only byte ranges known to be received.
use crate::{
    api::*,
    archive_io,
    parser::{self, Assembler},
    storage,
};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    fs::{self, File},
    io::{BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub enum RecordingError {
    Io(std::io::Error),
    Format(serde_json::Error),
    Limit(&'static str),
    MissingRange,
    Index(rusqlite::Error),
}
impl std::fmt::Display for RecordingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "recording I/O: {e}"),
            Self::Format(e) => write!(f, "recording format: {e}"),
            Self::Limit(e) => f.write_str(e),
            Self::MissingRange => f.write_str("requested range includes missing capture bytes"),
            Self::Index(e) => write!(f, "archive index: {e}; saved raw archive retained"),
        }
    }
}
impl std::error::Error for RecordingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Format(e) => Some(e),
            Self::Index(e) => Some(e),
            _ => None,
        }
    }
}
impl From<rusqlite::Error> for RecordingError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Index(e)
    }
}
impl From<std::io::Error> for RecordingError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for RecordingError {
    fn from(e: serde_json::Error) -> Self {
        Self::Format(e)
    }
}

/// Most processes a recorded tree lists. A busier recording lists the first
/// ones and reports that the rest were left out.
pub const PROCESS_TREE_LIMIT: usize = 262_144;

mod async_page;
mod call_reader;
mod index_cache;
mod issues;
use issues::push_issue;
mod launch;
pub use launch::LaunchRecord;
mod segments;
pub use segments::{RunSegment, run_segments};
mod facts;
pub use facts::{RunFilterFacts, run_filter_facts};
mod matching;
pub use matching::{ArchiveStamp, MatchTotals, MatchingPage};

pub struct Recording {
    pub directory: PathBuf,
    pub manifest: serde_json::Value,
    pub events: Vec<EventSummary>,
}

/// A bounded matching page of the retained invocation stream.
///
/// | Field | Meaning |
/// | --- | --- |
/// | `page` | At most the requested number of matching calls and a stable next raw cursor |
/// | `total` | Matching calls over the entire fixed retained prefix, including before the cursor |
/// | `source_total` | Reconstructed saved calls for the selected process before the predicate |
pub struct FilteredInvocationPage {
    pub page: InvocationPage,
    pub total: u64,
    pub source_total: u64,
}

fn event_preview_size(event: &EventSummary) -> usize {
    let mut size = std::mem::size_of::<EventSummary>().saturating_add(event.syscall_name.len());
    for issue in &event.issues {
        size = size.saturating_add(issue.len());
    }
    for field in &event.fields {
        size = size
            .saturating_add(std::mem::size_of::<FieldSummary>())
            .saturating_add(field.key.len())
            .saturating_add(field.layout.len())
            .saturating_add(field.preview.len())
            .saturating_add(
                field
                    .ranges
                    .len()
                    .saturating_mul(std::mem::size_of::<(u64, u64)>()),
            )
            .saturating_add(
                field
                    .raw_path
                    .as_ref()
                    .map_or(0, |path| path.as_os_str().as_encoded_bytes().len()),
            );
    }
    size
}

pub fn open_recording(directory: &Path) -> Result<Recording, RecordingError> {
    open_recording_cancellable(directory, &AtomicBool::new(false))
}
pub fn open_recording_cancellable(
    directory: &Path,
    cancel: &AtomicBool,
) -> Result<Recording, RecordingError> {
    if cancel.load(Ordering::Relaxed) {
        return Err(RecordingError::Limit("archive read cancelled"));
    }
    let directory = fs::canonicalize(directory)?;
    let manifest_file = archive_io::open_regular(&directory, Path::new("manifest.json"))?;
    if manifest_file.metadata()?.len() > 1024 * 1024 {
        return Err(RecordingError::Limit("manifest exceeds reader limit"));
    }
    let manifest = serde_json::from_reader(manifest_file)?;
    if directory.join("telemetry.raw").exists() {
        let mut recording = Recording {
            directory,
            manifest,
            events: Vec::new(),
        };
        recording.events = recording
            .invocation_page_cancellable(0, 128, cancel)?
            .invocations
            .into_iter()
            .flat_map(|row| {
                row.entry
                    .into_iter()
                    .chain(row.exit)
                    .chain(row.async_events)
            })
            .collect();
        return Ok(recording);
    }
    let events_file = archive_io::open_regular(&directory, Path::new("events.json"))?;
    if events_file.metadata()?.len() > 64 * 1024 * 1024 {
        return Err(RecordingError::Limit(
            "event summaries exceed reader limit; raw archive retained",
        ));
    }
    let events: Vec<EventSummary> = serde_json::from_reader(events_file)?;
    if events.len() > 2112
        || events.iter().any(|e| {
            e.fields.len() > parser::MAX_RETAINED_FIELDS
                || e.fields
                    .iter()
                    .any(|f| f.preview.len() > 256 || f.ranges.len() > 4096)
        })
    {
        return Err(RecordingError::Limit(
            "recording exceeds parser state limits",
        ));
    }
    Ok(Recording {
        directory,
        manifest,
        events,
    })
}

type InvocationKey = (u64, u64, u64);
fn invocation_key(packet: &[u8]) -> Option<InvocationKey> {
    packet_key(packet).map(|(_, key)| key)
}

/// The packet's header and the invocation it belongs to, if it belongs to one.
fn packet_key(packet: &[u8]) -> Option<(parser::Header, InvocationKey)> {
    let (header, _) = parser::parse_packet(packet).ok()?;
    let key = (header.record_type == 1 && matches!(header.phase, 1..=3)).then_some((
        header.stream_id,
        header.task_cookie,
        header.call_id,
    ))?;
    Some((header, key))
}

fn next_packet(reader: &mut BufReader<File>) -> Result<Option<(u64, Vec<u8>)>, RecordingError> {
    let offset = reader.stream_position()?;
    let mut prefix = [0; 4];
    let first = reader.read(&mut prefix)?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut prefix[first..])?;
    let size = u32::from_le_bytes(prefix) as usize;
    if !(128..=262112).contains(&size) {
        return Err(RecordingError::Limit("invalid raw packet length"));
    }
    let mut packet = vec![0; size];
    reader.read_exact(&mut packet)?;
    Ok(Some((offset, packet)))
}

fn key_blob(key: InvocationKey) -> Vec<u8> {
    [
        key.0.to_le_bytes(),
        key.1.to_le_bytes(),
        key.2.to_le_bytes(),
    ]
    .concat()
}
/// The raw archive as a file: its device and inode, and its length. The
/// archive only grows while it is recorded, so the same file with more bytes
/// is the same archive.
fn raw_identity(path: &Path) -> Result<(String, u64), RecordingError> {
    let m = archive_io::open_regular(
        path.parent()
            .ok_or(RecordingError::Limit("raw archive has no directory"))?,
        path,
    )?
    .metadata()?;
    Ok((format!("index-v8:{}:{}", m.dev(), m.ino()), m.len()))
}
/// The packet index of a recording, kept in the user's cache. A recording
/// still being written (a run whose programs live on, a running capture) is
/// indexed as far as it goes; later reads add what was appended since.
fn archive_index(
    directory: &Path,
    cancel: &AtomicBool,
) -> Result<(rusqlite::Connection, String), RecordingError> {
    let mut repaired = false;
    retry_index_busy(cancel, || {
        match open_archive_index(directory, cancel) {
            // The cache is written without syncing; one damaged by a crash or
            // power loss is discarded and built again from the recording.
            Err(RecordingError::Index(error)) if !repaired && index_damaged(&error) => {
                let index_path = archive_index_path(directory)?;
                for suffix in ["", "-journal"] {
                    let mut path = index_path.clone().into_os_string();
                    path.push(suffix);
                    let _ = fs::remove_file(PathBuf::from(path));
                }
                repaired = true;
                open_archive_index(directory, cancel)
            }
            result => result,
        }
    })
}

fn retry_index_busy<T>(
    cancel: &AtomicBool,
    mut read: impl FnMut() -> Result<T, RecordingError>,
) -> Result<T, RecordingError> {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(RecordingError::Limit("archive read cancelled"));
        }
        match read() {
            Err(RecordingError::Index(error))
                if matches!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                ) =>
            {
                // Index builds and queries share this cache. Only lock contention
                // is transient; retain real I/O, corruption and quota failures.
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

fn index_damaged(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase)
    )
}

/// Where the packet index of `directory` is cached.
fn archive_index_path(directory: &Path) -> Result<PathBuf, RecordingError> {
    let cache_root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cache")
        })
        .join("antinomie/browse");
    storage::private_dir(&cache_root)?;
    let digest = Sha256::digest(directory.as_os_str().as_encoded_bytes());
    let name = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok(cache_root.join(format!("{name}.sqlite")))
}

/// Layout of the cached packet index. 2: a lifecycle row's `task_exit` column
/// is a kind (see `async_page::LifecycleKind`), so credential and hash records
/// can be read back with their call; an index built before is rebuilt. Every
/// cursor row carries this number (`indexed.writer`): an older build that
/// appends to the index rewrites the row without it, which forces a rebuild.
const INDEX_VERSION: i64 = 2;

/// Bytes of the archive indexed per transaction. A first index of a large
/// archive commits at this pace, so a crash or a cancel keeps what was indexed
/// and the next open resumes from the cursor, and other readers are not held
/// off for the whole build.
const INDEX_CHUNK_BYTES: u64 = 256 * 1024 * 1024;

fn open_archive_index(
    directory: &Path,
    cancel: &AtomicBool,
) -> Result<(rusqlite::Connection, String), RecordingError> {
    index_archive(directory, cancel, INDEX_CHUNK_BYTES, usize::MAX)
}

/// Build or extend the packet index in transactions of about `chunk_bytes` of
/// archive each. `max_chunks` stops the build with an error after that many
/// committed chunks (a crash, for tests); a real build passes `usize::MAX`.
///
/// Dropping a stale index is a transaction of its own that leaves an empty,
/// stamped index with its cursor at zero. Every chunk reads the cursor again
/// under the write reservation, so a builder that waited for another one
/// continues after it instead of appending the same packets twice.
fn index_archive(
    directory: &Path,
    cancel: &AtomicBool,
    chunk_bytes: u64,
    max_chunks: usize,
) -> Result<(rusqlite::Connection, String), RecordingError> {
    let raw = directory.join("telemetry.raw");
    let index_path = archive_index_path(directory)?;
    let mut connection = rusqlite::Connection::open(&index_path)?;
    fs::set_permissions(&index_path, fs::Permissions::from_mode(0o600))?;
    connection.busy_timeout(std::time::Duration::from_millis(50))?;
    // The index is a cache rebuilt from the recording when it is missing or
    // stale, so its writes are not synced to disk: building it must not wait
    // for the disk behind a recording that is being saved.
    connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA page_size=4096; PRAGMA cache_size=-2048; PRAGMA temp_store=FILE; PRAGMA synchronous=OFF; CREATE TABLE IF NOT EXISTS indexed(identity TEXT NOT NULL, length INTEGER NOT NULL, writer INTEGER);")?;
    let mut chunks = 0;
    loop {
        // Own the writer reservation before reading the resume cursor.
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // An index written before the `writer` stamp existed has no such column.
        let stamped: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('indexed') WHERE name='writer'",
            [],
            |row| row.get(0),
        )?;
        if stamped == 0 {
            transaction.execute_batch("ALTER TABLE indexed ADD COLUMN writer INTEGER")?;
        }
        let (identity, length) = raw_identity(&raw)?;
        // Four times the archive: a pathological archive of tiny packets
        // indexes to more than twice its size, and hitting the cap would
        // rebuild the index on every open.
        let budget = length
            .checked_mul(4)
            .and_then(|size| size.checked_add(1024 * 1024))
            .ok_or(RecordingError::Limit("archive index budget overflow"))?
            .min(16 * 1024 * 1024 * 1024);
        transaction.pragma_update(None, "max_page_count", (budget / 4096) as i64)?;
        let cached: Option<(String, i64, Option<i64>)> = transaction
            .query_row(
                "SELECT identity,length,writer FROM indexed LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        // Go on from where the index stopped, unless the archive is another
        // file (or, impossibly for an append-only archive, shorter).
        let version: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let resume = cached
            .filter(|(cached, indexed, writer)| {
                // An older build resumes any index without looking at its
                // layout and appends rows of its own kind; it also rewrites
                // the cursor row without the writer stamp, so such an index is
                // rebuilt.
                *cached == identity
                    && *indexed as u64 <= length
                    && version == INDEX_VERSION
                    && *writer == Some(INDEX_VERSION)
            })
            .map(|(_, indexed, _)| indexed as u64);
        let Some(start) = resume else {
            // Rebuilt from scratch: an index from an older version has another
            // schema. The secondary indexes are built once the rows are in:
            // faster than keeping them current for every packet of a first
            // pass. The empty index is committed on its own, with its cursor
            // at zero, before any packet is read.
            transaction.execute_batch(
                "DROP TABLE IF EXISTS metadata; DROP TABLE IF EXISTS invocations; DROP TABLE IF EXISTS packets; DROP TABLE IF EXISTS lifecycle; \
                 CREATE TABLE invocations(key BLOB PRIMARY KEY, first_offset INTEGER NOT NULL, pid INTEGER NOT NULL); \
                 CREATE TABLE packets(key BLOB NOT NULL, offset INTEGER NOT NULL, phase INTEGER NOT NULL, seq INTEGER NOT NULL); \
                 CREATE TABLE lifecycle(key BLOB NOT NULL, seq INTEGER NOT NULL, task_exit INTEGER NOT NULL, PRIMARY KEY(key, seq)) WITHOUT ROWID;",
            )?;
            transaction.pragma_update(None, "user_version", INDEX_VERSION)?;
            transaction.execute("DELETE FROM indexed", [])?;
            transaction.execute(
                "INSERT INTO indexed(identity,length,writer) VALUES(?1,0,?2)",
                rusqlite::params![identity, INDEX_VERSION],
            )?;
            transaction.commit()?;
            continue;
        };
        if start == length {
            transaction.commit()?;
            index_cache::used(&index_path);
            return Ok((connection, identity));
        }
        let mut indexed = start;
        let mut finished = true;
        {
            let mut invocation = transaction.prepare(
                "INSERT OR IGNORE INTO invocations(key,first_offset,pid) VALUES(?1,?2,?3)",
            )?;
            let mut packets = transaction
                .prepare("INSERT INTO packets(key,offset,phase,seq) VALUES(?1,?2,?3,?4)")?;
            let mut lifecycle = transaction.prepare(
                "INSERT INTO lifecycle(key,seq,task_exit) VALUES(?1,?2,?3) \
                 ON CONFLICT(key,seq) DO UPDATE SET task_exit=MAX(task_exit,excluded.task_exit)",
            )?;
            let mut reader = BufReader::new(archive_io::open_regular(directory, &raw)?);
            reader.seek(SeekFrom::Start(indexed))?;
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return Err(RecordingError::Limit("archive read cancelled"));
                }
                if reader.stream_position()? >= length {
                    break;
                }
                if indexed - start >= chunk_bytes {
                    finished = false;
                    break;
                }
                let (offset, packet) = match next_packet(&mut reader) {
                    Ok(Some(next)) => next,
                    Ok(None) => break,
                    // The packet being written: the index stops before it.
                    Err(RecordingError::Io(error))
                        if error.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        break;
                    }
                    Err(error) => return Err(error),
                };
                if reader.stream_position()? > length {
                    break;
                }
                indexed = reader.stream_position()?;
                if let Some((header, key)) = packet_key(&packet) {
                    let key = key_blob(key);
                    let offset = i64::try_from(offset).map_err(|_| {
                        RecordingError::Limit("raw archive offset exceeds index range")
                    })?;
                    // Index candidates even when all identifying fields were lost.
                    // Assembly/pairing excludes known lifecycle-only observations.
                    let async_parent = header.phase == 3 && header.call_id != 0;
                    if matches!(header.phase, 1 | 2) || async_parent {
                        invocation.execute(rusqlite::params![key, offset, header.pid])?;
                    }
                    let seq = async_page::seq_index(header.event_seq);
                    packets.execute(rusqlite::params![key, offset, header.phase, seq])?;
                    if let Some(kind) = async_page::lifecycle_field(&header, &packet) {
                        lifecycle.execute(rusqlite::params![key, seq, kind as i64])?;
                    }
                }
            }
        }
        if finished {
            transaction.execute_batch(
                "CREATE INDEX IF NOT EXISTS invocation_order ON invocations(first_offset); \
                 CREATE INDEX IF NOT EXISTS invocation_process ON invocations(pid, first_offset); \
                 CREATE INDEX IF NOT EXISTS packet_events ON packets(key,phase,seq,offset);",
            )?;
            if raw_identity(&raw)?.0 != identity {
                return Err(RecordingError::Limit(
                    "raw archive was replaced while being indexed; open it again",
                ));
            }
        }
        let indexed = i64::try_from(indexed)
            .map_err(|_| RecordingError::Limit("raw archive offset exceeds index range"))?;
        transaction.execute("DELETE FROM indexed", [])?;
        transaction.execute(
            "INSERT INTO indexed(identity,length,writer) VALUES(?1,?2,?3)",
            rusqlite::params![identity, indexed, INDEX_VERSION],
        )?;
        transaction.commit()?;
        if finished {
            index_cache::used(&index_path);
            return Ok((connection, identity));
        }
        chunks += 1;
        if chunks >= max_chunks {
            return Err(RecordingError::Limit("archive index build stopped"));
        }
    }
}

impl Recording {
    /// Match the full retained recording off the UI thread, retaining only one page.
    ///
    /// | Argument | Meaning |
    /// | --- | --- |
    /// | `offset` | Inclusive stable raw-file cursor returned by a previous matching page |
    /// | `limit` | Maximum returned calls, in `1..=256` |
    /// | `pid` | Optional guest process/thread-group predicate |
    /// | `cancel` | Cooperative per-request cancellation, checked while indexing and reading packets |
    /// | `keep` | Predicate on the same bounded reconstructed summaries used by ordinary archive pages |
    ///
    /// The disk index and packet previews remain bounded. Only complete saved
    /// packets in the indexed prefix are read; a growing tail is included on the
    /// next request. Replaced/shrunk archives and cancelled reads return errors.
    pub fn filtered_page_cancellable(
        &self,
        offset: u64,
        limit: usize,
        pid: Option<u32>,
        cancel: &AtomicBool,
        mut keep: impl FnMut(&InvocationSummary) -> bool,
    ) -> Result<FilteredInvocationPage, RecordingError> {
        let MatchingPage { page, .. } =
            self.matching_page_cancellable(offset, limit, pid, cancel, &mut keep)?;
        let totals = self.matching_totals_cancellable(pid, cancel, keep)?;
        Ok(FilteredInvocationPage {
            page,
            total: totals.total,
            source_total: totals.source_total,
        })
    }

    /// Count indexed calls for page navigation without loading all call previews.
    pub fn invocation_count_cancellable(
        &self,
        pid: Option<u32>,
        cancel: &AtomicBool,
    ) -> Result<u64, RecordingError> {
        retry_index_busy(cancel, || {
            let (connection, _) = archive_index(&self.directory, cancel)?;
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM invocations WHERE (?1 IS NULL OR pid=?1)",
                rusqlite::params![pid],
                |row| row.get(0),
            )?;
            u64::try_from(count).map_err(|_| RecordingError::Limit("negative invocation count"))
        })
    }

    /// Reconstruct the descriptive process tree up to a fixed raw-file boundary.
    /// Lifecycle loss and PID reuse can limit this view; run ownership still uses cookies.
    pub fn process_tree_cancellable(
        &self,
        root_pid: u32,
        path: &str,
        cancel: &AtomicBool,
    ) -> Result<(Vec<crate::capture_processes::CaptureProcess>, Vec<String>), RecordingError> {
        self.process_tree_within(root_pid, path, cancel, PROCESS_TREE_LIMIT)
    }

    fn process_tree_within(
        &self,
        root_pid: u32,
        path: &str,
        cancel: &AtomicBool,
        limit: usize,
    ) -> Result<(Vec<crate::capture_processes::CaptureProcess>, Vec<String>), RecordingError> {
        let mut tracker = crate::capture_processes::ProcessTracker::default();
        tracker.name_launched(root_pid, path);
        let mut issues = Vec::new();
        let mut truncated = false;
        let mut reader = BufReader::new(archive_io::open_regular(
            &self.directory,
            Path::new("telemetry.raw"),
        )?);
        let boundary = reader.get_ref().metadata()?.len();
        let mut assembler = Assembler::open_archive(self.directory.join("objects"))
            .map_err(|_| RecordingError::Limit("cannot open archived objects"))?;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(RecordingError::Limit("archive read cancelled"));
            }
            if reader.stream_position()? >= boundary {
                break;
            }
            let packet = match next_packet(&mut reader) {
                Ok(Some((_, packet))) if reader.stream_position()? <= boundary => packet,
                Ok(_) => break,
                Err(RecordingError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    issues.push("Unfinished record: showing complete saved packets only".into());
                    break;
                }
                Err(e) => return Err(e),
            };
            let (header, _) = parser::parse_packet(&packet)
                .map_err(|_| RecordingError::Limit("invalid process-tree packet"))?;
            if tracker.tracked_count() >= limit && !tracker.tracks(header.pid) {
                // Later processes are left out, not an error: the rest still reads.
                truncated = true;
                continue;
            }
            tracker.packet(&header);
            // Only exec names and lifecycle records need object assembly.
            if header.phase == 3 || (header.phase == 1 && matches!(header.syscall_nr, 59 | 322)) {
                match assembler.ingest(&packet) {
                    Ok(Some(event)) => tracker.event(&event),
                    Ok(None) => {}
                    Err(e) => push_issue(&mut issues, e.to_string()),
                }
            }
        }
        let mut list = tracker.list();
        if list.len() > limit {
            list.truncate(limit);
            truncated = true;
        }
        if truncated {
            issues.push(format!(
                "Process tree limited to {limit} processes; later processes are not listed"
            ));
        }
        Ok((list, issues))
    }

    /// Cursor is a raw-file byte offset returned by the previous page, not a row number.
    /// Rebuildable SQLite cache is outside capture with a 2 MiB page cache and
    /// disk budget twice the raw size plus 1 MiB, capped at 16 GiB.
    pub fn invocation_page(
        &self,
        offset: u64,
        limit: usize,
    ) -> Result<InvocationPage, RecordingError> {
        self.invocation_page_cancellable(offset, limit, &AtomicBool::new(false))
    }
    pub fn invocation_page_cancellable(
        &self,
        offset: u64,
        limit: usize,
        cancel: &AtomicBool,
    ) -> Result<InvocationPage, RecordingError> {
        self.process_page_cancellable(offset, limit, None, cancel)
    }
    /// Like [`Self::invocation_page_cancellable`], limited to one guest process
    /// (thread group ID) when `pid` is set.
    pub fn process_page_cancellable(
        &self,
        offset: u64,
        limit: usize,
        pid: Option<u32>,
        cancel: &AtomicBool,
    ) -> Result<InvocationPage, RecordingError> {
        retry_index_busy(cancel, || {
            self.process_page_once(offset, limit, pid, cancel)
        })
    }

    fn process_page_once(
        &self,
        offset: u64,
        limit: usize,
        pid: Option<u32>,
        cancel: &AtomicBool,
    ) -> Result<InvocationPage, RecordingError> {
        // The same bounded reconstruction the filtered pages use: entry, exit
        // and task end are kept, and async observations beyond the preview
        // are counted, not dropped.
        Ok(self
            .matching_page_cancellable(offset, limit, pid, cancel, |_| true)?
            .page)
    }

    /// Journal cursor is a byte offset; output and resize order are preserved.
    pub fn terminal_replay(
        &self,
        offset: u64,
        limit: usize,
    ) -> Result<TerminalPage, RecordingError> {
        if !(1..=256).contains(&limit) {
            return Err(RecordingError::Limit("terminal page size must be 1..256"));
        }
        let mut file = archive_io::open_regular(&self.directory, Path::new("terminal.journal"))?;
        let size = file.metadata()?.len();
        if offset > size {
            return Err(RecordingError::Limit("cursor beyond terminal journal"));
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut records = Vec::with_capacity(limit);
        let mut output_len = 0;
        let mut unfinished = false;
        while records.len() < limit && file.stream_position()? < size && output_len < 65536 {
            if size - file.stream_position()? < 5 {
                unfinished = true;
                break;
            }
            let mut prefix = [0; 5];
            file.read_exact(&mut prefix)?;
            let data_len = u32::from_le_bytes(
                prefix[1..]
                    .try_into()
                    .map_err(|_| RecordingError::Limit("invalid terminal journal"))?,
            ) as usize;
            if data_len > 4096 {
                return Err(RecordingError::Limit(
                    "terminal journal record exceeds limit",
                ));
            }
            if data_len as u64 > size - file.stream_position()? {
                unfinished = true;
                break;
            }
            let mut data = vec![0; data_len];
            file.read_exact(&mut data)?;
            records.push(match prefix[0] {
                1 => {
                    output_len += data_len;
                    TerminalRecord::Output(data)
                }
                2 if data_len == 4 => TerminalRecord::Resize {
                    rows: u16::from_le_bytes([data[0], data[1]]),
                    cols: u16::from_le_bytes([data[2], data[3]]),
                },
                3 if data_len == 0 => TerminalRecord::Eof,
                _ => return Err(RecordingError::Limit("invalid terminal journal record")),
            });
        }
        let cursor = file.stream_position()?;
        Ok(TerminalPage {
            records,
            next_offset: (!unfinished && cursor < size).then_some(cursor),
        })
    }

    pub fn terminal_screen(&self) -> Result<Vec<u8>, RecordingError> {
        let file = archive_io::open_regular(&self.directory, Path::new("terminal-screen.ansi"))?;
        if file.metadata()?.len() > 2 * 1024 * 1024 {
            return Err(RecordingError::Limit("terminal screen exceeds limit"));
        }
        let mut data = Vec::new();
        file.take(2 * 1024 * 1024).read_to_end(&mut data)?;
        Ok(data)
    }
}

/// Read bounded history for one stable VM identity, including prior recording parents.
pub fn list_vm_runs(
    options: &BackendOptions,
    vm_id: &str,
) -> Result<Vec<RunSummary>, RecordingError> {
    let location = crate::locations::locations(options, vm_id)
        .map_err(|error| RecordingError::Io(std::io::Error::other(error)))?;
    let mut runs = Vec::new();
    let mut scanned = 0usize;
    for directory in location.recording_directories {
        if !directory.exists() {
            continue;
        }
        let root = fs::canonicalize(&directory)?;
        // Launched runs live in `runs/`; a run continued after a reconnect or a
        // snapshot restore lives under its new boot in `boots/<boot>/runs/`.
        let mut run_directories = vec![root.join("runs")];
        if let Ok(boots) = fs::read_dir(root.join("boots")) {
            for boot in boots.flatten() {
                if boot.file_type().is_ok_and(|kind| kind.is_dir()) {
                    run_directories.push(boot.path().join("runs"));
                }
            }
        }
        for run_directory in run_directories {
            let Ok(entries) = fs::read_dir(&run_directory) else {
                continue;
            };
            for entry in entries.flatten() {
                if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    continue;
                }
                scanned += 1;
                if scanned > MAX_HISTORY_SCAN {
                    return Ok(newest_runs(runs));
                }
                // One damaged run must not hide the others.
                let Ok(Some(run)) = saved_run(&root, &entry.path(), vm_id) else {
                    continue;
                };
                // A run that lived through a transport reconnect has a record in
                // each segment's boot under one id; the newest segment is listed.
                match runs
                    .iter()
                    .position(|existing: &RunSummary| existing.id == run.id)
                {
                    None => runs.push(run),
                    Some(at) if run.segments() > runs[at].segments() => runs[at] = run,
                    Some(_) => {}
                }
            }
        }
    }
    let legacy = options.data_dir.join("captures");
    if legacy.exists() {
        for run in list_runs(&options.data_dir)?
            .into_iter()
            .filter(|run| run.vm_id == vm_id && run.root_task_cookie == 0)
        {
            if !runs.iter().any(|existing| existing.id == run.id) {
                runs.push(run);
            }
        }
    }
    Ok(newest_runs(runs))
}

/// Runs a VM's history lists; the newest are kept.
const MAX_HISTORY_RUNS: usize = 1024;
/// Run directories looked at for one listing.
const MAX_HISTORY_SCAN: usize = 16 * 1024;

/// Newest first, at most [`MAX_HISTORY_RUNS`].
fn newest_runs(mut runs: Vec<RunSummary>) -> Vec<RunSummary> {
    runs.sort_by(|a, b| {
        b.started_ms
            .cmp(&a.started_ms)
            .then_with(|| b.id.cmp(&a.id))
    });
    runs.truncate(MAX_HISTORY_RUNS);
    runs
}

/// The run saved in `directory` under `root`, if it belongs to `vm_id`.
fn saved_run(
    root: &Path,
    directory: &Path,
    vm_id: &str,
) -> Result<Option<RunSummary>, RecordingError> {
    let path = directory.join("run.json");
    if !path.exists() {
        return Ok(None);
    }
    let file = archive_io::open_regular(root, &path)?;
    if file.metadata()?.len() > 1024 * 1024 {
        return Err(RecordingError::Limit("run metadata exceeds limit"));
    }
    let mut run: RunSummary = serde_json::from_reader(file)?;
    if let Some(report) = &run.analysis {
        crate::analysis::validation::validate_report(report)
            .map_err(|_| RecordingError::Limit("archived analysis report violates bounds"))?;
    }
    if run.vm_id != vm_id {
        return Ok(None);
    }
    run.directory = directory.to_path_buf();
    if run.started_ms.is_none() {
        run.started_ms = run_filter_facts(&run.directory, &run.id, &run.vm_id, &run.boot_id)
            .ok()
            .and_then(|facts| facts.started_ms);
    }
    reopen_analysis_sidecar(root, &mut run)?;
    if matches!(run.state, RunState::Running | RunState::StopRequested) {
        run.state = RunState::Unknown;
    }
    Ok(Some(run))
}

pub fn list_runs(data_root: &Path) -> Result<Vec<RunSummary>, RecordingError> {
    let data_root = fs::canonicalize(data_root)?;
    let mut runs = Vec::new();
    for vm in fs::read_dir(&data_root)? {
        let vm = vm?;
        if !vm.file_type()?.is_dir() {
            continue;
        }
        let run_dir = vm.path().join("runs");
        if !run_dir.exists() {
            continue;
        }
        for entry in fs::read_dir(run_dir)? {
            let entry = entry?;
            let path = entry.path().join("run.json");
            if !path.is_file() {
                continue;
            }
            let file = archive_io::open_regular(&data_root, &path)?;
            if file.metadata()?.len() > 1024 * 1024 {
                return Err(RecordingError::Limit("run metadata exceeds limit"));
            }
            let mut run: RunSummary = serde_json::from_reader(file)?;
            if let Some(report) = &run.analysis {
                crate::analysis::validation::validate_report(report).map_err(|_| {
                    RecordingError::Limit("archived analysis report violates bounds")
                })?;
            }
            run.directory = entry.path();
            if run.started_ms.is_none() {
                run.started_ms =
                    run_filter_facts(&run.directory, &run.id, &run.vm_id, &run.boot_id)
                        .ok()
                        .and_then(|facts| facts.started_ms);
            }
            reopen_analysis_sidecar(&data_root, &mut run)?;
            if matches!(run.state, RunState::Running | RunState::StopRequested) {
                run.state = RunState::Unknown;
            }
            runs.push(run);
            if runs.len() > 1024 {
                return Err(RecordingError::Limit(
                    "more than 1024 run summaries; open a recording directory directly",
                ));
            }
        }
    }
    let legacy = data_root.join("captures");
    if legacy.exists() {
        for entry in fs::read_dir(legacy)? {
            let entry = entry?;
            let directory = entry.path();
            let path = directory.join("manifest.json");
            if !path.is_file() {
                continue;
            }
            let file = archive_io::open_regular(&data_root, &path)?;
            if file.metadata()?.len() > 1024 * 1024 {
                return Err(RecordingError::Limit(
                    "legacy manifest exceeds reader limit",
                ));
            }
            let manifest: serde_json::Value = serde_json::from_reader(file)?;
            let id = format!("legacy-{}", entry.file_name().to_string_lossy());
            runs.push(RunSummary {
                started_ms: None,
                clock_anchor: None,
                id,
                vm_id: manifest
                    .get("vm")
                    .and_then(|vm| vm.get("id"))
                    .and_then(|id| id.as_str())
                    .unwrap_or("unknown")
                    .into(),
                boot_id: entry.file_name().to_string_lossy().into(),
                session_id: 0,
                root_task_cookie: 0,
                pid: 0,
                request: ExecRequest {
                    path: "[legacy VM recording; run ownership unknown]".into(),
                    ..ExecRequest::default()
                },
                directory,
                terminal_eof: true,
                state: RunState::Finalized,
                notes: Vec::new(),
                recording_error: manifest
                    .get("persistence_error")
                    .and_then(|e| e.as_str())
                    .map(String::from),
                execution: None,
                analysis: None,
            });
            if runs.len() > 1024 {
                return Err(RecordingError::Limit(
                    "more than 1024 run summaries; open a recording directory directly",
                ));
            }
        }
    }
    runs.sort_by(|a, b| {
        b.started_ms
            .cmp(&a.started_ms)
            .then_with(|| b.id.cmp(&a.id))
    });
    Ok(runs)
}
fn reopen_analysis_sidecar(root: &Path, run: &mut RunSummary) -> Result<(), RecordingError> {
    let Some(embedded) = run.analysis.as_ref() else {
        return Ok(());
    };
    let path = run.directory.join("analysis/report.json");
    let file = match archive_io::open_regular(root, &path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() > 128 * 1024 {
        return Err(RecordingError::Limit("analysis sidecar exceeds bound"));
    }
    let report: crate::analysis::AnalysisReport = serde_json::from_reader(file)?;
    crate::analysis::validation::validate_report(&report)
        .map_err(|_| RecordingError::Limit("analysis sidecar violates bounds"))?;
    if report.id != embedded.id
        || report.source_path != embedded.source_path
        || report.sections.len() != embedded.sections.len()
        || report
            .sections
            .iter()
            .zip(&embedded.sections)
            .any(|(section, expected)| section.kind != expected.kind)
    {
        return Err(RecordingError::Limit(
            "analysis sidecar identity does not match run",
        ));
    }
    run.analysis = Some(report);
    Ok(())
}
pub fn read_captured_range(
    recording: &Path,
    field: &FieldSummary,
    offset: u64,
    data_len: usize,
) -> Result<Vec<u8>, RecordingError> {
    if data_len > 65536 {
        return Err(RecordingError::Limit(
            "read at most 65536 captured bytes at a time",
        ));
    }
    let end = offset
        .checked_add(data_len as u64)
        .ok_or(RecordingError::MissingRange)?;
    let mut covered = offset;
    for &(range_offset, range_len) in &field.ranges {
        let range_end = range_offset
            .checked_add(range_len)
            .ok_or(RecordingError::MissingRange)?;
        if range_offset <= covered && range_end > covered {
            covered = range_end;
        }
        if covered >= end {
            break;
        }
    }
    if covered < end {
        return Err(RecordingError::MissingRange);
    }
    let recording_root = fs::canonicalize(recording)?;
    let root = fs::canonicalize(recording_root.join("objects"))?;
    if !root.starts_with(&recording_root) {
        return Err(RecordingError::Limit("objects directory escapes recording"));
    }
    let saved_path = field
        .raw_path
        .as_ref()
        .ok_or(RecordingError::MissingRange)?;
    // Archives made since objects were packed hold the field in segments.
    if let Some(key) = saved_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(crate::object_pack::FieldKey::parse)
        && let Some(data) = crate::object_pack::read_field_range(&root, &key, offset, data_len)?
    {
        return Ok(data);
    }
    let candidate = if saved_path.is_absolute() {
        // Older archives held absolute paths. Relocate only their object basename.
        root.join(saved_path.file_name().ok_or(RecordingError::MissingRange)?)
    } else {
        recording.join(saved_path)
    };
    let path = fs::canonicalize(candidate)?;
    if !path.starts_with(&root) {
        return Err(RecordingError::Limit(
            "field path escapes recording objects",
        ));
    }
    let mut file = archive_io::open_regular(&root, &path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0; data_len];
    file.read_exact(&mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    mod async_browse;
    mod index_concurrency;
    fn facts_for_health(
        health: serde_json::Value,
        recording_error: serde_json::Value,
    ) -> Option<bool> {
        let directory =
            std::env::temp_dir().join(format!("ant-run-facts-{}", storage::unique_id()));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "run": {"id": "r", "vm_id": "v", "boot_id": "b",
                        "execution": {"flags": 2}, "recording_error": recording_error},
                "terminal_complete": true,
                "persistence_error": null,
                "bytes": 1,
                "health": health,
            }))
            .unwrap(),
        )
        .unwrap();
        let facts = run_filter_facts(&directory, "r", "v", "b").unwrap();
        std::fs::remove_dir_all(&directory).unwrap();
        facts.complete
    }
    #[test]
    fn dropped_ui_previews_do_not_make_a_complete_recording_incomplete() {
        let health = |ui_dropped| serde_json::json!({"dropped": 0, "ui_dropped": ui_dropped, "storage_dropped_packets": 0});
        assert_eq!(
            facts_for_health(health(0), serde_json::Value::Null),
            Some(true)
        );
        assert_eq!(
            facts_for_health(health(3), serde_json::Value::Null),
            Some(true)
        );
    }
    #[test]
    fn transport_loss_storage_loss_and_a_recording_error_still_make_a_run_incomplete() {
        let health = |dropped, storage| serde_json::json!({"dropped": dropped, "ui_dropped": 0, "storage_dropped_packets": storage});
        let none = serde_json::Value::Null;
        assert_eq!(facts_for_health(health(1, 0), none.clone()), Some(false));
        assert_eq!(facts_for_health(health(0, 1), none.clone()), Some(false));
        assert_eq!(
            facts_for_health(health(0, 0), serde_json::json!("disk full")),
            Some(false)
        );
    }
    #[test]
    fn matching_analysis_sidecar_refreshes_reaper_state_and_rejects_identity_change() {
        use crate::analysis::{AnalysisSelection, AnalysisState};
        let root =
            std::env::temp_dir().join(format!("ant-analysis-sidecar-{}", storage::unique_id()));
        storage::private_dir(&root.join("analysis")).unwrap();
        let selection = AnalysisSelection::default();
        let mut report = crate::analysis::jobs::new_report("/tmp/sample", &selection);
        report.state = AnalysisState::Partial;
        report.reason = Some("worker cleanup pending".into());
        let mut run = RunSummary {
            started_ms: None,
            clock_anchor: None,
            id: "run".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            session_id: 1,
            root_task_cookie: 2,
            pid: 3,
            request: ExecRequest::default(),
            directory: root.clone(),
            terminal_eof: true,
            state: RunState::Finalized,
            notes: Vec::new(),
            recording_error: None,
            execution: None,
            analysis: Some(report.clone()),
        };
        reopen_analysis_sidecar(&root, &mut run).unwrap();
        assert_eq!(
            run.analysis.as_ref().unwrap().reason.as_deref(),
            Some("worker cleanup pending")
        );
        report.reason = Some("worker cleanup completed".into());
        storage::atomic_bytes(
            &root.join("analysis/report.json"),
            &serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        reopen_analysis_sidecar(&root, &mut run).unwrap();
        assert_eq!(
            run.analysis.as_ref().unwrap().reason.as_deref(),
            Some("worker cleanup completed")
        );
        report.id = "different-job".into();
        storage::atomic_bytes(
            &root.join("analysis/report.json"),
            &serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        assert!(reopen_analysis_sidecar(&root, &mut run).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn raw_and_terminal_fifo_members_are_rejected_before_reader_open() {
        let directory =
            std::env::temp_dir().join(format!("ant-fifo-archive-{}", storage::unique_id()));
        storage::private_dir(&directory).unwrap();
        storage::atomic_json(&directory.join("manifest.json"), &serde_json::json!({})).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(directory.join("telemetry.raw"))
                .status()
                .unwrap()
                .success()
        );
        assert!(open_recording(&directory).is_err());
        let recording = Recording {
            directory: directory.clone(),
            manifest: serde_json::json!({}),
            events: vec![],
        };
        assert!(
            std::process::Command::new("mkfifo")
                .arg(directory.join("terminal.journal"))
                .status()
                .unwrap()
                .success()
        );
        assert!(recording.terminal_replay(0, 1).is_err());
        assert!(
            std::process::Command::new("mkfifo")
                .arg(directory.join("terminal-screen.ansi"))
                .status()
                .unwrap()
                .success()
        );
        assert!(recording.terminal_screen().is_err());
        fs::remove_dir_all(directory).unwrap();
    }
    fn event_packet(call: u64, phase: u8, fragment: u8, sequence: u64) -> Vec<u8> {
        let body = if fragment == 1 {
            vec![0; 120]
        } else {
            vec![0; 32]
        };
        let mut packet = vec![0; 136];
        packet[..4].copy_from_slice(b"ANTT");
        packet[4..6].copy_from_slice(&1u16.to_le_bytes());
        packet[6..8].copy_from_slice(&1u16.to_le_bytes());
        packet[8..10].copy_from_slice(&136u16.to_le_bytes());
        packet[10..12].copy_from_slice(&1u16.to_le_bytes());
        packet[12..16].copy_from_slice(&(136u32 + body.len() as u32).to_le_bytes());
        packet[20..24].copy_from_slice(&1u32.to_le_bytes());
        packet[24..32].copy_from_slice(&9u64.to_le_bytes());
        packet[32..40].copy_from_slice(&10u64.to_le_bytes());
        packet[40..48].copy_from_slice(&call.to_le_bytes());
        packet[48..56].copy_from_slice(&(call * 2 + u64::from(phase)).to_le_bytes());
        packet[56..64].copy_from_slice(&sequence.to_le_bytes());
        packet[96..98].copy_from_slice(&1u16.to_le_bytes());
        packet[98] = phase;
        packet[99] = fragment;
        packet[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
        packet[128..136].copy_from_slice(&99u64.to_le_bytes());
        packet.extend(body);
        packet
    }
    #[test]
    fn filtered_archive_finds_late_matches_and_counts_all_matching_pages() {
        let directory =
            std::env::temp_dir().join(format!("ant-filtered-archive-{}", storage::unique_id()));
        storage::private_dir(&directory).unwrap();
        let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
        for call in 0..350_u64 {
            for (fragment, sequence) in [(1, 1), (5, 2)] {
                let mut packet = event_packet(call, 1, fragment, sequence);
                packet[72..76]
                    .copy_from_slice(&(if call % 2 == 0 { 41_u32 } else { 42 }).to_le_bytes());
                raw.write_all(&(packet.len() as u32).to_le_bytes()).unwrap();
                raw.write_all(&packet).unwrap();
            }
        }
        // An incomplete tail cannot become an invented invocation.
        let tail = event_packet(350, 1, 1, 1);
        raw.write_all(&(tail.len() as u32).to_le_bytes()).unwrap();
        raw.write_all(&tail[..80]).unwrap();
        raw.sync_all().unwrap();
        storage::atomic_json(&directory.join("manifest.json"), &serde_json::json!({})).unwrap();
        let recording = open_recording(&directory).unwrap();
        let cancel = AtomicBool::new(false);
        let first = recording
            .filtered_page_cancellable(0, 100, None, &cancel, |call| call.call_id >= 150)
            .unwrap();
        assert_eq!((first.total, first.source_total), (200, 350));
        assert_eq!(first.page.invocations.len(), 100);
        assert_eq!(first.page.invocations.first().unwrap().call_id, 150);
        assert_eq!(first.page.invocations.last().unwrap().call_id, 249);
        let second = recording
            .filtered_page_cancellable(
                first.page.next_offset.unwrap(),
                100,
                None,
                &cancel,
                |call| call.call_id >= 150,
            )
            .unwrap();
        assert_eq!((second.total, second.source_total), (200, 350));
        assert_eq!(second.page.invocations.first().unwrap().call_id, 250);
        assert_eq!(second.page.invocations.last().unwrap().call_id, 349);
        assert!(second.page.next_offset.is_none());
        let process = recording
            .filtered_page_cancellable(0, 100, Some(42), &cancel, |call| call.call_id >= 150)
            .unwrap();
        assert_eq!((process.total, process.source_total), (100, 175));
        assert!(
            process
                .page
                .invocations
                .iter()
                .all(|call| call.entry.as_ref().unwrap().pid == 42)
        );
        assert!(process.page.next_offset.is_none());
        // A next read sees the completed tail, with the same original IDs/cursors.
        raw.write_all(&tail[80..]).unwrap();
        raw.sync_all().unwrap();
        let grown = recording
            .filtered_page_cancellable(0, 100, None, &cancel, |call| call.call_id == 350)
            .unwrap();
        assert_eq!((grown.total, grown.source_total), (1, 351));
        assert_eq!(grown.page.invocations[0].call_id, 350);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_page_reads_only_its_own_calls_and_the_totals_follow_separately() {
        let directory =
            std::env::temp_dir().join(format!("ant-page-cost-{}", storage::unique_id()));
        storage::private_dir(&directory).unwrap();
        let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
        let write_call = |raw: &mut File, call: u64| {
            for (fragment, sequence) in [(1, 1), (5, 2)] {
                let packet = event_packet(call, 1, fragment, sequence);
                raw.write_all(&(packet.len() as u32).to_le_bytes()).unwrap();
                raw.write_all(&packet).unwrap();
            }
        };
        for call in 0..1000_u64 {
            write_call(&mut raw, call);
        }
        raw.sync_all().unwrap();
        storage::atomic_json(&directory.join("manifest.json"), &serde_json::json!({})).unwrap();
        let recording = open_recording(&directory).unwrap();
        let cancel = AtomicBool::new(false);
        // The predicate sees the page and one call past it, not the other 899.
        let mut seen = 0;
        let first = recording
            .matching_page_cancellable(0, 100, None, &cancel, |_| {
                seen += 1;
                true
            })
            .unwrap();
        assert_eq!((first.page.invocations.len(), seen), (100, 101));
        // A later page starts at its cursor and does not read the calls before it.
        let mut seen_calls = Vec::new();
        let second = recording
            .matching_page_cancellable(
                first.page.next_offset.unwrap(),
                100,
                None,
                &cancel,
                |call| {
                    seen_calls.push(call.call_id);
                    true
                },
            )
            .unwrap();
        assert_eq!(seen_calls.first(), Some(&100));
        assert_eq!(second.page.invocations.first().unwrap().call_id, 100);
        assert_eq!(second.stamp, first.stamp);
        let totals = recording
            .matching_totals_cancellable(None, &cancel, |call| call.call_id % 2 == 0)
            .unwrap();
        assert_eq!((totals.total, totals.source_total), (500, 1000));
        assert_eq!(totals.stamp, first.stamp);
        // A recording that grew is another prefix of the same file.
        write_call(&mut raw, 1000);
        raw.sync_all().unwrap();
        let grown = recording
            .matching_totals_cancellable(None, &cancel, |_| true)
            .unwrap();
        assert_eq!(grown.total, 1001);
        assert_eq!(grown.stamp.identity, first.stamp.identity);
        assert!(grown.stamp.length > first.stamp.length);
        cancel.store(true, Ordering::Relaxed);
        assert!(
            recording
                .matching_totals_cancellable(None, &cancel, |_| true)
                .is_err()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_busy_recording_lists_the_first_processes_and_says_so() {
        let directory =
            std::env::temp_dir().join(format!("ant-many-pids-{}", storage::unique_id()));
        storage::private_dir(&directory).unwrap();
        let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
        for pid in 1..=10_u32 {
            let mut packet = event_packet(u64::from(pid), 1, 1, 1);
            packet[72..76].copy_from_slice(&pid.to_le_bytes());
            raw.write_all(&(packet.len() as u32).to_le_bytes()).unwrap();
            raw.write_all(&packet).unwrap();
        }
        raw.sync_all().unwrap();
        storage::atomic_json(&directory.join("manifest.json"), &serde_json::json!({})).unwrap();
        let recording = open_recording(&directory).unwrap();
        let cancel = AtomicBool::new(false);
        let (all, issues) = recording
            .process_tree_within(1, "/bin/first", &cancel, 100)
            .unwrap();
        assert_eq!(all.len(), 10);
        assert!(issues.is_empty());
        let (some, issues) = recording
            .process_tree_within(1, "/bin/first", &cancel, 4)
            .unwrap();
        assert_eq!(
            some.len(),
            4,
            "a cap lists the first processes, not an error"
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("limited to 4 processes"))
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn filtered_archive_cancellation_stops_during_global_scan() {
        let directory =
            std::env::temp_dir().join(format!("ant-filter-cancel-{}", storage::unique_id()));
        storage::private_dir(&directory).unwrap();
        let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
        for call in 0..350_u64 {
            let packet = event_packet(call, 1, 1, 1);
            raw.write_all(&(packet.len() as u32).to_le_bytes()).unwrap();
            raw.write_all(&packet).unwrap();
        }
        raw.sync_all().unwrap();
        storage::atomic_json(&directory.join("manifest.json"), &serde_json::json!({})).unwrap();
        let recording = open_recording(&directory).unwrap();
        let cancel = AtomicBool::new(false);
        let mut examined = 0;
        let result = recording.filtered_page_cancellable(0, 100, None, &cancel, |_| {
            examined += 1;
            if examined == 125 {
                cancel.store(true, Ordering::Relaxed);
            }
            false
        });
        assert!(matches!(
            result,
            Err(RecordingError::Limit("archive read cancelled"))
        ));
        assert_eq!(examined, 125);
        assert!(
            recording
                .filtered_page_cancellable(0, 100, None, &cancel, |_| true)
                .is_err()
        );
        assert!(
            recording
                .filtered_page_cancellable(0, 257, None, &AtomicBool::new(false), |_| true)
                .is_err()
        );
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn archive_page_attaches_distinct_async_events_to_parent_only() {
        let directory =
            std::env::temp_dir().join(format!("ant-async-archive-{}", storage::unique_id()));
        storage::private_dir(&directory).unwrap();
        let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
        let mut write = |packet: Vec<u8>| {
            raw.write_all(&(packet.len() as u32).to_le_bytes()).unwrap();
            raw.write_all(&packet).unwrap();
        };
        write(event_packet(1, 1, 1, 1));
        write(event_packet(1, 1, 5, 2));
        write(event_packet(1, 3, 1, 3));
        write(event_packet(1, 3, 5, 4));
        for (call, event_seq) in [(1u64, 100u64), (1, 101), (2, 200)] {
            let mut start = event_packet(call, 3, 1, 1);
            start[48..56].copy_from_slice(&event_seq.to_le_bytes());
            write(start);
            let key: &[u8] = if call == 2 {
                b"async.stage"
            } else {
                b"async.request_id"
            };
            let mut body = vec![0; 40];
            body[0] = 255;
            body[1] = 1;
            body[2..4].copy_from_slice(&1u16.to_le_bytes());
            body[4..6].copy_from_slice(&1u16.to_le_bytes());
            body[32..34].copy_from_slice(&(key.len() as u16).to_le_bytes());
            body.extend(key);
            let mut field = event_packet(call, 3, 2, 2);
            field.truncate(136);
            field[48..56].copy_from_slice(&event_seq.to_le_bytes());
            field[100..104].copy_from_slice(&1u32.to_le_bytes());
            field[12..16].copy_from_slice(&(136u32 + body.len() as u32).to_le_bytes());
            field[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
            field.extend(body);
            write(field);
            let mut end = event_packet(call, 3, 5, 3);
            end[48..56].copy_from_slice(&event_seq.to_le_bytes());
            write(end);
        }
        write(event_packet(3, 3, 1, 1));
        let mut orphan_end = event_packet(3, 3, 5, 10);
        orphan_end[136..144].copy_from_slice(&10u64.to_le_bytes());
        orphan_end[160..168].copy_from_slice(&1u64.to_le_bytes());
        write(orphan_end);
        raw.sync_all().unwrap();
        storage::atomic_json(&directory.join("manifest.json"), &serde_json::json!({})).unwrap();
        let recording = open_recording(&directory).unwrap();
        let page = recording.invocation_page(0, 10).unwrap();
        assert_eq!(page.invocations.len(), 3);
        assert_eq!(page.invocations[0].async_events.len(), 3);
        assert!(page.invocations[0].async_events[0].fields.is_empty());
        assert!(!page.invocations[0].async_events[0].complete);
        assert_eq!(page.invocations[0].async_events[1].event_seq, 100);
        assert_eq!(page.invocations[0].async_events[2].event_seq, 101);
        assert!(page.invocations[1].entry.is_none());
        assert!(page.invocations[1].exit.is_none());
        assert_eq!(page.invocations[1].async_events[0].event_seq, 200);
        assert_eq!(page.invocations[2].call_id, 3);
        assert!(page.invocations[2].entry.is_none());
        assert!(page.invocations[2].exit.is_none());
        assert!(!page.invocations[2].async_events[0].complete);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn a_recording_still_being_written_opens_and_grows() {
        let directory = std::env::temp_dir().join(format!("ant-live-{}", storage::unique_id()));
        storage::private_dir(&directory).unwrap();
        let path = directory.join("telemetry.raw");
        let mut raw = File::create(&path).unwrap();
        let write = |file: &mut File, packet: Vec<u8>| {
            file.write_all(&(packet.len() as u32).to_le_bytes())
                .unwrap();
            file.write_all(&packet).unwrap();
        };
        for call in 0..10 {
            write(&mut raw, event_packet(call, 1, 1, 1));
            write(&mut raw, event_packet(call, 2, 5, 2));
        }
        // A packet being written: its length, half its bytes.
        let pending = event_packet(10, 1, 1, 1);
        raw.write_all(&(pending.len() as u32).to_le_bytes())
            .unwrap();
        raw.write_all(&pending[..pending.len() / 2]).unwrap();
        raw.sync_all().unwrap();
        storage::atomic_json(
            &directory.join("manifest.json"),
            &serde_json::json!({"test":true}),
        )
        .unwrap();
        let recording = open_recording(&directory).unwrap();
        let calls = |recording: &Recording| {
            recording
                .invocation_page(0, 256)
                .unwrap()
                .invocations
                .iter()
                .map(|row| row.call_id)
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(calls(&recording).len(), 10);
        assert_eq!(
            recording
                .invocation_count_cancellable(None, &AtomicBool::new(false))
                .unwrap(),
            10
        );
        // The rest of that packet and more calls arrive.
        raw.write_all(&pending[pending.len() / 2..]).unwrap();
        write(&mut raw, event_packet(10, 2, 5, 2));
        for call in 11..15 {
            write(&mut raw, event_packet(call, 1, 1, 1));
        }
        raw.sync_all().unwrap();
        assert_eq!(calls(&recording).len(), 15);
        assert_eq!(
            recording
                .invocation_count_cancellable(None, &AtomicBool::new(false))
                .unwrap(),
            15
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pages_all_three_thousand_calls_with_missing_phases_and_lifecycle() {
        let directory = std::env::temp_dir().join(format!("ant-archive-{}", storage::unique_id()));
        storage::private_dir(&directory).unwrap();
        let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
        let write = |file: &mut File, packet: Vec<u8>| {
            file.write_all(&(packet.len() as u32).to_le_bytes())
                .unwrap();
            file.write_all(&packet).unwrap();
        };
        for call in 0..3000 {
            if call % 3 != 0 {
                write(&mut raw, event_packet(call, 1, 1, 1));
            }
            if call % 3 != 1 {
                write(&mut raw, event_packet(call, 2, 5, 2));
            }
            write(&mut raw, event_packet(call, 3, 1, 3));
            write(&mut raw, event_packet(call, 3, 5, 4));
        }
        raw.sync_all().unwrap();
        storage::atomic_json(
            &directory.join("manifest.json"),
            &serde_json::json!({"test":true}),
        )
        .unwrap();
        let recording = open_recording(&directory).unwrap();
        assert!(
            !directory.join("objects").exists(),
            "offline paging created archive objects"
        );
        let mut cursor = 0;
        let mut seen = std::collections::BTreeSet::new();
        loop {
            let page = recording.invocation_page(cursor, 7).unwrap();
            assert!(page.invocations.len() <= 7);
            for row in page.invocations {
                assert!(
                    seen.insert(row.call_id),
                    "duplicate invocation across pages"
                );
                assert_eq!(row.entry.is_some(), row.call_id % 3 != 0);
                assert_eq!(row.exit.is_some(), row.call_id % 3 != 1);
            }
            match page.next_offset {
                Some(next) => {
                    assert!(next > cursor);
                    cursor = next;
                }
                None => break,
            }
        }
        assert_eq!(seen.len(), 3000);
        assert_eq!(
            recording
                .invocation_count_cancellable(None, &AtomicBool::new(false))
                .unwrap()
                .div_ceil(100),
            30
        );
        let (index, _) = archive_index(&directory, &AtomicBool::new(false)).unwrap();
        let pages: i64 = index
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .unwrap();
        assert!(
            (pages as u64) * 4096
                < fs::metadata(directory.join("telemetry.raw")).unwrap().len() * 2 + 1024 * 1024
        );
        // A cache damaged by a crash is discarded and built again.
        drop(index);
        fs::write(archive_index_path(&directory).unwrap(), b"not an index").unwrap();
        let (index, _) = archive_index(&directory, &AtomicBool::new(false)).unwrap();
        let rows: i64 = index
            .query_row("SELECT count(*) FROM invocations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 3000);
        drop(index);
        assert!(
            recording
                .invocation_page_cancellable(0, 7, &AtomicBool::new(true))
                .is_err()
        );
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn unfinished_terminal_keeps_complete_output_and_partial_tree_has_warning() {
        let directory = std::env::temp_dir().join(format!("ant-partial-{}", storage::unique_id()));
        storage::private_dir(&directory).unwrap();
        let mut journal = vec![1, 3, 0, 0, 0];
        journal.extend(b"abc");
        journal.extend([1, 5, 0, 0, 0, b'x']);
        fs::write(directory.join("terminal.journal"), journal).unwrap();
        let mut packet = event_packet(1, 1, 1, 1);
        packet[72..76].copy_from_slice(&123u32.to_le_bytes());
        packet[76..80].copy_from_slice(&123u32.to_le_bytes());
        let mut raw = (packet.len() as u32).to_le_bytes().to_vec();
        raw.extend(&packet);
        raw.extend((packet.len() as u32).to_le_bytes());
        raw.extend(&packet[..40]);
        fs::write(directory.join("telemetry.raw"), raw).unwrap();
        storage::atomic_json(&directory.join("manifest.json"), &serde_json::json!({})).unwrap();
        let recording = open_recording(&directory).unwrap();
        let terminal = recording.terminal_replay(0, 32).unwrap();
        assert!(
            matches!(terminal.records.as_slice(), [TerminalRecord::Output(data)] if data == b"abc")
        );
        assert!(terminal.next_offset.is_none());
        let (tree, issues) = recording
            .process_tree_cancellable(123, "/bin/test", &AtomicBool::new(false))
            .unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].name, "test");
        assert!(issues.iter().any(|text| text.contains("Unfinished")));
        assert!(
            recording
                .process_tree_cancellable(123, "/bin/test", &AtomicBool::new(true))
                .is_err()
        );
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn external_objects_symlink_is_rejected() {
        let directory = std::env::temp_dir().join(format!("ant-symlink-{}", storage::unique_id()));
        let external = std::env::temp_dir().join(format!("ant-external-{}", storage::unique_id()));
        storage::private_dir(&directory).unwrap();
        storage::private_dir(&external).unwrap();
        fs::write(external.join("secret.raw"), b"secret").unwrap();
        std::os::unix::fs::symlink(&external, directory.join("objects")).unwrap();
        let field = FieldSummary {
            arg: None,
            object_id: 1,
            key: String::new(),
            layout: String::new(),
            logical_len: Some(6),
            captured_len: 6,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: vec![],
            raw_path: Some(external.join("secret.raw")),
            ranges: vec![(0, 6)],
        };
        assert!(matches!(
            read_captured_range(&directory, &field, 0, 6),
            Err(RecordingError::Limit(_))
        ));
        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(external).unwrap();
    }
    #[test]
    fn refuses_to_present_a_sparse_hole_as_captured() {
        let field = FieldSummary {
            arg: None,
            object_id: 1,
            key: "arg1".into(),
            layout: String::new(),
            logical_len: Some(10),
            captured_len: 2,
            status: Some(0),
            capture_error: 0,
            complete: false,
            preview: vec![],
            raw_path: None,
            ranges: vec![(0, 2), (8, 2)],
        };
        assert!(matches!(
            read_captured_range(Path::new("/unused"), &field, 1, 8),
            Err(RecordingError::MissingRange)
        ));
    }
}
