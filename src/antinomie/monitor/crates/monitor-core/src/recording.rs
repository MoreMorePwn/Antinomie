//! Reopen finalized captures and inspect only byte ranges known to be received.
use crate::{
    api::*,
    archive_io,
    parser::{self, Assembler},
    storage,
};
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

pub struct Recording {
    pub directory: PathBuf,
    pub manifest: serde_json::Value,
    pub events: Vec<EventSummary>,
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
            .flat_map(|row| row.entry.into_iter().chain(row.exit))
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
            e.fields.len() > 256
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
    let (header, _) = parser::parse_packet(packet).ok()?;
    (header.record_type == 1 && matches!(header.phase, 1 | 2)).then_some((
        header.stream_id,
        header.task_cookie,
        header.call_id,
    ))
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
fn raw_identity(path: &Path) -> Result<String, RecordingError> {
    let m = archive_io::open_regular(
        path.parent()
            .ok_or(RecordingError::Limit("raw archive has no directory"))?,
        path,
    )?
    .metadata()?;
    Ok(format!(
        "index-v2:{}:{}:{}:{}:{}",
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec()
    ))
}
fn archive_index(
    directory: &Path,
    cancel: &AtomicBool,
) -> Result<(rusqlite::Connection, String), RecordingError> {
    let raw = directory.join("telemetry.raw");
    let identity = raw_identity(&raw)?;
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
    let index_path = cache_root.join(format!("{name}.sqlite"));
    let mut connection = rusqlite::Connection::open(&index_path)?;
    fs::set_permissions(&index_path, fs::Permissions::from_mode(0o600))?;
    connection.busy_timeout(std::time::Duration::from_secs(1))?;
    connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA page_size=4096; PRAGMA cache_size=-2048; PRAGMA temp_store=FILE; CREATE TABLE IF NOT EXISTS metadata(identity TEXT); CREATE TABLE IF NOT EXISTS invocations(key BLOB PRIMARY KEY, first_offset INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS invocation_order ON invocations(first_offset); CREATE TABLE IF NOT EXISTS packets(key BLOB NOT NULL, offset INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS packet_keys ON packets(key,offset);")?;
    let budget = fs::metadata(&raw)?
        .len()
        .checked_mul(2)
        .and_then(|size| size.checked_add(1024 * 1024))
        .ok_or(RecordingError::Limit("archive index budget overflow"))?
        .min(16 * 1024 * 1024 * 1024);
    connection.pragma_update(None, "max_page_count", (budget / 4096) as i64)?;
    let cached: Option<String> = connection
        .query_row("SELECT identity FROM metadata LIMIT 1", [], |row| {
            row.get(0)
        })
        .ok();
    if cached.as_deref() != Some(&identity) {
        let transaction = connection.transaction()?;
        transaction
            .execute_batch("DELETE FROM metadata; DELETE FROM invocations; DELETE FROM packets;")?;
        {
            let mut invocation = transaction
                .prepare("INSERT OR IGNORE INTO invocations(key,first_offset) VALUES(?1,?2)")?;
            let mut packets =
                transaction.prepare("INSERT INTO packets(key,offset) VALUES(?1,?2)")?;
            let mut reader = BufReader::new(archive_io::open_regular(directory, &raw)?);
            while let Some((offset, packet)) = next_packet(&mut reader)? {
                if cancel.load(Ordering::Relaxed) {
                    return Err(RecordingError::Limit("archive read cancelled"));
                }
                if let Some(key) = invocation_key(&packet) {
                    let key = key_blob(key);
                    let offset = i64::try_from(offset).map_err(|_| {
                        RecordingError::Limit("raw archive offset exceeds index range")
                    })?;
                    invocation.execute(rusqlite::params![key, offset])?;
                    packets.execute(rusqlite::params![key, offset])?;
                }
            }
        }
        if raw_identity(&raw)? != identity {
            return Err(RecordingError::Limit(
                "raw archive changed while building index; retry after capture settles",
            ));
        }
        transaction.execute("INSERT INTO metadata(identity) VALUES(?1)", [&identity])?;
        transaction.commit()?;
    }
    Ok((connection, identity))
}

impl Recording {
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
        if cancel.load(Ordering::Relaxed) {
            return Err(RecordingError::Limit("archive read cancelled"));
        }
        if !(1..=256).contains(&limit) {
            return Err(RecordingError::Limit("page size must be 1..256"));
        }
        let path = self.directory.join("telemetry.raw");
        if offset > fs::metadata(&path)?.len() {
            return Err(RecordingError::Limit("cursor beyond raw archive"));
        }
        let (connection, identity) = archive_index(&self.directory, cancel)?;
        let mut query=connection.prepare("SELECT key,first_offset FROM invocations WHERE first_offset>=?1 ORDER BY first_offset LIMIT ?2")?;
        let selected = query
            .query_map(
                rusqlite::params![
                    i64::try_from(offset).map_err(|_| RecordingError::Limit("cursor too large"))?,
                    (limit + 1) as i64
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let next_offset = selected
            .get(limit)
            .map(|row| u64::try_from(row.1))
            .transpose()
            .map_err(|_| RecordingError::Limit("negative cached offset"))?;
        let selected = &selected[..selected.len().min(limit)];
        let keys: Vec<_> = selected.iter().map(|row| row.0.clone()).collect();
        let mut assembler = Assembler::open_archive(self.directory.join("objects"))
            .map_err(|_| RecordingError::Limit("cannot open archived objects"))?;
        let mut latest = std::collections::BTreeMap::new();
        let mut issues = Vec::new();
        let mut reader = BufReader::new(archive_io::open_regular(&self.directory, &path)?);
        let mut packet_query =
            connection.prepare("SELECT offset FROM packets WHERE key=?1 ORDER BY offset")?;
        for key in &keys {
            let offsets = packet_query.query_map([key], |row| row.get::<_, i64>(0))?;
            for offset in offsets {
                if cancel.load(Ordering::Relaxed) {
                    return Err(RecordingError::Limit("archive read cancelled"));
                }
                reader.seek(SeekFrom::Start(u64::try_from(offset?).map_err(|_| {
                    RecordingError::Limit("negative cached packet offset")
                })?))?;
                let (_, packet) = next_packet(&mut reader)?
                    .ok_or(RecordingError::Limit("indexed packet is missing"))?;
                if invocation_key(&packet).map(key_blob).as_ref() != Some(key) {
                    return Err(RecordingError::Limit("indexed packet identity changed"));
                }
                match assembler.ingest(&packet) {
                    Ok(Some(event)) => {
                        latest.insert(
                            (
                                event.stream_id,
                                event.task_cookie,
                                event.call_id,
                                event.phase,
                            ),
                            event,
                        );
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if issues.len() < 32 {
                            issues.push(error.to_string());
                        }
                    }
                }
            }
        }
        if raw_identity(&path)? != identity {
            return Err(RecordingError::Limit(
                "raw archive changed during paging; retry after capture settles",
            ));
        }
        let events: Vec<_> = latest.into_values().collect();
        let mut invocations = pair_events(&events);
        invocations.sort_by_key(|row| {
            keys.iter()
                .position(|key| *key == key_blob((row.stream_id, row.task_cookie, row.call_id)))
                .unwrap_or(usize::MAX)
        });
        Ok(InvocationPage {
            invocations,
            next_offset,
            issues,
        })
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
        while records.len() < limit && file.stream_position()? < size && output_len < 65536 {
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
            next_offset: (cursor < size).then_some(cursor),
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
            run.directory = entry.path();
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
                recording_error: manifest
                    .get("persistence_error")
                    .and_then(|e| e.as_str())
                    .map(String::from),
            });
            if runs.len() > 1024 {
                return Err(RecordingError::Limit(
                    "more than 1024 run summaries; open a recording directory directly",
                ));
            }
        }
    }
    runs.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(runs)
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
        let (index, _) = archive_index(&directory, &AtomicBool::new(false)).unwrap();
        let pages: i64 = index
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .unwrap();
        assert!(
            (pages as u64) * 4096
                < fs::metadata(directory.join("telemetry.raw")).unwrap().len() * 2 + 1024 * 1024
        );
        assert!(
            recording
                .invocation_page_cancellable(0, 7, &AtomicBool::new(true))
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
