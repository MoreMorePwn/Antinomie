// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The rows of a run's query tables as the scan made them, before each table's
//! filter, sort and page (ANT-T0590). A filter, sort or page change on a run
//! whose recording is as it was is answered from these rows ([`crate::requery`])
//! and the recording is not read again.
//!
//! A scan that keeps its index records through a [`Tap`] as it goes. Table rows
//! go to a log on disk each (a SQLite file in the temp folder, like the sort
//! spool); the findings and the changed files stay in memory, as the engine and
//! the Retention setting already bound them. A log or the whole index that would
//! pass its cap voids the index: every request then scans as before. Nothing is
//! shed: a row that does not fit means no index, not a missing row.
use super::*;
use std::sync::Mutex;

/// The tables whose rows are logged: Opened, HTTP, Read, the operation tabs
/// and the Network tabs.
pub const LOGGED: [usize; 14] = [
    1,
    3,
    5,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    ENDPOINT_SLOT,
    DOMAIN_SLOT,
    TLS_SLOT,
];

/// Pages one table's log may hold, 768 MiB: the rows the index may hold, with the fields a filter reads beside each.
pub const LOG_PAGES: u64 = 196_608;
/// Bytes of rows all the logs of one index may hold together.
pub const INDEX_BYTES: u64 = 512 * 1024 * 1024;

/// One table's rows in scan order.
pub struct RowLog {
    connection: rusqlite::Connection,
    // Connection drops before this directory and its temporary database.
    _directory: PacketSpool,
    codec: sorting::Codec,
    pub rows: u64,
    pub bytes: u64,
}

impl RowLog {
    fn new() -> Result<Self, String> {
        let directory = PacketSpool::new()?;
        let connection = rusqlite::Connection::open(directory.directory.join("rows.sqlite"))
            .map_err(|error| error.to_string())?;
        connection
            .execute_batch(&format!(
                "PRAGMA trusted_schema=OFF; PRAGMA page_size=4096; PRAGMA max_page_count={LOG_PAGES}; PRAGMA cache_size=-2048; PRAGMA temp_store=FILE; PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; CREATE TABLE rows(seq INTEGER PRIMARY KEY, fields BLOB NOT NULL, payload BLOB NOT NULL); BEGIN;"
            ))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            connection,
            _directory: directory,
            codec: sorting::Codec::default(),
            rows: 0,
            bytes: 0,
        })
    }

    fn push(&mut self, row: &[Cell]) -> Result<u64, String> {
        let payload = self.codec.encode(row)?;
        // The fields a filter reads, beside the row: a filter change decodes
        // these and only the rows it keeps in full (ANT-T0592).
        let fields = self
            .codec
            .encode_values(row.first().map_or(&[][..], |cell| cell.values.as_slice()))?;
        // The index's cap counts the rows, as before the fields were kept.
        let size = payload.len() as u64;
        self.connection
            .prepare_cached("INSERT INTO rows(fields,payload) VALUES(?1,?2)")
            .and_then(|mut insert| insert.execute(rusqlite::params![fields, payload]))
            .map_err(|error| error.to_string())?;
        self.rows += 1;
        self.bytes += size;
        Ok(size)
    }

    fn commit(&mut self) -> Result<(), String> {
        self.connection
            .execute_batch("COMMIT")
            .map_err(|error| error.to_string())
    }

    /// Every row in scan order; stops at the first error `visit` returns.
    pub fn each(
        &self,
        cancel: &AtomicBool,
        mut visit: impl FnMut(Vec<Cell>) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut query = self
            .connection
            .prepare_cached("SELECT payload FROM rows ORDER BY seq")
            .map_err(|error| error.to_string())?;
        let mut rows = query.query([]).map_err(|error| error.to_string())?;
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            if cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            let payload = row
                .get_ref(0)
                .and_then(|value| value.as_blob().map_err(Into::into))
                .map_err(|error| error.to_string())?;
            visit(self.codec.decode(payload)?)?;
        }
        Ok(())
    }
}

/// One field of a row's first cell.
pub type RowField = (&'static str, RowValue);

/// One table's row, read back by its number in the log.
type RowAt<'a> = &'a dyn Fn() -> Result<Vec<Cell>, String>;

impl RowLog {
    /// The rows whose fields `keep` accepts, in scan order, each with its
    /// number in the log and a way to decode it in full: a row that is not
    /// wanted is never decoded.
    pub fn each_matching(
        &self,
        cancel: &AtomicBool,
        keep: &dyn Fn(&[RowField]) -> bool,
        mut visit: impl FnMut(u64, RowAt) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut query = self
            .connection
            .prepare_cached("SELECT seq, fields, payload FROM rows ORDER BY seq")
            .map_err(|error| error.to_string())?;
        let mut rows = query.query([]).map_err(|error| error.to_string())?;
        let mut counted = 0u32;
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            counted = counted.wrapping_add(1);
            if counted.is_multiple_of(1024) && cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            let blob = |at| {
                row.get_ref(at)
                    .and_then(|value| value.as_blob().map_err(Into::into))
                    .map_err(|error: rusqlite::Error| error.to_string())
            };
            let values = self.codec.decode_values(blob(1)?)?;
            if keep(&values) {
                let seq: i64 = row.get(0).map_err(|error| error.to_string())?;
                let payload = blob(2)?;
                visit(seq as u64, &|| self.codec.decode(payload))?;
            }
        }
        Ok(())
    }

    /// Row number `seq`, in full.
    pub fn row(&self, seq: u64) -> Result<Vec<Cell>, String> {
        let payload: Vec<u8> = self
            .connection
            .prepare_cached("SELECT payload FROM rows WHERE seq=?1")
            .and_then(|mut query| query.query_row([seq as i64], |row| row.get(0)))
            .map_err(|error| error.to_string())?;
        self.codec.decode(&payload)
    }
}

/// What a scan records while it runs. Shared by the passes through the request.
pub struct Tap {
    logs: Vec<(usize, Mutex<RowLog>)>,
    failed: std::sync::atomic::AtomicBool,
    bytes: std::sync::atomic::AtomicU64,
    limit: u64,
    changes: Mutex<Option<Vec<files::Change>>>,
}

impl Tap {
    pub fn new() -> Result<Arc<Self>, String> {
        Self::with_limit(INDEX_BYTES)
    }

    /// A tap whose logs may hold `limit` bytes of rows together.
    pub fn with_limit(limit: u64) -> Result<Arc<Self>, String> {
        static SWEPT: std::sync::Once = std::sync::Once::new();
        SWEPT.call_once(|| sweep_dead_spools(&std::env::temp_dir()));
        let mut logs = Vec::new();
        for slot in LOGGED {
            logs.push((slot, Mutex::new(RowLog::new()?)));
        }
        Ok(Arc::new(Self {
            logs,
            failed: Default::default(),
            bytes: Default::default(),
            limit,
            changes: Mutex::new(None),
        }))
    }

    /// Record one row of table `slot`. A failure (a cap, the disk) voids the
    /// index; the scan itself goes on unchanged.
    pub fn push(&self, slot: usize, row: &[Cell]) {
        if self.failed.load(Ordering::Relaxed) {
            return;
        }
        let Some((_, log)) = self.logs.iter().find(|(at, _)| *at == slot) else {
            return;
        };
        let pushed = log
            .lock()
            .map_err(|_| "row log lock poisoned".to_owned())
            .and_then(|mut log| log.push(row));
        match pushed {
            Ok(size) => {
                let total = self.bytes.fetch_add(size, Ordering::Relaxed) + size;
                if total > self.limit {
                    self.failed.store(true, Ordering::Relaxed);
                }
            }
            Err(_) => self.failed.store(true, Ordering::Relaxed),
        }
    }

    /// The files the Changed table lists before its filter, in order.
    pub fn keep_changes(&self, changes: Vec<files::Change>) {
        if let Ok(mut held) = self.changes.lock() {
            *held = Some(changes);
        }
    }

    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    /// Bytes of rows the logs hold.
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// End the recording and make the index; `None` when it is void.
    pub fn seal(
        self: &Arc<Self>,
        request: &ScanRequest,
        findings: Vec<Finding>,
        info: Vec<rules::InfoMark>,
        verdicts: Vec<antinomie_monitor_core::ioc::verdict::Verdict>,
    ) -> Option<Arc<RowIndex>> {
        if self.failed() {
            return None;
        }
        for (_, log) in &self.logs {
            log.lock().ok()?.commit().ok()?;
        }
        let changes = self.changes.lock().ok()?.take()?;
        Some(Arc::new(RowIndex {
            file_visibility: request.file_visibility,
            show_info: request.finding_view.show_info,
            facts: facts(request),
            tap: Arc::clone(self),
            findings,
            info,
            changes,
            verdicts,
        }))
    }
}

/// The rows of one run's tables, and what the passes counted that they depend on.
pub struct RowIndex {
    /// The toggles the rows were made under: a request with others scans.
    pub file_visibility: file_visibility::FileVisibility,
    pub show_info: bool,
    /// The request facts the rows depend on that the recording's stamp does not carry.
    pub facts: String,
    /// Holds the logs; nothing is recorded into it after the seal.
    pub tap: Arc<Tap>,
    pub findings: Vec<Finding>,
    pub info: Vec<rules::InfoMark>,
    pub changes: Vec<files::Change>,
    pub verdicts: Vec<antinomie_monitor_core::ioc::verdict::Verdict>,
}

impl RowIndex {
    /// Whether a new index made with `request` would have the same rows.
    pub fn fits(&self, request: &ScanRequest) -> bool {
        self.file_visibility == request.file_visibility
            && self.show_info == request.finding_view.show_info
            && self.facts == facts(request)
    }

    /// The rows of table `slot`, in scan order.
    pub fn each(
        &self,
        slot: usize,
        cancel: &AtomicBool,
        visit: impl FnMut(Vec<Cell>) -> Result<(), String>,
    ) -> Result<(), String> {
        let (_, log) = self
            .tap
            .logs
            .iter()
            .find(|(at, _)| *at == slot)
            .ok_or("table has no kept rows")?;
        log.lock()
            .map_err(|_| "row log lock poisoned".to_owned())?
            .each(cancel, visit)
    }

    /// The rows of table `slot` whose fields `keep` accepts, in scan order
    /// ([`RowLog::each_matching`]).
    pub fn each_matching(
        &self,
        slot: usize,
        cancel: &AtomicBool,
        keep: &dyn Fn(&[RowField]) -> bool,
        visit: impl FnMut(u64, RowAt) -> Result<(), String>,
    ) -> Result<(), String> {
        let (_, log) = self
            .tap
            .logs
            .iter()
            .find(|(at, _)| *at == slot)
            .ok_or("table has no kept rows")?;
        log.lock()
            .map_err(|_| "row log lock poisoned".to_owned())?
            .each_matching(cancel, keep, visit)
    }

    /// Row number `seq` of table `slot`, in full.
    pub fn row(&self, slot: usize, seq: u64) -> Result<Vec<Cell>, String> {
        let (_, log) = self
            .tap
            .logs
            .iter()
            .find(|(at, _)| *at == slot)
            .ok_or("table has no kept rows")?;
        log.lock()
            .map_err(|_| "row log lock poisoned".to_owned())?
            .row(seq)
    }

    /// Rows of every log.
    pub fn row_count(&self) -> u64 {
        self.tap
            .logs
            .iter()
            .filter_map(|(_, log)| log.lock().ok().map(|log| log.rows))
            .sum()
    }
}

/// What else in the request shapes the rows: the packer verdict, the address
/// lookup mode, the guest's gateway, the launch and the run's identity.
fn facts(request: &ScanRequest) -> String {
    format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}",
        request.packed,
        request.address_lookup,
        request.guest_gateway,
        request.launch,
        request.identity
    )
}

/// Remove the spool folders (`antinomie-triage-<pid>-<n>`) of processes that are
/// gone. The kept index is held by the process until it exits, and a process
/// that exits (or is killed) does not run its destructors, so its logs would
/// stay in the temp folder for good. The next process to keep an index clears them.
pub fn sweep_dead_spools(temp: &Path) {
    // Without /proc nothing says a process is gone.
    if !Path::new("/proc/self").exists() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(temp) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid = name
            .to_str()
            .and_then(|name| name.strip_prefix("antinomie-triage-"))
            .and_then(|rest| rest.split('-').next())
            .and_then(|pid| pid.parse::<u32>().ok());
        let (Some(pid), Ok(kind)) = (pid, entry.file_type()) else {
            continue;
        };
        if kind.is_dir()
            && pid != std::process::id()
            && !Path::new(&format!("/proc/{pid}")).exists()
        {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}
