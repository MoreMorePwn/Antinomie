// SPDX-License-Identifier: GPL-3.0-only
//! The job store (design 4.3, 4.8, 5.5, 5.6): SQLite in WAL mode, one writer.
//! The `jobs` table is the queue and the source of truth; every state
//! transition is one transaction that also inserts its event rows, and the
//! mirror line in `jobs/<id>/events.ndjson` is appended after the commit. On
//! start `recover` repairs the mirror and puts back jobs a dead process left
//! `running`.
//!
//! Layout under `<data>/service/`: `jobs.sqlite`, `jobs/<job-id>/spec.json`
//! and `events.ndjson`.

pub mod admission;
mod artifacts;
pub mod canon;
mod events;
mod lifecycle;
pub mod machine;
mod mirror;
mod model;
mod patch;
mod query;
pub mod recover;
pub mod schema;
mod submit;

#[cfg(test)]
pub(crate) mod tests;

pub use artifacts::NewArtifact;
pub use lifecycle::{Eligibility, RequeueKind};
pub use patch::JobPatch;
pub use query::QueueCounts;
pub use recover::RecoveryReport;
pub use submit::{
    IDEMPOTENCY_WINDOW_MS, IntakeError, SampleAdmission, SubmitContext, SubmitLimits, redact_remote,
};

use crate::{
    api::{
        error::{ApiError, ErrorCode},
        event::{Event, EventBody, EventScope},
        ids::JobId,
    },
    clock::{Clock, SystemClock, new_epoch},
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::{
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::Duration,
};

pub type R<T> = Result<T, ApiError>;

/// How long a reader waits for the writer (design 4.3).
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn db(error: rusqlite::Error) -> ApiError {
    let busy = matches!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    );
    let code = if busy {
        ErrorCode::Unavailable
    } else {
        ErrorCode::Internal
    };
    ApiError::new(code, format!("job store: {error}"))
}

pub(crate) fn internal(message: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Internal, format!("job store: {message}"))
}

/// A point where a test makes the store stop, as a process kill would.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// After the rows are written, before the commit: nothing may remain.
    BeforeCommit,
    /// After the commit, before the mirror line is appended.
    AfterCommit,
    /// Half a mirror line is written.
    MidMirror,
}

/// What reaching a [`Fault`] does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultAction {
    /// The call returns `internal`, as if the process had died there (the
    /// caller drops the store and opens it again).
    Fail,
    /// `std::process::abort()`: a real kill, for a test that runs a child.
    Abort,
}

pub struct Store {
    conn: Mutex<Connection>,
    root: PathBuf,
    clock: Arc<dyn Clock>,
    epoch: String,
    engine_seq: AtomicU64,
    subscribers: Mutex<Vec<mpsc::Sender<Event>>>,
    fault: Mutex<Option<(Fault, FaultAction)>>,
    read_only: bool,
}

/// A write in progress: the open transaction, the time, and the events the
/// caller inserted (sent to the mirror and the subscribers after the commit).
pub(crate) struct Tx<'a> {
    pub tx: rusqlite::Transaction<'a>,
    pub now: u64,
    pending: Vec<Event>,
    engine_seq: &'a AtomicU64,
}

impl Tx<'_> {
    /// Insert an event row. A stored event of a job gets the next `seq` of
    /// that job; an engine event the next of this epoch.
    pub fn emit(&mut self, job: Option<&JobId>, body: EventBody) -> R<()> {
        let scope = body.scope();
        debug_assert!(!body.is_ephemeral());
        debug_assert_eq!(scope == EventScope::Job, job.is_some());
        let seq: u64 = match job {
            Some(id) => self
                .tx
                .query_row(
                    "SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE job_id = ?1",
                    [id.as_str()],
                    |row| row.get(0),
                )
                .map_err(db)?,
            None => self.engine_seq.fetch_add(1, Ordering::SeqCst) + 1,
        };
        let value = serde_json::to_value(&body).map_err(internal)?;
        let kind = value["type"].as_str().unwrap_or_default().to_owned();
        let data = value.get("data").cloned().unwrap_or_default().to_string();
        self.tx
            .execute(
                "INSERT INTO events(job_id, seq, ts_ms, type, data_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![job.map(JobId::as_str), seq, self.now, kind, data],
            )
            .map_err(db)?;
        let gseq = self.tx.last_insert_rowid() as u64;
        self.pending.push(Event {
            seq: Some(seq),
            gseq: Some(gseq),
            ts_ms: self.now,
            scope,
            job_id: job.cloned(),
            body,
        });
        Ok(())
    }
}

impl Store {
    /// Open (and create) the store under `service_dir`
    /// (`<data>/service`) as its one writer.
    pub fn open(service_dir: &Path) -> R<Self> {
        Self::open_with_clock(service_dir, Arc::new(SystemClock))
    }

    pub fn open_with_clock(service_dir: &Path, clock: Arc<dyn Clock>) -> R<Self> {
        for dir in [service_dir.to_path_buf(), service_dir.join("jobs")] {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .map_err(|e| internal(format!("{}: {e}", dir.display())))?;
        }
        let path = service_dir.join("jobs.sqlite");
        // The database holds sample names and labels: owner only.
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| internal(format!("{}: {e}", path.display())))?;
        let conn = Connection::open(&path).map_err(db)?;
        conn.busy_timeout(BUSY_TIMEOUT).map_err(db)?;
        // WAL: job churn is not custody data, so readers need no rollback
        // journal (design 4.3).
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(db)?;
        let version: Option<u32> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|text| text.parse().ok());
        if let Some(found) = version
            && found > schema::SCHEMA_VERSION
        {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                format!(
                    "the job store was made by a newer Antinomie (layout {found}); this one reads layout {}",
                    schema::SCHEMA_VERSION
                ),
            ));
        }
        conn.execute_batch(schema::SCHEMA).map_err(db)?;
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?1)",
            [schema::SCHEMA_VERSION.to_string()],
        )
        .map_err(db)?;
        Ok(Self::with(conn, service_dir, clock, false))
    }

    /// Open for reading only (a second process beside the daemon): writes
    /// fail, reads wait up to five seconds for the writer.
    pub fn open_read_only(service_dir: &Path) -> R<Self> {
        let path = service_dir.join("jobs.sqlite");
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(db)?;
        conn.busy_timeout(BUSY_TIMEOUT).map_err(db)?;
        Ok(Self::with(conn, service_dir, Arc::new(SystemClock), true))
    }

    fn with(conn: Connection, root: &Path, clock: Arc<dyn Clock>, read_only: bool) -> Self {
        Self {
            conn: Mutex::new(conn),
            root: root.to_path_buf(),
            clock,
            epoch: new_epoch(),
            engine_seq: AtomicU64::new(0),
            subscribers: Mutex::new(Vec::new()),
            fault: Mutex::new(None),
            read_only,
        }
    }

    /// The random id of this start (`engine.hello.epoch`).
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// `<service>/jobs/<id>`.
    pub fn job_dir(&self, id: &JobId) -> PathBuf {
        self.root.join("jobs").join(id.as_str())
    }

    /// Arm a fault: the next time the store reaches `at`, it acts.
    pub fn inject_fault(&self, at: Fault, action: FaultAction) {
        *lock(&self.fault) = Some((at, action));
    }

    fn hit(&self, at: Fault) -> R<()> {
        let armed = {
            let mut fault = lock(&self.fault);
            match *fault {
                Some((point, action)) if point == at => fault.take().map(|_| action),
                _ => None,
            }
        };
        match armed {
            Some(FaultAction::Abort) => std::process::abort(),
            Some(FaultAction::Fail) => Err(internal(format!("fault injected at {at:?}"))),
            None => Ok(()),
        }
    }

    pub(crate) fn conn(&self) -> MutexGuard<'_, Connection> {
        lock(&self.conn)
    }

    /// Run `body` in one transaction. On `Err` nothing is kept. On success the
    /// events it inserted are mirrored and sent to the subscribers after the
    /// commit.
    pub(crate) fn write<T>(&self, body: impl FnOnce(&mut Tx<'_>) -> R<T>) -> R<T> {
        if self.read_only {
            return Err(internal("this store is open for reading only"));
        }
        let mut guard = lock(&self.conn);
        let (out, pending) = {
            let tx = guard
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db)?;
            let mut open = Tx {
                tx,
                now: self.clock.now_ms(),
                pending: Vec::new(),
                engine_seq: &self.engine_seq,
            };
            let out = body(&mut open)?;
            self.hit(Fault::BeforeCommit)?;
            let Tx { tx, pending, .. } = open;
            tx.commit().map_err(db)?;
            (out, pending)
        };
        self.hit(Fault::AfterCommit)?;
        // The connection stays locked so mirror lines of one job keep their
        // order.
        self.mirror(&pending)?;
        drop(guard);
        self.publish(pending);
        Ok(out)
    }

    /// Send committed events to every subscriber; a dropped receiver is
    /// forgotten.
    fn publish(&self, events: Vec<Event>) {
        let mut subscribers = lock(&self.subscribers);
        subscribers.retain(|sender| {
            events
                .iter()
                .all(|event| sender.send(event.clone()).is_ok())
        });
    }

    /// Every event committed (and every ephemeral one published) after this
    /// call arrives on the receiver. The socket server builds `events.subscribe`
    /// on it: it first reads the stored events after the client's resume point,
    /// then follows this channel and skips what it has already sent.
    pub fn subscribe(&self) -> mpsc::Receiver<Event> {
        let (sender, receiver) = mpsc::channel();
        lock(&self.subscribers).push(sender);
        receiver
    }

    /// Send an ephemeral event (`job.progress`, `job.metrics`): not stored, no
    /// `seq`, no `gseq`, never replayed.
    pub fn publish_ephemeral(&self, job: &JobId, body: EventBody) {
        debug_assert!(body.is_ephemeral());
        let event = Event {
            seq: None,
            gseq: None,
            ts_ms: self.clock.now_ms(),
            scope: EventScope::Job,
            job_id: Some(job.clone()),
            body,
        };
        self.publish(vec![event]);
    }
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
