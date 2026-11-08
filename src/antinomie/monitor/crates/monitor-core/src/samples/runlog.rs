// SPDX-License-Identifier: GPL-3.0-only
//! What a run writes to the custody log of the library sample it runs: its
//! start, what the analyst did to it, and its end. One [`RunLog`] belongs to
//! one run of one library sample (found by hash when the run is launched); a
//! run of anything else has none, so nothing here costs it anything.
//!
//! Every write is best effort. A custody log that cannot be written (the
//! library is locked, the disk is full) must never fail or slow a run, so the
//! error is dropped here and the Samples page's Verify says what is missing.
//!
//! The entries, and the record that a sample was sent into a VM
//! ([`record_push_later`]), are written by one background thread, in the
//! order they were made: a database commit syncs the disk, and on a busy disk
//! that took tens of seconds on the transport thread (ANT-T0203), long enough
//! for the guest to drop telemetry. [`settle_custody`] waits for what is
//! queued.
use super::{
    Library, Push, SampleRef,
    actor::{self, ANALYST},
    chain::ChainedEvents,
    custody::{ActionKind, CustodyEvent, CustodySink},
    library::{DATABASE, now_ms},
    samples_dir,
};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::Path,
    path::PathBuf,
    sync::{OnceLock, mpsc},
};

/// Entries that may wait for the custody writer; past that, an entry is
/// dropped like one the database refused.
const QUEUED_ENTRIES: usize = 4096;

/// Work for the custody writer thread.
enum Job {
    Entry {
        database: PathBuf,
        sha256: String,
        by: String,
        at_ms: u64,
        event: CustodyEvent,
    },
    /// A sample was sent into a VM: its push record and custody entry.
    Push {
        data_dir: PathBuf,
        sha256: String,
        push: Push,
        by: String,
    },
    /// Answered once everything queued before it is written.
    Settle(mpsc::SyncSender<()>),
}

/// The custody writer's queue; `None` when its thread could not start, and
/// entries are then written by their caller.
fn queue() -> Option<&'static mpsc::SyncSender<Job>> {
    static QUEUE: OnceLock<Option<mpsc::SyncSender<Job>>> = OnceLock::new();
    QUEUE
        .get_or_init(|| {
            let (sender, jobs) = mpsc::sync_channel::<Job>(QUEUED_ENTRIES);
            std::thread::Builder::new()
                .name("antinomie-custody".into())
                .spawn(move || {
                    for job in jobs {
                        match job {
                            Job::Entry {
                                database,
                                sha256,
                                by,
                                at_ms,
                                event,
                            } => write(&database, &sha256, &by, at_ms, &event),
                            Job::Push {
                                data_dir,
                                sha256,
                                push,
                                by,
                            } => write_push(&data_dir, &sha256, push, &by),
                            Job::Settle(done) => {
                                let _ = done.send(());
                            }
                        }
                    }
                })
                .ok()
                .map(|_| sender)
        })
        .as_ref()
}

fn write(database: &Path, sha256: &str, by: &str, at_ms: u64, event: &CustodyEvent) {
    let _ = ChainedEvents::new(database).record(sha256, by, at_ms, event);
}

fn write_push(data_dir: &Path, sha256: &str, push: Push, by: &str) {
    let _ = Library::open(data_dir)
        .and_then(|library| library.with_actor(by))
        .and_then(|mut library| library.record_push(sha256, push));
}

/// Record that a sample was sent into a VM, now, without waiting for the
/// database: written in order with the run entries that follow it, and
/// dropped like them when it cannot be written.
pub fn record_push_later(data_dir: &Path, sha256: &str, push: Push) {
    let push = Push {
        at_ms: now_ms(),
        ..push
    };
    let by = actor::current();
    let Some(queue) = queue() else {
        write_push(data_dir, sha256, push, &by);
        return;
    };
    let _ = queue.try_send(Job::Push {
        data_dir: data_dir.to_path_buf(),
        sha256: sha256.to_ascii_lowercase(),
        push,
        by,
    });
}

/// Wait until every custody entry made so far is written (or refused).
pub fn settle_custody() {
    let Some(queue) = queue() else {
        return;
    };
    let (done, settled) = mpsc::sync_channel(1);
    if queue.send(Job::Settle(done)).is_ok() {
        let _ = settled.recv();
    }
}

pub struct RunLog {
    /// Who the program's own entries name ([`actor::current`] when the run
    /// started).
    app: String,
    database: PathBuf,
    sha256: String,
    run: String,
    vm: String,
    /// Bytes typed since the last entry. Only this number is ever kept.
    typed: u64,
}

impl RunLog {
    pub fn new(data_dir: &Path, sample: &SampleRef, run: &str, vm: &str) -> Self {
        Self::with_actor(data_dir, sample, run, vm, &actor::current())
    }

    /// A run log whose program entries (start, end) name `app` as their
    /// actor: the caller that caused the run. What the analyst does to the
    /// guest is always `analyst`.
    pub fn with_actor(data_dir: &Path, sample: &SampleRef, run: &str, vm: &str, app: &str) -> Self {
        Self {
            app: app.to_owned(),
            database: samples_dir(data_dir).join(DATABASE),
            sha256: sample.sha256.to_ascii_lowercase(),
            run: run.into(),
            vm: vm.into(),
            typed: 0,
        }
    }

    fn note(&self, by: &str, event: CustodyEvent) {
        let at_ms = now_ms();
        let Some(queue) = queue() else {
            write(&self.database, &self.sha256, by, at_ms, &event);
            return;
        };
        let _ = queue.try_send(Job::Entry {
            database: self.database.clone(),
            sha256: self.sha256.clone(),
            by: by.to_owned(),
            at_ms,
            event,
        });
    }

    /// The run started: what it ran on and under.
    pub fn started(&self, detail: String) {
        self.note(
            &self.app,
            CustodyEvent::RunStarted {
                vm: self.vm.clone(),
                run: self.run.clone(),
                detail,
            },
        );
    }

    /// Input went to the guest terminal. A line sent (Enter) writes an entry
    /// with the number of bytes typed since the last one; the text is not
    /// looked at beyond that.
    pub fn typed(&mut self, data: &[u8]) {
        self.typed = self.typed.saturating_add(data.len() as u64);
        if data.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
            self.flush_typed();
        }
    }

    /// Write what was typed and not yet noted.
    pub fn flush_typed(&mut self) {
        if self.typed > 0 {
            let bytes = std::mem::take(&mut self.typed);
            self.note(
                ANALYST,
                CustodyEvent::TerminalInput {
                    run: self.run.clone(),
                    bytes,
                },
            );
        }
    }

    /// The analyst did something to the running guest.
    pub fn action(&mut self, what: ActionKind, detail: &str) {
        self.flush_typed();
        self.note(
            ANALYST,
            CustodyEvent::Action {
                run: self.run.clone(),
                what,
                detail: detail.into(),
            },
        );
    }

    /// The run's recording is final: `detail` says how much and what hash.
    pub fn ended(&mut self, detail: String) {
        self.flush_typed();
        self.note(
            &self.app,
            CustodyEvent::RunEnded {
                vm: self.vm.clone(),
                run: self.run.clone(),
                detail,
            },
        );
    }
}

/// SHA-256 of a file read in blocks; `None` when it cannot be read.
pub fn file_sha256(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut block = vec![0u8; 1 << 16];
    loop {
        let read = file.read(&mut block).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&block[..read]);
    }
    Some(format!("{:x}", hasher.finalize()))
}
