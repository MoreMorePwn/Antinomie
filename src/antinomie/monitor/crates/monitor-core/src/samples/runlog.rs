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
    Library, Push, SampleRef, SeenRun,
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

/// Entries that may wait for the custody writer; past that, the caller waits
/// for room (an entry is never dropped for a full queue).
const QUEUED_ENTRIES: usize = 4096;

/// Times the custody writer tries an entry, each after the database's own
/// long busy wait ([`super::library::BUSY_WRITER`]), before it reports the
/// entry as lost.
const WRITE_ATTEMPTS: u32 = 6;

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
    /// A run ended: its entries in the seen-run index (ANT-T0441).
    Index {
        data_dir: PathBuf,
        runs: Vec<SeenRun>,
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
                            Job::Index { data_dir, runs, by } => {
                                let _ = Library::open(&data_dir)
                                    .and_then(|library| library.with_actor(&by))
                                    .and_then(|mut library| library.index_runs(&runs));
                            }
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

/// Write one custody entry, trying again while the database is busy. When it
/// still cannot be written the loss is reported on stderr: an entry is never
/// skipped silently.
fn write(database: &Path, sha256: &str, by: &str, at_ms: u64, event: &CustodyEvent) {
    let sink = ChainedEvents::new(database);
    retry("custody entry", || sink.record(sha256, by, at_ms, event));
}

fn write_push(data_dir: &Path, sha256: &str, push: Push, by: &str) {
    retry("push record", || {
        Library::open(data_dir)
            .and_then(|library| library.with_actor(by))
            .and_then(|library| {
                library.set_busy_timeout(super::library::BUSY_WRITER)?;
                Ok(library)
            })
            .and_then(|mut library| library.record_push(sha256, push.clone()))
    });
}

fn retry(what: &str, mut attempt: impl FnMut() -> Result<(), String>) {
    let mut last = String::new();
    for round in 0..WRITE_ATTEMPTS {
        match attempt() {
            Ok(()) => return,
            Err(error) => {
                // Only a busy database is retried, and never a change that is
                // already saved (its entry alone failed): that would double it.
                let busy = (error.contains("locked") || error.contains("busy"))
                    && !error.starts_with("saved, but");
                last = error;
                if !busy || round + 1 == WRITE_ATTEMPTS {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(200 << round));
            }
        }
    }
    eprintln!("antinomie: LOST {what}: {last}");
}

/// Record that a sample was sent into a VM, now, without waiting for the
/// database: written in order with the run entries that follow it, and
/// retried like them when the database is busy.
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
    let _ = queue.send(Job::Push {
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
    data_dir: PathBuf,
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
            data_dir: data_dir.to_path_buf(),
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
        let _ = queue.send(Job::Entry {
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

    /// The run is over: put it into the seen-run index for every library
    /// sample it is linked to (the sample and the libraries it loaded), so the
    /// command line and the sidebar list it without the window (ANT-T0441).
    /// Written in order with the entries, and dropped when it cannot be.
    pub fn index_run(&self, run: &crate::RunSummary) {
        let runs = super::seen_runs_of(run, &self.vm);
        if runs.is_empty() {
            return;
        }
        let by = self.app.clone();
        let Some(queue) = queue() else {
            let _ = Library::open(&self.data_dir)
                .and_then(|library| library.with_actor(&by))
                .and_then(|mut library| library.index_runs(&runs));
            return;
        };
        let _ = queue.try_send(Job::Index {
            data_dir: self.data_dir.clone(),
            runs,
            by,
        });
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
