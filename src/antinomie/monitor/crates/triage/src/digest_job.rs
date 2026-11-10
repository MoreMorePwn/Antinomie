// SPDX-License-Identifier: GPL-3.0-only
//! The digest of a finished run, built on its own (ANT-T0400).
//!
//! The window used to write a run's digest only once the run was selected and
//! its scan had finished, so a run nobody opened (and above all a heavy one:
//! a write flood of a million calls, a recording that lost telemetry) had none
//! until someone did. [`needs`] says which runs lack one; [`build`] makes it
//! from a streamed, budgeted read of the recording ([`Budget`]) and marks it
//! partial when the budget ended the read or telemetry was lost; the [`Queue`]
//! runs the builds one at a time, smallest recording first, off every caller's
//! thread. The window, the Auto lane and `antinomie-cli digest` all go through
//! these, and a build that is cut short (the app quits, the process is killed)
//! leaves no file behind and is simply made again: the digest is written
//! whole, once, at the end, and only when [`needs`] still says so.
use super::*;
use crate::scan_progress::{ScanProgress, ScanStop};
use antinomie_monitor_core::{
    run_digest::{self, RunDigest},
    BackendOptions, RunSummary,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;

/// The calls one background build reads at most. A recording past it gives a
/// partial digest of its first calls; the window reads the rest when the run
/// is opened.
pub const MAX_CALLS: u64 = 400_000;
/// The time one background build may take.
pub const MAX_TIME: Duration = Duration::from_secs(20 * 60);

/// What one build may spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub calls: u64,
    pub time: Duration,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            calls: MAX_CALLS,
            time: MAX_TIME,
        }
    }
}

/// How a build ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Built {
    /// The digest was made from the whole run.
    Whole,
    /// The digest was made, from part of the run (the reasons say why).
    Partial(Vec<String>),
    /// The run already has its digest, or needs none.
    Current,
    /// Another build of this run holds it (this process or another).
    Busy,
    /// The recording could not be read; the digest says so and is not retried
    /// until the recording changes.
    Failed(String),
}

fn lock_path(directory: &Path) -> PathBuf {
    directory.join(".triage-digest.lock")
}

/// Whether a digest of `run` is still to be made: it ended, its program
/// started, its telemetry is there, and it has no digest, or its digest was
/// made from a recording that was still being written and has changed since.
pub fn needs(run: &RunSummary) -> bool {
    if run.state.is_live()
        || run.root_task_cookie == 0
        || !run.directory.join("telemetry.raw").is_file()
    {
        return false;
    }
    match RunDigest::read(&run.directory) {
        None => true,
        Some(digest) if digest.launch_failure.is_some() => false,
        // Written by the window before 0.9.0: from the whole run.
        Some(digest) => match digest.coverage {
            None => digest.behaviour.is_none(),
            Some(coverage) => {
                coverage.revisit && coverage.source != run_digest::source_stamp(&run.directory)
            }
        },
    }
}

/// The runs of `runs` that [`needs`] a digest.
pub fn pending(runs: impl IntoIterator<Item = RunSummary>) -> Vec<RunSummary> {
    runs.into_iter().filter(needs).collect()
}

/// An advisory lock on a run's digest build, held until dropped. Taken by the
/// build, so two builds of one run, in this process or two, never both read it.
struct Held(#[allow(dead_code)] std::fs::File);

impl Held {
    fn take(directory: &Path) -> Option<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(lock_path(directory))
            .ok()?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).ok()?;
        Some(Self(file))
    }
}

/// Make the digest of `saved` now, on this thread, if it needs one: a streamed
/// read of the recording within `budget`, `progress` told as it goes. Nothing is
/// written into the run but the digest (and the programs the run wrote, for the
/// YARA scan); the Triage journals are the window's.
pub fn build(
    saved: &SavedRun,
    budget: Budget,
    cancel: &Arc<AtomicBool>,
    progress: &Arc<ScanProgress>,
) -> Result<Built, String> {
    let directory = saved.run.directory.as_path();
    // Nothing to read (and no lock file to leave in a folder that is not there).
    if !directory.join("telemetry.raw").is_file() {
        return Ok(Built::Current);
    }
    let Some(_held) = Held::take(directory) else {
        return Ok(Built::Busy);
    };
    // Another builder may have finished while this one waited its turn.
    if !needs(&saved.run) {
        return Ok(Built::Current);
    }
    let mut request = saved.request();
    // A background build leaves nothing in the process for a report to find.
    request.keep_index = false;
    request.read_only = true;
    request.progress = Some(Arc::clone(progress));
    request.stop = Some(Arc::new(ScanStop::new(budget.calls, budget.time)));
    match saved.scan_with(request, cancel) {
        Ok(scan) => {
            let partial = scan.partial.then(|| scan.partial_reasons.clone());
            digest::Update::of(&scan, None).write(directory)?;
            Ok(partial.map_or(Built::Whole, Built::Partial))
        }
        Err(error) if error == "cancelled" => Err(error),
        Err(error) => {
            let reason = format!("the recording could not be read: {error}");
            RunDigest::update(directory, |digest| {
                digest.coverage = Some(run_digest::Coverage {
                    partial: true,
                    reasons: vec![reason.clone()],
                    source: run_digest::source_stamp(directory),
                    ..Default::default()
                });
            })?;
            Ok(Built::Failed(reason))
        }
    }
}

/// A run to build the digest of.
#[derive(Clone)]
pub struct Job {
    pub run: RunSummary,
    pub options: BackendOptions,
    pub budget: Budget,
}

/// Where a run's digest build stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Idle,
    /// Waiting its turn behind another build.
    Queued,
    /// Being built; the line says how far it has got.
    Building(String),
}

struct Entry {
    job: Job,
    size: u64,
    cancel: Arc<AtomicBool>,
    progress: Arc<ScanProgress>,
    done: Option<std::sync::mpsc::Sender<Result<Built, String>>>,
}

#[derive(Default)]
struct Inner {
    waiting: Vec<Entry>,
    running: Option<(PathBuf, Arc<ScanProgress>, Arc<AtomicBool>)>,
    worker: bool,
    /// The run the window is reading for itself: its own scan writes that
    /// run's digest, so a build waits for the window to leave it.
    window: Option<PathBuf>,
    /// Runs whose digest is partial only because their recording was still
    /// being written, with the recording's state then; asked again by [`Queue::recheck`].
    watching: HashMap<PathBuf, (Job, String)>,
}

/// The builds waiting for their turn and the one that has it. One thread
/// builds, so at most one digest, heavy or not, is under way in the process;
/// the smallest recording goes first so a quick one never waits behind a flood.
#[derive(Default)]
pub struct Queue {
    inner: Mutex<Inner>,
    idle: Condvar,
}

/// The process's queue: the window and the daemon share it.
pub fn queue() -> &'static Queue {
    static QUEUE: OnceLock<Queue> = OnceLock::new();
    QUEUE.get_or_init(Queue::default)
}

impl Queue {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Ask for the digest of `job.run`, built in the background when its turn
    /// comes. `false` when the run is already queued or being built.
    pub fn submit(&'static self, job: Job) -> bool {
        self.enqueue(job, None).is_some()
    }

    /// [`submit`](Self::submit) and wait for the end of the build. `cancel`
    /// stops it (the build then ends with an error). A run another caller
    /// already queued answers [`Built::Busy`] at once.
    pub fn build_blocking(
        &'static self,
        job: Job,
        cancel: &Arc<AtomicBool>,
    ) -> Result<Built, String> {
        let (tx, rx) = std::sync::mpsc::channel();
        let Some(entry_cancel) = self.enqueue(job.clone(), Some(tx)) else {
            return Ok(Built::Busy);
        };
        loop {
            if cancel.load(Ordering::Relaxed) {
                entry_cancel.store(true, Ordering::Relaxed);
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(result) => return result,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("the digest build ended without an answer".into());
                }
            }
        }
    }

    fn enqueue(
        &'static self,
        job: Job,
        done: Option<std::sync::mpsc::Sender<Result<Built, String>>>,
    ) -> Option<Arc<AtomicBool>> {
        let directory = job.run.directory.clone();
        let mut inner = self.lock();
        let running = inner
            .running
            .as_ref()
            .is_some_and(|(running, _, _)| *running == directory);
        if running
            || inner
                .waiting
                .iter()
                .any(|e| e.job.run.directory == directory)
        {
            return None;
        }
        inner.watching.remove(&directory);
        let cancel = Arc::new(AtomicBool::new(false));
        let size = std::fs::metadata(directory.join("telemetry.raw")).map_or(0, |meta| meta.len());
        inner.waiting.push(Entry {
            job,
            size,
            cancel: Arc::clone(&cancel),
            progress: Arc::default(),
            done,
        });
        if !inner.worker {
            inner.worker = true;
            if std::thread::Builder::new()
                .name("triage-digest-queue".into())
                .spawn(move || self.work())
                .is_err()
            {
                inner.worker = false;
                inner.waiting.pop();
                return None;
            }
        }
        Some(cancel)
    }

    fn work(&self) {
        loop {
            let entry = {
                let mut inner = self.lock();
                let window = inner.window.clone();
                let Some(at) = inner
                    .waiting
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| Some(&entry.job.run.directory) != window.as_ref())
                    .min_by_key(|(_, entry)| entry.size)
                    .map(|(at, _)| at)
                else {
                    if inner.waiting.is_empty() {
                        inner.worker = false;
                        self.idle.notify_all();
                        return;
                    }
                    // Only the run the window reads is left: wait for it to move on.
                    drop(inner);
                    std::thread::sleep(Duration::from_millis(300));
                    continue;
                };
                let entry = inner.waiting.remove(at);
                inner.running = Some((
                    entry.job.run.directory.clone(),
                    Arc::clone(&entry.progress),
                    Arc::clone(&entry.cancel),
                ));
                entry
            };
            let job = entry.job.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if entry.cancel.load(Ordering::Relaxed) {
                    return Err("cancelled".to_owned());
                }
                let saved = SavedRun::open(job.run.clone(), &job.options)?;
                build(&saved, job.budget, &entry.cancel, &entry.progress)
            }))
            .unwrap_or_else(|_| Err("the digest build panicked".into()));
            let mut inner = self.lock();
            inner.running = None;
            if matches!(&result, Ok(Built::Partial(_))) {
                let directory = job.run.directory.clone();
                if RunDigest::read(&directory)
                    .and_then(|digest| digest.coverage)
                    .is_some_and(|coverage| coverage.revisit)
                {
                    let stamp = run_digest::source_stamp(&directory);
                    inner.watching.insert(directory, (job, stamp));
                }
            }
            drop(inner);
            if let Some(done) = entry.done {
                let _ = done.send(result);
            }
            self.idle.notify_all();
        }
    }

    /// Where the digest build of the run in `directory` stands.
    pub fn status(&self, directory: &Path) -> Status {
        let inner = self.lock();
        if let Some((running, progress, _)) = &inner.running {
            if running == directory {
                return Status::Building(
                    progress
                        .text()
                        .unwrap_or_else(|| "Starting the digest build".into()),
                );
            }
        }
        if inner
            .waiting
            .iter()
            .any(|entry| entry.job.run.directory == directory)
        {
            return Status::Queued;
        }
        Status::Idle
    }

    /// The window now reads the run in `directory` itself (`None`: none).
    pub fn window_reads(&self, directory: Option<&Path>) {
        let mut inner = self.lock();
        if inner.window.as_deref() != directory {
            inner.window = directory.map(Path::to_path_buf);
        }
    }

    /// Give the run in `directory` up to a caller that reads it itself (the
    /// window, once it opens the run): a waiting build is dropped, a running
    /// one is cancelled.
    pub fn release(&self, directory: &Path) {
        let mut inner = self.lock();
        inner.waiting.retain(|entry| {
            let ours = entry.job.run.directory == directory;
            if ours {
                entry.cancel.store(true, Ordering::Relaxed);
                if let Some(done) = &entry.done {
                    let _ = done.send(Err("cancelled".into()));
                }
            }
            !ours
        });
        if let Some((running, _, cancel)) = &inner.running {
            if running == directory {
                cancel.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Ask again for the digests that were partial only because their
    /// recording was still being written, now that it changed. Cheap (a few
    /// `stat`s); call it every few seconds.
    pub fn recheck(&'static self) {
        let due: Vec<Job> = {
            let mut inner = self.lock();
            let changed: Vec<PathBuf> = inner
                .watching
                .iter()
                .filter(|(directory, (_, stamp))| run_digest::source_stamp(directory) != *stamp)
                .map(|(directory, _)| directory.clone())
                .collect();
            changed
                .into_iter()
                .filter_map(|directory| inner.watching.remove(&directory))
                .map(|(job, _)| job)
                .collect()
        };
        for job in due {
            self.submit(job);
        }
    }

    /// Wait until nothing is queued or running (tests, `digest --pending`).
    pub fn wait_idle(&self, limit: Duration) -> bool {
        let deadline = std::time::Instant::now() + limit;
        let mut inner = self.lock();
        while inner.worker || !inner.waiting.is_empty() {
            let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
                return false;
            };
            inner = self
                .idle
                .wait_timeout(inner, left)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
        true
    }
}
