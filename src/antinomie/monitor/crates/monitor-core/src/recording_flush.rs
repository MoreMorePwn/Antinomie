// SPDX-License-Identifier: MIT
//! Making a stopped boot's recordings durable in the background.
//!
//! Disk work is serialized through one bounded worker. This preserves the
//! order between retired capture archives and the final boot manifest while
//! keeping thread and queued-job counts fixed even if storage stalls.
use std::{
    collections::VecDeque,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        mpsc::{self, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
};

/// One unit of disk work, named for the status line.
pub(crate) type Step = (String, Box<dyn FnOnce() -> Result<(), String> + Send>);

/// Boots with a flush in progress.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordingFlushStatus {
    pub boot_ids: Vec<String>,
    pub total_count: usize,
    pub done_count: usize,
    pub current: String,
    pub errors: Vec<String>,
}

impl RecordingFlushStatus {
    /// "Saving recordings 3/8: run 4f2a" for the status line.
    pub fn label(&self) -> String {
        let mut label = format!(
            "Saving recordings {}/{}",
            self.done_count.min(self.total_count),
            self.total_count
        );
        if !self.current.is_empty() {
            label.push_str(": ");
            label.push_str(&self.current);
        }
        label
    }
}

pub(crate) const MAX_FLUSH_JOBS: usize = 4;
const MAX_RETAINED_ERRORS: usize = 256;
const MAX_ERRORS_PER_JOB: usize = 64;
const MAX_FLUSH_ERROR_BYTES: usize = 4096;

struct JobProgress {
    boot_id: String,
    total_count: usize,
    done_count: usize,
    current: String,
    errors: Vec<String>,
    omitted_errors: usize,
}

struct Job {
    progress: Arc<Mutex<JobProgress>>,
    steps: Vec<Step>,
}

#[derive(Default)]
struct Shared {
    outstanding: usize,
    active: Vec<Arc<Mutex<JobProgress>>>,
    completed_errors: VecDeque<String>,
    omitted_errors: usize,
}

fn retain_error(shared: &mut Shared, error: String) {
    if shared.completed_errors.len() < MAX_RETAINED_ERRORS {
        shared.completed_errors.push_back(error);
    } else {
        shared.omitted_errors = shared.omitted_errors.saturating_add(1);
    }
}

fn bounded_error(mut error: String) -> String {
    if error.len() <= MAX_FLUSH_ERROR_BYTES {
        return error;
    }
    const SUFFIX: &str = " [truncated]";
    let mut end = MAX_FLUSH_ERROR_BYTES - SUFFIX.len();
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    error.truncate(end);
    error.push_str(SUFFIX);
    error
}

fn retain_step_error(progress: &mut JobProgress, error: String) {
    if progress.errors.len() < MAX_ERRORS_PER_JOB {
        progress.errors.push(bounded_error(error));
    } else {
        progress.omitted_errors = progress.omitted_errors.saturating_add(1);
    }
}

fn run_job(mut job: Job, shared: &Arc<Mutex<Shared>>) {
    for (name, step) in job.steps.drain(..) {
        if let Ok(mut progress) = job.progress.lock() {
            progress.current.clone_from(&name);
        }
        let result = catch_unwind(AssertUnwindSafe(step));
        let error = match result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(format!("{name}: {error}")),
            Err(_) => Some(format!("{name}: step stopped unexpectedly")),
        };
        if let Ok(mut progress) = job.progress.lock() {
            if let Some(error) = error {
                retain_step_error(&mut progress, error);
            }
            progress.done_count = progress.done_count.saturating_add(1);
        }
    }
    let errors = if let Ok(mut progress) = job.progress.lock() {
        progress.current.clear();
        if progress.omitted_errors != 0 {
            let omitted_errors = progress.omitted_errors;
            progress.errors.push(format!(
                "{} further flush step errors were omitted",
                omitted_errors
            ));
        }
        std::mem::take(&mut progress.errors)
    } else {
        vec!["flush progress lock was poisoned".into()]
    };
    if let Ok(mut state) = shared.lock() {
        state
            .active
            .retain(|progress| !Arc::ptr_eq(progress, &job.progress));
        state.outstanding = state.outstanding.saturating_sub(1);
        for error in errors {
            retain_error(&mut state, error);
        }
    }
}

/// Runs steps in order and returns the errors of those that failed.
#[cfg(test)]
pub(crate) fn run_inline(steps: Vec<Step>) -> Vec<String> {
    let mut errors = Vec::new();
    for (name, step) in steps {
        match catch_unwind(AssertUnwindSafe(step)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(format!("{name}: {error}")),
            Err(_) => errors.push(format!("{name}: step stopped unexpectedly")),
        }
    }
    errors
}

/// A rejected job retains its steps so the owner can put them back on a
/// bounded queue instead of silently dropping finalizers.
pub(crate) struct RejectedFlushJob {
    pub boot_id: String,
    pub steps: Vec<Step>,
    pub reason: String,
}

impl std::fmt::Debug for RejectedFlushJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RejectedFlushJob")
            .field("boot_id", &self.boot_id)
            .field("step_count", &self.steps.len())
            .field("reason", &self.reason)
            .finish()
    }
}

pub(crate) struct Flusher {
    sender: Option<SyncSender<Job>>,
    shared: Arc<Mutex<Shared>>,
    worker: Option<JoinHandle<()>>,
    startup_error: Option<String>,
}

impl Flusher {
    /// Start the single persistence thread before the worker can start a VM.
    pub(crate) fn new() -> Result<Self, String> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(MAX_FLUSH_JOBS);
        let shared = Arc::new(Mutex::new(Shared::default()));
        let worker_shared = shared.clone();
        #[cfg(test)]
        let inherited = (
            crate::writer::held::inherit(),
            crate::storage::slow_disk::inherit(),
        );
        let worker = thread::Builder::new()
            .name("antinomie-flush".into())
            .spawn(move || {
                #[cfg(test)]
                {
                    inherited.0();
                    inherited.1();
                }
                while let Ok(job) = receiver.recv() {
                    run_job(job, &worker_shared);
                }
            })
            .map_err(|error| format!("recording flush worker could not start: {error}"))?;
        Ok(Self {
            sender: Some(sender),
            shared,
            worker: Some(worker),
            startup_error: None,
        })
    }

    /// Whether a retired-capture job can be admitted while reserving one slot
    /// for the current boot's eventual seal.
    pub(crate) fn can_submit_retired(&self) -> bool {
        self.shared
            .lock()
            .is_ok_and(|state| state.outstanding < MAX_FLUSH_JOBS.saturating_sub(1))
    }

    /// Submit without waiting for disk or queue capacity. Jobs are executed in
    /// submission order on one worker, including jobs for the same boot.
    pub fn spawn(&mut self, boot_id: String, steps: Vec<Step>) -> Result<(), RejectedFlushJob> {
        if steps.is_empty() {
            return Ok(());
        }
        let Some(sender) = self.sender.as_ref() else {
            return Err(RejectedFlushJob {
                boot_id,
                steps,
                reason: self
                    .startup_error
                    .clone()
                    .unwrap_or_else(|| "recording flush worker is unavailable".into()),
            });
        };
        let progress = Arc::new(Mutex::new(JobProgress {
            boot_id: boot_id.clone(),
            total_count: steps.len(),
            done_count: 0,
            current: String::new(),
            errors: Vec::new(),
            omitted_errors: 0,
        }));
        let mut state = self
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.outstanding >= MAX_FLUSH_JOBS {
            return Err(RejectedFlushJob {
                boot_id,
                steps,
                reason: "recording flush queue is full".into(),
            });
        }
        let job = Job {
            progress: progress.clone(),
            steps,
        };
        match sender.try_send(job) {
            Ok(()) => {
                state.outstanding += 1;
                state.active.push(progress);
                Ok(())
            }
            Err(TrySendError::Full(job)) => Err(RejectedFlushJob {
                boot_id,
                steps: job.steps,
                reason: "recording flush queue is full".into(),
            }),
            Err(TrySendError::Disconnected(job)) => Err(RejectedFlushJob {
                boot_id,
                steps: job.steps,
                reason: "recording flush worker stopped".into(),
            }),
        }
    }

    /// Whether any job is still queued or running.
    pub fn is_busy(&self) -> bool {
        self.shared.lock().is_ok_and(|state| state.outstanding != 0)
    }

    /// The jobs in progress, or `None` when all are done.
    pub fn status(&self) -> Option<RecordingFlushStatus> {
        let state = self
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut status = RecordingFlushStatus::default();
        for progress in &state.active {
            let Ok(progress) = progress.lock() else {
                continue;
            };
            status.boot_ids.push(progress.boot_id.clone());
            status.total_count = status.total_count.saturating_add(progress.total_count);
            status.done_count = status.done_count.saturating_add(progress.done_count);
            if status.current.is_empty() {
                status.current.clone_from(&progress.current);
            }
            status.errors.extend(progress.errors.iter().cloned());
        }
        (!status.boot_ids.is_empty()).then_some(status)
    }

    /// Return completed-step errors, preserving the first failures if the
    /// caller temporarily falls behind the bounded diagnostic queue.
    pub fn collect(&mut self) -> Vec<String> {
        let mut state = self
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut errors: Vec<_> = state.completed_errors.drain(..).collect();
        if state.omitted_errors != 0 {
            errors.push(format!(
                "{} additional recording flush errors were omitted",
                state.omitted_errors
            ));
            state.omitted_errors = 0;
        }
        if let Some(error) = self.startup_error.take() {
            errors.insert(0, error);
        }
        errors
    }
}

impl Default for Flusher {
    fn default() -> Self {
        match Self::new() {
            Ok(flusher) => flusher,
            Err(error) => Self {
                sender: None,
                shared: Arc::new(Mutex::new(Shared::default())),
                worker: None,
                startup_error: Some(error),
            },
        }
    }
}

impl Drop for Flusher {
    fn drop(&mut self) {
        self.sender.take();
        // Normal shutdown drains before dropping. If a caller drops early,
        // detaching lets the worker finish accepted finalizers without making
        // this destructor wait on a blocked filesystem.
        if !self.is_busy()
            && let Some(worker) = self.worker.take()
        {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests;
