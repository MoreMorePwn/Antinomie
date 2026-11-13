// SPDX-License-Identifier: GPL-3.0-only
//! The walk runs on a thread named `statistics`, one at a time, with its own
//! cancel flag (design 4.5). The window polls it every frame. The last four
//! complete results are kept in memory.
use antinomie_triage::statistics::{
    self, Parts, Progress, RunStatistics, StatsError, StatsRequest,
};
use eframe::egui;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Results kept in memory (design 4.5).
pub(super) const KEPT: usize = 4;

/// What a result is for: the walk's whole input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Key {
    pub directory: PathBuf,
    pub capture: bool,
    pub root_cookie: u64,
    pub filter: String,
    /// Custom Call rate lines: a key with lines is a `RateOnly` walk.
    pub lines: Vec<String>,
}

impl Key {
    pub(super) fn request(&self) -> StatsRequest {
        let mut request = StatsRequest::new(&self.directory);
        request.capture = self.capture;
        request.root_cookie = self.root_cookie;
        request.filter.clone_from(&self.filter);
        if !self.lines.is_empty() {
            request.lines.clone_from(&self.lines);
            request.parts = Parts::RateOnly;
        }
        request
    }
}

/// Where the walk is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Where {
    #[default]
    Starting,
    Indexing {
        done: u64,
        total: u64,
    },
    Reading {
        read: u64,
        total: u64,
    },
}

#[derive(Default)]
struct Shared {
    at: Where,
    partial: Option<Arc<RunStatistics>>,
    outcome: Option<Result<RunStatistics, StatsError>>,
}

struct Active {
    key: Key,
    cancel: Arc<AtomicBool>,
    shared: Arc<Mutex<Shared>>,
}

/// What the window draws a result with.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Phase {
    /// Nothing asked yet.
    Idle,
    Running(Where),
    /// The person pressed Stop (or the walk was stopped); the result covers the calls read.
    Stopped,
    /// The error text (design 10). The previous result stays, greyed.
    Failed(String),
    Done,
}

pub(super) struct Worker {
    cache: Vec<(Key, Arc<RunStatistics>)>,
    active: Option<Active>,
    /// The latest result drawn, whatever it was made for.
    shown: Option<(Key, Arc<RunStatistics>)>,
    pub(super) phase: Phase,
    /// Calls in the recording, as the last walk counted them.
    pub(super) total: u64,
    /// The key of the walk the person stopped: not restarted until asked.
    stopped: Option<Key>,
    /// Walks started, for tests.
    pub(super) started: u64,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Default for Worker {
    fn default() -> Self {
        Self {
            cache: Vec::new(),
            active: None,
            shown: None,
            phase: Phase::Idle,
            total: 0,
            stopped: None,
            started: 0,
        }
    }
}

impl Worker {
    /// The result to draw: the walk's partial counts while it runs, else the
    /// last result (greyed when it is not for `wanted`).
    pub(super) fn shown(&self) -> Option<&(Key, Arc<RunStatistics>)> {
        self.shown.as_ref()
    }

    pub(super) fn running(&self) -> bool {
        self.active.is_some()
    }

    /// Make sure `wanted` is being read or is in memory.
    pub(super) fn ensure(&mut self, ctx: &egui::Context, wanted: &Key) {
        if self.active.as_ref().is_some_and(|a| &a.key == wanted) {
            return;
        }
        if self.stopped.as_ref() == Some(wanted) {
            return;
        }
        if let Some(position) = self.cache.iter().position(|(key, _)| key == wanted) {
            let entry = self.cache.remove(position);
            self.cancel();
            self.shown = Some(entry.clone());
            self.cache.push(entry);
            self.phase = Phase::Done;
            return;
        }
        self.start(ctx, wanted);
    }

    fn start(&mut self, ctx: &egui::Context, key: &Key) {
        self.cancel();
        self.stopped = None;
        self.started += 1;
        let cancel = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Mutex::new(Shared::default()));
        let request = key.request();
        let (worker_cancel, worker_shared, repaint) =
            (Arc::clone(&cancel), Arc::clone(&shared), ctx.clone());
        let progress_shared = Arc::clone(&shared);
        let progress_ctx = ctx.clone();
        let progress: Arc<dyn Fn(Progress) + Send + Sync> = Arc::new(move |note| {
            let mut shared = locked(&progress_shared);
            match note {
                Progress::Indexing { done, total } => shared.at = Where::Indexing { done, total },
                Progress::Reading { read, total } => shared.at = Where::Reading { read, total },
                Progress::Partial(partial) => shared.partial = Some(Arc::new(*partial)),
            }
            drop(shared);
            progress_ctx.request_repaint();
        });
        let spawned = std::thread::Builder::new()
            .name("statistics".into())
            .spawn(move || {
                let outcome = statistics::compute(&request, &worker_cancel, &progress);
                locked(&worker_shared).outcome = Some(outcome);
                repaint.request_repaint();
            });
        if let Err(error) = spawned {
            self.phase = Phase::Failed(format!("The statistics thread did not start: {error}"));
            return;
        }
        self.active = Some(Active {
            key: key.clone(),
            cancel,
            shared,
        });
        self.phase = Phase::Running(Where::Starting);
    }

    /// Stop the walk in progress; its thread ends within one step.
    pub(super) fn cancel(&mut self) {
        if let Some(active) = self.active.take() {
            active.cancel.store(true, Ordering::Relaxed);
        }
    }

    /// The person pressed Stop: the counts so far stay, marked stopped.
    pub(super) fn stop(&mut self) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        active.cancel.store(true, Ordering::Relaxed);
        // The thread answers with the partial counts; poll keeps them.
        self.stopped = Some(active.key.clone());
    }

    /// Forget the results of `key`, so the next `ensure` reads it again.
    pub(super) fn forget(&mut self, key: &Key) {
        self.cache.retain(|(known, _)| known != key);
        if self.stopped.as_ref() == Some(key) {
            self.stopped = None;
        }
        if self.shown.as_ref().is_some_and(|(known, _)| known == key) {
            self.phase = Phase::Idle;
        }
    }

    /// Forget everything (another run was chosen).
    pub(super) fn reset(&mut self) {
        self.cancel();
        self.shown = None;
        self.stopped = None;
        self.phase = Phase::Idle;
    }

    /// Take what the thread has made. Call every frame.
    pub(super) fn poll(&mut self) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let (at, partial, outcome) = {
            let mut shared = locked(&active.shared);
            (shared.at, shared.partial.take(), shared.outcome.take())
        };
        let key = active.key.clone();
        if let Where::Reading { total, .. } = at {
            self.total = total;
        }
        if let Some(partial) = partial {
            self.shown = Some((key.clone(), partial));
        }
        match outcome {
            None => self.phase = Phase::Running(at),
            Some(Ok(result)) => {
                self.active = None;
                let complete = result.complete;
                let result = Arc::new(result);
                self.shown = Some((key.clone(), Arc::clone(&result)));
                if complete {
                    self.stopped = None;
                    self.cache.retain(|(known, _)| known != &key);
                    self.cache.push((key, result));
                    if self.cache.len() > KEPT {
                        self.cache.remove(0);
                    }
                    self.phase = Phase::Done;
                } else {
                    self.stopped = Some(key);
                    self.phase = Phase::Stopped;
                }
            }
            Some(Err(StatsError::Cancelled)) => {
                self.active = None;
                self.stopped.get_or_insert(key);
                self.phase = Phase::Stopped;
            }
            Some(Err(error)) => {
                self.active = None;
                self.phase = Phase::Failed(error.to_string());
                self.stopped = Some(key);
            }
        }
    }
}
