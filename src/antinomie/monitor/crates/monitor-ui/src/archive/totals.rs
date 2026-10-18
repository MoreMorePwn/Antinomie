//! Match counts of an archive view, computed apart from the page reads.
//!
//! A page seeks to its cursor and costs about one page. The counts behind
//! "page N of M" walk every call, so a big recording gets them from a
//! separate thread, once per recording, filter and indexed length; later
//! pages of the same view read them from here.
use super::Answer;
use antinomie_monitor_core::{capture, recording, syscall_groups::SyscallGroup, InvocationSummary};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
};

/// Raw bytes up to which the counts are computed in the page request itself.
const INLINE_RAW_LEN: u64 = 2 * 1024 * 1024;
/// Counted views kept in memory.
const CACHE_SIZE: usize = 8;

/// What a page request reads: one recording through one filter.
#[derive(Clone)]
pub(crate) struct View {
    pub(crate) directory: PathBuf,
    pub(crate) capture: bool,
    pub(crate) pid: Option<u32>,
    pub(crate) query: String,
    pub(crate) hidden_categories: Vec<SyscallGroup>,
}

impl View {
    /// Identity of the counts: pages of the same view share them.
    pub(crate) fn key(&self) -> String {
        key(
            &self.directory,
            self.capture,
            self.pid,
            &self.query,
            &self.hidden_categories,
        )
    }

    pub(super) fn open(&self, cancel: &AtomicBool) -> Result<recording::Recording, String> {
        if self.capture {
            capture::open_capture_recording_cancellable(&self.directory, cancel)
        } else {
            recording::open_recording_cancellable(&self.directory, cancel)
        }
        .map_err(|error| error.to_string())
    }
}

/// The key of a view, as [`View::key`] builds it.
pub(crate) fn key(
    directory: &std::path::Path,
    capture: bool,
    pid: Option<u32>,
    query: &str,
    hidden_categories: &[SyscallGroup],
) -> String {
    let mut hidden: Vec<_> = hidden_categories.to_vec();
    hidden.sort();
    hidden.dedup();
    format!(
        "{}\0{capture}\0{pid:?}\0{query}\0{hidden:?}",
        directory.display()
    )
}

/// Whether a call belongs to the view: it is in a shown category and passes the filter.
pub(super) fn predicate<'a>(
    filter: &'a crate::query::Compiled,
    hidden_categories: &'a [SyscallGroup],
) -> impl FnMut(&InvocationSummary) -> bool + 'a {
    move |invocation| {
        let visible = crate::trace::representative(invocation).is_some_and(|event| {
            SyscallGroup::of(&event.syscall_name)
                .is_none_or(|group| !hidden_categories.contains(&group))
        });
        visible && filter.keep(invocation)
    }
}

fn count(view: &View, cancel: &AtomicBool) -> Result<recording::MatchTotals, String> {
    let filter = crate::query::compile_note(&view.query);
    if let Some(error) = filter.error.as_ref() {
        return Err(error.clone());
    }
    view.open(cancel)?
        .matching_totals_cancellable(
            view.pid,
            cancel,
            predicate(&filter, &view.hidden_categories),
        )
        .map_err(|error| error.to_string())
}

struct Active {
    key: String,
    cancel: Arc<AtomicBool>,
}

/// The counted views and the thread that is counting one.
pub(super) struct Counts {
    cache: Mutex<Vec<(String, recording::MatchTotals)>>,
    active: Mutex<Option<Active>>,
    threads: Mutex<Vec<thread::JoinHandle<()>>>,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Counts {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            cache: Mutex::new(Vec::new()),
            active: Mutex::new(None),
            threads: Mutex::new(Vec::new()),
        })
    }

    fn cached(&self, key: &str, stamp: &recording::ArchiveStamp) -> Option<(u64, u64)> {
        locked(&self.cache)
            .iter()
            .find(|(cached, totals)| cached == key && totals.stamp == *stamp)
            .map(|(_, totals)| (totals.total, totals.source_total))
    }

    fn remember(&self, key: String, totals: recording::MatchTotals) {
        let mut cache = locked(&self.cache);
        cache.retain(|(cached, _)| *cached != key);
        if cache.len() >= CACHE_SIZE {
            cache.remove(0);
        }
        cache.push((key, totals));
    }

    /// The counts of `view` over the prefix `stamp`: from memory, computed
    /// now for a small recording, or `None` while a thread counts them and
    /// later reports through `answers`.
    pub(super) fn totals(
        self: &Arc<Self>,
        view: &View,
        stamp: &recording::ArchiveStamp,
        cancel: &AtomicBool,
        answers: &mpsc::SyncSender<Answer>,
        wake: &Option<eframe::egui::Context>,
    ) -> Result<Option<(u64, u64)>, String> {
        let key = view.key();
        if let Some(found) = self.cached(&key, stamp) {
            return Ok(Some(found));
        }
        if stamp.length <= INLINE_RAW_LEN {
            let totals = count(view, cancel)?;
            let found = (totals.total, totals.source_total);
            self.remember(key, totals);
            return Ok(Some(found));
        }
        self.start(key, view.clone(), answers.clone(), wake.clone());
        Ok(None)
    }

    fn start(
        self: &Arc<Self>,
        key: String,
        view: View,
        answers: mpsc::SyncSender<Answer>,
        wake: Option<eframe::egui::Context>,
    ) {
        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut active = locked(&self.active);
            if let Some(running) = active.as_ref() {
                if running.key == key && !running.cancel.load(Ordering::Relaxed) {
                    return;
                }
                // Another view of the user's: the old count is not wanted.
                running.cancel.store(true, Ordering::Relaxed);
            }
            *active = Some(Active {
                key: key.clone(),
                cancel: Arc::clone(&cancel),
            });
        }
        let counts = Arc::clone(self);
        let job_key = key.clone();
        let job_cancel = Arc::clone(&cancel);
        let spawned = thread::Builder::new()
            .name("archive-totals".into())
            .spawn(move || {
                let result = count(&view, &job_cancel);
                let cancelled = job_cancel.load(Ordering::Relaxed);
                let answer = match result {
                    Ok(totals) => {
                        let found = (totals.total, totals.source_total);
                        if !cancelled {
                            counts.remember(job_key.clone(), totals);
                        }
                        Ok(found)
                    }
                    Err(error) => Err(error),
                };
                {
                    let mut active = locked(&counts.active);
                    if active
                        .as_ref()
                        .is_some_and(|running| running.key == job_key)
                    {
                        *active = None;
                    }
                }
                if cancelled {
                    return;
                }
                if answers
                    .send(Answer::Totals {
                        key: job_key,
                        result: answer,
                    })
                    .is_ok()
                {
                    if let Some(ctx) = wake {
                        ctx.request_repaint_of(eframe::egui::ViewportId::ROOT);
                    }
                }
            });
        let mut threads = locked(&self.threads);
        threads.retain(|thread| !thread.is_finished());
        match spawned {
            Ok(handle) => threads.push(handle),
            Err(_) => *locked(&self.active) = None,
        }
    }

    /// Stop counting and wait for the thread; the answers channel is closed first.
    pub(super) fn shut_down(&self) {
        if let Some(running) = locked(&self.active).as_ref() {
            running.cancel.store(true, Ordering::Relaxed);
        }
        let threads: Vec<_> = locked(&self.threads).drain(..).collect();
        for thread in threads {
            if thread.join().is_err() {
                eprintln!("archive totals thread panicked");
            }
        }
    }
}
