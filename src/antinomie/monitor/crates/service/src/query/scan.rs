// SPDX-License-Identifier: GPL-3.0-only
//! The Triage scan a class T read needs (design 5.12.3 class T, 5.12.6).
//!
//! The scan of a run is the index the GUI makes when the run is selected
//! (`antinomie_triage::SavedRun`). A read that finds no scan of the run's
//! current `generation` starts one on its own thread and answers `building`
//! with the scan's progress; the client asks again after `retry_after_ms`. The
//! scan is made with `read_only` set: it writes nothing into the recording (no
//! finding journal, no Sigma journal, and never `triage-digest.json`).
//!
//! Two scans are kept in memory, the least recently used one is dropped, and a
//! scan of a recording whose `generation` changed is dropped. At most
//! `heavy_concurrency` scans run at once; one more is `quota_exceeded`.

use super::{
    cursor::Generation,
    page::{Building, ScanProgress},
};
use crate::api::error::ApiError;
use antinomie_monitor_core::{BackendOptions, RunSummary};
use antinomie_triage::{ArchiveScan, SavedRun, scan_progress};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// Scans kept in memory.
const KEPT: usize = 2;
/// What a `building` answer asks the client to wait.
const RETRY_AFTER_MS: u64 = 750;

/// A finished scan with the run it indexed.
#[derive(Clone)]
pub struct Scanned {
    pub saved: Arc<SavedRun>,
    pub scan: ArchiveScan,
    /// The summary and indicators of the report builder, made on first use.
    pub derived: Arc<OnceLock<Result<super::triage::Derived, String>>>,
}

enum State {
    Building(Arc<scan_progress::ScanProgress>),
    Ready(Scanned),
    Failed(String),
}

struct Slot {
    dir: PathBuf,
    generation: Generation,
    state: State,
    used: Instant,
}

/// The result of asking for a scan.
pub enum Scan {
    Ready(Scanned),
    Building(Building),
}

/// The scans of one service.
pub struct ScanStore {
    slots: Arc<Mutex<Vec<Slot>>>,
    /// Scans running at once.
    max_running: usize,
    /// A scan that runs longer than this is cancelled (`scan_s`).
    deadline: Duration,
    /// `service.toml [privacy] address_lookup`.
    address_lookup: antinomie_monitor_core::settings::AddressLookup,
}

impl ScanStore {
    pub fn new(
        max_running: u32,
        deadline: Duration,
        address_lookup: antinomie_monitor_core::settings::AddressLookup,
    ) -> Self {
        Self {
            slots: Arc::new(Mutex::new(Vec::new())),
            max_running: max_running.max(1) as usize,
            deadline,
            address_lookup,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Slot>> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Scans in memory, finished or not.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The scan of `run` at `generation`: the finished one, or `building` with
    /// the progress of the one running (started now when none is).
    pub fn get(
        &self,
        run: &RunSummary,
        dir: &std::path::Path,
        generation: Generation,
        options: &BackendOptions,
        retry_after_s: u64,
        scrub: &super::scrub::Scrub,
    ) -> Result<Scan, ApiError> {
        let mut slots = self.lock();
        // A scan of an older generation of this recording is of no use.
        slots.retain(|slot| slot.dir != dir || slot.generation == generation);
        if let Some(slot) = slots.iter_mut().find(|slot| slot.dir == dir) {
            slot.used = Instant::now();
            let failed = match &slot.state {
                State::Ready(done) => return Ok(Scan::Ready(done.clone())),
                State::Building(progress) => return Ok(Scan::Building(building(progress))),
                State::Failed(text) => text.clone(),
            };
            // The next call starts it again.
            slots.retain(|slot| slot.dir != dir);
            return Err(
                ApiError::scan_failed().with_detail("text", serde_json::json!(scrub.text(&failed)))
            );
        }
        let running = slots
            .iter()
            .filter(|slot| matches!(slot.state, State::Building(_)))
            .count();
        if running >= self.max_running {
            return Err(ApiError::heavy_read_limit(retry_after_s));
        }
        let saved =
            SavedRun::open_with(run.clone(), options, self.address_lookup).map_err(|error| {
                ApiError::new(
                    crate::api::error::ErrorCode::PreconditionFailed,
                    format!("settings.json cannot be read: {error}"),
                )
            })?;
        let progress = Arc::new(scan_progress::ScanProgress::default());
        slots.push(Slot {
            dir: dir.to_path_buf(),
            generation,
            state: State::Building(Arc::clone(&progress)),
            used: Instant::now(),
        });
        self.evict(&mut slots);
        drop(slots);
        self.spawn(saved, dir.to_path_buf(), generation, Arc::clone(&progress));
        Ok(Scan::Building(building(&progress)))
    }

    /// Drop the least recently used finished scans above [`KEPT`].
    fn evict(&self, slots: &mut Vec<Slot>) {
        loop {
            let finished = slots
                .iter()
                .filter(|slot| !matches!(slot.state, State::Building(_)))
                .count();
            if finished <= KEPT {
                return;
            }
            let oldest = slots
                .iter()
                .enumerate()
                .filter(|(_, slot)| !matches!(slot.state, State::Building(_)))
                .min_by_key(|(_, slot)| slot.used)
                .map(|(at, _)| at);
            match oldest {
                Some(at) => {
                    slots.remove(at);
                }
                None => return,
            }
        }
    }

    fn spawn(
        &self,
        saved: SavedRun,
        dir: PathBuf,
        generation: Generation,
        progress: Arc<scan_progress::ScanProgress>,
    ) {
        let slots = Arc::clone(&self.slots);
        let deadline = self.deadline;
        std::thread::spawn(move || {
            let cancel = Arc::new(AtomicBool::new(false));
            let finished = Arc::new(AtomicBool::new(false));
            // The scan's own deadline (`scan_s`).
            {
                let (cancel, finished) = (Arc::clone(&cancel), Arc::clone(&finished));
                std::thread::spawn(move || {
                    let end = Instant::now() + deadline;
                    while !finished.load(Ordering::Relaxed) {
                        if Instant::now() >= end {
                            cancel.store(true, Ordering::Relaxed);
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                });
            }
            let mut request = saved.request();
            request.progress = Some(progress);
            request.read_only = true;
            // The Triage crate keeps the index in the process too, so a report
            // or `triage --parts` that follows in this process reads it again
            // at no cost.
            request.keep_index = true;
            let result = saved.scan_with(request, &cancel);
            finished.store(true, Ordering::Relaxed);
            let state = match result {
                Ok(scan) => State::Ready(Scanned {
                    saved: Arc::new(saved),
                    scan,
                    derived: Arc::new(OnceLock::new()),
                }),
                Err(error) => State::Failed(error),
            };
            let mut slots = slots.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(slot) = slots
                .iter_mut()
                .find(|slot| slot.dir == dir && slot.generation == generation)
            {
                slot.state = state;
                slot.used = Instant::now();
            }
        });
    }
}

fn building(progress: &scan_progress::ScanProgress) -> Building {
    let (done, total) = progress.counts();
    Building {
        progress: (total > 0).then_some(ScanProgress { done, total }),
        retry_after_ms: RETRY_AFTER_MS,
    }
}
