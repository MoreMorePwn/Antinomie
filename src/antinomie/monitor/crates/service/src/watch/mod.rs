// SPDX-License-Identifier: GPL-3.0-only
//! Watch folders (design 4.2.1, card P4-2): a file that appears in a folder
//! named in `service.toml [[inbox.watch]]` becomes a job.
//!
//! | Rule | How |
//! |---|---|
//! | Detection | A scan of every folder every 2 s (polling, decided B-H13); files present at the start are taken in name order |
//! | Stability | A file is taken after its size, mtime and ctime have been unchanged for 3 s; names starting with `.` or ending in `.part`, `.tmp`, `.crdownload` are never taken |
//! | Links | The folder and every file are opened with `O_NOFOLLOW`, relative to the folder's descriptor; a symbolic link, device, FIFO, socket, directory is refused, and so is a file with more than one hard link |
//! | Ownership | The folder must be ours and writable by no one else (a group-writable one only with `allow_group_write`; a world-writable one never); a file must belong to the daemon's user (or, with `allow_group_write`, to the folder's group when the daemon is in it) |
//! | Policy | `policy`, or with `policy_by_dir` the subfolder named after an existing policy (other folders are ignored); never created from a folder name; no sidecar overrides |
//! | Actor | The job's client and custody actor is `auto:policy-<policy>`; the label `watch` names the folder |
//! | After intake | `move` to `<inbox>/processed/`, `delete`, or `keep` (remembered by device, inode, size and mtime, so a restart does not take it again) |
//! | Failure | A file that fails intake moves to `<inbox>/rejected/` with `<name>.reason` and is not tried again; a refused entry (link, foreign file) is left alone and shown by `auto watch list` |
//! | Rate | At most `watch_rate` files a minute per folder; above that the folder pauses for a minute and `engine.alert` `watch_flood` is raised |
//!
//! The file is read from the descriptor opened in the folder, never from a
//! path (the staged and watched file never runs on the host).

pub mod safety;
pub mod scan;
pub mod settle;
#[cfg(test)]
mod tests;

use crate::config::service::{OnDuplicate, Watch};
use safety::Identity;
use scan::{FolderRun, FolderStatus, Places, Scan};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::File,
    path::{Path, PathBuf},
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// How often every folder is scanned.
pub const SCAN_EVERY: Duration = Duration::from_secs(2);

/// One file to turn into a job.
pub struct Admit {
    /// Opened relative to its folder with no link followed; read from this.
    pub file: File,
    /// The folder-relative name, for the sample's origin.
    pub shown: String,
    /// The file's own name, for the job.
    pub file_name: String,
    /// The folder's last component, the value of the `watch` label.
    pub folder_label: String,
    pub policy: String,
    pub on_duplicate: Option<OnDuplicate>,
}

/// What came of a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// A job was made (or an earlier one answered).
    Submitted { job: String },
    /// Intake or the job's validation refused the file for good.
    Rejected { code: String, message: String },
}

/// The file was not looked at and should be tried again later (the queue
/// refused it, the policy does not let this actor submit, ...).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Defer(pub String);

/// What a folder needs from the daemon.
pub trait WatchEnv: Send + Sync {
    fn policy_exists(&self, name: &str) -> bool;
    /// False when the queue is at its `max_queued`.
    fn queue_has_room(&self) -> bool;
    /// True while the queue is paused for low disk: nothing new is taken.
    fn intake_held(&self) -> bool;
    fn admit(&self, request: Admit) -> Result<Admission, Defer>;
    fn alert(&self, code: &str, text: &str);
    fn log(&self, line: &str);
}

/// All the folders.
pub struct Watcher {
    folders: BTreeMap<PathBuf, FolderRun>,
    places: Places,
    inbox: PathBuf,
    state_file: PathBuf,
    loaded: settle::Remembered,
    me: Identity,
}

impl Watcher {
    pub fn new(inbox: &Path) -> Self {
        Self {
            folders: BTreeMap::new(),
            places: Places::new(inbox),
            inbox: inbox.to_path_buf(),
            loaded: settle::Remembered::load(&inbox.join(".watch-state.json")),
            state_file: inbox.join(".watch-state.json"),
            me: Identity::current(),
        }
    }

    /// A watcher that sees the files as another user (tests).
    pub fn with_identity(mut self, me: Identity) -> Self {
        self.me = me;
        self
    }

    /// Make the folders match the configuration: new ones start, removed
    /// ones stop, a changed one keeps its state.
    pub fn configure(&mut self, config: &[Watch]) {
        self.folders
            .retain(|path, _| config.iter().any(|w| &w.path == path));
        for watch in config {
            match self.folders.get_mut(&watch.path) {
                Some(run) => run.reconfigure(watch.clone()),
                None => {
                    let known = self
                        .loaded
                        .folders
                        .get(&watch.path.display().to_string())
                        .map(|keys| keys.iter().copied().collect())
                        .unwrap_or_default();
                    self.folders
                        .insert(watch.path.clone(), FolderRun::new(watch.clone(), known));
                }
            }
        }
    }

    /// Scan every folder once at `now_ms`.
    pub fn scan_all(&mut self, env: &dyn WatchEnv, now_ms: u64) {
        self.places.refresh(&self.inbox);
        for run in self.folders.values_mut() {
            run.scan(&Scan {
                env,
                places: &self.places,
                me: &self.me,
                now_ms,
            });
        }
        if self.folders.values().any(|run| run.remembered_dirty) {
            let mut all = settle::Remembered::default();
            for run in self.folders.values_mut() {
                run.remembered_dirty = false;
                all.folders.insert(
                    run.cfg.path.display().to_string(),
                    run.remembered.iter().copied().collect(),
                );
            }
            if let Err(error) = all.save(&self.state_file) {
                env.log(&format!(
                    "watch: the record of kept files is not saved: {error}"
                ));
            }
        }
    }

    pub fn statuses(&self) -> Vec<FolderStatus> {
        self.folders.values().map(FolderRun::status).collect()
    }
}

/// The daemon's view of the folders: statuses for `watch.list`, and the
/// request/response pair behind `watch.scan`.
#[derive(Default)]
pub struct WatchHub {
    statuses: Mutex<Vec<FolderStatus>>,
    scans: Mutex<u64>,
    scanned: Condvar,
    scan_now: AtomicBool,
}

/// The answer of `watch.list`.
#[derive(Clone, Debug, Serialize)]
pub struct WatchList {
    pub folders: Vec<FolderStatus>,
}

impl WatchHub {
    pub fn list(&self) -> WatchList {
        WatchList {
            folders: crate::store::lock(&self.statuses).clone(),
        }
    }

    pub fn publish(&self, statuses: Vec<FolderStatus>) {
        *crate::store::lock(&self.statuses) = statuses;
        *crate::store::lock(&self.scans) += 1;
        self.scanned.notify_all();
    }

    /// Ask for a scan now and wait for it (at most `wait`).
    pub fn scan_now(&self, wait: Duration) -> WatchList {
        let mut scans = crate::store::lock(&self.scans);
        let target = *scans + 1;
        self.scan_now.store(true, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + wait;
        while *scans < target {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            scans = self
                .scanned
                .wait_timeout(scans, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        drop(scans);
        self.list()
    }

    /// Whether a scan was asked for (clears the request).
    pub fn take_request(&self) -> bool {
        self.scan_now.swap(false, Ordering::SeqCst)
    }
}
