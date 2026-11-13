// SPDX-License-Identifier: GPL-3.0-only
//! One watch folder, scanned (design 4.2.1). [`FolderRun`] keeps what a
//! folder needs between scans: the files it has seen and since when, the
//! jobs it made in the last minute, the files it must not take again.
//!
//! A scan opens the folder without following a link, checks it, lists it
//! through its descriptor, and looks at every entry with `fstatat` and no
//! link following. Only regular, single-link files that belong to the
//! daemon's user (or the shared group) whose size, mtime and ctime have not
//! changed for [`STABLE_MS`] are taken; each is opened relative to its
//! folder's descriptor with `O_NOFOLLOW`, checked again on the open
//! descriptor, and read from that descriptor only.

use super::{
    Admission, Admit, WatchEnv,
    safety::{Facts, Identity, Kind, file_problem, folder_problem, looks_partial},
    settle::{self, MAX_REMEMBERED},
};
use crate::config::service::{DeleteAfter, Watch};
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{AtFlags, Dir, Mode, OFlags, fstat, openat, statat},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    ffi::CString,
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

/// A file is taken after its size and times have been unchanged this long.
pub const STABLE_MS: u64 = 3_000;
/// The window of the rate limit, and the length of the pause.
pub const RATE_WINDOW_MS: u64 = 60_000;
/// Deepest folder level followed.
pub const MAX_DEPTH: usize = 8;
/// Most directory entries looked at in one scan of a folder.
pub const MAX_ENTRIES: usize = 20_000;
/// Most refused entries a folder lists.
const MAX_REFUSALS: usize = 20;

/// Where processed and rejected files go, and the folders a scan must never
/// walk into.
#[derive(Clone, Debug)]
pub struct Places {
    pub processed: PathBuf,
    pub rejected: PathBuf,
    /// `<inbox>/uploads` and the two above, by device and inode.
    pub skip: Vec<(u64, u64)>,
}

impl Places {
    pub fn new(inbox: &Path) -> Self {
        let mut places = Self {
            processed: inbox.join("processed"),
            rejected: inbox.join("rejected"),
            skip: Vec::new(),
        };
        places.refresh(inbox);
        places
    }

    /// Look the folders up again (they may be made after the first scan).
    pub fn refresh(&mut self, inbox: &Path) {
        self.skip = [
            self.processed.clone(),
            self.rejected.clone(),
            inbox.join("uploads"),
        ]
        .iter()
        .filter_map(|path| std::fs::symlink_metadata(path).ok())
        .map(|meta| {
            use std::os::unix::fs::MetadataExt;
            (meta.dev(), meta.ino())
        })
        .collect();
    }
}

/// A file that was refused, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Refusal {
    pub name: String,
    pub reason: String,
}

/// What `watch.list` shows of a folder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FolderStatus {
    pub path: String,
    pub policy: String,
    /// `watching`, `paused` (flood), `held` (low disk or a full queue),
    /// `refused` (the folder is not safe), `error`.
    pub state: String,
    pub detail: Option<String>,
    /// Files made into jobs.
    pub taken: u64,
    /// Files moved to `rejected/`.
    pub rejected: u64,
    /// Entries seen and refused (links, hard links, foreign files).
    pub refused: Vec<Refusal>,
    /// Files waiting for their size to settle or for the rate limit.
    pub pending: u32,
    pub last_scan_ms: u64,
    pub paused_until_ms: Option<u64>,
}

struct Seen {
    facts: Facts,
    since_ms: u64,
}

struct Candidate {
    dir: Arc<OwnedFd>,
    folder_gid: u32,
    name: Vec<u8>,
    c_name: CString,
    rel: String,
    policy: String,
    facts: Facts,
}

/// Everything a scan reads that is not the folder's own state.
pub struct Scan<'a> {
    pub env: &'a dyn WatchEnv,
    pub places: &'a Places,
    pub me: &'a Identity,
    pub now_ms: u64,
}

pub struct FolderRun {
    pub cfg: Watch,
    seen: HashMap<(u64, u64), Seen>,
    window: VecDeque<u64>,
    paused_until: u64,
    flood_alerted: bool,
    pub remembered: BTreeSet<[i128; 4]>,
    pub remembered_dirty: bool,
    logged: BTreeSet<String>,
    alerted: Option<String>,
    status: FolderStatus,
}

/// A name for people: control characters become spaces.
fn shown(text: &[u8]) -> String {
    String::from_utf8_lossy(text)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

impl FolderRun {
    pub fn new(cfg: Watch, remembered: BTreeSet<[i128; 4]>) -> Self {
        let status = FolderStatus {
            path: cfg.path.display().to_string(),
            policy: cfg.policy.clone(),
            state: "watching".into(),
            detail: None,
            taken: 0,
            rejected: 0,
            refused: Vec::new(),
            pending: 0,
            last_scan_ms: 0,
            paused_until_ms: None,
        };
        Self {
            cfg,
            seen: HashMap::new(),
            window: VecDeque::new(),
            paused_until: 0,
            flood_alerted: false,
            remembered,
            remembered_dirty: false,
            logged: BTreeSet::new(),
            alerted: None,
            status,
        }
    }

    /// Take a changed configuration of the same folder (a reload).
    pub fn reconfigure(&mut self, cfg: Watch) {
        self.status.policy = cfg.policy.clone();
        self.cfg = cfg;
    }

    pub fn status(&self) -> FolderStatus {
        self.status.clone()
    }

    fn set(&mut self, state: &str, detail: Option<String>) {
        self.status.state = state.into();
        self.status.detail = detail;
    }

    /// Log a line once per distinct text.
    fn log_once(&mut self, scan: &Scan<'_>, line: String) {
        if self.logged.len() > 1000 {
            self.logged.clear();
        }
        if self.logged.insert(line.clone()) {
            scan.env.log(&line);
        }
    }

    /// One pass over the folder.
    pub fn scan(&mut self, scan: &Scan<'_>) {
        let now = scan.now_ms;
        self.status.last_scan_ms = now;
        self.status.paused_until_ms = None;
        if now < self.paused_until {
            self.status.paused_until_ms = Some(self.paused_until);
            self.set("paused", Some("too many new jobs in a minute".into()));
            return;
        }
        self.window
            .retain(|t| now.saturating_sub(*t) < RATE_WINDOW_MS);
        if self.window.len() < self.cfg.watch_rate as usize {
            self.flood_alerted = false;
        }
        if scan.env.intake_held() {
            self.set("held", Some("the disk is low; the queue is paused".into()));
            return;
        }
        if !scan.env.policy_exists(&self.cfg.policy) {
            let words = format!("policy {} does not exist", self.cfg.policy);
            self.set("error", Some(words));
            return;
        }
        let root = match super::settle::open_dir(&self.cfg.path) {
            Ok(fd) => fd,
            Err(error) => {
                let words = format!("cannot open the folder: {error}");
                self.set("error", Some(words));
                return;
            }
        };
        let Ok(root_stat) = fstat(&root) else {
            self.set("error", Some("cannot read the folder".into()));
            return;
        };
        let root_facts = Facts::from(&root_stat);
        if let Some(problem) = folder_problem(&root_facts, scan.me, self.cfg.allow_group_write) {
            let words = format!("{}: {problem}", self.cfg.path.display());
            self.set("refused", Some(problem));
            if self.alerted.as_deref() != Some(&words) {
                scan.env
                    .alert("watch_folder_refused", &format!("watch folder {words}"));
                self.alerted = Some(words);
            }
            return;
        }
        self.alerted = None;
        self.set("watching", None);

        let mut found = Vec::new();
        let mut refusals: BTreeMap<String, String> = BTreeMap::new();
        let mut regular_keys: BTreeSet<[i128; 4]> = BTreeSet::new();
        let mut budget = MAX_ENTRIES;
        let root = Arc::new(root);
        let cfg = self.cfg.clone();
        let policy = cfg.policy.clone();
        walk(
            &Walk {
                cfg: &cfg,
                scan,
                remembered: &self.remembered,
            },
            &root,
            root_facts.gid,
            "",
            &policy,
            0,
            &mut State {
                found: &mut found,
                refusals: &mut refusals,
                regular_keys: &mut regular_keys,
                budget: &mut budget,
            },
        );
        let complete = budget > 0;

        // What was seen before and has not changed keeps its clock.
        let mut seen = HashMap::new();
        for candidate in &found {
            let key = (candidate.facts.dev, candidate.facts.ino);
            let since = match self.seen.get(&key) {
                Some(old) if old.facts.unchanged_since(&candidate.facts) => old.since_ms,
                _ => now,
            };
            seen.insert(
                key,
                Seen {
                    facts: candidate.facts,
                    since_ms: since,
                },
            );
        }
        self.seen = seen;
        if complete {
            let before = self.remembered.len();
            self.remembered.retain(|key| regular_keys.contains(key));
            self.remembered_dirty |= before != self.remembered.len();
        }
        for (name, reason) in &refusals {
            self.log_once(
                scan,
                format!("watch {}: {name}: {reason}", self.status.path),
            );
        }
        self.status.refused = refusals
            .into_iter()
            .take(MAX_REFUSALS)
            .map(|(name, reason)| Refusal { name, reason })
            .collect();

        found.sort_by(|a, b| a.rel.as_bytes().cmp(b.rel.as_bytes()));
        let ready: Vec<Candidate> = found
            .into_iter()
            .filter(|candidate| {
                self.seen
                    .get(&(candidate.facts.dev, candidate.facts.ino))
                    .is_some_and(|seen| now.saturating_sub(seen.since_ms) >= STABLE_MS)
            })
            .collect();
        self.status.pending = (self.seen.len() - ready.len().min(self.seen.len())) as u32;
        for (index, candidate) in ready.iter().enumerate() {
            if self.window.len() >= self.cfg.watch_rate as usize {
                self.paused_until = now + RATE_WINDOW_MS;
                self.status.paused_until_ms = Some(self.paused_until);
                self.status.pending += (ready.len() - index) as u32;
                self.set("paused", Some("too many new jobs in a minute".into()));
                if !self.flood_alerted {
                    self.flood_alerted = true;
                    scan.env.alert(
                        "watch_flood",
                        &format!(
                            "watch folder {} made {} jobs in a minute; it is paused for a minute",
                            self.status.path, self.cfg.watch_rate
                        ),
                    );
                }
                return;
            }
            if !scan.env.queue_has_room() {
                self.status.pending += (ready.len() - index) as u32;
                self.set("held", Some("the queue is full".into()));
                return;
            }
            if !self.take(scan, candidate) {
                self.status.pending += (ready.len() - index - 1) as u32;
                return;
            }
        }
    }

    /// Take one ready file. `false` stops the scan (the folder is paused).
    fn take(&mut self, scan: &Scan<'_>, candidate: &Candidate) -> bool {
        let key = (candidate.facts.dev, candidate.facts.ino);
        let now = scan.now_ms;
        let opened = openat(
            candidate.dir.as_fd(),
            &candidate.c_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let fd = match opened {
            Ok(fd) => fd,
            Err(error) => {
                self.seen.remove(&key);
                self.log_once(
                    scan,
                    format!(
                        "watch {}: {}: not opened: {error}",
                        self.status.path, candidate.rel
                    ),
                );
                return true;
            }
        };
        let facts = match fstat(&fd) {
            Ok(stat) => Facts::from(&stat),
            Err(_) => return true,
        };
        if let Some(problem) = file_problem(
            &facts,
            scan.me,
            candidate.folder_gid,
            self.cfg.allow_group_write,
        ) {
            self.seen.remove(&key);
            self.log_once(
                scan,
                format!("watch {}: {}: {problem}", self.status.path, candidate.rel),
            );
            return true;
        }
        if !facts.unchanged_since(&candidate.facts) {
            // Written to, or replaced, since it was looked at: wait again.
            self.seen.remove(&key);
            return true;
        }
        self.window.push_back(now);
        let admitted = scan.env.admit(Admit {
            file: File::from(fd),
            shown: shown(candidate.rel.as_bytes()),
            file_name: shown(&candidate.name),
            folder_label: self.cfg.label(),
            policy: candidate.policy.clone(),
            on_duplicate: self.cfg.on_duplicate,
            permissions: self.cfg.permissions.clone(),
        });
        match admitted {
            Ok(Admission::Submitted { job }) => {
                self.status.taken += 1;
                scan.env.log(&format!(
                    "watch {}: {} became job {job}",
                    self.status.path, candidate.rel
                ));
                self.finish_taken(scan, candidate);
                true
            }
            Ok(Admission::Rejected { code, message }) => {
                self.status.rejected += 1;
                scan.env.log(&format!(
                    "watch {}: {} was rejected ({code}): {}",
                    self.status.path,
                    candidate.rel,
                    shown(message.as_bytes())
                ));
                self.finish_rejected(scan, candidate, &code, &message);
                true
            }
            Err(defer) => {
                // The file is untouched and will be tried again after a pause.
                self.window.pop_back();
                self.paused_until = now + RATE_WINDOW_MS;
                self.status.paused_until_ms = Some(self.paused_until);
                self.set("error", Some(defer.0.clone()));
                self.log_once(
                    scan,
                    format!(
                        "watch {}: {}: held: {}",
                        self.status.path, candidate.rel, defer.0
                    ),
                );
                false
            }
        }
    }

    fn remember(&mut self, facts: &Facts) {
        if self.remembered.len() < MAX_REMEMBERED && self.remembered.insert(settle::key_of(facts)) {
            self.remembered_dirty = true;
        }
    }

    fn finish_taken(&mut self, scan: &Scan<'_>, candidate: &Candidate) {
        let dir = candidate.dir.as_fd();
        let outcome = match self.cfg.delete_after {
            DeleteAfter::Delete => settle::delete(dir, &candidate.c_name, &candidate.facts),
            DeleteAfter::Move => self.move_to(scan, candidate, &scan.places.processed.clone()),
            DeleteAfter::Keep => {
                self.remember(&candidate.facts);
                return;
            }
        };
        if let Err(error) = outcome {
            scan.env.log(&format!(
                "watch {}: {}: not removed after intake: {error}",
                self.status.path, candidate.rel
            ));
            // It was taken; it must not be taken again.
            self.remember(&candidate.facts);
        }
    }

    fn finish_rejected(
        &mut self,
        scan: &Scan<'_>,
        candidate: &Candidate,
        code: &str,
        message: &str,
    ) {
        let target = scan.places.rejected.clone();
        if let Err(error) =
            self.move_to_with_reason(scan, candidate, &target, Some((code, message)))
        {
            scan.env.log(&format!(
                "watch {}: {}: not moved to rejected: {error}",
                self.status.path, candidate.rel
            ));
            self.remember(&candidate.facts);
        }
    }

    fn move_to(
        &self,
        scan: &Scan<'_>,
        candidate: &Candidate,
        target: &Path,
    ) -> std::io::Result<()> {
        self.move_to_with_reason(scan, candidate, target, None)
    }

    fn move_to_with_reason(
        &self,
        scan: &Scan<'_>,
        candidate: &Candidate,
        target: &Path,
        reason: Option<(&str, &str)>,
    ) -> std::io::Result<()> {
        let target_fd = settle::open_private_dir(target)?;
        let mut last = std::io::Error::other("no free name");
        for attempt in 0..8 {
            let name = settle::settled_name(scan.now_ms, &candidate.name, attempt);
            match settle::move_into(
                candidate.dir.as_fd(),
                &candidate.c_name,
                &candidate.facts,
                target_fd.as_fd(),
                &name,
            ) {
                Ok(()) => {
                    if let Some((code, message)) = reason {
                        settle::write_reason(target_fd.as_fd(), &name, code, message);
                    }
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => last = error,
                Err(error) => return Err(error),
            }
        }
        Err(last)
    }
}

struct Walk<'a, 'b> {
    cfg: &'a Watch,
    scan: &'a Scan<'b>,
    remembered: &'a BTreeSet<[i128; 4]>,
}

struct State<'a> {
    found: &'a mut Vec<Candidate>,
    refusals: &'a mut BTreeMap<String, String>,
    regular_keys: &'a mut BTreeSet<[i128; 4]>,
    budget: &'a mut usize,
}

fn walk(
    w: &Walk<'_, '_>,
    dir: &Arc<OwnedFd>,
    folder_gid: u32,
    rel: &str,
    policy: &str,
    depth: usize,
    state: &mut State<'_>,
) {
    let Ok(listing) = Dir::read_from(dir.as_fd()) else {
        return;
    };
    let mut names: Vec<Vec<u8>> = Vec::new();
    for entry in listing.flatten() {
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if *state.budget == 0 {
            break;
        }
        *state.budget -= 1;
        names.push(name.to_vec());
    }
    names.sort();
    for name in names {
        let Ok(c_name) = CString::new(name.clone()) else {
            continue;
        };
        let Ok(stat) = statat(dir.as_fd(), &c_name, AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        let facts = Facts::from(&stat);
        let rel_name = if rel.is_empty() {
            shown(&name)
        } else {
            format!("{rel}/{}", shown(&name))
        };
        match facts.kind {
            Kind::Directory => {
                if looks_partial(&name) || w.scan.places.skip.contains(&(facts.dev, facts.ino)) {
                    continue;
                }
                let child_policy = if w.cfg.policy_by_dir && depth == 0 {
                    // Only folders named after a policy are used.
                    match std::str::from_utf8(&name) {
                        Ok(text) if w.scan.env.policy_exists(text) => text.to_owned(),
                        _ => continue,
                    }
                } else if w.cfg.recursive {
                    policy.to_owned()
                } else {
                    continue;
                };
                if depth + 1 > MAX_DEPTH {
                    state.refusals.insert(
                        rel_name,
                        "folders are followed 8 levels deep at most".into(),
                    );
                    continue;
                }
                if let Some(problem) = folder_problem(&facts, w.scan.me, w.cfg.allow_group_write) {
                    state.refusals.insert(rel_name, problem);
                    continue;
                }
                let Ok(child) = openat(
                    dir.as_fd(),
                    &c_name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) else {
                    continue;
                };
                // The name may have been swapped between the stat and the open.
                if !fstat(&child).is_ok_and(|s| Facts::from(&s).same_file(&facts)) {
                    continue;
                }
                walk(
                    w,
                    &Arc::new(child),
                    facts.gid,
                    &rel_name,
                    &child_policy,
                    depth + 1,
                    state,
                );
            }
            Kind::Regular => {
                if looks_partial(&name) {
                    continue;
                }
                state.regular_keys.insert(settle::key_of(&facts));
                if w.remembered.contains(&settle::key_of(&facts)) {
                    continue;
                }
                if let Some(problem) =
                    file_problem(&facts, w.scan.me, folder_gid, w.cfg.allow_group_write)
                {
                    state.refusals.insert(rel_name, problem);
                    continue;
                }
                state.found.push(Candidate {
                    dir: Arc::clone(dir),
                    folder_gid,
                    name,
                    c_name,
                    rel: rel_name,
                    policy: policy.to_owned(),
                    facts,
                });
            }
            Kind::Symlink | Kind::Other => {
                if looks_partial(&name) {
                    continue;
                }
                let reason = file_problem(&facts, w.scan.me, folder_gid, false)
                    .unwrap_or_else(|| "not a regular file".into());
                state.refusals.insert(rel_name, reason);
            }
        }
    }
}
