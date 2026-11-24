// SPDX-License-Identifier: GPL-3.0-only
//! A static job reads its rule profile in place (ANT-T0618, audit AN-04).
//!
//! A profile (`rules/profiles/<engine>/<digest>/`) is content addressed and
//! never written after it is complete, so a job's sandbox mounts it read-only
//! instead of copying 1,700 files into every job folder (15 MB and about half
//! a second each). The job holds a [`ProfileUse`] for as long as the worker
//! runs; pruning ([`prune_profiles`]) leaves a profile that has a live marker.
//!
//! The marker is a small file in `profiles/<engine>/.in-use/`, named
//! `<digest>.<unique id>`, holding the pid of the process that owns the job.
//! It is live while that process exists and the file is under a day old (a job
//! that long is stuck; a crashed engine must not keep a profile for ever).
//! Dropping the [`ProfileUse`] removes it.
use super::*;
use std::time::{Duration, SystemTime};

/// The profile the static Rules check reads.
const ENGINE: &str = "yara";
/// A marker older than this is stale whatever its pid says.
const MARKER_LIFE: Duration = Duration::from_secs(24 * 3600);
/// Profiles kept per engine whatever their age (the newest by last use).
const KEEP_PROFILES: usize = 4;
/// A profile nobody asked for in this long may be pruned.
const IDLE_BEFORE_PRUNE: Duration = Duration::from_secs(24 * 3600);
const MARKER_DIR: &str = ".in-use";

/// A rule profile a job reads. Hold it until the job's worker is gone.
#[derive(Debug)]
pub struct ProfileUse {
    marker: PathBuf,
    directory: PathBuf,
    digest: String,
}

impl ProfileUse {
    /// The profile folder, to be mounted read-only.
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl Drop for ProfileUse {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.marker);
    }
}

/// Mark the profile of the current YARA selection in use by the job in `owner`
/// and give it back, building it when it is not there. `None` when no rule is
/// enabled. The registry is found from `data_dir` (a job folder inside the
/// data folder finds it by walking up, like the worker's staging did).
pub fn use_static_profile(data_dir: &Path, owner: &Path) -> Result<Option<ProfileUse>, String> {
    let tools = ToolConfig::default();
    let mut last = String::from("the rule profile is gone");
    for _ in 0..3 {
        let snap = snapshot(data_dir, ENGINE, &tools)?;
        let Some(directory) = snap.directory else {
            return Ok(None);
        };
        let marker = {
            let _lock = registry_lock(data_dir);
            let dir = markers(&directory);
            crate::storage::private_dir(&dir).map_err(|error| error.to_string())?;
            let marker = dir.join(format!("{}.{}", snap.digest, crate::storage::unique_id()));
            fs::write(
                &marker,
                format!("{} {}\n", std::process::id(), owner.display()),
            )
            .map_err(|error| error.to_string())?;
            marker
        };
        let user = ProfileUse {
            marker,
            directory,
            digest: snap.digest,
        };
        // Another process may have pruned between the snapshot and the
        // marker (the in-process lock does not reach it): look again, and
        // build the profile anew when it is gone.
        if user.directory.join(".complete").is_file() {
            let _ = prune_profiles(data_dir, ENGINE);
            return Ok(Some(user));
        }
        last = format!("{} vanished while it was marked", user.directory.display());
    }
    Err(last)
}

/// `profiles/<engine>/.in-use` beside a profile folder.
fn markers(profile: &Path) -> PathBuf {
    profile.parent().map_or_else(
        || PathBuf::from(MARKER_DIR),
        |parent| parent.join(MARKER_DIR),
    )
}

/// Record that the profile was just asked for, so pruning sees it as recent.
/// An hour's resolution keeps this to one tiny write per hour and profile.
pub(super) fn note_use(profile: &Path) {
    let complete = profile.join(".complete");
    let stale = fs::metadata(&complete)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| SystemTime::now().duration_since(time).ok())
        .is_some_and(|age| age >= Duration::from_secs(3600));
    if stale && let Ok(file) = fs::OpenOptions::new().write(true).open(&complete) {
        let _ = file.set_modified(SystemTime::now());
    }
}

/// Whether some live job reads `digest` of the profile folder `engine_dir`.
fn in_use(engine_dir: &Path, digest: &str) -> bool {
    let Ok(entries) = fs::read_dir(engine_dir.join(MARKER_DIR)) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        if name.split('.').next() != Some(digest) {
            return false;
        }
        let fresh = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|time| SystemTime::now().duration_since(time).ok())
            .is_some_and(|age| age < MARKER_LIFE);
        let pid = fs::read_to_string(entry.path()).ok().and_then(|text| {
            text.split_whitespace()
                .next()
                .and_then(|p| p.parse::<u32>().ok())
        });
        if fresh && pid.is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists()) {
            return true;
        }
        // A dead owner or an old marker holds nothing.
        let _ = fs::remove_file(entry.path());
        false
    })
}

/// Remove complete profiles of `engine` that no job reads and nothing has
/// asked for in a day, keeping the newest few. A profile is rebuilt from the
/// registry when it is asked for again, so pruning loses nothing.
///
/// A profile with a live marker is never removed. Pruning moves a candidate
/// aside first and looks at the markers again, so a job that marked it in
/// between (another process) keeps it: the folder goes back.
pub fn prune_profiles(data_dir: &Path, engine: &str) -> Result<u32, String> {
    let _lock = registry_lock(data_dir);
    let root = rules_root(data_dir);
    let engine_dir = root.join("profiles").join(engine);
    let Ok(entries) = fs::read_dir(&engine_dir) else {
        return Ok(0);
    };
    let mut profiles = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let Ok(used) =
            fs::metadata(entry.path().join(".complete")).and_then(|meta| meta.modified())
        else {
            continue; // not complete: a build in progress or a failed one
        };
        profiles.push((used, name, entry.path()));
    }
    profiles.sort_by(|a, b| b.cmp(a));
    let mut removed = 0;
    for (used, name, path) in profiles.into_iter().skip(KEEP_PROFILES) {
        let idle = SystemTime::now()
            .duration_since(used)
            .is_ok_and(|age| age >= IDLE_BEFORE_PRUNE);
        if !idle || in_use(&engine_dir, &name) {
            continue;
        }
        let aside = root
            .join("staging")
            .join(format!("pruned-{}", crate::storage::unique_id()));
        if crate::storage::private_dir(&root.join("staging")).is_err()
            || fs::rename(&path, &aside).is_err()
        {
            continue;
        }
        if in_use(&engine_dir, &name) {
            let _ = fs::rename(&aside, &path);
            continue;
        }
        let _ = fs::remove_dir_all(&aside);
        removed += 1;
    }
    Ok(removed)
}
