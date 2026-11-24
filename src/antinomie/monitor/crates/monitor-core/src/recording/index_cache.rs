// SPDX-License-Identifier: GPL-3.0-only
//! Keeping the archive index cache bounded.
//!
//! An index is rebuilt from its recording whenever it is missing, so the cache
//! can drop any of them. Indexes not used for [`MAX_AGE`] are removed, and the
//! least recently used ones go first while the cache is above [`MAX_BYTES`].
//! The index in use is never removed.
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};

/// Bytes the cache may hold before the least recently used indexes go.
pub(super) const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// An index not used for this long is removed.
pub(super) const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Pruning scans the directory at most this often.
const INTERVAL: Duration = Duration::from_secs(60 * 60);

/// When each cache folder was last pruned.
static LAST_PRUNE: Mutex<Vec<(PathBuf, Instant)>> = Mutex::new(Vec::new());

/// Mark `index` as used now, then prune the cache if it has not been pruned
/// within the interval.
pub(super) fn used(index: &Path) {
    used_within(index, MAX_BYTES);
}

/// [`used`] for a cache folder with its own size cap (the packed-object
/// caches, which sit in their own folder).
pub(crate) fn used_within(index: &Path, max_bytes: u64) {
    if let Ok(file) = fs::OpenOptions::new().write(true).open(index) {
        let _ = file.set_modified(SystemTime::now());
    }
    let Some(cache_root) = index.parent() else {
        return;
    };
    {
        let mut last = LAST_PRUNE.lock().unwrap_or_else(|error| error.into_inner());
        match last.iter_mut().find(|(root, _)| root == cache_root) {
            Some((_, at)) if at.elapsed() < INTERVAL => return,
            Some((_, at)) => *at = Instant::now(),
            None => last.push((cache_root.to_path_buf(), Instant::now())),
        }
    }
    prune(cache_root, index, max_bytes, MAX_AGE, SystemTime::now());
}

/// The derived caches of one recording: its packet index and its
/// packed-object index. Both are rebuilt from the recording when asked for, so
/// they go with it (ANT-T0618, audit AN-05); a recording that stays keeps them,
/// and the size caps bound what is left.
pub(crate) struct DerivedCaches {
    objects: PathBuf,
    browse: Option<PathBuf>,
    packed: Option<PathBuf>,
}

impl DerivedCaches {
    /// Name the caches of the run folder `run_dir`. Take this before the
    /// folder is removed: the packed-object cache is named by the folder.
    pub(crate) fn of(run_dir: &Path) -> Self {
        let objects = run_dir.join("objects");
        Self {
            browse: super::archive_index_path(run_dir).ok(),
            packed: crate::object_pack::cache_file_of(&objects),
            objects,
        }
    }

    /// Remove them. Returns the bytes freed.
    pub(crate) fn remove(self) -> u64 {
        let mut freed = 0;
        if let Some(browse) = &self.browse {
            let len = fs::metadata(browse).map_or(0, |meta| meta.len());
            if remove(browse) {
                freed += len;
            }
        }
        if let Some(packed) = &self.packed {
            freed += crate::object_pack::discard_cache(&self.objects, packed);
        }
        freed
    }
}

/// Remove indexes older than `max_age` and, oldest use first, more until the
/// remaining ones fit in `max_bytes`. `keep` is never removed.
pub(super) fn prune(
    cache_root: &Path,
    keep: &Path,
    max_bytes: u64,
    max_age: Duration,
    now: SystemTime,
) {
    let Ok(entries) = fs::read_dir(cache_root) else {
        return;
    };
    let mut indexes = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .extension()
            .is_none_or(|extension| extension != "sqlite")
            || path == keep
        {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let used = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        indexes.push((used, metadata.len(), path));
    }
    let mut total = fs::metadata(keep).map_or(0, |metadata| metadata.len())
        + indexes.iter().map(|(_, len, _)| len).sum::<u64>();
    indexes.sort_by_key(|(used, _, _)| *used);
    for (used, len, path) in indexes {
        let stale = now.duration_since(used).is_ok_and(|age| age > max_age);
        if !stale && total <= max_bytes {
            continue;
        }
        if remove(&path) {
            total = total.saturating_sub(len);
        }
    }
}

fn remove(index: &Path) -> bool {
    let removed = fs::remove_file(index).is_ok();
    let mut journal = index.as_os_str().to_owned();
    journal.push("-journal");
    let _ = fs::remove_file(journal);
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_and_least_recently_used_indexes_go_and_the_one_in_use_stays() {
        let root =
            std::env::temp_dir().join(format!("ant-index-cache-{}", crate::storage::unique_id()));
        fs::create_dir_all(&root).unwrap();
        let now = SystemTime::now();
        let write = |name: &str, len: usize, age_days: u64| {
            let path = root.join(name);
            fs::write(&path, vec![0; len]).unwrap();
            let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.set_modified(now - Duration::from_secs(age_days * 24 * 60 * 60))
                .unwrap();
            path
        };
        let stale = write("stale.sqlite", 10, 40);
        let oldest = write("oldest.sqlite", 400, 5);
        let older = write("older.sqlite", 400, 3);
        let recent = write("recent.sqlite", 400, 1);
        let keep = write("keep.sqlite", 400, 20);
        let other = write("notes.txt", 10, 90);
        // 1,600 bytes of indexes besides the stale one; 1,000 may stay.
        prune(&root, &keep, 1000, MAX_AGE, now);
        assert!(!stale.exists(), "unused for longer than the age limit");
        assert!(
            !oldest.exists() && !older.exists(),
            "least recently used first"
        );
        assert!(recent.exists());
        assert!(keep.exists(), "the index in use stays");
        assert!(other.exists(), "only indexes are pruned");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_caches_of_a_deleted_run_go_with_it_and_those_of_other_runs_stay() {
        let base =
            std::env::temp_dir().join(format!("ant-derived-{}", crate::storage::unique_id()));
        let mut runs = Vec::new();
        for name in ["gone", "kept"] {
            let run = base.join(name);
            fs::create_dir_all(run.join("objects")).unwrap();
            let browse = super::super::archive_index_path(&run).unwrap();
            let packed = crate::object_pack::cache_file_of(&run.join("objects")).unwrap();
            for file in [&browse, &packed] {
                fs::write(file, vec![0; 100]).unwrap();
            }
            fs::write(format!("{}-journal", browse.display()), b"j").unwrap();
            runs.push((run, browse, packed));
        }
        let (run, browse, packed) = &runs[0];
        let caches = DerivedCaches::of(run);
        fs::remove_dir_all(run).unwrap();
        assert_eq!(caches.remove(), 200);
        assert!(!browse.exists() && !packed.exists());
        assert!(!Path::new(&format!("{}-journal", browse.display())).exists());
        let (_, browse, packed) = &runs[1];
        assert!(
            browse.is_file() && packed.is_file(),
            "another run's caches stay"
        );
        for (_, browse, packed) in &runs[1..] {
            let _ = fs::remove_file(browse);
            let _ = fs::remove_file(packed);
            let _ = fs::remove_file(format!("{}-journal", browse.display()));
        }
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn each_cache_folder_is_pruned_on_its_own_clock() {
        let base = std::env::temp_dir().join(format!("ant-prune-{}", crate::storage::unique_id()));
        let folders = [base.join("a"), base.join("b")];
        for folder in &folders {
            fs::create_dir_all(folder).unwrap();
        }
        let write = |folder: &Path, name: &str, age: u64| {
            let path = folder.join(name);
            fs::write(&path, vec![0; 500]).unwrap();
            let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.set_modified(SystemTime::now() - Duration::from_secs(age))
                .unwrap();
            path
        };
        let old_a = write(&folders[0], "old.sqlite", 1000);
        let in_use_a = write(&folders[0], "use.sqlite", 0);
        let old_b = write(&folders[1], "old.sqlite", 1000);
        let in_use_b = write(&folders[1], "use.sqlite", 0);
        used_within(&in_use_a, 600);
        // The first folder was pruned just now; the second one is still due.
        used_within(&in_use_b, 600);
        assert!(!old_a.exists() && !old_b.exists());
        assert!(in_use_a.exists() && in_use_b.exists());
        fs::remove_dir_all(base).unwrap();
    }

    fn tree_len(path: &Path) -> u64 {
        fs::read_dir(path)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| {
                let meta = entry.metadata().unwrap();
                if meta.is_dir() {
                    tree_len(&entry.path())
                } else {
                    meta.len()
                }
            })
            .sum()
    }

    /// By hand (ANT-T0618 measurement): after a whole-run scan of the copy in
    /// `ANT_TIMING_RUN` with `XDG_CACHE_HOME` set, free its derived caches and
    /// print what they held.
    #[test]
    #[ignore = "needs ANT_TIMING_RUN and the caches of a scan"]
    fn free_the_caches_of_a_real_run() {
        let Some(run) = std::env::var_os("ANT_TIMING_RUN") else {
            return;
        };
        let run = PathBuf::from(run);
        let cache = super::super::browse_cache_root(
            std::env::var_os("XDG_CACHE_HOME"),
            std::env::var_os("HOME"),
        )
        .unwrap();
        let before = tree_len(cache.parent().unwrap());
        let freed = DerivedCaches::of(&run).remove();
        let after = tree_len(cache.parent().unwrap());
        eprintln!("TIMING caches {before} bytes before, {after} after, {freed} freed");
        assert_eq!(before - after, freed);
    }
}
