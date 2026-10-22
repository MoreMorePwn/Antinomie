// SPDX-License-Identifier: GPL-3.0-only
//! Keeping the archive index cache bounded.
//!
//! An index is rebuilt from its recording whenever it is missing, so the cache
//! can drop any of them. Indexes not used for [`MAX_AGE`] are removed, and the
//! least recently used ones go first while the cache is above [`MAX_BYTES`].
//! The index in use is never removed.
use std::{
    fs,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};

/// Bytes the cache may hold before the least recently used indexes go.
pub(super) const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// An index not used for this long is removed.
pub(super) const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Pruning scans the directory at most this often.
const INTERVAL: Duration = Duration::from_secs(60 * 60);

static LAST_PRUNE: Mutex<Option<Instant>> = Mutex::new(None);

/// Mark `index` as used now, then prune the cache if it has not been pruned
/// within the interval.
pub(super) fn used(index: &Path) {
    if let Ok(file) = fs::OpenOptions::new().write(true).open(index) {
        let _ = file.set_modified(SystemTime::now());
    }
    let Some(cache_root) = index.parent() else {
        return;
    };
    {
        let mut last = LAST_PRUNE.lock().unwrap_or_else(|error| error.into_inner());
        if last.is_some_and(|last| last.elapsed() < INTERVAL) {
            return;
        }
        *last = Some(Instant::now());
    }
    prune(cache_root, index, MAX_BYTES, MAX_AGE, SystemTime::now());
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
}
