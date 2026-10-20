// SPDX-License-Identifier: MIT
//! Comparing two ext4 images: the entries added to, deleted from and changed
//! in the image since a reference (the "before").
//!
//! Both trees are walked together in name order, so the listing runs
//! directory by directory, by name inside each. A rename is not detected: it is a deleted entry and an added one.
//! A file counts as changed when its kind, size, mode, owner, modification
//! time or link target differs; when only the time differs the bytes are
//! compared (up to [`DIFF_COMPARE_LIMIT`]) to say whether the content changed.
//! Two files that agree on all of these are called equal without reading
//! them. A directory counts as changed only when its kind, mode or owner
//! differs (its own times change whenever its contents do).
//!
//! The walk is bounded by the number of entries, depth, wall-clock time and
//! the length of the listing; the totals go on counting past the listing
//! limit. Symbolic links are compared, never followed.
use super::{
    image::{entry_of, is_dot, link_target},
    protocol::*,
};
use ext4_view::{Ext4, FileType};
use std::time::{Duration, Instant};

/// The bounds of one comparison (the protocol's constants; tests use smaller).
#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    pub results: usize,
    pub scanned: u64,
    pub seconds: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            results: DIFF_RESULT_LIMIT,
            scanned: DIFF_SCAN_LIMIT,
            seconds: DIFF_SECONDS,
        }
    }
}

/// One side of a name: what the directory entry says.
struct Side {
    name: Vec<u8>,
    kind: FileType,
    entry: DiskEntry,
}

/// Which tree the entries of a one-sided subtree belong to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Only {
    Before,
    After,
}

enum Job {
    /// A directory present on both sides.
    Both(ext4_view::PathBuf, usize),
    /// A directory present on one side only: everything under it is added
    /// or deleted.
    One(ext4_view::PathBuf, Only, usize),
}

struct Walk<'a> {
    before: &'a Ext4,
    after: &'a Ext4,
    deadline: Instant,
    limits: Limits,
    results: DiffResults,
}

/// Read a directory's entries, sorted by name, without `.` and `..`.
fn sides(fs: &Ext4, directory: &ext4_view::PathBuf, unreadable: &mut u64) -> Vec<Side> {
    let Ok(entries) = fs.read_dir(directory) else {
        *unreadable += 1;
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            *unreadable += 1;
            continue;
        };
        let name = entry.file_name().as_ref().to_vec();
        if is_dot(&name) {
            continue;
        }
        if out.len() >= DIRECTORY_ENTRY_LIMIT {
            *unreadable += 1;
            break;
        }
        let Ok(metadata) = entry.metadata() else {
            *unreadable += 1;
            continue;
        };
        let target = metadata
            .is_symlink()
            .then(|| link_target(fs, &entry.path()))
            .flatten();
        out.push(Side {
            kind: metadata.file_type(),
            entry: entry_of(&name, &metadata, target),
            name,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn join(directory: &ext4_view::PathBuf, name: &[u8]) -> Option<ext4_view::PathBuf> {
    let mut path = directory.as_ref().to_vec();
    if path.last() != Some(&b'/') {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    ext4_view::PathBuf::try_from(path.as_slice()).ok()
}

fn text(path: &ext4_view::PathBuf) -> String {
    let mut text = String::from_utf8_lossy(path.as_ref()).into_owned();
    text.truncate(PATH_LIMIT);
    text
}

impl Walk<'_> {
    fn add(&mut self, entry: DiffEntry) {
        match entry.status {
            DiffStatus::Added => self.results.added += 1,
            DiffStatus::Deleted => self.results.deleted += 1,
            DiffStatus::Changed => self.results.changed += 1,
        }
        if self.results.entries.len() < self.limits.results {
            self.results.entries.push(entry);
        } else {
            self.results.truncated = true;
        }
    }

    /// Account for one entry looked at; false when the walk must stop.
    fn tick(&mut self) -> bool {
        self.results.scanned += 1;
        if self.results.scanned > self.limits.scanned {
            self.results.timed_out = true;
            return false;
        }
        if Instant::now() >= self.deadline {
            self.results.timed_out = true;
            return false;
        }
        true
    }

    /// Whether `before` and `after`, two regular files of equal size that
    /// differ in time, hold the same bytes. `None` when they were not
    /// compared (too large, unreadable).
    fn same_bytes(&self, path: &ext4_view::PathBuf, size: u64) -> Option<bool> {
        if size > DIFF_COMPARE_LIMIT {
            return None;
        }
        let mut a = self.before.open(path).ok()?;
        let mut b = self.after.open(path).ok()?;
        let (mut left, mut right) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
        loop {
            let first = a.read_bytes(&mut left).ok()?;
            // Fill the second buffer to the same length.
            let mut second = 0;
            while second < first {
                let count = b.read_bytes(&mut right[second..first]).ok()?;
                if count == 0 {
                    return Some(false);
                }
                second += count;
            }
            if first == 0 {
                return Some(b.read_bytes(&mut right[..1]).ok()? == 0);
            }
            if left[..first] != right[..first] {
                return Some(false);
            }
        }
    }

    fn compare(&mut self, path: &ext4_view::PathBuf, before: Side, after: Side) -> bool {
        let mut reasons = Vec::new();
        let (old, new) = (&before.entry, &after.entry);
        if before.kind != after.kind {
            reasons.push(DiffReason::Type);
        }
        if old.mode != new.mode {
            reasons.push(DiffReason::Mode);
        }
        if old.uid != new.uid || old.gid != new.gid {
            reasons.push(DiffReason::Owner);
        }
        let same_kind = before.kind == after.kind;
        let directory = same_kind && before.kind == FileType::Directory;
        if same_kind && !directory {
            if old.size != new.size {
                reasons.push(DiffReason::Size);
            }
            if old.link_target != new.link_target {
                reasons.push(DiffReason::Target);
            }
            if old.mtime != new.mtime {
                // Same size, different time: the bytes say whether it is a
                // touch or an edit.
                if before.kind == FileType::Regular && old.size == new.size {
                    if self.same_bytes(path, new.size) == Some(false) {
                        reasons.push(DiffReason::Content);
                    } else {
                        reasons.push(DiffReason::Time);
                    }
                } else {
                    reasons.push(DiffReason::Time);
                }
            }
        }
        if reasons.is_empty() {
            return directory;
        }
        self.add(DiffEntry {
            path: text(path),
            status: DiffStatus::Changed,
            before: Some(before.entry),
            after: Some(after.entry),
            reasons,
        });
        directory
    }
}

/// Compare `before` (the reference) with `after` (the image).
pub(super) fn diff(before: &Ext4, after: &Ext4, limits: Limits) -> DiffResults {
    let mut walk = Walk {
        before,
        after,
        deadline: Instant::now() + Duration::from_secs(limits.seconds),
        limits,
        results: DiffResults::default(),
    };
    let Ok(root) = ext4_view::PathBuf::try_from("/") else {
        return walk.results;
    };
    let mut stack = vec![Job::Both(root, 0)];
    'walk: while let Some(job) = stack.pop() {
        match job {
            Job::One(directory, only, depth) => {
                let fs = if only == Only::Before { before } else { after };
                let mut children = Vec::new();
                for side in sides(fs, &directory, &mut walk.results.unreadable) {
                    if !walk.tick() {
                        break 'walk;
                    }
                    let Some(path) = join(&directory, &side.name) else {
                        continue;
                    };
                    let recurse = side.kind == FileType::Directory && depth < FIND_DEPTH_LIMIT;
                    let (status, old, new) = if only == Only::Before {
                        (DiffStatus::Deleted, Some(side.entry), None)
                    } else {
                        (DiffStatus::Added, None, Some(side.entry))
                    };
                    walk.add(DiffEntry {
                        path: text(&path),
                        status,
                        before: old,
                        after: new,
                        reasons: Vec::new(),
                    });
                    if recurse {
                        children.push(Job::One(path, only, depth + 1));
                    }
                }
                children.reverse();
                stack.extend(children);
            }
            Job::Both(directory, depth) => {
                let old = sides(before, &directory, &mut walk.results.unreadable);
                let new = sides(after, &directory, &mut walk.results.unreadable);
                let mut children = Vec::new();
                let (mut old, mut new) = (old.into_iter().peekable(), new.into_iter().peekable());
                loop {
                    let order = match (old.peek(), new.peek()) {
                        (None, None) => break,
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (Some(a), Some(b)) => a.name.cmp(&b.name),
                    };
                    if !walk.tick() {
                        break 'walk;
                    }
                    let deeper = depth < FIND_DEPTH_LIMIT;
                    match order {
                        std::cmp::Ordering::Less => {
                            let Some(side) = old.next() else { break };
                            let Some(path) = join(&directory, &side.name) else {
                                continue;
                            };
                            let recurse = side.kind == FileType::Directory && deeper;
                            walk.add(DiffEntry {
                                path: text(&path),
                                status: DiffStatus::Deleted,
                                before: Some(side.entry),
                                after: None,
                                reasons: Vec::new(),
                            });
                            if recurse {
                                children.push(Job::One(path, Only::Before, depth + 1));
                            }
                        }
                        std::cmp::Ordering::Greater => {
                            let Some(side) = new.next() else { break };
                            let Some(path) = join(&directory, &side.name) else {
                                continue;
                            };
                            let recurse = side.kind == FileType::Directory && deeper;
                            walk.add(DiffEntry {
                                path: text(&path),
                                status: DiffStatus::Added,
                                before: None,
                                after: Some(side.entry),
                                reasons: Vec::new(),
                            });
                            if recurse {
                                children.push(Job::One(path, Only::After, depth + 1));
                            }
                        }
                        std::cmp::Ordering::Equal => {
                            let (Some(a), Some(b)) = (old.next(), new.next()) else {
                                break;
                            };
                            let Some(path) = join(&directory, &a.name) else {
                                continue;
                            };
                            let (a_dir, b_dir) =
                                (a.kind == FileType::Directory, b.kind == FileType::Directory);
                            let both_dirs = a_dir && b_dir;
                            // A kind change keeps the sides' own subtrees.
                            let (a_kind, b_kind) = (a.kind, b.kind);
                            let recurse_both = walk.compare(&path, a, b);
                            if both_dirs && recurse_both && deeper {
                                children.push(Job::Both(path, depth + 1));
                            } else if a_kind != b_kind && deeper {
                                if a_dir {
                                    children.push(Job::One(path.clone(), Only::Before, depth + 1));
                                }
                                if b_dir {
                                    children.push(Job::One(path, Only::After, depth + 1));
                                }
                            }
                        }
                    }
                }
                children.reverse();
                stack.extend(children);
            }
        }
    }
    walk.results
}
