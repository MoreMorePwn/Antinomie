// SPDX-License-Identifier: GPL-3.0-only
//! One writer at a time per library, inside this process.
//!
//! SQLite already serialises writers, but it does so by sleeping and trying
//! again until the busy timeout, which starves a writer when several threads
//! (intake, the custody writer, tag edits) keep the file busy. Writers that
//! take this lock queue in the process instead and only compete with other
//! processes through the busy timeout. The lock is reentrant on a thread: a
//! library write that reports its custody event while it holds the lock does
//! not wait for itself.
use std::{
    cell::RefCell,
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
};

#[derive(Default)]
struct Slot {
    /// The thread that holds the lock, if any.
    owner: Mutex<Option<std::thread::ThreadId>>,
    freed: Condvar,
}

thread_local! {
    /// The databases this thread holds, with how deep.
    static HELD: RefCell<HashMap<PathBuf, usize>> = RefCell::new(HashMap::new());
}

/// The canonical path of `database`. A file not created yet takes its
/// folder's canonical path, so it keeps the same key once it exists.
fn key(database: &Path) -> PathBuf {
    std::fs::canonicalize(database)
        .ok()
        .or_else(|| {
            let folder = std::fs::canonicalize(database.parent()?).ok()?;
            Some(folder.join(database.file_name()?))
        })
        .unwrap_or_else(|| database.to_path_buf())
}

fn slot(database: &Path) -> Arc<Slot> {
    static SLOTS: Mutex<Option<HashMap<PathBuf, Arc<Slot>>>> = Mutex::new(None);
    let mut slots = SLOTS.lock().unwrap_or_else(|e| e.into_inner());
    slots
        .get_or_insert_with(HashMap::new)
        .entry(database.to_path_buf())
        .or_default()
        .clone()
}

/// Held while a thread writes to one library database.
pub struct WriteGuard {
    database: PathBuf,
    slot: Arc<Slot>,
}

/// Wait for the write lock of `database`. The lock is keyed by the file's
/// canonical path, so every engine of a process (the lanes of a daemon, which
/// reach lane 0's library from their own data folders) and every spelling of
/// the path share one lock.
pub fn lock(database: &Path) -> WriteGuard {
    let canonical = key(database);
    let database = canonical.as_path();
    let slot = slot(database);
    let me = std::thread::current().id();
    let nested = HELD.with(|held| {
        let mut held = held.borrow_mut();
        match held.get_mut(database) {
            Some(depth) => {
                *depth += 1;
                true
            }
            None => false,
        }
    });
    if !nested {
        let mut owner = slot.owner.lock().unwrap_or_else(|e| e.into_inner());
        while owner.is_some() {
            owner = slot.freed.wait(owner).unwrap_or_else(|e| e.into_inner());
        }
        *owner = Some(me);
        HELD.with(|held| held.borrow_mut().insert(database.to_path_buf(), 1));
    }
    WriteGuard {
        database: database.to_path_buf(),
        slot,
    }
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        let last = HELD.with(|held| {
            let mut held = held.borrow_mut();
            match held.get_mut(&self.database) {
                Some(depth) if *depth > 1 => {
                    *depth -= 1;
                    false
                }
                _ => {
                    held.remove(&self.database);
                    true
                }
            }
        });
        if last {
            let mut owner = self.slot.owner.lock().unwrap_or_else(|e| e.into_inner());
            *owner = None;
            self.slot.freed.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// The lanes of a daemon reach lane 0's library from their own folders;
    /// whatever the spelling, one database has one lock.
    #[test]
    fn two_spellings_of_one_database_share_its_lock() {
        let root =
            std::env::temp_dir().join(format!("ant-write-lock-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(root.join("data/samples")).unwrap();
        let database = root.join("data/samples/library.sqlite");
        std::os::unix::fs::symlink(root.join("data"), root.join("link")).unwrap();
        let other = root.join("link/samples/../samples/library.sqlite");
        // A library not created yet has the key it will have once it exists.
        let before = key(&other);
        std::fs::write(&database, b"").unwrap();
        assert_eq!(before, key(&other));
        assert_eq!(key(&database), key(&other));
        let held = lock(&database);
        let (sender, taken) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let began = Instant::now();
            let _second = lock(&other);
            sender.send(began.elapsed()).unwrap();
        });
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            taken.try_recv().is_err(),
            "the second spelling did not wait"
        );
        drop(held);
        let waited = taken.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(waited >= Duration::from_millis(250), "{waited:?}");
        waiter.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
