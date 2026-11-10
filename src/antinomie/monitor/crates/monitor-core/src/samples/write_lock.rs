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

/// Wait for the write lock of `database`.
pub fn lock(database: &Path) -> WriteGuard {
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
