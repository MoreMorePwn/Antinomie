// SPDX-License-Identifier: GPL-3.0-only
//! Which analyses a job queue of this process still owns.
//!
//! A run saved on disk keeps the state its analysis had when it was last
//! written. Reading it back after the owning app session ended means nothing
//! will ever finish that analysis, so the loader settles it as interrupted. The
//! same read made while this session's queue is still working on it (the
//! program ended, the analysis did not) must leave it alone: the queue
//! publishes here the ids it holds, and the loader asks.
use super::Jobs;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

static OWNED: Mutex<BTreeMap<u64, BTreeSet<String>>> = Mutex::new(BTreeMap::new());
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

/// One queue's place in the registry; leaving it (the queue is dropped) takes
/// the queue's ids out.
#[derive(Debug)]
pub(super) struct Owner {
    id: u64,
    /// Ids held at the last refresh. They stay published through the next one,
    /// so a job that finished is still owned while its final report is being
    /// written to the run.
    grace: BTreeSet<String>,
}

impl Default for Owner {
    fn default() -> Self {
        Self {
            id: NEXT_OWNER.fetch_add(1, Ordering::Relaxed),
            grace: BTreeSet::new(),
        }
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        if let Ok(mut owned) = OWNED.lock() {
            owned.remove(&self.id);
        }
    }
}

/// Whether some queue of this process holds the analysis `id`.
pub fn owned_here(id: &str) -> bool {
    OWNED
        .lock()
        .is_ok_and(|owned| owned.values().any(|ids| ids.contains(id)))
}

#[cfg(test)]
pub(crate) fn test_claim(owner: u64, ids: &[&str]) {
    OWNED
        .lock()
        .unwrap()
        .insert(owner, ids.iter().map(|id| (*id).to_owned()).collect());
}

#[cfg(test)]
pub(crate) fn test_release(owner: u64) {
    OWNED.lock().unwrap().remove(&owner);
}

impl Jobs {
    fn held_ids(&self) -> BTreeSet<String> {
        let mut ids: BTreeSet<String> = self
            .queue
            .iter()
            .chain(self.active.iter())
            .chain(self.acquiring.iter())
            .map(|job| job.report.id.clone())
            .collect();
        ids.extend(self.detached.iter().cloned());
        for carried in &self.carried {
            ids.extend(carried.held_ids());
        }
        ids
    }

    /// Publish what this queue holds now, plus what it held since the last
    /// `rotate_published`.
    pub(super) fn publish(&mut self) {
        let held = self.held_ids();
        let mut ids = held.clone();
        ids.extend(self.owner.grace.iter().cloned());
        self.owner.grace.extend(held);
        if let Ok(mut owned) = OWNED.lock() {
            owned.insert(self.owner.id, ids);
        }
    }

    /// Publish, then remember what is held now for the next time.
    pub(super) fn rotate_published(&mut self) {
        let mut ids = self.held_ids();
        ids.extend(self.owner.grace.iter().cloned());
        if let Ok(mut owned) = OWNED.lock() {
            owned.insert(self.owner.id, ids);
        }
        self.owner.grace = self.held_ids();
    }
}
