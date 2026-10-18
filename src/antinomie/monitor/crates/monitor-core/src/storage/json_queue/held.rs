//! Test control of the persistence thread. [`SlowDisk`] gives the calling
//! thread (and threads that inherit it, see [`inherit`]) a queue of its own
//! that can be stopped, as a disk that does not answer would stop the real
//! one, without holding up the tests that run beside it.
use super::{Queue, start_queue};
use std::cell::Cell;

thread_local! {
    static PRIVATE: Cell<Option<&'static Queue>> = const { Cell::new(None) };
}

pub(super) fn private_queue() -> Option<&'static Queue> {
    PRIVATE.with(Cell::get)
}

/// Make a thread started from here use the same private queue.
pub(crate) fn inherit() -> impl FnOnce() + Send + 'static {
    let queue = private_queue();
    move || PRIVATE.with(|private| private.set(queue))
}

/// A private persistence queue for this thread while it lives.
pub(crate) struct SlowDisk(&'static Queue);

impl SlowDisk {
    pub(crate) fn install() -> Self {
        let queue = start_queue().expect("test JSON writer thread starts");
        PRIVATE.with(|private| private.set(Some(queue)));
        Self(queue)
    }
    /// Stop publishing: queued and new values wait for [`Self::resume`].
    pub(crate) fn pause(&self) {
        self.0.0.lock().unwrap_or_else(|e| e.into_inner()).paused = true;
    }
    pub(crate) fn resume(&self) {
        self.0.0.lock().unwrap_or_else(|e| e.into_inner()).paused = false;
        self.0.1.notify_all();
    }
}

impl Drop for SlowDisk {
    fn drop(&mut self) {
        self.resume();
        let _ = super::flush_json();
        PRIVATE.with(|private| private.set(None));
    }
}
