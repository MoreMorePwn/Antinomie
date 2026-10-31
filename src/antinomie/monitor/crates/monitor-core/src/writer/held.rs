// SPDX-License-Identifier: GPL-3.0-only
//! Test control of the recording writer. [`SlowWriter`] gives the calling
//! thread a writer of its own that can be stopped, as a disk that stops
//! answering would stop the real one, without holding up the tests that run
//! beside it.
use super::{Writer, start_with_limit};
use std::{cell::Cell, sync::atomic::Ordering};

thread_local! {
    static PRIVATE: Cell<Option<&'static Writer>> = const { Cell::new(None) };
}

pub(super) fn private_writer() -> Option<&'static Writer> {
    PRIVATE.with(Cell::get)
}

/// Make a thread started from here use the same private writer.
pub(crate) fn inherit() -> impl FnOnce() + Send + 'static {
    let writer = private_writer();
    move || PRIVATE.with(|private| private.set(writer))
}

/// A private writer for this thread while it lives. The writer thread it
/// starts stays blocked on its queue for the rest of the test run.
pub(crate) struct SlowWriter(&'static Writer);

impl SlowWriter {
    pub(crate) fn install() -> Self {
        Self::install_with_limit(super::QUEUE_LIMIT)
    }
    pub(crate) fn install_with_limit(limit: usize) -> Self {
        let writer = start_with_limit("antinomie-test-writer", limit);
        PRIVATE.with(|private| private.set(Some(writer)));
        Self(writer)
    }
    /// Stop writing: queued and new writes wait for [`Self::resume`].
    pub(crate) fn pause(&self) {
        self.0.paused.store(true, Ordering::Release);
    }
    pub(crate) fn resume(&self) {
        self.0.paused.store(false, Ordering::Release);
        let _state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        self.0.changed.notify_all();
    }
    /// Writes queued and not yet written.
    pub(crate) fn queued_len(&self) -> usize {
        self.0
            .state
            .lock()
            .map(|state| state.bytes)
            .unwrap_or_default()
    }
}

impl Drop for SlowWriter {
    fn drop(&mut self) {
        self.resume();
        super::barrier();
        PRIVATE.with(|private| private.set(None));
    }
}
