// SPDX-License-Identifier: MIT
//! Admission credits bound command results until the frontend consumes them.
use super::*;

/// Must equal the reliable completion channel capacity.
pub(super) const COMMAND_COMPLETION_CAPACITY: usize = 1024;

#[derive(Default)]
pub(super) struct CompletionCredits {
    in_use: AtomicUsize,
}

impl CompletionCredits {
    pub(super) fn reserve(&self) -> bool {
        self.in_use
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |in_use| {
                if in_use < COMMAND_COMPLETION_CAPACITY {
                    Some(in_use + 1)
                } else {
                    None
                }
            })
            .is_ok()
    }

    pub(super) fn release(&self) -> bool {
        self.in_use
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |in_use| {
                in_use.checked_sub(1)
            })
            .is_ok()
    }

    #[cfg(test)]
    pub(super) fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Acquire)
    }
}
