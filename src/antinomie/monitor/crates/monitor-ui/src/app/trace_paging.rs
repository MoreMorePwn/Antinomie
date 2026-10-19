// SPDX-License-Identifier: MIT
//! Persisted syscall page size and cursor invalidation.
use super::*;

pub(super) fn deserialize_page_size<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<usize, D::Error> {
    usize::deserialize(deserializer).map(|size| size.clamp(1, 256))
}

impl MonitorApp {
    pub(super) fn set_trace_page_size(&mut self, size: usize) {
        let size = size.clamp(1, 256);
        if self.settings.trace_page_size == size {
            return;
        }
        self.settings.trace_page_size = size;
        // Cursors describe the old page boundaries, not call numbers. Restart
        // the same filtered view and let the reply retain selection by identity.
        self.archive_previous.clear();
        self.archive_next = None;
        self.archive_offset = 0;
        self.request_page(0);
    }
}
