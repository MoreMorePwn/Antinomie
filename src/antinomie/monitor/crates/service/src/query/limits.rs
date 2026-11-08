// SPDX-License-Identifier: GPL-3.0-only
//! The limits of 5.12.5 and 5.12.6 as one settings value: row and byte limits,
//! the two pools' sizes and the deadlines (`service.toml [query]`).

use super::catalogue::QueryLimits;
use std::time::Duration;

/// A page is cut before its encoded size would pass this (1 MiB); fewer rows,
/// never a truncated row.
pub const PAGE_BYTES: usize = 1 << 20;

/// Settings of the read side. The defaults are the contract's.
#[derive(Clone, Debug)]
pub struct QuerySettings {
    /// `capabilities.queries.limits`.
    pub limits: QueryLimits,
    /// Deadline of a light read.
    pub light_timeout: Duration,
    /// Deadline of a heavy read page.
    pub heavy_timeout: Duration,
    /// What `retry_after_s` says when the heavy pool is full.
    pub heavy_retry_after_s: u64,
}

impl Default for QuerySettings {
    fn default() -> Self {
        Self {
            limits: QueryLimits::default(),
            light_timeout: Duration::from_secs(10),
            heavy_timeout: Duration::from_secs(60),
            heavy_retry_after_s: 2,
        }
    }
}

impl QuerySettings {
    /// Rows per page: `(default, max)` for a row page.
    pub fn rows(&self) -> (u32, u32) {
        (self.limits.row.default, self.limits.row.max)
    }
}

/// How many leading items of `sizes` fit in [`PAGE_BYTES`]; at least one when
/// there is one, because a single row is bounded by the engine's previews.
pub fn fit_in_page(sizes: impl IntoIterator<Item = usize>) -> usize {
    let mut total = 0usize;
    let mut kept = 0usize;
    for size in sizes {
        if kept > 0 && total.saturating_add(size) > PAGE_BYTES {
            break;
        }
        total = total.saturating_add(size);
        kept += 1;
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_keeps_whole_rows_under_one_mebibyte() {
        assert_eq!(fit_in_page([]), 0);
        assert_eq!(fit_in_page([10, 10, 10]), 3);
        assert_eq!(fit_in_page([600_000, 600_000, 1]), 1);
        assert_eq!(fit_in_page([PAGE_BYTES * 2, 1]), 1, "one row always goes");
        assert_eq!(fit_in_page([PAGE_BYTES - 1, 1, 1]), 2);
    }
}
