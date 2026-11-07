// SPDX-License-Identifier: GPL-3.0-only
//! The earlier-bytes copier, hosted by every binary that records VM runs.
//!
//! When a boot ends, the core re-runs the running program with
//! `--copy-earlier-bytes` to copy the earlier bytes of the files the boot's
//! runs changed into the recording (the Triage scan reads the trace, so the
//! copy is its work). A binary serves that role with [`host_copier`] first
//! thing in `main`, next to the analysis worker roles.
use antinomie_monitor_core::file_before_store;

/// Serve the copy role if this process was started for it (returns the exit
/// code to exit with), else register this program as the one the core runs
/// for it and return `None`.
pub fn host_copier() -> Option<i32> {
    if let Some(code) = file_before_store::worker_main_if_requested(copy_boot) {
        return Some(code);
    }
    file_before_store::register_copier_host();
    None
}

pub use crate::file_activity::earlier::copy_boot;
