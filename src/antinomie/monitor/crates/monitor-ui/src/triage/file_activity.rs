// SPDX-License-Identifier: GPL-3.0-only
//! The File activity window: the history of every file a run touched. The
//! model is in `antinomie_triage::file_activity`.
use super::file_category::{Category, Hit};
use super::files::result_label;
use super::*;
use antinomie_monitor_core::file_reconstruct::{Action, Step, Timeline};
use antinomie_monitor_core::file_writes::{
    Budget, Captured, Extent, Gap, Limits, Piece, Tally, Writes,
};
use antinomie_monitor_core::kernel_notes::{
    FileHash, FileId, FileKey, FileMapped, MappedCause, MappedCut,
};
use std::collections::BTreeMap;

mod graph;
mod overview;
mod reconstruct;
mod window;

pub(super) use antinomie_triage::file_activity::*;
pub(super) use antinomie_triage::file_activity::earlier;

pub(super) use reconstruct::{
    menu as reconstruct_menu, start_of, DATA_DIR as RECONSTRUCT_DATA_DIR, HISTORY_REQUEST,
    REQUEST as RECONSTRUCT_REQUEST,
};
pub(super) use window::{Window, CALLS_TABLE, FILE_TABLE};

#[cfg(test)]
mod overview_tests;
#[cfg(test)]
pub(super) mod reconstruct_tests;
#[cfg(test)]
pub(super) mod tests;
