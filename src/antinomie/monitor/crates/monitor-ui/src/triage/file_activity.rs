// SPDX-License-Identifier: GPL-3.0-only
//! The File activity window: the history of every file a run touched. The
//! model is in `antinomie_triage::file_activity`.
#[cfg(test)]
use super::*;

mod graph;
mod overview;
mod reconstruct;
mod window;

pub(super) use antinomie_triage::file_activity::earlier;
pub(super) use antinomie_triage::file_activity::*;

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
