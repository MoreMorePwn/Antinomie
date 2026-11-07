// SPDX-License-Identifier: GPL-3.0-only
//! The activity graph: the Suspicious activity findings on process swimlanes
//! against time, with the severity curve, the category heat strip and the
//! phases of the run.
//!
//! The scan worker builds a [`GraphIndex`] from the same rows the Suspicious
//! table filters, so the graph shows exactly the table's set. The widget in
//! [`widget`] is custom-painted and returns [`Action`]s; this module applies
//! them to the Triage view (selection, Details, the shared filter and chips).
use super::*;

mod input;
mod legend;
mod mermaid;
mod watch;
mod paint;
mod ruler;
mod strip;
mod tab;
mod view;
mod widget;
mod window;

/// The icon the graph draws for a finding category.
pub(super) fn category_icon(category: rules::Category) -> &'static str {
    paint::icon(category.index() as u8)
}

#[cfg(test)]
mod bench;
#[cfg(test)]
mod fill_tests;
#[cfg(test)]
mod spacing_tests;
#[cfg(test)]
mod sync_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod window_tests;

pub(crate) use antinomie_triage::graph::Spacing;
use antinomie_triage::graph::{axis, filter, index, lanes, notify, phases};
pub(super) use antinomie_triage::graph::{Builder, Collector, GraphIndex, GraphScan, HighRule, Lanes};
pub(super) use strip::Strip;
pub(super) use view::State;
pub(super) use watch::HighWatch;
pub(super) use window::{Window, DEFAULT_SIZE};
