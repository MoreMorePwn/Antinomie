// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's Relationships box: a graph of the processes, files,
//! endpoints and injected-into processes of the run, in a Compact and a Full
//! view, built from the scan (see `model`).
pub(super) mod canvas;
pub(super) mod chart;
pub(super) mod fold;
// The facts and the graph are in `antinomie_triage::summary::relations`.
pub(super) use antinomie_triage::summary::relations::{facts, model};
pub(super) mod group;
pub(super) mod layout;
pub(super) mod ui;
pub(super) mod window;
