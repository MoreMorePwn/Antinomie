// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's Relationships box: a graph of the processes, files,
//! endpoints and injected-into processes of the run, in a Compact and a Full
//! view, built from the scan (see `model`).
pub(super) mod canvas;
pub(super) mod chart;
pub(super) mod facts;
pub(super) mod fold;
pub(super) mod group;
pub(super) mod layout;
pub(super) mod model;
pub(super) mod ui;
pub(super) mod window;
