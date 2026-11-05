// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's Relationships box: a graph of the processes, files,
//! endpoints and injected-into processes of the run, and a Timeline of the
//! same, both built from the scan (see `model`).
pub(super) mod canvas;
pub(super) mod chart;
pub(super) mod facts;
pub(super) mod model;
pub(super) mod timeline;
pub(super) mod timeline_view;
pub(super) mod ui;
