// SPDX-License-Identifier: GPL-3.0-only
//! The service layer of headless mode: config and policy loading, the job
//! store, lanes, the pipeline, the event log and the shared job and query API
//! that the CLI, the local socket and the web process call (design 2.1, 2.8).
//!
//! This crate must stay UI-free: it never depends on egui, eframe, winit or
//! `antinomie-monitor-ui` (checked by `crates/cli/tests/dependency_tree.rs`).
//! It is a skeleton; later cards fill the modules below.

/// The version of the job and query contract (`"api_version"` in every CLI
/// and socket reply, design 3.2 and 5.2).
pub const API_VERSION: u32 = 1;

/// `JobApi`, the job objects, events and errors (cards P3-1 and later).
pub mod api;
/// `QueryApi`, the read-only recording queries (cards Q-1 and later).
pub mod query;
