// SPDX-License-Identifier: GPL-3.0-only
//! The service layer of headless mode: config and policy loading, the job
//! store, lanes, the pipeline, the event log and the shared job and query API
//! that the CLI, the local socket and the web process call (design 2.1, 2.8).
//!
//! This crate must stay UI-free: it never depends on egui, eframe, winit or
//! `antinomie-monitor-ui` (checked by `crates/cli/tests/dependency_tree.rs`).
//! It is a skeleton; later cards fill the modules below.

// `ApiError` is the contract's error type and the design's trait signatures
// return it by value (`Result<_, ApiError>`, design 2.8, 5.12.1); it carries
// its `details` map, so it is larger than clippy likes.
#![allow(clippy::result_large_err)]

/// The version of the job and query contract (`"api_version"` in every CLI
/// and socket reply, design 3.2 and 5.2).
pub const API_VERSION: u32 = 1;

/// `JobApi`, the job objects, events and errors (cards P3-1 and later).
pub mod api;
/// Time and ids behind small seams.
pub mod clock;
/// `service.toml`, `policies/*.toml` and `config validate` (card P3-3).
pub mod config;
/// Custody actors and the `automation` entry of a job (card P3-7).
pub mod custody;
/// The seam to the engine, and the fake behind it (design 7.1).
pub mod engine;
/// Staging, uploads and the common intake checks (card P3-2b).
pub mod intake;
/// Lanes: the state file, the checks and recovery (card P3-4a).
pub mod lane;
/// `QueryApi`, the read-only recording queries (cards Q-1 and later).
pub mod query;
/// The JSON Schema generated from the types above.
pub mod schema;
/// The lane stages `prechecks` to `collect`, retries and the watchdog (cards P3-4b, P3-4c).
pub mod stages;
/// The job store: SQLite, the state machine and the queue (card P3-2).
pub mod store;
/// The assessment and the label, and the policy's verdict rules (card P3-5).
pub mod verdict;
/// The engine waiter: commands, results and the waits a headless caller needs.
pub mod waiter;
/// The watchdog of a lane job (design 4.7.1).
pub mod watchdog;
