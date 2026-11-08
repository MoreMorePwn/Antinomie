// SPDX-License-Identifier: GPL-3.0-only
//! The read-only recording query API: `QueryApi` and its types (design 5.12).

/// Operations on one run's analysis report (cards Q-2).
pub mod analysis;
/// The files, captures and cores a run kept (Q-2).
pub mod artifacts;
/// `capabilities.queries` (design 5.12.4a).
pub mod catalogue;
/// `ReadContext`: caller, cancel flag, deadline (Q-3).
pub mod context;
/// Engine call records as API objects (Q-2).
pub mod convert;
/// Opaque paging cursors and generations (5.12.5).
pub mod cursor;
/// Custody entries (Q-2).
pub mod custody;
/// Mapping of engine errors (5.12.8).
pub mod errors;
/// The Files tables of the Triage scan (Q-4).
pub mod files;
/// The `generation` of a recording (5.12.2).
pub mod generation;
/// `RunKey`, the opaque address of a run (5.12.1).
pub mod key;
/// Row and byte limits, deadlines (5.12.5, 5.12.6).
pub mod limits;
/// The Network tabs of the Triage scan (Q-4).
pub mod network;
/// The table every operation is defined by; the catalogue is generated from it.
pub mod ops;
/// Packet reads through the packet filter worker (Q-5).
pub mod packets;
/// `Page<T>`, `Single<T>` and `PageRequest` (5.12.1).
pub mod page;
/// The recording phase: live, finalizing, complete, interrupted (5.12.2, Q-3).
pub mod phase;
/// The light and heavy read pools, deadlines and leases (5.12.6, Q-3).
pub mod pool;
/// The observed process tree (Q-2).
pub mod process;
/// The request of each operation and `RecordingRead` (5.12.3, 5.12.4).
pub mod request;
/// Run list and run detail (Q-2).
pub mod runs;
/// The Triage scan a class T read needs, built in the background (Q-4).
pub mod scan;
/// Host paths removed from replies (5.12.7).
pub mod scrub;
/// `QueryApi` and `QueryService`.
pub mod service;
/// Filter, sort and page over Triage tables (Q-4).
pub mod tables;
/// The terminal transcript (Q-2).
pub mod terminal;
/// The merged timeline (Q-4).
pub mod timeline;
/// Trace pages, calls and captured bytes (Q-2).
pub mod trace;
/// The summary, findings and indicators of the Triage scan (Q-4).
pub mod triage;
/// The result objects of 5.12.3.
pub mod types;

pub use context::ReadContext;
pub use service::{JobIndex, QueryApi, QueryService};

#[cfg(test)]
mod packet_tests;
#[cfg(test)]
mod read_tests;
#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod triage_tests;
