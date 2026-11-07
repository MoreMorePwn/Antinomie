// SPDX-License-Identifier: GPL-3.0-only
//! The read-only recording query API: `QueryApi` and its types (design 5.12).

/// `capabilities.queries` (design 5.12.4a).
pub mod catalogue;
/// Opaque paging cursors and generations (5.12.5).
pub mod cursor;
/// `RunKey`, the opaque address of a run (5.12.1).
pub mod key;
/// The table every operation is defined by; the catalogue is generated from it.
pub mod ops;
/// `Page<T>`, `Single<T>` and `PageRequest` (5.12.1).
pub mod page;
/// The request of each operation and `RecordingRead` (5.12.3, 5.12.4).
pub mod request;
/// The result objects of 5.12.3.
pub mod types;
