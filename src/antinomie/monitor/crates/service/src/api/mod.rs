// SPDX-License-Identifier: GPL-3.0-only
//! The run API (`docs/run-api-1.md`): the objects, events, operations and
//! errors the local socket serves and the web binding will expose. A run is
//! one analysis of one sample; "job" is left for work the engine still has to
//! do (the store's tables, the host work pool).

pub mod artifact;
pub mod assessment;
pub mod error;
pub mod event;
pub mod failure;
pub mod ids;
pub mod ops;
pub mod run;
pub mod spec;
pub mod status;

pub use error::{ApiError, ErrorCode, ErrorReason};
pub use event::{Event, EventBody, Frame};
pub use failure::{Failure, FailureCode};
pub use ids::{ArtifactId, LaneId, RunId, Sha256Hex, UploadId};
pub use run::{Run, RunState, Stage};
pub use spec::RunRequest;
