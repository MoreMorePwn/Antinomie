// SPDX-License-Identifier: GPL-3.0-only
//! The job API: the objects, events, operations and errors of design section 5
//! (contract for ANT-T0192). The Docker web UI and the HTTP API expose exactly
//! these; if the two documents disagree, section 5 wins. The Rust traits
//! (`JobApi`, `QueryApi`) are added by the cards that implement them.

pub mod artifact;
pub mod assessment;
pub mod error;
pub mod event;
pub mod failure;
pub mod ids;
pub mod job;
pub mod ops;
pub mod spec;
pub mod status;

pub use error::{ApiError, ErrorCode, ErrorReason};
pub use event::{Event, EventBody, Frame};
pub use failure::{Failure, FailureCode};
pub use ids::{ArtifactId, JobId, LaneId, Sha256Hex, UploadId};
pub use job::{Job, JobState, Stage};
pub use spec::JobSpec;
