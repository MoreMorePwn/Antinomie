// SPDX-License-Identifier: GPL-3.0-only
//! Lanes (design 4.5, 4.7.3, 4.8): the state file of a lane, the checks that
//! decide whether it can take a job, and recovery after a crash. The stages
//! themselves are cards P3-4b and P3-4c; they build on [`state`] for their
//! checkpoints and on [`crate::engine::Engine`] for the engine.
pub mod check;
pub mod process;
pub mod recover;
pub mod reset;
pub mod state;
#[cfg(test)]
pub(crate) mod tests;

pub use check::{LaneProblem, check_lane, layer_pending};
pub use process::{ProcFs, Processes};
pub use recover::{
    FileState, LaneRecovery, QemuOutcome, RecoverError, RecoverOptions, StartupRecovery,
    recover_startup,
};
pub use reset::{Cleared, ResetRefused, clear_for_reset};
pub use state::{
    Checkpoint, Collected, LANE_FILE_VERSION, LaneDir, LaneFile, LaneStateError, LaneWork,
    QUARANTINE_AFTER, QemuRecord, Quarantine, WriteFault,
};
