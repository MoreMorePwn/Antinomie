// SPDX-License-Identifier: GPL-3.0-only
//! The bookkeeping of `auto lane reset` (design 3.4.4, decided with card
//! P3-4b): before the lane's revert is redone, the count of start failures and
//! the recorded QEMU process are cleared, but **only after confirming that
//! the recorded QEMU is gone** with the same test recovery uses (the pid, its
//! start time and its command line). A QEMU that is still the lane VM's
//! refuses the reset and changes nothing. The quarantine flag is not touched
//! here: it is cleared by [`LaneFile::unquarantine`] once the revert worked.
//!
//! [`LaneFile::unquarantine`]: super::state::LaneFile::unquarantine
use super::{
    process::{Processes, is_recorded_qemu},
    state::{LaneDir, LaneStateError},
};
use crate::api::ids::LaneId;

/// What was cleared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cleared {
    /// The recorded pid, if there was one.
    pub qemu: Option<u32>,
    /// The failure count before.
    pub failures: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ResetRefused {
    /// The lane's QEMU still runs; stop the VM first.
    #[error("the lane VM's QEMU process {0} is still running")]
    QemuAlive(u32),
    #[error("{0}")]
    State(#[from] LaneStateError),
}

/// Clear `failures` and the recorded `qemu` of `lane`, if its QEMU is gone.
pub fn clear_for_reset(
    lanes: &LaneDir,
    lane: &LaneId,
    procs: &dyn Processes,
    now_ms: u64,
) -> Result<Cleared, ResetRefused> {
    let file = lanes
        .load(lane)?
        .ok_or_else(|| LaneStateError::Missing(lane.clone()))?;
    if let Some(record) = &file.qemu
        && let Some(info) = procs.info(record.pid)
        && is_recorded_qemu(record, &info)
    {
        return Err(ResetRefused::QemuAlive(record.pid));
    }
    lanes
        .update(lane, |file| {
            let cleared = Cleared {
                qemu: file.qemu.as_ref().map(|q| q.pid),
                failures: file.failures,
            };
            file.failures = 0;
            file.clear_qemu(now_ms);
            cleared
        })
        .map_err(ResetRefused::from)
}
