// SPDX-License-Identifier: GPL-3.0-only
//! Leaving the VM stopped and its recording final, whatever happened: the
//! ending of `collect`, and the cleanup after a failed, cancelled or
//! watchdog-stopped stage (design 4.1 "Cancellation", 4.7.3).
//!
//! `Stop` is asked first and given `stop_s` (120 s). A stop the engine does
//! not answer is the **hard path**: the QEMU process recorded in the lane file
//! is killed, but only after its `/proc/<pid>/cmdline` and start time still
//! match the record (the same test recovery uses), and the engine is given
//! 30 s to notice. Then the recording and the disk layer are waited for
//! (`layer_s`, 1800 s).
use super::{LaneStages, StageStop};
use crate::{
    api::job::Job,
    engine::Engine,
    lane::process::is_recorded_qemu,
    waiter::{SETTLE_WAIT, WaitError, settled_after_stop},
    watchdog::HARD_PATH_WAIT,
};
use antinomie_monitor_core::{Command, VmState};
use std::time::Duration;

/// How the VM was left.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stopped {
    /// Stopped, recording flushed, no disk layer pending.
    Settled,
    /// `Stop` was not answered; the recorded QEMU was killed (or could not be).
    Killed(String),
    /// Stopped but not settled, or the engine refused: the reason.
    Unsettled(String),
}

impl<E: Engine> LaneStages<'_, E> {
    /// Stop the lane VM if the engine runs it and wait until the recording is
    /// final. `stop_limit` bounds the answer to `Stop`.
    pub(crate) fn stop_lane_vm(
        &mut self,
        job: &Job,
        vm: &str,
        stop_limit: Duration,
    ) -> Result<Stopped, StageStop> {
        self.waiter.drain()?;
        let snapshot = self.waiter.snapshot();
        if snapshot
            .active_vm
            .as_deref()
            .is_some_and(|active| active != vm)
        {
            // Another VM is not ours to stop.
            return Ok(Stopped::Unsettled("another VM is running".into()));
        }
        if snapshot.state != VmState::Stopped {
            self.progress(job, crate::api::job::Stage::Collect, "stopping the VM");
            match self.waiter.command(Command::Stop, Some(stop_limit)) {
                Ok(_) => {}
                Err(WaitError::TimedOut { .. }) => {
                    let how = self.hard_stop(job)?;
                    return Ok(Stopped::Killed(how));
                }
                Err(WaitError::Failed(message)) => {
                    self.waiter.drain()?;
                    if self.waiter.snapshot().state != VmState::Stopped {
                        return Ok(Stopped::Unsettled(format!(
                            "the VM did not stop cleanly: {message}"
                        )));
                    }
                }
                Err(other) => return Err(StageStop::Abort(other)),
            }
        }
        let id = vm.to_owned();
        match self.waiter.wait_until(
            "the recording to settle after the stop",
            Some(SETTLE_WAIT),
            move |s| settled_after_stop(s, &id),
        ) {
            Ok(()) => Ok(Stopped::Settled),
            Err(WaitError::TimedOut { what }) => {
                Ok(Stopped::Unsettled(format!("timed out waiting for {what}")))
            }
            Err(other) => Err(StageStop::Abort(other)),
        }
    }

    /// The hard path: kill the recorded QEMU if it is still the one we
    /// started, then let the engine notice. Returns what happened, in words.
    pub(crate) fn hard_stop(&mut self, job: &Job) -> Result<String, StageStop> {
        let record = self.lane_file()?.qemu;
        let how = match record {
            None => "no QEMU process is recorded; nothing was killed".to_owned(),
            Some(record) => match self.env.procs.info(record.pid) {
                None => "the recorded QEMU is already gone".to_owned(),
                Some(info) if is_recorded_qemu(&record, &info) => {
                    match self.env.procs.kill(record.pid) {
                        Ok(()) => format!("the recorded QEMU (pid {}) was killed", record.pid),
                        Err(error) => format!("killing pid {} failed: {error}", record.pid),
                    }
                }
                Some(_) => "the recorded pid belongs to another process; left alone".to_owned(),
            },
        };
        self.warn(job, "vm_hard_stop", &how);
        // Let the engine see the process end.
        let _ = self.waiter.wait_until(
            "the engine to notice the VM ended",
            Some(HARD_PATH_WAIT),
            |s| {
                !matches!(
                    s.state,
                    VmState::Running | VmState::Starting | VmState::Stopping
                )
            },
        );
        Ok(how)
    }
}
