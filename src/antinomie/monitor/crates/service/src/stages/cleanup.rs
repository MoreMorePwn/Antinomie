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
//! (`layer_s`, 1800 s). While the disk is below its floor that wait ends after
//! [`LOW_DISK_SETTLE`] with the VM stopped ([`Stopped::Deferred`]): the engine
//! cannot finish a recording on a full disk, and a lane that waited the whole
//! `layer_s` for it would hang the job and the daemon's stop (ANT-T0475). The
//! layer stays pending, so the lane takes no job until the engine has finished
//! it.
use super::{LaneStages, StageStop, collect_parts::CollectClock};
use crate::{
    api::run::{Outcome, Run, RunState},
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
    /// Stopped, but the recording or its disk layer could not be finished
    /// because the disk is below its floor: the words of the floor.
    Deferred(String),
}

/// How long the settle wait goes on while the disk is below its floor.
pub const LOW_DISK_SETTLE: Duration = Duration::from_secs(60);
/// How often the floor is looked at during the settle wait.
const SETTLE_LOOK: Duration = Duration::from_secs(5);
/// How often a timed settle wait reads the snapshot (`run.collect`).
const SETTLE_TICK: Duration = Duration::from_millis(250);

impl<E: Engine> LaneStages<'_, E> {
    /// Stop the lane VM if the engine runs it and wait until the recording is
    /// final. `stop_limit` bounds the answer to `Stop`.
    pub(crate) fn stop_lane_vm(
        &mut self,
        job: &Run,
        vm: &str,
        stop_limit: Duration,
    ) -> Result<Stopped, StageStop> {
        self.stop_lane_vm_with(job, vm, stop_limit, false)
    }

    /// [`stop_lane_vm`](Self::stop_lane_vm) for `collect`: with `end_cancel`
    /// a person's cancel that comes in while the recording settles ends the
    /// job `cancelled` at once (A37); the lane still waits for the recording.
    pub(crate) fn stop_lane_vm_with(
        &mut self,
        job: &Run,
        vm: &str,
        stop_limit: Duration,
        end_cancel: bool,
    ) -> Result<Stopped, StageStop> {
        self.stop_lane_vm_timed(job, vm, stop_limit, end_cancel, None)
    }

    /// [`stop_lane_vm_with`](Self::stop_lane_vm_with) that notes in `clock`
    /// when the VM stopped, the recording was saved and the layer settled.
    pub(crate) fn stop_lane_vm_timed(
        &mut self,
        job: &Run,
        vm: &str,
        stop_limit: Duration,
        end_cancel: bool,
        mut clock: Option<&mut CollectClock>,
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
            self.progress(job, crate::api::run::Stage::Collect, "stopping the VM");
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
        self.settle_recording(vm, end_cancel.then_some(job), clock.as_deref_mut())
    }

    /// Wait until the VM is stopped and its recording final (`layer_s`), or
    /// until the disk has been below its floor for [`LOW_DISK_SETTLE`].
    fn settle_recording(
        &mut self,
        vm: &str,
        cancel_ends: Option<&Run>,
        mut clock: Option<&mut CollectClock>,
    ) -> Result<Stopped, StageStop> {
        let what = "the recording to settle after the stop";
        let deadline = self.waiter.now_ms() + crate::waiter::millis(SETTLE_WAIT);
        let mut low_since: Option<u64> = None;
        // Timed waits look every `SETTLE_TICK`; the floor still every
        // `SETTLE_LOOK`.
        let tick = if clock.is_some() {
            SETTLE_TICK
        } else {
            SETTLE_LOOK
        };
        let mut next_look = self.waiter.now_ms() + crate::waiter::millis(SETTLE_LOOK);
        loop {
            if let Some(job) = cancel_ends {
                self.end_cancel_early(job);
            }
            let left = deadline.saturating_sub(self.waiter.now_ms());
            let slice = Duration::from_millis(left).min(tick);
            let waited = self
                .waiter
                .wait_until(what, Some(slice), |s| settled_after_stop(s, vm));
            if let Some(clock) = clock.as_deref_mut() {
                clock
                    .settle
                    .see(self.waiter.now_ms(), self.waiter.snapshot(), vm);
            }
            match waited {
                Ok(()) => return Ok(Stopped::Settled),
                Err(WaitError::TimedOut { what }) => {
                    let now = self.waiter.now_ms();
                    if now >= deadline {
                        return Ok(Stopped::Unsettled(format!("timed out waiting for {what}")));
                    }
                    if now < next_look {
                        continue;
                    }
                    next_look = now + crate::waiter::millis(SETTLE_LOOK);
                    let Some(words) = self.env.host.low_disk() else {
                        low_since = None;
                        continue;
                    };
                    let since = *low_since.get_or_insert(now);
                    if self.waiter.snapshot().state == VmState::Stopped
                        && now.saturating_sub(since) >= crate::waiter::millis(LOW_DISK_SETTLE)
                    {
                        return Ok(Stopped::Deferred(words));
                    }
                }
                Err(other) => return Err(StageStop::Abort(other)),
            }
        }
    }

    /// A person's cancel of a job whose lane is still stopping the VM and
    /// saving the recording (A37): the job ends `cancelled` now, with its
    /// finish time and outcome, instead of staying `cancelling` for as long
    /// as a big recording takes to save. The lane keeps the job's VM until
    /// the recording is final, so no other job starts on it before. A cancel
    /// for the daemon's shutdown is left alone (that job goes back to the
    /// queue). `true` when the job has ended `cancelled`.
    pub(crate) fn end_cancel_early(&self, job: &Run) -> bool {
        let store = self.env.store;
        let Ok(current) = store.get(&job.id) else {
            return false;
        };
        match current.state {
            RunState::Cancelled => true,
            RunState::Cancelling if !store.cancel_is_shutdown(&job.id).unwrap_or(true) => store
                .finish(&job.id, Outcome::Cancelled, None)
                .is_ok_and(|ended| ended.state == RunState::Cancelled),
            _ => false,
        }
    }

    /// The hard path: kill the recorded QEMU if it is still the one we
    /// started, then let the engine notice. Returns what happened, in words.
    pub(crate) fn hard_stop(&mut self, job: &Run) -> Result<String, StageStop> {
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
