// SPDX-License-Identifier: MIT
//! Recording storage health and the decision to stop saving.
use super::*;
use crate::quota::QuotaState;

impl Session {
    pub(super) fn stored_len(&self) -> u64 {
        self.capture
            .bytes
            .saturating_add(self.assembler.stored_len())
            .saturating_add(self.runs.values().map(ProgramRun::stored_len).sum::<u64>())
            .saturating_add(self.analysis.stored_len())
            .saturating_add(
                self.captures
                    .values()
                    .map(CaptureSession::stored_len)
                    .sum::<u64>(),
            )
            .saturating_add(self.network_bytes)
            .saturating_add(self.core_stored_len)
            .saturating_add(self.core_reserved_len)
    }
    pub(super) fn available(&self) -> u64 {
        self.capture.quota().saturating_sub(self.stored_len())
    }
    pub(super) fn refresh_storage_health(&self, health: &mut Health) {
        refresh_storage_health(
            health,
            &self.capture,
            self.assembler
                .stored_len()
                .saturating_add(self.analysis.persisted_len()),
            &self.runs,
        );
        health.persisted_len = health
            .persisted_len
            .saturating_add(
                self.captures
                    .values()
                    .map(CaptureSession::stored_len)
                    .sum::<u64>(),
            )
            .saturating_add(self.network_bytes);
        health.persisted_len = health.persisted_len.saturating_add(self.core_stored_len);
        health.persistence_error = health.persistence_error.clone().or_else(|| {
            self.captures
                .values()
                .find_map(|capture| capture.summary.recording_error.clone())
        });
    }
    /// Stop saving new data for the boot. Recordings that are already complete
    /// (programs that ended, closed captures) keep their final state.
    pub(super) fn stop_saving(&mut self, error: String) {
        Sinks {
            capture: &mut self.capture,
            assembler: &mut self.assembler,
            runs: &mut self.runs,
            captures: &mut self.captures,
        }
        .stop_saving(error);
    }
    /// The recording quota is exhausted by a packet owned by `root` (0 when no run
    /// owns it); see [`Sinks::quota_reached`].
    pub(super) fn quota_reached(&mut self, root: u64) {
        let quota_size = self.capture.quota();
        Sinks {
            capture: &mut self.capture,
            assembler: &mut self.assembler,
            runs: &mut self.runs,
            captures: &mut self.captures,
        }
        .quota_reached(&mut self.quota, quota_size, root);
    }
    /// Stop saving when an object store or a capture archive reports a failure.
    /// A failed observing capture stops the boot (its packets are the ones no
    /// other archive keeps); a finalized capture's old error does not.
    pub(super) fn propagate_saving_failures(&mut self, root: u64) {
        let object_error = object_saving_error(&mut self.assembler, &mut self.runs);
        let capture_error = self
            .captures
            .values()
            .filter(|capture| capture.summary.state != CaptureState::Finalized)
            .find_map(|capture| capture.summary.recording_error.clone());
        // Unknown command outcomes are status, not persistence failures.
        if let Some(error) = object_error.or(capture_error) {
            self.saving_refused(root, error);
        }
    }
    /// Route a refusal to save: the quota is a boot-wide condition of its own,
    /// anything else stops saving as before.
    pub(super) fn saving_refused(&mut self, root: u64, error: String) {
        if crate::quota::is_quota_error(&error) {
            self.quota_reached(root);
        } else {
            self.stop_saving(error);
        }
    }
}

/// Everything a boot records into, borrowed together to stop it saving.
pub(super) struct Sinks<'a> {
    pub capture: &'a mut RawCapture,
    pub assembler: &'a mut Assembler,
    pub runs: &'a mut BTreeMap<u64, ProgramRun>,
    pub captures: &'a mut BTreeMap<String, CaptureSession>,
}

impl Sinks<'_> {
    pub(super) fn stop_saving(&mut self, error: String) {
        stop_capture_saving(self.capture, self.assembler, self.runs, error.clone());
        for capture in self.captures.values_mut() {
            if capture.summary.state != CaptureState::Finalized {
                capture.storage_error(error.clone());
            }
        }
    }
    /// The first time, the boot stops saving new data with one clear message
    /// (see [`crate::quota`]); recordings that were already complete are left
    /// exactly as they are. A later packet of such a run is only noted on it.
    pub(super) fn quota_reached(&mut self, state: &mut QuotaState, quota_size: u64, root: u64) {
        if state.reached.is_none() {
            let message = crate::quota::message(quota_size);
            self.stop_saving(message.clone());
            state.reached = Some(message);
        }
        if let Some(run) = self.runs.get_mut(&root)
            && run.recording_complete()
        {
            run.add_note(
                "telemetry that arrived after the recording quota was reached was not saved",
            );
        }
    }
}

/// True when an observing capture, not the boot's unassigned archive, keeps a
/// packet nobody else owns: a packet is saved once, not once per archive.
pub(super) fn held_by_capture(owned_by_run: bool, observer: Option<&CaptureSession>) -> bool {
    !owned_by_run && observer.is_some_and(CaptureSession::can_save)
}

/// What a failed terminal write of one run means for the boot.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum TerminalFailure {
    /// Only this run stops saving; the cause is its first recorded error.
    RunOnly(String),
    /// The shared quota is exhausted, which stops every open recording.
    Quota(String),
}

/// Stop saving for `run` after its terminal write failed with `error`. The
/// run's first recorded error stays its cause: a later "already stopped" never
/// replaces it.
pub(super) fn terminal_failure(run: &mut ProgramRun, error: String) -> TerminalFailure {
    run.storage_error(error.clone());
    let cause = run.summary.recording_error.clone().unwrap_or(error);
    if crate::quota::is_quota_error(&cause) {
        TerminalFailure::Quota(cause)
    } else {
        TerminalFailure::RunOnly(cause)
    }
}

/// Save a packet no run owns in the boot's unassigned archive, unless an
/// observing capture keeps it (`held`). True when this archive stored it.
/// The assembler is told how much of the shared quota is left either way.
pub(super) fn save_unowned(
    capture: &mut RawCapture,
    assembler: &mut Assembler,
    held: bool,
    packet: &[u8],
    reserved: u64,
) -> bool {
    let stored =
        !held && capture.append_with_reserved(packet, reserved.saturating_sub(capture.bytes));
    if !held && !stored {
        assembler.stop_saving();
    }
    let used = reserved + if stored { packet.len() as u64 + 4 } else { 0 };
    assembler.set_storage_limit(
        assembler
            .stored_len()
            .saturating_add(capture.quota().saturating_sub(used)),
    );
    stored
}

pub(super) fn stop_capture_saving(
    capture: &mut RawCapture,
    assembler: &mut Assembler,
    runs: &mut BTreeMap<u64, ProgramRun>,
    error: String,
) {
    capture.error.get_or_insert(error.clone());
    assembler.stop_saving();
    for run in runs.values_mut() {
        // A run whose program ended and whose terminal closed is complete; a
        // later failure of the boot is not a failure of that run.
        if !run.recording_complete() {
            run.capture.error.get_or_insert(error.clone());
            run.storage_error(error.clone());
        }
    }
}

/// The first object-store failure of the boot's own assembler or of any run's.
pub(super) fn object_saving_error(
    assembler: &mut Assembler,
    runs: &mut BTreeMap<u64, ProgramRun>,
) -> Option<String> {
    assembler.saving_error().map(str::to_owned).or_else(|| {
        runs.values_mut()
            .find_map(|run| run.assembler.saving_error().map(str::to_owned))
    })
}

#[cfg(test)]
pub(super) fn propagate_object_saving_failure(
    capture: &mut RawCapture,
    assembler: &mut Assembler,
    runs: &mut BTreeMap<u64, ProgramRun>,
) {
    if let Some(error) = object_saving_error(assembler, runs) {
        stop_capture_saving(capture, assembler, runs, error);
    }
}

pub(super) fn refresh_storage_health(
    health: &mut Health,
    capture: &RawCapture,
    object_len: u64,
    runs: &BTreeMap<u64, ProgramRun>,
) {
    health.persisted_len = capture
        .bytes
        .saturating_add(object_len)
        .saturating_add(runs.values().map(ProgramRun::stored_len).sum::<u64>());
    health.persistence_error = capture.error.clone().or_else(|| {
        runs.values()
            .find_map(|run| run.summary.recording_error.clone())
    });
}

#[cfg(test)]
mod tests;
