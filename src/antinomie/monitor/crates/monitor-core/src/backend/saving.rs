// SPDX-License-Identifier: MIT
//! Recording storage health and the decision to stop saving.
use super::*;

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
    pub(super) fn stop_saving(&mut self, error: String) {
        stop_capture_saving(
            &mut self.capture,
            &mut self.assembler,
            &mut self.runs,
            error.clone(),
        );
        for capture in self.captures.values_mut() {
            capture.storage_error(error.clone());
        }
    }
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
        run.capture.error.get_or_insert(error.clone());
        run.storage_error(error.clone());
    }
}

pub(super) fn propagate_object_saving_failure(
    capture: &mut RawCapture,
    assembler: &mut Assembler,
    runs: &mut BTreeMap<u64, ProgramRun>,
) {
    let error = assembler.saving_error().map(str::to_owned).or_else(|| {
        runs.values_mut()
            .find_map(|run| run.assembler.saving_error().map(str::to_owned))
    });
    if let Some(error) = error {
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
