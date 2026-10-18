// SPDX-License-Identifier: MIT
//! How one run's recording is shown wherever the run is: Trace, Run History,
//! Details, Triage and Summary read the same words from here.
//!
//! A run whose saving stopped is incomplete; notes are facts about the
//! recording (for example telemetry sent before the launch was acknowledged
//! that the host could not keep) and never mean saving stopped.
use crate::theme;
use antinomie_monitor_core::{RunSummary, Snapshot};
use eframe::egui::{self, RichText};

/// Longest list of runs the Summary names before counting the rest.
const SUMMARY_RUN_LIMIT: usize = 6;

/// Short mark for a Run History row; `None` while saving works.
pub(crate) fn badge(run: &RunSummary) -> Option<&'static str> {
    run.recording_error.as_ref().map(|_| "Saving stopped")
}

/// What the run's recording state says, one line per fact, for tooltips.
pub(crate) fn tooltip(run: &RunSummary) -> String {
    let mut lines = Vec::new();
    if let Some(error) = &run.recording_error {
        lines.push(format!("Recording incomplete: saving stopped: {error}"));
    }
    lines.extend(run.notes.iter().map(|note| format!("Note: {note}")));
    lines.join("\n")
}

/// The recording state of `run`: a warning when saving stopped, then each
/// note as muted text. Draws nothing for a run with neither.
pub(crate) fn show(ui: &mut egui::Ui, run: &RunSummary) {
    if let Some(error) = &run.recording_error {
        crate::activity::warning(ui, format!("Recording incomplete: saving stopped: {error}"));
    }
    for note in &run.notes {
        ui.add(
            egui::Label::new(RichText::new(format!("Note: {note}")).color(theme::muted())).wrap(),
        );
    }
}

/// Summary of the runs of `vm_id` that this session still holds: those whose
/// saving stopped, then how many carry notes.
pub(crate) fn summary(ui: &mut egui::Ui, snapshot: &Snapshot, history: &[RunSummary], vm_id: &str) {
    let mut seen = std::collections::HashSet::new();
    let mut stopped = Vec::with_capacity(SUMMARY_RUN_LIMIT);
    let mut stopped_count = 0;
    let mut noted = 0;
    for run in snapshot.runs.iter().chain(history) {
        if run.vm_id != vm_id || !seen.insert(run.id.as_str()) {
            continue;
        }
        if run.recording_error.is_some() {
            stopped_count += 1;
            if stopped.len() < SUMMARY_RUN_LIMIT {
                stopped.push(run);
            }
        }
        if !run.notes.is_empty() {
            noted += 1;
        }
    }
    for run in stopped {
        let id: String = run.id.chars().take(8).collect();
        crate::activity::warning(
            ui,
            format!(
                "Recording incomplete for {} [{id}]: saving stopped: {}",
                run.request.path,
                run.recording_error.as_deref().unwrap_or_default()
            ),
        );
    }
    if stopped_count > SUMMARY_RUN_LIMIT {
        crate::activity::warning(
            ui,
            format!(
                "{} more runs stopped saving",
                stopped_count - SUMMARY_RUN_LIMIT
            ),
        );
    }
    if noted > 0 {
        ui.colored_label(
            theme::muted(),
            format!("{noted} run(s) have recording notes; open the run to read them"),
        );
    }
}

/// The boot-wide saving failure and the last backend error, as red text.
pub(crate) fn health_errors(ui: &mut egui::Ui, snapshot: &Snapshot) {
    for error in [&snapshot.health.persistence_error, &snapshot.last_error]
        .into_iter()
        .flatten()
    {
        crate::activity::error(ui, error);
    }
}
