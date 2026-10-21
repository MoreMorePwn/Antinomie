// SPDX-License-Identifier: MIT
//! How one run's recording is shown wherever the run is: Trace, Run History,
//! Details and Triage read the same words from here.
//!
//! A run whose saving stopped is incomplete; notes are facts about the
//! recording (for example telemetry sent before the launch was acknowledged
//! that the host could not keep) and never mean saving stopped.
use crate::theme;
use antinomie_monitor_core::{run_note_text, RunSummary, Snapshot};
use eframe::egui::{self, RichText};

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
    lines.extend(
        run.notes
            .iter()
            .map(|note| format!("Note: {}", run_note_text(note))),
    );
    lines.join("\n")
}

/// The recording state of `run`: a warning when saving stopped, then each
/// note as muted text. Draws nothing for a run with neither.
pub(crate) fn show(ui: &mut egui::Ui, run: &RunSummary) {
    if let Some(message) = warning_message(run) {
        crate::activity::warning(ui, message);
    }
    for note in &run.notes {
        ui.add(
            egui::Label::new(
                RichText::new(format!("Note: {}", run_note_text(note))).color(theme::muted()),
            )
            .wrap(),
        );
    }
}

/// Shared run identity keeps Activity and inline dismissal in sync without
/// suppressing another run that stopped for the same reason.
pub(crate) fn warning_message(run: &RunSummary) -> Option<String> {
    run.recording_error.as_ref().map(|error| {
        format!(
            "Recording incomplete for {} [{}]: saving stopped: {error}",
            run.request.path, run.id
        )
    })
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
