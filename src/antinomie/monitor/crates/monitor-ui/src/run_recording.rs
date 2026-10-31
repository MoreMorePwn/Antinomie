// SPDX-License-Identifier: GPL-3.0-only
//! How one run's recording is shown wherever the run is: Trace, Run History,
//! Details and Triage read the same words from here.
//!
//! A run whose saving stopped is incomplete; notes are facts about the
//! recording (for example telemetry sent before the launch was acknowledged
//! that the host could not keep) and never mean saving stopped.
use crate::theme;
use antinomie_monitor_core::{run_note_text, RunState, RunSummary, Snapshot};
use eframe::egui::{self, RichText};

/// Short mark for a Run History row; `None` while saving works. A run that
/// never ran has no recording to be incomplete: its status says what happened.
pub(crate) fn badge(run: &RunSummary) -> Option<&'static str> {
    if run.state.never_recorded() {
        return None;
    }
    run.recording_error.as_ref().map(|_| "Saving stopped")
}

/// What happened to a run whose program never ran, with the reason saved
/// for it; `None` for any other run.
pub(crate) fn launch_outcome(run: &RunSummary) -> Option<String> {
    let reason = run
        .recording_error
        .as_deref()
        .unwrap_or("no reason was saved");
    match run.state {
        RunState::FailedToStart => Some(format!(
            "Failed to start: {reason}. Nothing of the program was recorded."
        )),
        RunState::LaunchUnconfirmed => Some(format!(
            "Launch unconfirmed: {reason}. The program may have started in the guest, but \
             nothing of it was recorded."
        )),
        RunState::Interrupted => Some(
            "Interrupted: the recording ended before the end of the process tree was seen \
             (Antinomie closed or the VM stopped while the run was going)."
                .into(),
        ),
        _ => None,
    }
}

/// What the run's recording state says, one line per fact, for tooltips.
pub(crate) fn tooltip(run: &RunSummary) -> String {
    let mut lines = Vec::new();
    if let Some(outcome) = launch_outcome(run) {
        lines.push(outcome);
    }
    if let Some(error) = run
        .recording_error
        .as_ref()
        .filter(|_| !run.state.never_recorded())
    {
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

/// Only the warning of `show`: Triage lists the notes in its own section.
pub(crate) fn show_warning(ui: &mut egui::Ui, run: &RunSummary) {
    if let Some(message) = warning_message(run) {
        crate::activity::warning(ui, message);
    }
}

/// The run's notes, one line each, as plain text.
pub(crate) fn note_lines(run: &RunSummary) -> Vec<String> {
    run.notes
        .iter()
        .map(|note| run_note_text(note).to_owned())
        .collect()
}

/// Shared run identity keeps Activity and inline dismissal in sync without
/// suppressing another run that stopped for the same reason.
pub(crate) fn warning_message(run: &RunSummary) -> Option<String> {
    if run.state.never_recorded() {
        return launch_outcome(run)
            .map(|outcome| format!("{} [{}]: {outcome}", run.request.path, run.id));
    }
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
