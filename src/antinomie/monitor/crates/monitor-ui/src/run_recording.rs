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
    lines.extend(reduced_lines(run).into_iter().take(1));
    lines.join("\n")
}

/// The recording state of `run`: a warning when saving stopped, then each
/// note as muted text. Draws nothing for a run with neither.
pub(crate) fn show(ui: &mut egui::Ui, run: &RunSummary) {
    show_removable(ui, run, false);
}

/// [`show`], with a Remove button under the warning of a run in the boot's
/// list that `RunSummary::forgettable` says is only a leftover entry. Returns whether
/// Remove was clicked.
pub(crate) fn show_removable(ui: &mut egui::Ui, run: &RunSummary, in_run_list: bool) -> bool {
    let mut remove = false;
    if let Some(message) = warning_message(run) {
        crate::activity::error(ui, message);
        if in_run_list
            && run.forgettable().is_ok()
            && ui
                .button("Remove")
                .on_hover_text(
                    "Take this run off the list. Its recording folder is already gone, so no file is deleted.",
                )
                .clicked()
        {
            remove = true;
        }
    }
    show_loss(ui, run);
    for note in note_lines(run) {
        ui.add(
            egui::Label::new(RichText::new(format!("Note: {note}")).color(theme::muted())).wrap(),
        );
    }
    remove
}

/// Only the warnings of `show`: Triage lists the notes in its own section.
pub(crate) fn show_warning(ui: &mut egui::Ui, run: &RunSummary) {
    if let Some(message) = warning_message(run) {
        crate::activity::error(ui, message);
    }
    show_loss(ui, run);
}

/// Lost telemetry is a warning over the run, not a muted note: the trace and
/// the findings miss what was lost, though saving went on.
fn show_loss(ui: &mut egui::Ui, run: &RunSummary) {
    if let Some(note) = run.telemetry_loss_note() {
        crate::activity::warning(ui, note);
    }
    // Not a failure: the recorder kept the part that matters, and says so.
    let lines = reduced_lines(run);
    if !lines.is_empty() {
        crate::activity::info(ui, lines.join(" "));
    }
}

/// What the run's recording says about the reduced mode (a full quota with
/// only suspicious-activity calls kept); empty for a run it did not touch.
pub(crate) fn reduced_lines(run: &RunSummary) -> Vec<String> {
    run.reduced
        .as_ref()
        .map(|reduced| crate::reduced_text::lines(reduced, run.started_ms))
        .unwrap_or_default()
}

/// The notes shown as muted lines: all but the telemetry loss.
fn quiet_notes(run: &RunSummary) -> impl Iterator<Item = &String> {
    let loss = run.telemetry_loss_note();
    run.notes
        .iter()
        .filter(move |note| Some(note.as_str()) != loss)
}

/// The run's notes but the telemetry loss (a warning), one line each, as plain text.
pub(crate) fn note_lines(run: &RunSummary) -> Vec<String> {
    let mut lines: Vec<String> = quiet_notes(run)
        .map(|note| run_note_text(note).to_owned())
        .collect();
    // What the static analysis found in the file's headers: a cut-off
    // download, a library run as if it were a program.
    if let Some(report) = &run.analysis {
        lines.extend(antinomie_monitor_core::report_notes(report));
    }
    lines
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
            "Recording incomplete for {} [{}]: saving stopped: {}",
            run.request.path,
            run.id,
            explained(run, error)
        )
    })
}

/// A saving failure with its subject and the next step: which folder is gone,
/// or what to do about a full disk.
fn explained(run: &RunSummary, error: &str) -> String {
    if error.contains("No such file or directory") {
        format!(
            "the recording folder {} is missing ({error}). Run the sample again to record it.",
            run.directory.display()
        )
    } else if error.contains("No space left on device") {
        format!(
            "the disk is full ({error}). Free space or lower the recording quota in Settings > Recording."
        )
    } else {
        error.to_owned()
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
