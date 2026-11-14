// SPDX-License-Identifier: GPL-3.0-only
//! How one run's recording is shown wherever the run is: Trace, Run History,
//! Details and Triage read the same words from here.
//!
//! A run whose saving stopped is incomplete; notes are facts about the
//! recording (for example telemetry sent before the launch was acknowledged
//! that the host could not keep) and never mean saving stopped.
use antinomie_monitor_core::{run_note_text, RunState, RunSummary, Snapshot};
use eframe::egui;

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
        antinomie_monitor_core::fold_skipped_notes(
            run.notes.iter().map(|note| run_note_text(note)),
        )
        .into_iter()
        .map(|note| format!("Note: {note}")),
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
            && crate::widgets::with_help(ui, "Take this run off the list. Its recording folder is already gone, so no file is deleted.", |ui| ui
                .button("Remove"))
                .clicked()
        {
            remove = true;
        }
    }
    show_loss(ui, run);
    // Each note is dismissible like the app's other notices; the run is part
    // of the identity, so a note that repeats on other runs stays there.
    let scope = format!("run {}", crate::run_link::short(&run.id));
    for note in note_lines(run) {
        crate::activity::info_scoped(ui, format!("Note: {note}"), &scope);
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
    let mut lines: Vec<String> = antinomie_monitor_core::fold_skipped_notes(
        quiet_notes(run).map(|note| run_note_text(note)),
    );
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

#[cfg(test)]
mod skipped_tests {
    use super::*;

    #[test]
    fn a_run_with_thirteen_skipped_dumps_notes_one_line_in_every_place() {
        let mut run = crate::run_link::test_run("r", "/tmp/x");
        run.notes = (1362..1375)
            .map(|pid| {
                format!("Dump skipped for credential.shadow_read (High, process {pid}): The process exited 1 ms after the match, before the core could be taken.")
            })
            .collect();
        let lines = note_lines(&run);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("Dump skipped 13 times for credential.shadow_read (High)"));
        assert_eq!(tooltip(&run).matches("Dump skipped").count(), 1);
    }
}

#[cfg(test)]
mod note_dismiss_tests {
    use super::*;

    const SILENT: &str = "Dump trigger armed (core at High or higher), but no rule of that tier matched while the program ran: no dump was taken.";
    const SHOTS: &str = "Timed screenshots every 10 s: 1 saved, 0 skipped (screen unchanged).";

    /// Draw the notes of `run`; the texts drawn and the centre of the first
    /// dismiss button.
    fn draw(
        ctx: &egui::Context,
        run: &RunSummary,
        events: Vec<egui::Event>,
    ) -> (Vec<String>, Option<egui::Pos2>) {
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 300.0),
                )),
                events,
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    show(ui, run);
                });
            },
        );
        let mut texts = Vec::new();
        let mut close = None;
        for shape in &output.shapes {
            if let egui::Shape::Text(text) = &shape.shape {
                let galley = text.galley.text().to_owned();
                if galley == "×" {
                    close.get_or_insert(text.visual_bounding_rect().center());
                } else {
                    texts.push(galley);
                }
            }
        }
        (texts, close)
    }

    #[test]
    fn a_run_note_has_a_dismiss_button_that_hides_it_for_that_run_only() {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let mut first = crate::run_link::test_run("aaaaaaaa11111111", "/tmp/x");
        first.notes = vec![SILENT.to_owned(), SHOTS.to_owned()];
        let mut second = crate::run_link::test_run("bbbbbbbb22222222", "/tmp/x");
        second.notes = first.notes.clone();
        for _ in 0..3 {
            draw(&ctx, &first, vec![]);
        }
        let (texts, close) = draw(&ctx, &first, vec![]);
        assert!(texts.iter().any(|text| text.contains(SILENT)), "{texts:?}");
        assert!(texts.iter().any(|text| text.contains(SHOTS)), "{texts:?}");
        let pos = close.expect("every note has a dismiss button");
        for pressed in [true, false] {
            draw(
                &ctx,
                &first,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
        let (texts, _) = draw(&ctx, &first, vec![]);
        let shown = |texts: &[String], note: &str| texts.iter().any(|text| text.contains(note));
        assert!(
            !shown(&texts, SILENT),
            "the dismissed note is gone: {texts:?}"
        );
        assert!(shown(&texts, SHOTS), "the other note stays: {texts:?}");
        // The same words on another run are not dismissed with it.
        let (texts, _) = draw(&ctx, &second, vec![]);
        assert!(shown(&texts, SILENT), "{texts:?}");
    }
}
