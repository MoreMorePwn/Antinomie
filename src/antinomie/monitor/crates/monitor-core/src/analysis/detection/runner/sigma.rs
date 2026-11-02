// SPDX-License-Identifier: GPL-3.0-only
//! The Sigma engine's run over staged sources (moved out of `runner`).
use super::*;

pub(super) fn sigma(staged: &Staged, work: &Path) -> Result<Report, String> {
    if staged.no_rules || staged.sigma_sources.is_empty() && staged.warnings.is_empty() {
        let mut report = Report::empty(Engine::Sigma, staged.request.identity.clone());
        report.state = State::NoRules;
        report.warnings.push("No rules enabled".into());
        report.selection = staged.selection.clone();
        return Ok(report);
    }
    if staged.sigma_sources.is_empty() {
        // The first line says why ("... pysigma is not installed"), not only
        // that nothing was evaluated: it is the line the cards show.
        let reason = match staged.warnings.first() {
            Some(why) => format!("No Sigma rule was evaluated: {why}"),
            None => "No compatible Sigma rules were evaluated.".to_owned(),
        };
        let mut report =
            Report::unavailable(Engine::Sigma, staged.request.identity.clone(), reason);
        report.selection = staged.selection.clone();
        return Ok(report);
    }
    let original = staged.request.directory.join(JOURNAL_FILE);
    let Some(journal) = &staged.journal else {
        let mut report = Report::empty(Engine::Sigma, staged.request.identity.clone());
        report.state = State::Missing;
        report
            .warnings
            .push("Evidence missing: the captured event journal is not ready.".into());
        report.input(
            super::ScannedInput::new(super::InputKind::EventJournal, &original)
                .skipped("the captured event journal is not ready"),
        );
        if staged.request.settings.partial {
            report.state = State::Partial;
            report
                .warnings
                .push("Partial: the event index was not ready, so the scan used only the part of the evidence saved so far.".into());
        }
        return Ok(report);
    };
    let script = work.join("sigma_scan.py");
    fs::write(&script, include_bytes!("../../../../assets/sigma_scan.py"))
        .map_err(|error| error.to_string())?;
    let input = work.join("sigma-request.json");
    crate::storage::atomic_json(&input, staged)?;
    let output = work.join("sigma-report.json");
    let python = crate::ruleset::sigma_interpreter(&staged.request.settings.sigma_python);
    let python = text(&python)?;
    let result = super::super::super::tools::run_with(
        &python,
        &[
            "-I",
            &text(&script)?,
            &text(journal)?,
            &text(&input)?,
            &text(&output)?,
        ],
        &[],
        Duration::from_secs(110),
        64 * 1024,
        true,
    )?;
    let input = super::inputs::journal_input(
        &original,
        journal,
        staged.request.source_digest.as_deref(),
        staged.request.settings.partial,
    );
    // A crash or timeout is a failed input with the adapter's own error lines;
    // unmapped categories or missing fields in the journal are not.
    if let Some(reason) = result.failure_text("Sigma adapter", Duration::from_secs(110)) {
        let mut report = Report::unavailable(
            Engine::Sigma,
            staged.request.identity.clone(),
            reason.clone(),
        );
        report.input(input.failed(reason));
        return Ok(report);
    }
    let data = read_bounded(work, Path::new("sigma-report.json"), REPORT_LIMIT)?;
    let mut report: Report = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    if let Some(coverage) = report.coverage.as_mut() {
        // Rules the managed selection already left out count the same as these.
        coverage.add_selection_exclusions(Engine::Sigma, &staged.warnings);
    }
    let missing = report.state == State::Unavailable
        && report
            .warnings
            .first()
            .is_some_and(|warning| warning.starts_with("Local pySigma"));
    report.inputs = Some(vec![if missing {
        // The engine never evaluated the journal.
        input.skipped("pySigma 2.x and its SQLite backend are not installed")
    } else {
        input
    }]);
    Ok(report)
}
