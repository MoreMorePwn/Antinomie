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
            .push("Evidence missing: the run's event journal was not built (the index of this run did not finish), so Sigma had nothing to scan. This is not a clean result.".into());
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
    let limit = Duration::from_secs(
        staged
            .request
            .settings
            .timeouts
            .seconds(super::super::EngineTime::Sigma),
    );
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
        limit,
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
    if let Some(reason) = result.failure_text("Sigma adapter", limit) {
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

#[cfg(test)]
mod tests {
    /// The adapter's loading and matching, run on a small journal with queries
    /// written as the SQLite backend writes them (ANT-T0588). The expected
    /// answers are those of the statement-per-event, scan-per-question form:
    /// the same counts, ids, evidence and inferred note, in the same order.
    /// Needs a `python3` with `sqlite3`; skipped without one.
    #[test]
    fn the_adapter_loads_and_matches_the_journal_as_it_did_one_event_at_a_time() {
        let Ok(python) = std::process::Command::new("python3")
            .args(["-I", "-c", "import sqlite3"])
            .output()
        else {
            return;
        };
        if !python.status.success() {
            return;
        }
        let directory =
            std::env::temp_dir().join(format!("ant-sigma-scan-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&directory).unwrap();
        let script = directory.join("sigma_scan.py");
        std::fs::write(&script, include_bytes!("../../../../assets/sigma_scan.py")).unwrap();
        let check = directory.join("check.py");
        std::fs::write(
            &check,
            r#"
import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
import sigma_scan as s
identity = {"vm_id": "v", "boot_id": "b", "run_id": "r", "root_cookie": 1}
events = []
for index in range(30):
    category = ["file_access", "process_creation", "auditd"][index % 3]
    fields = {"Image": "/bin/Tool%d" % (index % 4), "ProcessId": index}
    if index % 5 == 0:
        fields["CommandLine"] = "run --Flag %d" % index
    events.append({"category": category, "fields": fields, "evidence": {"kind": "call", "call": index},
                   "_inferred": ["CommandLine"] if index % 10 == 0 else []})
path = sys.argv[2] + "/events.jsonl"
with open(path, "w") as out:
    out.write(json.dumps({"kind": "header", "format_version": 3, "identity": identity}) + "\n")
    for event in events:
        out.write(json.dumps({"kind": "event", "event": event}) + "\n")
    out.write(json.dumps({"kind": "end", "complete": True, "events": len(events), "omitted": 0, "reasons": []}) + "\n")
connection = sqlite3.connect(":memory:", cached_statements=0)
count, complete, reasons = s.load_events(connection, path, identity)
assert (count, complete, reasons) == (30, True, []), (count, complete, reasons)
rows = connection.execute("SELECT _event_id, _category, Image, ProcessId, CommandLine, _inferred FROM logs ORDER BY _event_id").fetchall()
assert [row[0] for row in rows] == list(range(1, 31))
assert rows[0][4] == "run --Flag 0" and rows[1][4] is None and rows[1][2] == "/bin/Tool1"
queries = ["SELECT * FROM logs WHERE Image LIKE '%tool1' COLLATE NOCASE OR CommandLine LIKE '%flag%' COLLATE NOCASE"]
counts = {}
total, evidence, eligible, missing, ids, inferred = s.matching_rows(connection, queries, "file_access", counts)
want = [row for row in rows if row[1] == "file_access" and row[2] is not None and row[4] is not None
        and (row[2].lower().endswith("tool1") or "flag" in row[4].lower())]
all_category = [row for row in rows if row[1] == "file_access"]
eligible_rows = [row for row in all_category if row[4] is not None]
assert counts == {"file_access": len(all_category)}
assert eligible == len(eligible_rows)
assert missing == len(all_category) - len(eligible_rows)
assert ids == [row[0] for row in want] and total == len(want)
assert evidence == [{"kind": "call", "call": row[0] - 1} for row in want]
note = [row for row in want if row[5] is not None]
assert inferred == ((len(note), ["commandline"]) if note else (0, [])), inferred
assert total > 0 and note
# A query matching nothing in this category matches nothing, whatever the other categories hold.
none = s.matching_rows(connection, ["SELECT * FROM logs WHERE ProcessId = 1000"], "process_creation", counts)
assert none[0] == 0 and none[4] == [] and none[5] == (0, [])
print("ok")
"#,
        )
        .unwrap();
        let output = std::process::Command::new("python3")
            .arg("-I")
            .arg(&check)
            .arg(&directory)
            .arg(&directory)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&directory);
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
