// SPDX-License-Identifier: GPL-3.0-only
//! A run's finished report, reused (ANT-T0556, A45): an Auto job writes the
//! whole report as JSON (`jobs/<id>/artifacts/report-<sha8>.json`, every
//! part) from the index its host work made. Another format of the same run
//! (STIX, MISP, Markdown, ...) is written from that report instead of reading
//! the whole recording again, which took over 20 minutes for a 2.5 GB,
//! 1.05 million-call run. The recording is read again only when the report is
//! missing, was made by another app or schema, or is older than the
//! recording's data, the digest or a detection scan; the reason is returned.
use super::*;
use antinomie_monitor_core::report::{Report, SCHEMA, SCHEMA_VERSION};

/// The files whose change after the report makes it stale, in the run's
/// folder (the run record is left out: the run's end and sealing touch it).
const INPUTS: [&str; 4] = [
    "telemetry.raw",
    "artifacts.json",
    "manifest.json",
    "triage-digest.json",
];

fn modified_ms(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

/// The newest change, in ms since the epoch, of what the report was built
/// from: the recording's data, the digest and each detection scan's report.
pub fn inputs_changed_ms(archive: &Path) -> u64 {
    let mut newest = INPUTS
        .iter()
        .filter_map(|name| modified_ms(&archive.join(name)))
        .max()
        .unwrap_or(0);
    for engine in ["yara", "sigma", "ids"] {
        let scan = archive
            .join("triage-detection")
            .join(engine)
            .join("report.json");
        newest = newest.max(modified_ms(&scan).unwrap_or(0));
    }
    newest
}

/// The JSON report in `artifacts` (`report-*.json`, not the MISP or STIX
/// file), when there is exactly one.
fn report_file(artifacts: &Path) -> Result<PathBuf, String> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(artifacts)
        .map_err(|e| format!("the job's report folder cannot be read: {e}"))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| {
                    name.starts_with("report-")
                        && name.ends_with(".json")
                        && !name.ends_with(".misp.json")
                        && !name.ends_with(".stix.json")
                })
        })
        .collect();
    found.sort();
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err("the job that made the run wrote no JSON report".into()),
        _ => Err("the job's report folder holds more than one JSON report".into()),
    }
}

/// The finished report of `job`'s run in `artifacts` (the folder of the job
/// that made it), when it can stand for a new index: the same run, schema
/// and app, and nothing it was built from changed after it. `Err` says why
/// the recording must be read again.
pub fn stored_report(job: &Job, artifacts: &Path) -> Result<(Report, PathBuf), String> {
    let path = report_file(artifacts)?;
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let report: Report = serde_json::from_slice(&bytes)
        .map_err(|e| format!("the job's JSON report does not parse: {e}"))?;
    if report.schema != SCHEMA || report.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "the job's report has schema {} {}, this app writes {SCHEMA} {SCHEMA_VERSION}",
            report.schema, report.schema_version
        ));
    }
    let app = format!("Antinomie {}", antinomie_monitor_core::api::APP_VERSION);
    if report.app != app {
        return Err(format!(
            "the job's report was made by {}, not {app}",
            report.app
        ));
    }
    if report.run.run_id != job.run.run_id || report.run.vm_id != job.run.vm_id {
        return Err("the job's report is of another run".into());
    }
    let changed = inputs_changed_ms(&job.archive);
    if changed > report.generated_ms {
        return Err(format!(
            "the recording or its analysis changed after the job's report was made ({} > {})",
            report::iso(changed),
            report::iso(report.generated_ms)
        ));
    }
    Ok((report, path))
}

/// The parts of `report` that `choices` keeps, and the static analysis of
/// the sample when the stored report has none (one made before it existed).
pub fn chosen(mut report: Report, job: &Job) -> Report {
    report.keep_parts(&job.choices.parts);
    if job
        .choices
        .has(antinomie_monitor_core::report::Part::StaticAnalysis)
        && report.static_analysis.is_none()
    {
        report.static_analysis = super::build_sources::static_analysis(job);
    }
    report
}
