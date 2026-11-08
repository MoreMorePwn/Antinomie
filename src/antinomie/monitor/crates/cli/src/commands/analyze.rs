// SPDX-License-Identifier: GPL-3.0-only
//! `analyze FILE`: static analysis of a host file, no VM running (design 3.4.3).
//!
//! The file is added to the sample library first (the engine analyses library
//! copies only, and the custody chain records where it came from), then
//! `Command::AnalyzeSample` analyses that copy in the sandbox on the host. The
//! report lives in its own folder, `<data>/analyses/<report id>`, apart from any
//! VM; `--out` copies it (and the layers unpacking found) out.
use crate::{
    context::Context,
    engine::DirectEngine,
    error::{CliError, ErrorCode},
    exit::Exit,
    output::{Reply, block, table},
};
use antinomie_monitor_core::{
    AnalysisKind, AnalysisReport, AnalysisSelection, AnalysisState, Command,
    analysis::sample_analysis_directory,
    dependencies::{self, Dependency},
    samples::{Library, NewOrigin, NewSample},
    unpack_layers,
};
use clap::Args;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const DEFAULT_WAIT: Duration = Duration::from_secs(30 * 60);

#[derive(Args, Debug)]
pub struct Analyze {
    pub file: PathBuf,
    /// Checks to run, comma separated (default: the triage set). Names:
    /// metadata, structures, strings, regex, entropy, hardening, rules,
    /// identification, capabilities, disassembly, decompilation, embedded,
    /// floss, unpacking.
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    pub checks: Vec<String>,
    /// Minutes each analysis tool may run (0: each tool's own limit).
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub time_limit_min: u32,
    /// Also copy the report folder(s) into this directory, one folder per report.
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,
}

/// The checks named by `--checks`, or the triage set.
pub fn parse_checks(names: &[String]) -> Result<Vec<AnalysisKind>, CliError> {
    if names.is_empty() {
        return Ok(AnalysisKind::TRIAGE.to_vec());
    }
    names
        .iter()
        .map(|name| {
            serde_json::from_value::<AnalysisKind>(Value::String(name.trim().to_ascii_lowercase()))
                .map_err(|_| {
                    CliError::invalid(format!("unknown check {name:?}")).with_field("checks")
                })
        })
        .collect()
}

pub fn run(arguments: &Analyze, context: &Context) -> Result<Reply, CliError> {
    let path = std::fs::canonicalize(&arguments.file)
        .map_err(|error| CliError::io(&arguments.file, &error).with_field("file"))?;
    if !path.is_file() {
        return Err(
            CliError::invalid(format!("{} is not a regular file", path.display()))
                .with_field("file"),
        );
    }
    let checks = parse_checks(&arguments.checks)?;
    let selection = AnalysisSelection {
        enabled: true,
        checks,
        time_limit_minutes: arguments.time_limit_min,
        limits: Default::default(),
    };
    selection
        .validate()
        .map_err(|message| CliError::invalid(message).with_field("checks"))?;
    if let Err(problem) = dependencies::check(&context.options).require(&[Dependency::Bubblewrap]) {
        return Err(CliError::new(ErrorCode::DependencyMissing, problem));
    }
    let wait = context
        .global
        .timeout
        .map_or(DEFAULT_WAIT, Duration::from_secs);
    let deadline = Instant::now() + wait;

    let mut engine = DirectEngine::start(context)?;
    context
        .logger
        .debug("engine started; adding the file to the library");
    let outcome = add_and_analyze(&mut engine, &path, selection, deadline);
    let data_dir = engine.data_dir().to_path_buf();
    engine.finish();
    let (report, layers) = outcome?;

    let root = data_dir.join("analyses");
    let directory = sample_analysis_directory(&data_dir, &report.id);
    let mut copies = Vec::new();
    if let Some(out) = &arguments.out {
        for id in std::iter::once(&report.id).chain(layers.iter().map(|layer| &layer.id)) {
            let target = out.join(id);
            copy_dir(&root.join(id), &target).map_err(|error| CliError::io(&target, &error))?;
            copies.push(target);
        }
    }
    summary(&report, &layers, &directory, &copies)
}

fn finished(report: &AnalysisReport) -> bool {
    !matches!(
        report.state,
        AnalysisState::Acquiring | AnalysisState::Queued | AnalysisState::Running
    )
}

/// Add the file to the library, queue its analysis and wait for it and for
/// the layers unpacking found.
fn add_and_analyze(
    engine: &mut DirectEngine,
    path: &Path,
    selection: AnalysisSelection,
    deadline: Instant,
) -> Result<(AnalysisReport, Vec<AnalysisReport>), CliError> {
    let mut library = Library::open(engine.data_dir())
        .map_err(|message| CliError::new(ErrorCode::Internal, message))?;
    let added = library
        .add_file(
            path,
            NewSample {
                origin: NewOrigin::default(),
                ..Default::default()
            },
            false,
        )
        .map_err(|message| CliError::invalid(message).with_field("file"))?;
    drop(library);
    let id = engine.command(
        Command::AnalyzeSample {
            sha256: added.sha256,
            selection,
        },
        Some(deadline.saturating_duration_since(Instant::now())),
    )?;
    loop {
        engine.pump(Duration::from_millis(100))?;
        let main = engine
            .snapshot()
            .analysis_reports
            .iter()
            .find(|report| report.id == id)
            .filter(|report| finished(report));
        if let Some(main) = main {
            let wanted = unpack_layers(main)
                .iter()
                .filter(|layer| layer.index > 0)
                .count();
            let layers: Vec<AnalysisReport> = engine
                .snapshot()
                .analysis_reports
                .iter()
                .filter(|report| {
                    report.layer.is_some()
                        && report.source_path == main.source_path
                        && finished(report)
                })
                .cloned()
                .collect();
            if layers.len() >= wanted {
                return Ok((main.clone(), layers));
            }
        }
        if Instant::now() >= deadline {
            return Err(CliError::new(
                ErrorCode::Unavailable,
                "the analysis did not finish in time; it was stopped with the command",
            )
            .with_exit(Exit::WaitTimeout));
        }
    }
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn state_name(state: AnalysisState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn kind_name(kind: AnalysisKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn summary(
    report: &AnalysisReport,
    layers: &[AnalysisReport],
    directory: &Path,
    copies: &[PathBuf],
) -> Result<Reply, CliError> {
    let sections: Vec<Value> = report
        .sections
        .iter()
        .map(|section| {
            json!({
                "kind": kind_name(section.kind),
                "label": section.kind.label(),
                "state": serde_json::to_value(section.state).unwrap_or_default(),
                "summary": section.summary,
            })
        })
        .collect();
    let layer_values: Vec<Value> = layers
        .iter()
        .map(|layer| {
            json!({
                "report_id": layer.id,
                "index": layer.layer.as_ref().map(|l| l.index),
                "state": state_name(layer.state),
                "specimen_sha256": layer.specimen_sha256,
            })
        })
        .collect();
    let value = json!({
        "report_id": report.id,
        "state": state_name(report.state),
        "reason": report.reason,
        "source_path": report.source_path,
        "specimen_sha256": report.specimen_sha256,
        "specimen_len": report.specimen_len,
        "directory": directory,
        "copies": copies,
        "sections": sections,
        "layers": layer_values,
    });
    let rows: Vec<Vec<String>> = sections
        .iter()
        .map(|s| {
            vec![
                s["kind"].as_str().unwrap_or("").to_owned(),
                s["state"].as_str().unwrap_or("").to_owned(),
                s["summary"].as_str().unwrap_or("").to_owned(),
            ]
        })
        .collect();
    let mut text = block(&[
        ("report", report.id.clone()),
        ("state", state_name(report.state)),
        (
            "sha256",
            report.specimen_sha256.clone().unwrap_or_else(|| "-".into()),
        ),
        ("folder", directory.display().to_string()),
    ]);
    text.push('\n');
    text.push_str(&table(&["check", "state", "summary"], &rows));
    match report.state {
        AnalysisState::Complete | AnalysisState::Partial => {
            Ok(Reply::value(value).with_human(text))
        }
        _ => Err(CliError::new(
            ErrorCode::PreconditionFailed,
            format!(
                "the analysis ended {}: {}",
                state_name(report.state),
                report
                    .reason
                    .clone()
                    .unwrap_or_else(|| "no reason given".into())
            ),
        )
        .with_exit(Exit::Failed)
        .with_details(value)
        .with_human_output(text)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_parse_by_name_and_default_to_the_triage_set() {
        assert_eq!(parse_checks(&[]).unwrap(), AnalysisKind::TRIAGE.to_vec());
        assert_eq!(
            parse_checks(&["Strings".into(), "entropy".into()]).unwrap(),
            vec![AnalysisKind::Strings, AnalysisKind::Entropy]
        );
        let error = parse_checks(&["nope".into()]).unwrap_err();
        assert_eq!(error.exit.code(), 4);
        assert_eq!(error.field.as_deref(), Some("checks"));
    }
}
