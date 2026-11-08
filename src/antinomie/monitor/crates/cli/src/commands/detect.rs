// SPDX-License-Identifier: GPL-3.0-only
//! `detect RUN` (design 3.4.3): run YARA, Sigma and IDS over a saved run's
//! evidence, as the Detection tab does: the same evidence key, request and
//! frozen rule selection (`antinomie_triage::detection`), the same sandboxed
//! engines. Without `--save` nothing is written into the recording: the
//! results go to standard output and to `--out`. `--save` keeps them where
//! the Detection tab keeps them and adds them to the run's digest, so a later
//! `report` lists them; it takes the engine lock.
use super::recording::{RUN_HELP, index, open_saved, run_value};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    exit::Exit,
    output::{Reply, block, table},
};
use antinomie_monitor_core::{
    analysis::detection::{self as engine, Engine, Report},
    data_owner::{self, OwnerClaim, OwnerKind},
};
use antinomie_triage::detection::{self, DiskFiles, ENGINES, IndexState, Keep};
use clap::Args;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

#[derive(Args, Debug)]
pub struct Detect {
    #[arg(help = RUN_HELP)]
    pub run: String,
    /// Engines, comma separated: yara, sigma, ids [default: all three].
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    pub engine: Vec<String>,
    /// Write each engine's full result to DIR/detection-<engine>.json.
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,
    /// Keep the results in the recording (triage-detection/) and in its
    /// digest, as the Detection tab does. Takes the engine lock, so it is
    /// refused while a window or a daemon owns the data directory.
    #[arg(long)]
    pub save: bool,
}

fn parse_engines(items: &[String]) -> Result<Vec<Engine>, CliError> {
    if items.is_empty() {
        return Ok(ENGINES.to_vec());
    }
    let mut engines = Vec::new();
    for item in items.iter().map(|item| item.trim().to_ascii_lowercase()) {
        let engine = match item.as_str() {
            "all" => return Ok(ENGINES.to_vec()),
            "yara" => Engine::Yara,
            "sigma" => Engine::Sigma,
            "ids" | "suricata" => Engine::Ids,
            _ => {
                return Err(CliError::invalid(format!(
                    "unknown engine {item:?}; the engines are yara, sigma, ids"
                ))
                .with_field("engine"));
            }
        };
        if !engines.contains(&engine) {
            engines.push(engine);
        }
    }
    Ok(engines)
}

/// One engine's outcome.
enum Outcome {
    Scanned(Box<Report>),
    /// The evidence is not there or not final: the key and its words.
    Skipped(String, String),
    Failed(String),
}

pub fn run(arguments: &Detect, context: &Context) -> Result<Reply, CliError> {
    let engines = parse_engines(&arguments.engine)?;
    let saved = open_saved(context, &arguments.run)?;
    let data = context.data_dir();
    // Taken before anything is read: a window or daemon that owns the data
    // directory may be writing the same results.
    let _lock = if arguments.save {
        let claim = OwnerClaim {
            kind: OwnerKind::Cli,
            socket: None,
        };
        Some(
            data_owner::lock_data_dir(data, &claim)
                .map_err(|message| CliError::from_engine_start(data, &message))?,
        )
    } else {
        None
    };
    let settings = detection::headless_settings(data).map_err(|error| {
        CliError::new(
            ErrorCode::PreconditionFailed,
            format!("settings.json cannot be read: {error}"),
        )
    })?;
    // The index builds the event journal Sigma reads.
    let scan = index(context, &saved)?;
    let input = saved.input();
    let (directory, identity) = detection::identity(&input).ok_or_else(|| {
        CliError::new(
            ErrorCode::PreconditionFailed,
            "the run has no recorded program to scan",
        )
    })?;
    let keep = if arguments.save {
        Keep::Save
    } else {
        Keep::Discard
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let mut outcomes = Vec::new();
    for engine in &engines {
        let key = detection::evidence_key(
            *engine,
            &input,
            &settings,
            (&IndexState::Ready, false),
            &mut DiskFiles,
        );
        if !key.starts_with("ready:") {
            let words = detection::evidence_note(&key);
            context.logger.info(&format!(
                "{}: not scanned: {words}",
                detection::name(*engine)
            ));
            outcomes.push((*engine, Outcome::Skipped(key, words)));
            continue;
        }
        let mut engine_settings = settings.clone();
        engine_settings.evidence_key = key;
        engine_settings.partial = false;
        let request = detection::request(*engine, (&directory, &identity), &engine_settings, None);
        context
            .logger
            .info(&format!("{}: scanning", detection::name(*engine)));
        let outcome = match detection::scan(request, keep, &cancel, None) {
            Ok(report) => Outcome::Scanned(Box::new(report)),
            Err(error) => Outcome::Failed(error),
        };
        outcomes.push((*engine, outcome));
    }
    if arguments.save {
        save_digest(&saved, &scan, &directory, &identity, &settings, &outcomes)?;
    }
    let mut written = Vec::new();
    if let Some(out) = &arguments.out {
        std::fs::create_dir_all(out).map_err(|error| CliError::io(out, &error))?;
        for (engine, outcome) in &outcomes {
            if let Outcome::Scanned(report) = outcome {
                let path = out.join(format!("detection-{}.json", detection::engine_key(*engine)));
                let text = serde_json::to_vec_pretty(report)
                    .map_err(|error| CliError::internal(error.to_string()))?;
                std::fs::write(&path, text).map_err(|error| CliError::io(&path, &error))?;
                written.push((*engine, path));
            }
        }
    }
    let failed = outcomes
        .iter()
        .any(|(_, outcome)| matches!(outcome, Outcome::Failed(_)));
    let results: Vec<Value> = outcomes
        .iter()
        .map(|(engine, outcome)| {
            let file = written
                .iter()
                .find(|(written, _)| written == engine)
                .map(|(_, path)| path.clone());
            engine_value(*engine, outcome, file)
        })
        .collect();
    let value = json!({
        "run": run_value(&saved),
        "saved": arguments.save,
        "engines": results,
    });
    let reply = Reply::value(value).with_human(human(&saved.run.id, arguments.save, &outcomes));
    Ok(if failed {
        reply.with_exit(Exit::Failed)
    } else {
        reply
    })
}

/// Add the engines' results to the run's digest, as the GUI does once it
/// shows them: what this command scanned, and for the other engines what the
/// recording already keeps.
fn save_digest(
    saved: &antinomie_triage::SavedRun,
    scan: &antinomie_triage::ArchiveScan,
    directory: &std::path::Path,
    identity: &engine::Identity,
    settings: &engine::Settings,
    outcomes: &[(Engine, Outcome)],
) -> Result<(), CliError> {
    let results =
        ENGINES.map(
            |engine| match outcomes.iter().find(|(scanned, _)| *scanned == engine) {
                Some((_, Outcome::Scanned(report))) => Some(Ok((**report).clone())),
                Some((_, Outcome::Failed(error))) => Some(Err(error.clone())),
                _ => engine::load(&detection::request(
                    engine,
                    (directory, identity),
                    settings,
                    None,
                ))
                .ok()
                .map(Ok),
            },
        );
    antinomie_triage::digest::Update::of(scan, antinomie_triage::digest::detections(&results))
        .write(&saved.run.directory)
        .map_err(|error| CliError::internal(format!("cannot update the run's digest: {error}")))
}

fn engine_value(engine: Engine, outcome: &Outcome, file: Option<PathBuf>) -> Value {
    let name = detection::name(engine);
    match outcome {
        Outcome::Scanned(report) => json!({
            "engine": name,
            "outcome": "scanned",
            "state": report.state,
            "selection": report.selection,
            "matches": report.findings.len(),
            "findings": report.findings.iter().map(|finding| json!({
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "count": finding.count,
                "mitre": finding.mitre,
                "source": detection::pack_name(report, finding),
            })).collect::<Vec<_>>(),
            "warnings": report.warnings,
            "file": file,
        }),
        Outcome::Skipped(key, words) => json!({
            "engine": name,
            "outcome": "not_scanned",
            "evidence_key": key,
            "reason": words,
        }),
        Outcome::Failed(error) => json!({
            "engine": name,
            "outcome": "failed",
            "error": error,
        }),
    }
}

fn human(run_id: &str, saved: bool, outcomes: &[(Engine, Outcome)]) -> String {
    let mut text = block(&[
        ("run", run_id.to_owned()),
        (
            "saved",
            if saved {
                "yes: in the recording and its digest".into()
            } else {
                "no (use --save to keep the results in the recording)".into()
            },
        ),
    ]);
    text.push('\n');
    let mut rows = Vec::new();
    for (engine, outcome) in outcomes {
        let name = detection::name(*engine).to_owned();
        match outcome {
            Outcome::Scanned(report) => {
                rows.push(vec![
                    name.clone(),
                    format!("{:?}", report.state).to_lowercase(),
                    report.findings.len().to_string(),
                    String::new(),
                ]);
                for finding in &report.findings {
                    rows.push(vec![
                        String::new(),
                        finding.severity.clone(),
                        finding.count.to_string(),
                        if finding.title.is_empty() {
                            finding.rule_id.clone()
                        } else {
                            finding.title.clone()
                        },
                    ]);
                }
            }
            Outcome::Skipped(_, words) => rows.push(vec![
                name,
                "not scanned".into(),
                String::new(),
                words.clone(),
            ]),
            Outcome::Failed(error) => {
                rows.push(vec![name, "failed".into(), String::new(), error.clone()])
            }
        }
    }
    text.push_str(&table(
        &["ENGINE", "STATE", "MATCHES", "RULE / REASON"],
        &rows,
    ));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engines_parse_by_name_and_default_to_all_three() {
        assert_eq!(parse_engines(&[]).unwrap(), ENGINES);
        assert_eq!(
            parse_engines(&["sigma".into(), "YARA".into(), "sigma".into()]).unwrap(),
            [Engine::Sigma, Engine::Yara]
        );
        assert_eq!(parse_engines(&["suricata".into()]).unwrap(), [Engine::Ids]);
        assert!(parse_engines(&["clamav".into()]).is_err());
    }
}
