// SPDX-License-Identifier: GPL-3.0-only
//! `triage RUN` (design 3.4.3): index the whole saved run as the GUI does when
//! it is selected and print what Triage's Summary says of it: the assessment,
//! the counts and the key behaviours, from the same builder as the exported
//! report. `--parts` adds report parts to the result. No engine lock, nothing
//! written but the index Triage keeps in the recording.
use super::{
    recording::{RUN_HELP, index, open_saved, run_value},
    report::{parse_parts, part_name},
};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, block, table},
};
use antinomie_monitor_core::report::{Choices, Part, Summary};
use antinomie_triage::{report_export, time_format};
use clap::Args;
use serde_json::{Map, Value, json};

#[derive(Args, Debug)]
pub struct Triage {
    #[arg(help = RUN_HELP)]
    pub run: String,
    /// Report parts to add to the result, comma separated (see `report
    /// --help`); the summary is always there.
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    pub parts: Vec<String>,
}

pub fn run(arguments: &Triage, context: &Context) -> Result<Reply, CliError> {
    let mut parts = parse_parts(&arguments.parts)?;
    if !parts.contains(&Part::Summary) {
        parts.insert(0, Part::Summary);
    }
    let saved = open_saved(context, &arguments.run)?;
    let scan = index(context, &saved)?;
    let choices = Choices {
        parts: parts.clone(),
        formats: Vec::new(),
        bundle: false,
        ..Choices::default()
    };
    let job = report_export::Job::for_saved(&saved, choices, time_format::now_ms());
    let (_, built) = report_export::build_report(&job, &scan).map_err(|error| {
        CliError::new(
            ErrorCode::Internal,
            format!("cannot build the summary: {error}"),
        )
    })?;
    let report = built.report;
    let summary = report.summary.clone().unwrap_or_default();
    let all =
        serde_json::to_value(&report).map_err(|error| CliError::internal(error.to_string()))?;
    let mut value = Map::new();
    value.insert("run".into(), run_value(&saved));
    value.insert("sample".into(), all["sample"].clone());
    value.insert("state".into(), json!(report.run.state));
    value.insert("partial".into(), json!(scan.partial));
    for part in &parts {
        let name = part_name(*part);
        value.insert(name.clone(), all[name.as_str()].clone());
    }
    value.insert("notes".into(), json!(report.notes));
    let human = human(
        &saved.run.id,
        &report.run.state,
        &summary,
        &report.notes,
        &all,
        &parts,
    );
    Ok(Reply::value(Value::Object(value)).with_human(human))
}

fn human(
    run_id: &str,
    state: &str,
    summary: &Summary,
    notes: &[String],
    all: &Value,
    parts: &[Part],
) -> String {
    let tiers = &summary.tiers;
    let counts = &summary.counts;
    let mut text = block(&[
        ("run", run_id.to_owned()),
        ("state", state.to_owned()),
        ("assessment", summary.assessment.clone()),
        ("highest tier", summary.highest_tier.clone()),
        (
            "tiers",
            format!(
                "high {} · medium {} · low {} · info {}",
                tiers.high, tiers.medium, tiers.low, tiers.info
            ),
        ),
        (
            "counts",
            format!(
                "{} processes · {} findings · {} indicators ({} matched) · {} techniques · {} files changed · {} endpoints · {} domains",
                counts.processes,
                counts.findings,
                counts.indicators,
                counts.indicators_matched,
                counts.techniques,
                counts.files_changed,
                counts.endpoints,
                counts.domains
            ),
        ),
        ("families", summary.families.join(", ")),
    ]);
    text.push_str(&format!("\n{}\n", summary.statement));
    if !summary.key_behaviours.is_empty() {
        text.push_str("\nKey behaviours\n");
        text.push_str(&table(
            &["TIER", "RULE", "CATEGORY", "COUNT"],
            &summary
                .key_behaviours
                .iter()
                .map(|row| {
                    vec![
                        row.tier.to_uppercase(),
                        row.rule.clone(),
                        row.category.clone(),
                        row.count.to_string(),
                    ]
                })
                .collect::<Vec<_>>(),
        ));
    }
    if !summary.key_findings_text.is_empty() {
        text.push_str("\nKey findings\n");
        for line in &summary.key_findings_text {
            text.push_str(&format!("  {line}\n"));
        }
    }
    let extra: Vec<String> = parts
        .iter()
        .filter(|part| **part != Part::Summary)
        .map(|part| {
            let name = part_name(*part);
            let section = &all[name.as_str()];
            let rows = section
                .as_array()
                .map(Vec::len)
                .or_else(|| section["rows"].as_array().map(Vec::len))
                .or_else(|| section["tabs"].as_array().map(Vec::len));
            match rows {
                Some(rows) => format!("  {name}: {rows} rows (see -o json)"),
                None if section.is_null() => format!("  {name}: none"),
                None => format!("  {name}: see -o json"),
            }
        })
        .collect();
    if !extra.is_empty() {
        text.push_str("\nParts\n");
        text.push_str(&extra.join("\n"));
        text.push('\n');
    }
    if !notes.is_empty() {
        text.push_str("\nNotes\n");
        for note in notes {
            text.push_str(&format!("  - {note}\n"));
        }
    }
    text
}
