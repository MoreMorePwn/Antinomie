// SPDX-License-Identifier: GPL-3.0-only
//! `triage RUN` (design 3.4.3): index the whole saved run as the GUI does when
//! it is selected and print what Triage's Summary says of it: the assessment,
//! the counts and the key behaviours, from the same builder as the exported
//! report. `--parts` adds report parts to the result. No engine lock, nothing
//! written but the index Triage keeps in the recording.
use super::{
    query::Client,
    recording::{RUN_HELP, index, open_saved, run_value},
    report::{parse_parts, part_name},
};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, block, table},
};
use antinomie_monitor_core::report::{Choices, Part};
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

/// The summary comes from the query API (`recording.summary`), the one the web
/// pages use; the parts come from the report builder over the same index,
/// which the query service leaves in the process for them.
pub fn run(arguments: &Triage, context: &Context) -> Result<Reply, CliError> {
    let parts: Vec<Part> = parse_parts(&arguments.parts)?
        .into_iter()
        .filter(|part| *part != Part::Summary)
        .collect();
    let saved = open_saved(context, &arguments.run)?;
    let client = Client::new(context);
    let params = json!({"run_key": client.key_of(&saved.run)?});
    let reply = client.call("recording.summary", params.clone())?;
    let detail = client.call("recording.run.get", params)?;
    let summary = reply["value"].clone();
    let partial = reply["partial"] == json!(true);
    let mut value = Map::new();
    value.insert("run".into(), run_value(&saved));
    value.insert("sample".into(), json!(saved.run.request.sample));
    value.insert("state".into(), detail["value"]["state"].clone());
    value.insert("phase".into(), reply["phase"].clone());
    value.insert("partial".into(), json!(partial));
    value.insert("generation".into(), reply["generation"].clone());
    value.insert("summary".into(), summary.clone());
    let mut notes = Vec::new();
    let mut all = Value::Null;
    if !parts.is_empty() {
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
                format!("cannot build the report parts: {error}"),
            )
        })?;
        notes = built.report.notes.clone();
        all = serde_json::to_value(&built.report)
            .map_err(|error| CliError::internal(error.to_string()))?;
        for part in &parts {
            let name = part_name(*part);
            value.insert(name.clone(), all[name.as_str()].clone());
        }
        value.insert("notes".into(), json!(notes));
    }
    let human = human(
        &saved.run.id,
        &detail["value"],
        &summary,
        partial,
        &notes,
        &all,
        &parts,
    );
    Ok(Reply::value(Value::Object(value)).with_human(human))
}

fn text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn human(
    run_id: &str,
    detail: &Value,
    summary: &Value,
    partial: bool,
    notes: &[String],
    all: &Value,
    parts: &[Part],
) -> String {
    let counts = &summary["counts"];
    let list = |name: &str| {
        summary[name]
            .as_array()
            .map(|items| items.iter().map(text).collect::<Vec<_>>().join(", "))
            .unwrap_or_default()
    };
    let mut text_out = block(&[
        ("run", run_id.to_owned()),
        ("state", text(&detail["state"])),
        ("assessment", text(&summary["assessment"])),
        ("highest tier", text(&summary["highest_tier"])),
        (
            "counts",
            format!(
                "{} processes · {} findings · {} indicators ({} matched) · {} techniques · {} files changed · {} endpoints · {} domains",
                text(&counts["processes"]),
                text(&counts["findings"]),
                text(&counts["indicators"]),
                text(&counts["indicators_matched"]),
                text(&counts["techniques"]),
                text(&counts["files_changed"]),
                text(&counts["endpoints"]),
                text(&counts["domains"]),
            ),
        ),
        ("families", list("families")),
        ("techniques", list("techniques")),
    ]);
    text_out.push_str(&format!("\n{}\n", text(&summary["basis"])));
    let behaviours = summary["key_behaviours"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !behaviours.is_empty() {
        text_out.push_str("\nKey behaviours\n");
        text_out.push_str(&table(
            &["TIER", "RULE", "CATEGORY", "COUNT"],
            &behaviours
                .iter()
                .map(|row| {
                    vec![
                        text(&row["tier"]).to_uppercase(),
                        text(&row["rule"]),
                        text(&row["category"]),
                        text(&row["count"]),
                    ]
                })
                .collect::<Vec<_>>(),
        ));
    }
    let detections = summary["detections"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !detections.is_empty() {
        text_out.push_str("\nDetections\n");
        text_out.push_str(&table(
            &["ENGINE", "RULE", "SEVERITY", "COUNT"],
            &detections
                .iter()
                .map(|row| {
                    vec![
                        text(&row["engine"]),
                        text(&row["rule_id"]),
                        text(&row["severity"]),
                        text(&row["count"]),
                    ]
                })
                .collect::<Vec<_>>(),
        ));
    }
    if !parts.is_empty() {
        text_out.push_str("\nParts\n");
        for part in parts {
            let name = part_name(*part);
            let section = &all[name.as_str()];
            let rows = section
                .as_array()
                .map(Vec::len)
                .or_else(|| section["rows"].as_array().map(Vec::len))
                .or_else(|| section["tabs"].as_array().map(Vec::len));
            text_out.push_str(&match rows {
                Some(rows) => format!("  {name}: {rows} rows (see -o json)\n"),
                None if section.is_null() => format!("  {name}: none\n"),
                None => format!("  {name}: see -o json\n"),
            });
        }
    }
    if partial || !notes.is_empty() {
        text_out.push_str("\nNotes\n");
        if partial {
            text_out.push_str("  - the index is partial: the recording was not whole\n");
        }
        for note in notes {
            text_out.push_str(&format!("  - {note}\n"));
        }
    }
    text_out
}
