// SPDX-License-Identifier: GPL-3.0-only
//! `report RUN` (design 3.4.3): index the whole saved run and write its report
//! in the chosen formats. The job is the GUI's Export report job
//! (`antinomie_triage::report_export`), so the files are the ones the dialog
//! writes for the same run and choices. No engine lock: nothing is written
//! into the recording apart from the index Triage keeps there.
use super::recording::{RUN_HELP, index, open_saved, run_value};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, block, table},
};
use antinomie_monitor_core::report::{Choices, Format, Part};
use antinomie_triage::{report_export, time_format};
use clap::Args;
use serde_json::json;
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

#[derive(Args, Debug)]
pub struct Report {
    #[arg(help = RUN_HELP)]
    pub run: String,
    /// Formats, comma separated: html, pdf, json, misp, stix, md (or all)
    /// [default: the data directory's export choices, HTML and PDF unless set].
    /// (`--format` is the global output format.)
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    pub formats: Vec<String>,
    /// Parts, comma separated: summary, indicators, attack, processes,
    /// findings, files, file_activity, network, detections, evidence, custody
    /// (or all) [default: the export choices, every part unless set].
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    pub parts: Vec<String>,
    /// Also write the evidence bundle (.zip next to the report): the captures,
    /// the files the run dropped in an inner AES-256 zip (password: infected),
    /// the sample's custody export and a SHA-256 manifest. (`--bundle` is the
    /// global boot-bundle folder.)
    #[arg(long)]
    pub evidence_bundle: bool,
    /// Defang indicators in HTML, PDF and Markdown (hxxp://example[.]com).
    #[arg(long, conflicts_with = "no_defang")]
    pub defang: bool,
    /// Keep indicators as they are in every format.
    #[arg(long)]
    pub no_defang: bool,
    /// Keep a clipped, escaped preview of what the sample read in the Read
    /// files rows (never of a file the run wrote).
    #[arg(long)]
    pub include_content: bool,
    /// Folder for the files [default: report-<first 8 of the run id> in the
    /// current folder]. Created when missing.
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,
}

/// A comma list of report parts; `all` is every part.
pub fn parse_parts(items: &[String]) -> Result<Vec<Part>, CliError> {
    let mut parts = Vec::new();
    for item in items.iter().map(|item| item.trim().to_ascii_lowercase()) {
        if item == "all" {
            return Ok(Part::ALL.to_vec());
        }
        let part = serde_json::from_value::<Part>(json!(item.replace('-', "_"))).map_err(|_| {
            CliError::invalid(format!(
                "unknown part {item:?}; the parts are {}",
                Part::ALL
                    .iter()
                    .map(|part| part_name(*part))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .with_field("parts")
        })?;
        if !parts.contains(&part) {
            parts.push(part);
        }
    }
    Ok(parts)
}

/// The name of `part` on the command line and in JSON.
pub fn part_name(part: Part) -> String {
    serde_json::to_value(part)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// A comma list of formats; `md` is Markdown, `all` every format.
pub fn parse_formats(items: &[String]) -> Result<Vec<Format>, CliError> {
    let mut formats = Vec::new();
    for item in items.iter().map(|item| item.trim().to_ascii_lowercase()) {
        let format = match item.as_str() {
            "all" => return Ok(Format::ALL.to_vec()),
            "html" => Format::Html,
            "pdf" => Format::Pdf,
            "json" => Format::Json,
            "misp" => Format::Misp,
            "stix" | "stix2" => Format::Stix,
            "md" | "markdown" => Format::Markdown,
            _ => {
                return Err(CliError::invalid(format!(
                    "unknown format {item:?}; the formats are html, pdf, json, misp, stix, md"
                ))
                .with_field("formats"));
            }
        };
        if !formats.contains(&format) {
            formats.push(format);
        }
    }
    Ok(formats)
}

/// The choices the GUI's dialog would start with for this data directory
/// (`settings.json`'s `report_export`, the defaults when unset).
pub fn stored_choices(context: &Context) -> Result<Choices, CliError> {
    antinomie_monitor_core::settings::load(context.data_dir())
        .map(|stored| stored.unwrap_or_default().report_export)
        .map_err(|error| {
            CliError::new(
                ErrorCode::PreconditionFailed,
                format!("settings.json cannot be read: {error}"),
            )
        })
}

fn choices(arguments: &Report, context: &Context, run_id: &str) -> Result<Choices, CliError> {
    let mut choices = stored_choices(context)?;
    if !arguments.formats.is_empty() {
        choices.formats = parse_formats(&arguments.formats)?;
    }
    if !arguments.parts.is_empty() {
        choices.parts = parse_parts(&arguments.parts)?;
    }
    choices.bundle |= arguments.evidence_bundle;
    if arguments.defang {
        choices.defang = true;
    }
    if arguments.no_defang {
        choices.defang = false;
    }
    choices.include_content |= arguments.include_content;
    let out = arguments
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("report-{}", short(run_id))));
    let out = std::path::absolute(&out).unwrap_or(out);
    choices.folder = out.display().to_string();
    if choices.formats.is_empty() && !choices.bundle {
        return Err(
            CliError::invalid("choose a format (--formats) or --evidence-bundle")
                .with_field("formats"),
        );
    }
    Ok(choices)
}

fn short(id: &str) -> String {
    id.chars().take(8).collect()
}

pub fn run(arguments: &Report, context: &Context) -> Result<Reply, CliError> {
    let saved = open_saved(context, &arguments.run)?;
    let choices = choices(arguments, context, &saved.run.id)?;
    let job = report_export::Job::for_saved(&saved, choices, time_format::now_ms());
    // A large recording is read whole unless an index of it is at hand: say
    // so before the wait (the progress lines follow; Ctrl-C stops it).
    let large = report_export::large_run(&job);
    if let Some(large) = &large {
        context.logger.warn(&large.warning());
    }
    let scan = index(context, &saved)?;
    std::fs::create_dir_all(&job.folder).map_err(|error| CliError::io(&job.folder, &error))?;
    context.logger.info("building the report");
    let (job, built) = report_export::build_report(&job, &scan).map_err(|error| {
        CliError::new(
            ErrorCode::Internal,
            format!("cannot build the report: {error}"),
        )
    })?;
    let logger = context.logger;
    let written =
        report_export::write_built(&job, built, &Arc::new(AtomicBool::new(false)), &|status| {
            logger.info(status)
        })
        .map_err(|error| {
            CliError::new(
                ErrorCode::Internal,
                format!("cannot write the report: {error}"),
            )
        })?;
    let files: Vec<_> = written
        .files
        .iter()
        .map(|(label, path)| json!({"format": label, "path": path}))
        .collect();
    let skipped: Vec<_> = written
        .bundle
        .as_ref()
        .map(|bundle| {
            bundle
                .skipped
                .iter()
                .map(|(what, why)| json!({"what": what, "why": why}))
                .collect()
        })
        .unwrap_or_default();
    let mut value = json!({
        "run": run_value(&saved),
        "folder": job.folder,
        "formats": job.choices.formats.iter().map(|format| format.label()).collect::<Vec<_>>(),
        "parts": job.choices.parts.iter().map(|part| part_name(*part)).collect::<Vec<_>>(),
        "defang": job.choices.defang,
        "bundle": job.choices.bundle,
        "files": files,
        "not_in_bundle": skipped,
    });
    if let Some(large) = &large {
        value["large_recording"] = json!({
            "bytes": large.bytes,
            "estimated_seconds": large.seconds,
        });
    }
    let mut human = block(&[
        ("run", saved.run.id.clone()),
        ("folder", job.folder.display().to_string()),
    ]);
    human.push('\n');
    human.push_str(&table(
        &["FORMAT", "FILE"],
        &written
            .files
            .iter()
            .map(|(label, path)| vec![label.to_string(), path.display().to_string()])
            .collect::<Vec<_>>(),
    ));
    for row in &skipped {
        human.push_str(&format!(
            "Not in the bundle: {} ({})\n",
            row["what"].as_str().unwrap_or_default(),
            row["why"].as_str().unwrap_or_default()
        ));
    }
    Ok(Reply::value(value).with_human(human))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(text: &str) -> Vec<String> {
        text.split(',').map(str::to_owned).collect()
    }

    #[test]
    fn parts_and_formats_parse_by_their_names() {
        assert_eq!(
            parse_parts(&items("summary,file_activity,file-activity")).unwrap(),
            [Part::Summary, Part::FileActivity]
        );
        assert_eq!(parse_parts(&items("all")).unwrap(), Part::ALL);
        assert!(parse_parts(&items("summary,bogus")).is_err());
        assert_eq!(
            parse_formats(&items("html,md,STIX,json")).unwrap(),
            [Format::Html, Format::Markdown, Format::Stix, Format::Json]
        );
        assert_eq!(parse_formats(&items("all")).unwrap(), Format::ALL);
        assert!(parse_formats(&items("docx")).is_err());
        assert_eq!(part_name(Part::FileActivity), "file_activity");
    }

    /// `--format` (output) and `--bundle` (boot bundle) are global flags: the
    /// report's own are `--formats` and `--evidence-bundle`.
    #[test]
    fn the_report_flags_do_not_collide_with_the_global_ones() {
        use clap::Parser;
        let cli = crate::args::Cli::try_parse_from([
            "antinomie-cli",
            "report",
            "r1",
            "--formats",
            "json,md",
            "--evidence-bundle",
            "--no-defang",
            "--format",
            "json",
            "--bundle",
            "/b",
        ])
        .unwrap();
        let crate::commands::Command::Report(report) = cli.command else {
            panic!("report");
        };
        assert_eq!(report.formats, ["json", "md"]);
        assert!(report.evidence_bundle && report.no_defang && !report.defang);
        assert_eq!(cli.global.format, Some(crate::output::Format::Json));
        assert_eq!(cli.global.bundle, Some(PathBuf::from("/b")));
        for command in ["triage", "detect"] {
            assert!(
                crate::args::Cli::try_parse_from(["antinomie-cli", command, "r1", "-o", "json"])
                    .is_ok()
            );
        }
    }
}
