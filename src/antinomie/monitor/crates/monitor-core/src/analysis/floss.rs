// SPDX-License-Identifier: GPL-3.0-only
//! Strings an installed FLOSS recovers by emulating the program's own code:
//! decoded, stack and tight strings, and Go and Rust strings. FLOSS analyses
//! the file with its own disassembler; it never runs the specimen.
use super::tools;
use super::*;
use std::{path::Path, time::Duration};

const MANAGED: &str = "/opt/antinomie-tools/floss/floss";
/// Wall-clock budget of one FLOSS run. Emulating every candidate routine of a
/// statically linked program takes far longer than this, and is cut off.
pub(super) const TIMEOUT_SECONDS: u64 = 480;
/// FLOSS refuses larger files unless it is told to take them (`-L`).
const SPECIMEN_MAX_SIZE: u64 = 16 * 1024 * 1024;
/// FLOSS prints its whole result as one JSON document at the end.
const OUTPUT_MAX_SIZE: usize = 32 * 1024 * 1024;
/// Strings kept in the full listing.
const STRING_MAX_COUNT: usize = 50_000;
/// Strings shown in the report itself, before the listing.
const REPORT_ROWS: usize = 256;

/// One string FLOSS reported.
#[derive(Debug, PartialEq, Eq)]
struct Found {
    origin: &'static str,
    text: String,
    encoding: String,
    function: Option<u64>,
    address: Option<u64>,
    /// File offset, for the strings FLOSS finds by reading the file.
    offset: Option<u64>,
}

pub(super) fn strings(section: &mut AnalysisSection, specimen_len: u64, listings: &Path) {
    let Some(floss) = tools::find_tool(crate::analysis_tools::FLOSS_SYSTEM, MANAGED) else {
        section.state = AnalysisSectionState::Unavailable;
        section.summary =
            "FLOSS is not installed; install it from Tools > Analysis tools (or on the system)"
                .into();
        return;
    };
    run(section, floss, specimen_len, listings);
}

fn run(section: &mut AnalysisSection, floss: &str, specimen_len: u64, listings: &Path) {
    if specimen_len > SPECIMEN_MAX_SIZE {
        section.state = AnalysisSectionState::Unavailable;
        section.summary = format!(
            "FLOSS does not take files over {} MiB; this file is {} MiB",
            SPECIMEN_MAX_SIZE >> 20,
            specimen_len.div_ceil(1 << 20)
        );
        super::limits::add(
            section,
            AnalysisLimitKind::Size,
            format!(
                "The file is larger than the {} MiB FLOSS is given.",
                SPECIMEN_MAX_SIZE >> 20
            ),
            None,
        );
        return;
    }
    // The plain strings are the Strings category's job; `--` ends the list of
    // string types, which would otherwise take the file name.
    let timeout = Duration::from_secs(super::limits::seconds(TIMEOUT_SECONDS));
    let run = match tools::run_with(
        floss,
        &[
            "-j",
            "-q",
            "--disable-progress",
            "--no",
            "static",
            "--",
            "/input/specimen",
        ],
        &[("HOME", "/tmp")],
        timeout,
        OUTPUT_MAX_SIZE,
        true,
    ) {
        Ok(run) => run,
        Err(error) => {
            section.state = AnalysisSectionState::Unavailable;
            section.summary = format!("FLOSS failed to start: {error}");
            return;
        }
    };
    section.tools = vec![tools::version(floss, &["--version"])];
    let found = match parse(&run.stdout) {
        Ok(found) if !run.truncated => found,
        _ => {
            if run.timed_out && !run.truncated {
                super::limits::time_out(
                    section,
                    "FLOSS",
                    timeout.as_secs(),
                    "FLOSS found nothing before it was stopped; programs with many routines, statically linked ones especially, take it much longer",
                );
                return;
            }
            section.state = AnalysisSectionState::Unavailable;
            section.summary = if run.truncated {
                super::limits::add(
                    section,
                    AnalysisLimitKind::Size,
                    format!(
                        "FLOSS printed more than the {} MiB the analysis reads.",
                        OUTPUT_MAX_SIZE >> 20
                    ),
                    None,
                );
                format!(
                    "FLOSS printed more than {} MiB; its result was not read",
                    OUTPUT_MAX_SIZE >> 20
                )
            } else {
                run.failure_text("FLOSS", timeout).unwrap_or_else(|| {
                    "FLOSS printed no readable result; the file format may be unsupported by FLOSS (it takes PE and ELF programs and raw shellcode)".into()
                })
            };
            return;
        }
    };
    let mut writer = super::listing::ListingWriter::create(
        listings,
        AnalysisKind::Floss,
        super::listing::LISTING_MAX_SIZE,
    )
    .ok();
    let mut full = false;
    let mut counts = [0usize; 4];
    for (index, string) in found.iter().take(STRING_MAX_COUNT).enumerate() {
        let (location, data) = record(string, specimen_len);
        counts[ORIGINS
            .iter()
            .position(|o| *o == string.origin)
            .unwrap_or(0)] += 1;
        if index < REPORT_ROWS {
            super::worker::structured_entry(
                section,
                string.origin,
                string.text.clone(),
                location.clone(),
                data.clone(),
            );
        }
        if let Some(writer) = writer.as_mut()
            && !full
            && !writer.push(string.origin, string.text.clone(), location, data)
        {
            full = true;
        }
    }
    let capped = found.len() > STRING_MAX_COUNT;
    section.state = AnalysisSectionState::Complete;
    if capped {
        section.state = AnalysisSectionState::Partial;
        super::limits::add(
            section,
            AnalysisLimitKind::Rows,
            format!(
                "FLOSS found {} strings; the listing keeps the first {}.",
                super::detection::group_digits(found.len() as u64),
                super::detection::group_digits(STRING_MAX_COUNT as u64)
            ),
            None,
        );
    }
    if let Some(listing) = writer.and_then(|writer| writer.finish(full || capped).ok()) {
        if full {
            section.state = AnalysisSectionState::Partial;
            super::limits::add(
                section,
                AnalysisLimitKind::Size,
                format!(
                    "The listing reached its {} limit after {} strings; later strings are not listed.",
                    crate::byte_size::short_size(super::listing::LISTING_MAX_SIZE),
                    super::detection::group_digits(listing.rows)
                ),
                None,
            );
        }
        section.listing = Some(listing);
    } else if found.len() > REPORT_ROWS {
        section.state = AnalysisSectionState::Partial;
        super::limits::add(
            section,
            AnalysisLimitKind::Rows,
            format!(
                "The listing could not be written, so the report keeps only the first {REPORT_ROWS} of {} strings.",
                super::detection::group_digits(found.len() as u64)
            ),
            None,
        );
    }
    let [decoded, stack, tight, language] = counts;
    section.summary = format!(
        "{} strings from FLOSS: {decoded} decoded, {stack} stack, {tight} tight, {language} Go or Rust; addresses are the ones FLOSS reports",
        found.len().min(STRING_MAX_COUNT)
    );
}

const ORIGINS: [&str; 4] = ["decoded", "stack", "tight", "language"];

fn record(string: &Found, specimen_len: u64) -> (Option<AnalysisLocation>, AnalysisData) {
    let location = match (string.offset, string.function) {
        (Some(offset), _) if offset <= specimen_len => {
            let len = if string.encoding.starts_with("UTF-16") {
                string.text.chars().count() as u64 * 2
            } else {
                string.text.len() as u64
            };
            Some(AnalysisLocation {
                kind: AnalysisAddressKind::FileOffset,
                value: offset,
                file_range: offset
                    .checked_add(len)
                    .filter(|end| *end <= specimen_len && len > 0)
                    .map(|_| AnalysisRange { offset, len }),
            })
        }
        (None, Some(function)) => Some(AnalysisLocation {
            kind: AnalysisAddressKind::ObjectAddress,
            value: function,
            file_range: None,
        }),
        _ => None,
    };
    (
        location,
        AnalysisData::FlossString {
            origin: string.origin.into(),
            encoding: string.encoding.clone(),
            function: string.function.filter(|_| string.offset.is_none()),
            address: string.address,
        },
    )
}

/// The strings of FLOSS's JSON document, once each: decoded, then stack,
/// tight and language strings, in the order FLOSS lists them.
fn parse(output: &str) -> Result<Vec<Found>, String> {
    let json: serde_json::Value = serde_json::from_str(output).map_err(|e| e.to_string())?;
    let strings = json
        .get("strings")
        .and_then(|strings| strings.as_object())
        .ok_or("no strings object")?;
    let mut found: Vec<Found> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (key, origin, function_key, address_key) in [
        (
            "decoded_strings",
            "decoded",
            "decoding_routine",
            "decoded_at",
        ),
        ("stack_strings", "stack", "function", "program_counter"),
        ("tight_strings", "tight", "function", "program_counter"),
        ("language_strings", "language", "", ""),
    ] {
        let Some(items) = strings.get(key).and_then(|items| items.as_array()) else {
            continue;
        };
        for item in items {
            let Some(text) = item.get("string").and_then(|text| text.as_str()) else {
                continue;
            };
            let number = |key: &str| item.get(key).and_then(|value| value.as_u64());
            let string = Found {
                origin,
                text: text.to_owned(),
                encoding: item
                    .get("encoding")
                    .and_then(|encoding| encoding.as_str())
                    .filter(|encoding| !encoding.is_empty() && encoding.len() <= 32)
                    .unwrap_or("ASCII")
                    .to_owned(),
                function: number(function_key),
                address: number(address_key),
                offset: number("offset").filter(|_| origin == "language"),
            };
            let identity = (origin, text.to_owned(), string.function, string.offset);
            if !text.is_empty() && seen.insert(identity) {
                found.push(string);
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests;
