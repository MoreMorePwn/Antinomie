// SPDX-License-Identifier: GPL-3.0-only
//! The sample window's IOC tab as files: CSV and JSON of the rows chosen, and
//! the same rows as the merged indicators of a sample report, which the
//! report's MISP and STIX 2.1 writers turn into an event and a bundle. CSV
//! cells that could run as a formula are defused; the defang option rewrites
//! the indicator values (`hxxp`, `[.]`) in the CSV and JSON, never in MISP or
//! STIX, which keep raw values for tools. The app writes the files raw (the
//! JSON says `"defanged": false`): a defanged value fed to a blocklist is
//! useless, and the readable reports are where defanging belongs.
use super::ioc_union::SampleIoc;
use crate::{
    ioc::export::{cell, when},
    report::{IndicatorKind, defang, sample::MergedIndicator},
};
use serde_json::json;

/// The CSV columns, in order.
pub const COLUMNS: [&str; 13] = [
    "kind",
    "indicator",
    "path",
    "runs",
    "every_run",
    "observed",
    "first_seen",
    "last_seen",
    "process",
    "matched",
    "datasets",
    "families",
    "record_ids",
];

fn shown(row: &SampleIoc, defanged: bool) -> String {
    match (defanged, IndicatorKind::from_id(&row.ty)) {
        (true, Some(kind)) => defang::indicator(kind, &row.value),
        _ => row.value.clone(),
    }
}

fn runs_text(row: &SampleIoc) -> String {
    row.runs()
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

/// `dataset: family (id)` per hit.
pub fn hit_texts(row: &SampleIoc) -> Vec<String> {
    row.hits()
        .iter()
        .map(|hit| {
            format!(
                "{}{}{}",
                hit.dataset,
                if hit.family.is_empty() {
                    String::new()
                } else {
                    format!(": {}", hit.family)
                },
                if hit.record_id.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", hit.record_id)
                }
            )
        })
        .collect()
}

/// The rows as merged indicators of a sample report. `listed` is how many
/// runs have an indicator list.
pub fn merged(rows: &[SampleIoc], listed: usize) -> Vec<MergedIndicator> {
    rows.iter()
        .map(|row| MergedIndicator {
            kind: row.ty.clone(),
            value: row.value.clone(),
            matched: row.matched(),
            runs: row.runs(),
            path: row.path.clone(),
            every_run: row.in_every_run(listed),
            observed: row.observed(),
            first_us: row.first_us(),
            last_us: row.last_us(),
            hits: hit_texts(row),
        })
        .collect()
}

/// CSV of `rows`.
pub fn csv(rows: &[&SampleIoc], listed: usize, defanged: bool) -> String {
    let mut out = COLUMNS.join(",");
    out.push('\n');
    for row in rows {
        let hits = row.hits();
        let cells = [
            row.ty.clone(),
            shown(row, defanged),
            row.path.clone(),
            runs_text(row),
            row.in_every_run(listed).to_string(),
            row.observed().join("; "),
            when(row.first_us()),
            when(row.last_us()),
            row.processes().join("; "),
            row.matched().to_string(),
            hits.iter()
                .map(|hit| hit.dataset.clone())
                .collect::<Vec<_>>()
                .join("; "),
            hits.iter()
                .map(|hit| hit.family.clone())
                .collect::<Vec<_>>()
                .join("; "),
            hits.iter()
                .map(|hit| hit.record_id.clone())
                .collect::<Vec<_>>()
                .join("; "),
        ];
        let cells: Vec<String> = cells.iter().map(|text| cell(text)).collect();
        out.push_str(&cells.join(","));
        out.push('\n');
    }
    out
}

/// JSON of `rows`: one object per indicator with its sightings per run.
pub fn json(
    sample_sha256: &str,
    rows: &[&SampleIoc],
    listed: usize,
    defanged: bool,
    now_ms: u64,
) -> String {
    let items: Vec<_> = rows
        .iter()
        .map(|row| {
            json!({
                "kind": row.ty,
                "indicator": shown(row, defanged),
                "path": row.path,
                "runs": row.runs(),
                "every_run": row.in_every_run(listed),
                "observed": row.observed(),
                "first_seen": when(row.first_us()),
                "last_seen": when(row.last_us()),
                "processes": row.processes(),
                "matched": row.matched(),
                "hits": row.hits().iter().map(|hit| json!({
                    "dataset": hit.dataset,
                    "family": hit.family,
                    "record_id": hit.record_id,
                    "reference": hit.reference,
                })).collect::<Vec<_>>(),
                "sightings": row.sightings.iter().map(|seen| json!({
                    "run": seen.run,
                    "sources": seen.entry.sources,
                    "first_seen": when(seen.entry.first_us),
                    "last_seen": when(seen.entry.last_us),
                    "count": seen.entry.count,
                    "process": seen.entry.process,
                    "detail": seen.entry.sub,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "format": 1,
        "sample_sha256": sample_sha256,
        "generated_ms": now_ms,
        "defanged": defanged,
        "runs_with_indicators": listed,
        "indicators": items,
    }))
    .unwrap_or_default()
}
