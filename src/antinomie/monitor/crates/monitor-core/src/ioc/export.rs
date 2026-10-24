// SPDX-License-Identifier: GPL-3.0-only
//! CSV and JSON of the indicators on one IOC tab, with their verdicts and the
//! dataset dates. The CSV is safe to open in a spreadsheet: a cell that starts
//! with `=`, `+`, `-`, `@`, a tab or a carriage return is prefixed with an
//! apostrophe, because indicator values come from malware.
use super::{
    indicator::{Indicator, Type},
    verdict::Verdict,
};
use serde_json::json;

/// The columns of the CSV, in order.
pub const COLUMNS: [&str; 17] = [
    "type",
    "indicator",
    "detail",
    "sources",
    "process",
    "first_seen_in_run",
    "last_seen_in_run",
    "count",
    "verdict",
    "dataset",
    "dataset_date",
    "record_id",
    "family",
    "confidence",
    "reported",
    "reference",
    "online",
];

fn when(us: Option<u64>) -> String {
    us.map(|us| {
        let seconds = i64::try_from(us / 1_000_000).unwrap_or(0);
        let nanos = ((us % 1_000_000) * 1000) as u32;
        utc_text(seconds, nanos)
    })
    .unwrap_or_default()
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` without a time library.
fn utc_text(seconds: i64, nanos: u32) -> String {
    let date = super::feeds::date_text(u64::try_from(seconds).unwrap_or(0));
    let day_seconds = seconds.rem_euclid(86_400);
    format!(
        "{date}T{:02}:{:02}:{:02}.{:03}Z",
        day_seconds / 3600,
        day_seconds % 3600 / 60,
        day_seconds % 60,
        nanos / 1_000_000
    )
}

fn row(indicator: &Indicator, verdict: &Verdict) -> Vec<String> {
    let primary = verdict
        .primary()
        .or_else(|| verdict.excused.as_ref().map(|(found, _)| found));
    let process = match (&indicator.process, indicator.candidates.is_empty()) {
        (Some(process), _) => process.label(),
        (None, false) => format!(
            "unattributed; candidates: {}",
            indicator
                .candidates
                .iter()
                .map(|p| p.label())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        (None, true) => String::new(),
    };
    let shown = if indicator.ty == Type::File && !indicator.path.is_empty() {
        format!("{} {}", indicator.value, indicator.path)
    } else {
        indicator.value.clone()
    };
    vec![
        indicator.ty.id().to_owned(),
        shown,
        indicator.sub.clone(),
        indicator
            .sources
            .iter()
            .map(|s| s.label())
            .collect::<Vec<_>>()
            .join(" "),
        process,
        when(indicator.first_us),
        when(indicator.last_us),
        indicator.count.clone(),
        match verdict.outcome {
            super::verdict::Outcome::NotChecked => format!("not checked: {}", verdict.why),
            other => other.label().to_owned(),
        },
        primary.map(|m| m.record.feed.clone()).unwrap_or_default(),
        verdict.date.clone().unwrap_or_default(),
        primary
            .map(|m| m.record.record_id.clone())
            .unwrap_or_default(),
        primary.map(|m| m.record.family.clone()).unwrap_or_default(),
        primary
            .and_then(|m| m.record.confidence)
            .map(|c| c.to_string())
            .unwrap_or_default(),
        primary
            .map(|m| m.record.first_seen.clone())
            .unwrap_or_default(),
        primary
            .map(|m| m.record.reference.clone())
            .unwrap_or_default(),
        match primary.and_then(|m| m.online_at) {
            Some(at) => when(Some(at * 1_000_000)),
            None => String::new(),
        },
    ]
}

fn cell(text: &str) -> String {
    let mut text = text.to_owned();
    if text.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        text.insert(0, '\'');
    }
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text
    }
}

/// CSV of `rows` (an indicator and its verdict each).
pub fn csv(rows: &[(&Indicator, &Verdict)]) -> String {
    let mut out = COLUMNS.join(",");
    out.push('\n');
    for (indicator, verdict) in rows {
        let cells: Vec<String> = row(indicator, verdict).iter().map(|c| cell(c)).collect();
        out.push_str(&cells.join(","));
        out.push('\n');
    }
    out
}

/// JSON of `rows`: one object per indicator with its verdict.
pub fn json(rows: &[(&Indicator, &Verdict)]) -> String {
    let items: Vec<_> = rows
        .iter()
        .map(|(indicator, verdict)| {
            let cells = row(indicator, verdict);
            let mut object = serde_json::Map::new();
            for (name, value) in COLUMNS.iter().zip(cells) {
                object.insert((*name).to_owned(), json!(value));
            }
            object.insert(
                "matches".into(),
                json!(verdict
                    .matches
                    .iter()
                    .map(|m| json!({
                        "dataset": m.record.feed,
                        "record_id": m.record.record_id,
                        "family": m.record.family,
                        "confidence": m.record.confidence,
                        "reported": m.record.first_seen,
                        "detail": m.record.detail,
                        "reference": m.record.reference,
                        "matched_value": m.lookup.value,
                        "matched_kind": m.lookup.kind.id(),
                        "online": m.online_at.is_some(),
                    }))
                    .collect::<Vec<_>>()),
            );
            if let Some((found, entry)) = &verdict.excused {
                object.insert(
                    "known_false_positive".into(),
                    json!({"reason": entry.reason, "dataset": found.record.feed, "record_id": found.record.record_id}),
                );
            }
            serde_json::Value::Object(object)
        })
        .collect();
    serde_json::to_string_pretty(&json!({"format": 1, "indicators": items})).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::{
        indicator::{Collector, Seen, Source},
        verdict::{LoadedFeed, OnlineResults, Scan},
    };

    fn sample() -> (Vec<Indicator>, Vec<Verdict>) {
        let mut c = Collector::default();
        c.endpoint(
            "203.0.113.45".parse().unwrap(),
            443,
            "tcp",
            Source::Pcap,
            Seen {
                time_us: Some(1_792_000_000_123_456),
                ..Seen::default()
            },
        );
        c.endpoint(
            "10.0.2.3".parse().unwrap(),
            53,
            "udp",
            Source::Pcap,
            Seen::default(),
        );
        c.domain(
            "=cmd|' /C calc'!A0.example",
            super::super::indicator::Via::Dns,
            &[],
            Source::Pcap,
            Seen::default(),
        );
        let all = c.finish();
        let scan = Scan {
            loaded: vec![LoadedFeed {
                id: "threatfox",
                name: "ThreatFox",
                date: "2026-10-22".into(),
                fetched_unix: 0,
            }],
            ..Scan::default()
        };
        let verdicts =
            crate::ioc::verdict::evaluate_all(&all, &scan, &[], &OnlineResults::default());
        (all, verdicts)
    }

    #[test]
    fn csv_has_the_dataset_dates_and_verdicts_and_defuses_formulas() {
        let (all, verdicts) = sample();
        let rows: Vec<_> = all.iter().zip(&verdicts).collect();
        let text = csv(&rows);
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines[0], COLUMNS.join(","));
        assert_eq!(lines.len(), 4);
        let ep = lines
            .iter()
            .find(|l| l.contains("203.0.113.45:443"))
            .unwrap();
        assert!(ep.contains("No match"), "{ep}");
        assert!(ep.contains("2026-10-22"), "{ep}");
        assert!(ep.contains("2026-10-14T17:46:40.123Z"), "{ep}");
        let private = lines.iter().find(|l| l.contains("10.0.2.3:53")).unwrap();
        assert!(
            private.contains("not checked: private address"),
            "{private}"
        );
        let formula = lines.iter().find(|l| l.contains("cmd|")).unwrap();
        assert!(formula.starts_with("domain,'=cmd|"), "{formula}");
    }

    #[test]
    fn json_lists_every_indicator_with_its_matches() {
        let (all, verdicts) = sample();
        let rows: Vec<_> = all.iter().zip(&verdicts).collect();
        let value: serde_json::Value = serde_json::from_str(&json(&rows)).unwrap();
        assert_eq!(value["format"], 1);
        assert_eq!(value["indicators"].as_array().unwrap().len(), 3);
        let first = &value["indicators"][0];
        assert_eq!(first["verdict"], "No match");
        assert_eq!(first["dataset_date"], "2026-10-22");
        assert!(first["matches"].as_array().unwrap().is_empty());
    }

    #[test]
    fn cells_with_separators_are_quoted() {
        assert_eq!(cell("a,b"), "\"a,b\"");
        assert_eq!(cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(cell("plain"), "plain");
        assert_eq!(cell("@x"), "'@x");
    }
}
