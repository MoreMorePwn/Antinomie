// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The typed values of the report's table rows ([`report::RowData`]): pids
//! and task cookies, times in ms, counts, bytes, paths, endpoints, domains,
//! rules and techniques, read from the values Triage's cells carry. The core
//! links the report's entries from them (`report::refs::link`).
use super::*;
use antinomie_monitor_core::report::{KeyFinding, RowData};
use antinomie_monitor_core::HostClockAnchor;

/// A value of any cell of the row.
fn find<'a>(row: &'a [Cell], key: &str) -> Option<&'a RowValue> {
    row.iter()
        .flat_map(|cell| cell.values.iter())
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value)
}

fn number(row: &[Cell], key: &str) -> Option<u64> {
    match find(row, key)? {
        RowValue::Number(n) => u64::try_from(*n).ok(),
        _ => None,
    }
}

fn text(row: &[Cell], key: &str) -> String {
    match find(row, key) {
        Some(RowValue::Text(text)) => text.clone(),
        _ => String::new(),
    }
}

fn list(values: &[(&'static str, RowValue)], key: &str) -> Vec<String> {
    values
        .iter()
        .find_map(|(name, value)| match value {
            RowValue::List(items) if *name == key => Some(items.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// The moments of a guest event: ms since the epoch (through the clock
/// anchor) and ms since `start`.
fn when(
    ns: Option<u64>,
    clock: Option<HostClockAnchor>,
    start: Option<u64>,
) -> (Option<u64>, Option<u64>) {
    let Some(ns) = ns else {
        return (None, None);
    };
    let wall = clock
        .and_then(|clock| clock.host_us(ns))
        .map(|us| us / 1000);
    let relative = start.map(|start| ns.saturating_sub(start) / 1_000_000);
    (wall, relative)
}

fn pid(value: Option<u64>) -> Option<u32> {
    value
        .and_then(|v| u32::try_from(v).ok())
        .filter(|p| *p != 0)
}

/// The Process tree's rows.
pub fn processes(
    rows: &[Vec<Cell>],
    clock: Option<HostClockAnchor>,
    start: Option<u64>,
) -> Vec<RowData> {
    rows.iter()
        .map(|row| {
            let (time_ms, relative_ms) = when(number(row, "process.first_ns"), clock, start);
            RowData {
                pid: pid(number(row, "process.pid")),
                cookie: number(row, "process.cookie"),
                parent_pid: pid(number(row, "process.ppid")),
                parent_cookie: number(row, "process.parent_cookie"),
                depth: number(row, "process.depth").and_then(|d| u32::try_from(d).ok()),
                time_ms,
                relative_ms,
                count: number(row, "process.suspicious"),
                ..RowData::default()
            }
        })
        .collect()
}

/// Suspicious activity's rows.
pub fn findings(
    findings: &[Finding],
    clock: Option<HostClockAnchor>,
    start: Option<u64>,
) -> Vec<RowData> {
    findings
        .iter()
        .map(|finding| {
            let values = &finding.values;
            let num = |key: &str| super::super::files::number(values, key);
            let txt = |key: &str| {
                values
                    .iter()
                    .find_map(|(name, value)| match value {
                        RowValue::Text(text) if *name == key => Some(text.clone()),
                        _ => None,
                    })
                    .unwrap_or_default()
            };
            let first = num("finding.first_ns").or(num("event.time_ns"));
            let (time_ms, relative_ms) = when(first, clock, start);
            RowData {
                pid: pid(num("process.pid")),
                cookie: num("process.cookie"),
                rule: txt("finding.rule"),
                tier: txt("finding.tier"),
                target: txt("finding.object"),
                attack: list(values, "finding.technique"),
                count: num("finding.count"),
                time_ms,
                relative_ms,
                ..RowData::default()
            }
        })
        .collect()
}

/// A Files tab's rows: the path, the process and when.
pub fn files(
    rows: &[Vec<Cell>],
    path_column: usize,
    clock: Option<HostClockAnchor>,
    start: Option<u64>,
) -> Vec<RowData> {
    rows.iter()
        .map(|row| {
            let mut path = text(row, "file.path");
            if path.is_empty() {
                path = row
                    .get(path_column)
                    .map(|c| c.text.clone())
                    .unwrap_or_default();
            }
            let (time_ms, relative_ms) = when(number(row, "event.time_ns"), clock, start);
            RowData {
                pid: pid(number(row, "process.pid")),
                cookie: number(row, "process.cookie"),
                path: if path.starts_with('/') {
                    path
                } else {
                    String::new()
                },
                time_ms,
                relative_ms,
                ..RowData::default()
            }
        })
        .collect()
}

/// The leading number of a cell: `5480 bytes (5.4 KiB)` is 5480.
fn leading(text: &str) -> Option<u64> {
    let digits: String = text
        .trim_start_matches('#')
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == ',')
        .filter(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// A capture time (µs since the epoch) as ms since the epoch and ms since
/// `run_ms`, the run's first call; a time before the run has no relative.
pub fn capture_time(us: Option<u64>, run_ms: Option<u64>) -> (Option<u64>, Option<u64>) {
    let Some(ms) = us.map(|us| us / 1000) else {
        return (None, None);
    };
    (Some(ms), run_ms.and_then(|start| ms.checked_sub(start)))
}

/// The run's first call as ms since the epoch, through the clock anchor.
pub fn run_start_ms(clock: Option<HostClockAnchor>, start_ns: Option<u64>) -> Option<u64> {
    clock?.host_us(start_ns?).map(|us| us / 1000)
}

/// A Network tab's rows, by the tab's columns; `run_ms` is the run's first
/// call ([`run_start_ms`]) for the times.
pub fn network(
    name: &str,
    headers: &[&str],
    rows: &[Vec<Cell>],
    run_ms: Option<u64>,
) -> Vec<RowData> {
    let source = |row: &[Cell]| {
        (
            number(row, "network.source_pid"),
            number(row, "network.source_cookie"),
        )
    };
    let col = |title: &str| headers.iter().position(|h| *h == title);
    let cell = |row: &[Cell], title: &str| -> String {
        col(title)
            .and_then(|at| row.get(at))
            .map(|c| c.text.trim().to_owned())
            .unwrap_or_default()
    };
    rows.iter()
        .map(|row| {
            let mut data = network_row(name, row, &cell);
            if name == "Endpoints" {
                // The process that made the flow, so the Source links to it.
                let (pid, cookie) = source(row);
                data.pid = pid.and_then(|pid| u32::try_from(pid).ok());
                data.cookie = cookie;
            }
            let first = number(row, "network.first_us").or(number(row, "frame.time_us"));
            (data.time_ms, data.relative_ms) = capture_time(first, run_ms);
            (data.last_ms, data.last_relative_ms) =
                capture_time(number(row, "network.last_us"), run_ms);
            data
        })
        .collect()
}

fn network_row(name: &str, row: &[Cell], cell: &dyn Fn(&[Cell], &str) -> String) -> RowData {
    match name {
        "Endpoints" => RowData {
            endpoint: cell(row, "Endpoint"),
            count: leading(&cell(row, "Frames")),
            bytes: leading(&cell(row, "Bytes")),
            ..RowData::default()
        },
        "Domains" => RowData {
            domain: cell(row, "Domain"),
            addresses: cell(row, "Resolved / connected IPs")
                .split(", ")
                .map(str::trim)
                .filter(|ip| !ip.is_empty())
                .map(str::to_owned)
                .collect(),
            count: leading(&cell(row, "Queries")),
            ..RowData::default()
        },
        "URLs" => RowData {
            endpoint: cell(row, "Endpoint"),
            domain: cell(row, "Host"),
            ..RowData::default()
        },
        "TLS" => RowData {
            endpoint: cell(row, "Endpoint"),
            domain: cell(row, "Server name"),
            count: leading(&cell(row, "Sessions")),
            ..RowData::default()
        },
        _ => RowData::default(),
    }
}

/// The Summary's Key findings, worst first, with how many there are.
pub fn key_findings(
    findings: &[Finding],
    clock: Option<HostClockAnchor>,
    start: Option<u64>,
    limit: usize,
) -> (u64, Vec<KeyFinding>) {
    let (total, keys) = super::super::summary::key_findings_for_report(findings, limit);
    let rows = keys
        .into_iter()
        .map(|key| {
            let (first_ms, relative_ms) =
                when(Some(key.first_ns).filter(|ns| *ns > 0), clock, start);
            let process = std::path::Path::new(&key.exe)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or(key.exe.clone());
            KeyFinding {
                tier: key.tier,
                rule: key.rule,
                title: key.title,
                target: key.target,
                process,
                pid: (key.pid != 0).then_some(key.pid),
                cookie: (key.cookie != 0).then_some(key.cookie),
                count: key.count,
                first_ms,
                relative_ms,
                attack: findings
                    .get(key.index)
                    .map(|f| list(&f.values, "finding.technique"))
                    .unwrap_or_default(),
                why: key.why,
                finding: Some(key.index + 1),
                ..KeyFinding::default()
            }
        })
        .collect();
    (total as u64, rows)
}
