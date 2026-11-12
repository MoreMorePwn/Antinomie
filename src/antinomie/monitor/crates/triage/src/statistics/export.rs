// SPDX-License-Identifier: GPL-3.0-only
//! Tables as text for the clipboard and the export files (design 8).
//!
//! Pure functions: the window passes a result in and writes the text out.
//! Numbers are raw, in the base unit named in the column title (`ns`, calls).
use super::aggregate::GroupRow;
use super::blocking::BlockClass;
use super::{views, RunStatistics, SCHEMA};
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq)]
pub enum Cell {
    Text(String),
    Num(u64),
    Empty,
}

impl Cell {
    fn text(&self) -> String {
        match self {
            Self::Text(text) => text.clone(),
            Self::Num(n) => n.to_string(),
            Self::Empty => String::new(),
        }
    }

    fn json(&self) -> Value {
        match self {
            Self::Text(text) => json!(text),
            Self::Num(n) => json!(n),
            Self::Empty => Value::Null,
        }
    }
}

/// One table of the window.
#[derive(Clone, Debug, PartialEq)]
pub struct Table {
    /// `hierarchy`, `latency`, `rate`, `slowest`, `quality`.
    pub name: &'static str,
    /// Machine keys with the unit (`duration_ns`), also the CSV header.
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Cell>>,
}

impl Table {
    /// Tab-separated, header first; tabs and line breaks in a cell become spaces.
    pub fn to_tsv(&self) -> String {
        let mut out = self.columns.join("\t");
        out.push('\n');
        for row in &self.rows {
            let line: Vec<String> = row
                .iter()
                .map(|cell| cell.text().replace(['\t', '\r', '\n'], " "))
                .collect();
            out.push_str(&line.join("\t"));
            out.push('\n');
        }
        out
    }

    /// RFC 4180: CRLF line ends, a field with a comma, quote or line break in quotes.
    pub fn to_csv(&self) -> String {
        let mut out = String::new();
        let mut line = |fields: Vec<String>| {
            let quoted: Vec<String> = fields.into_iter().map(|f| csv_field(&f)).collect();
            out.push_str(&quoted.join(","));
            out.push_str("\r\n");
        };
        line(self.columns.clone());
        for row in &self.rows {
            line(row.iter().map(Cell::text).collect());
        }
        out
    }

    fn json_rows(&self) -> Vec<Value> {
        self.rows
            .iter()
            .map(|row| {
                let object: serde_json::Map<String, Value> = self
                    .columns
                    .iter()
                    .zip(row)
                    .map(|(key, cell)| (key.clone(), cell.json()))
                    .collect();
                Value::Object(object)
            })
            .collect()
    }
}

fn csv_field(field: &str) -> String {
    if field.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

/// What a table's JSON file says about where it came from.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ExportContext {
    pub run_id: String,
    pub vm: String,
    pub boot: String,
    /// `guest`, `since start`, `host clock` (design 7).
    pub time_base: String,
}

/// `{"schema", "run", "stamp", "filter", "time_base", "accelerator", "quality", "table", "rows"}`.
pub fn table_json(context: &ExportContext, stats: &RunStatistics, table: &Table) -> String {
    let document = json!({
        "schema": SCHEMA,
        "run": {"id": context.run_id, "vm": context.vm, "boot": context.boot},
        "stamp": stats.stamp,
        "filter": stats.filter,
        "time_base": context.time_base,
        "accelerator": stats.quality.accelerator,
        "quality": stats.quality,
        "table": table.name,
        "rows": table.json_rows(),
    });
    serde_json::to_string_pretty(&document).unwrap_or_default()
}

/// *All statistics as JSON*: the serialized result.
pub fn all_json(stats: &RunStatistics) -> String {
    serde_json::to_string_pretty(stats).unwrap_or_default()
}

fn cols(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

fn text(value: &str) -> Cell {
    Cell::Text(value.to_owned())
}

/// The hierarchy as flat rows: group, call, result, calls, failed.
/// `failed_only` and `by_error` are the window's two switches.
pub fn hierarchy_table(stats: &RunStatistics, failed_only: bool, by_error: bool) -> Table {
    if by_error {
        let pivot = views::by_error(&stats.hierarchy, failed_only);
        let mut rows = Vec::new();
        for row in &pivot.rows {
            rows.push(vec![
                Cell::Text(row.result.label()),
                Cell::Empty,
                Cell::Num(row.calls),
            ]);
            for (name, n) in &row.by_call {
                rows.push(vec![
                    Cell::Text(row.result.label()),
                    text(name),
                    Cell::Num(*n),
                ]);
            }
        }
        for (name, n) in &pivot.other_errors {
            rows.push(vec![text("other errors"), text(name), Cell::Num(*n)]);
        }
        return Table {
            name: "hierarchy",
            columns: cols(&["result", "call", "calls"]),
            rows,
        };
    }
    let groups: Vec<GroupRow> = if failed_only {
        views::failed_only(&stats.hierarchy)
    } else {
        stats.hierarchy.clone()
    };
    let mut rows = Vec::new();
    for group in &groups {
        rows.push(vec![
            text(&group.group),
            Cell::Empty,
            Cell::Empty,
            Cell::Num(group.calls),
            Cell::Num(group.failed),
        ]);
        for call in &group.calls_by_name {
            rows.push(vec![
                text(&group.group),
                text(&call.name),
                Cell::Empty,
                Cell::Num(call.calls),
                Cell::Num(call.failed),
            ]);
            for (key, n) in &call.results {
                let failed = u64::from(key.is_error()) * n;
                rows.push(vec![
                    text(&group.group),
                    text(&call.name),
                    Cell::Text(key.label()),
                    Cell::Num(*n),
                    Cell::Num(failed),
                ]);
            }
        }
    }
    Table {
        name: "hierarchy",
        columns: cols(&["group", "call", "result", "calls", "failed"]),
        rows,
    }
}

/// The latency rows of the calls that wait by design (`waits`) or of the others.
pub fn latency_table(stats: &RunStatistics, waits: bool) -> Table {
    let rows = stats
        .latency
        .iter()
        .filter(|row| (row.class == BlockClass::Waits) == waits)
        .map(|row| {
            vec![
                text(&row.name),
                text(row.class.label()),
                Cell::Num(row.timed),
                Cell::Num(row.min_ns),
                Cell::Num(row.median_ns),
                Cell::Num(row.p95_ns),
                Cell::Num(row.p99_ns),
                Cell::Num(row.max_ns),
                Cell::Num(row.total_ns),
                Cell::Num(row.mean_ns),
            ]
        })
        .collect();
    Table {
        name: "latency",
        columns: cols(&[
            "call",
            "class",
            "timed_calls",
            "min_ns",
            "median_ns",
            "p95_ns",
            "p99_ns",
            "max_ns",
            "total_ns",
            "mean_ns",
        ]),
        rows,
    }
}

/// The 20 slowest ordinary calls, or the 20 longest waits.
pub fn slowest_table(stats: &RunStatistics, waits: bool) -> Table {
    let list = if waits {
        &stats.longest_waits
    } else {
        &stats.slowest
    };
    let rows = list
        .iter()
        .map(|call| {
            vec![
                text(&call.name),
                Cell::Num(u64::from(call.pid)),
                Cell::Num(u64::from(call.tid)),
                Cell::Num(call.start_ns),
                Cell::Num(call.duration_ns),
                Cell::Num(call.key.0),
                Cell::Num(call.key.1),
                Cell::Num(call.key.2),
            ]
        })
        .collect();
    Table {
        name: "slowest",
        columns: cols(&[
            "call",
            "pid",
            "tid",
            "start_ns",
            "duration_ns",
            "stream_id",
            "task_cookie",
            "call_id",
        ]),
        rows,
    }
}

/// The call-rate series as one row per bin.
pub fn rate_table(stats: &RunStatistics) -> Table {
    let rate = &stats.rate;
    let bins = rate.series.first().map_or(0, |s| s.bins.len());
    let rows = (0..bins)
        .map(|i| {
            let mut row = vec![
                Cell::Num(rate.start_ns + i as u64 * rate.bin_ns),
                Cell::Num(rate.bin_ns),
            ];
            row.extend(rate.series.iter().map(|s| Cell::Num(u64::from(s.bins[i]))));
            row
        })
        .collect();
    let mut columns = cols(&["start_ns", "bin_ns"]);
    columns.extend(rate.series.iter().map(|s| format!("calls_{}", s.name)));
    Table {
        name: "rate",
        columns,
        rows,
    }
}
