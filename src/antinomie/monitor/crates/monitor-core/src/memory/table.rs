// SPDX-License-Identifier: GPL-3.0-only
//! Typed result tables read from a plugin run's output (moved out of `memory`).
use super::*;

/// Kind of a result column, for display.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColumnKind {
    Int,
    Hex,
    Bin,
    Bool,
    Bytes,
    Time,
    Disasm,
    #[default]
    Str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ColumnKind,
}

/// One result row: its depth in the result tree and its values (JSON; an
/// absent value is `{"absent": "<reason>"}`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResultRow {
    pub depth: u16,
    pub values: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResultTable {
    pub columns: Vec<Column>,
    pub rows: Vec<ResultRow>,
    /// More rows than `limit` were saved.
    pub truncated: bool,
}

/// Read a saved result (at most `limit` rows).
pub fn read_result(path: &Path, limit: usize) -> Result<ResultTable, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut lines = BufReader::new(file).lines();
    let mut table = ResultTable::default();
    #[derive(Deserialize)]
    struct Header {
        columns: Vec<Column>,
    }
    #[derive(Deserialize)]
    struct Row {
        d: u16,
        v: Vec<serde_json::Value>,
    }
    if let Some(first) = lines.next() {
        let first = first.map_err(|e| e.to_string())?;
        let header: Header =
            serde_json::from_str(&first).map_err(|e| format!("result columns: {e}"))?;
        table.columns = header.columns;
    }
    for line in lines {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        if table.rows.len() >= limit {
            table.truncated = true;
            break;
        }
        // A run cut short can leave a partial last line, and results saved
        // before plugin prints were kept out of them can hold such lines.
        let Ok(row) = serde_json::from_str::<Row>(&line) else {
            continue;
        };
        table.rows.push(ResultRow {
            depth: row.d,
            values: row.v,
        });
    }
    Ok(table)
}

/// A value as text, the way the result table shows and copies it.
pub fn value_text(kind: ColumnKind, value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Null => String::new(),
        Value::Object(map) => match map.get("absent").and_then(Value::as_str) {
            Some("NotApplicableValue") => "N/A".into(),
            Some("UnreadableValue") => "Unreadable".into(),
            Some("UnparsableValue") => "Unparsable".into(),
            Some(_) => "-".into(),
            None => value.to_string(),
        },
        Value::Number(number) => match (kind, number.as_u64(), number.as_i64()) {
            (ColumnKind::Hex, Some(n), _) => format!("{n:#x}"),
            (ColumnKind::Hex, None, Some(n)) => format!("-{:#x}", n.unsigned_abs()),
            (ColumnKind::Bin, Some(n), _) => format!("{n:#b}"),
            _ => number.to_string(),
        },
        Value::Bool(flag) => flag.to_string(),
        Value::String(text) => text.clone(),
        Value::Array(_) => value.to_string(),
    }
}

/// An absent value (`N/A`, unreadable...) or none at all.
pub(super) fn is_absent(value: &serde_json::Value) -> bool {
    value.is_null() || value.get("absent").is_some()
}

/// Order of two values of one column: numbers by value, text ignoring case,
/// then the rest by their text.
pub fn compare_values(a: &serde_json::Value, b: &serde_json::Value) -> Ordering {
    use serde_json::Value;
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_i64(), y.as_i64()) {
            (Some(x), Some(y)) => x.cmp(&y),
            _ => match (x.as_u64(), y.as_u64()) {
                (Some(x), Some(y)) => x.cmp(&y),
                _ => {
                    let (x, y) = (x.as_f64().unwrap_or(0.0), y.as_f64().unwrap_or(0.0));
                    x.partial_cmp(&y).unwrap_or(Ordering::Equal)
                }
            },
        },
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        (Value::String(x), Value::String(y)) => x
            .to_lowercase()
            .cmp(&y.to_lowercase())
            .then_with(|| x.cmp(y)),
        (Value::Number(_), _) => Ordering::Less,
        (_, Value::Number(_)) => Ordering::Greater,
        _ => a.to_string().cmp(&b.to_string()),
    }
}

/// `rows` (indices into `table.rows`) ordered by `column`; rows of equal
/// value keep their order, and absent values stay last either way.
pub fn sort_rows(table: &ResultTable, rows: &mut [usize], column: usize, descending: bool) {
    let value = |row: usize| table.rows[row].values.get(column);
    rows.sort_by(|&a, &b| match (value(a), value(b)) {
        (Some(x), Some(y)) => match (is_absent(x), is_absent(y)) {
            (false, false) if descending => compare_values(y, x),
            (false, false) => compare_values(x, y),
            (x, y) => x.cmp(&y),
        },
        (x, y) => y.is_some().cmp(&x.is_some()),
    });
}

/// `rows` of the result as Volatility prints them by default (its quick text
/// renderer): a header line, then tab-separated values, nested rows marked
/// with a `*` per level.
pub fn result_text(table: &ResultTable, rows: &[usize]) -> String {
    use std::fmt::Write as _;
    let mut text = String::from("\n");
    let names: Vec<&str> = table.columns.iter().map(|c| c.name.as_str()).collect();
    text.push_str(&names.join("\t"));
    text.push('\n');
    for &index in rows {
        let row = &table.rows[index];
        text.push('\n');
        if row.depth > 0 {
            let _ = write!(text, "{} ", "*".repeat(row.depth as usize));
        }
        let values: Vec<String> = row
            .values
            .iter()
            .zip(&table.columns)
            .map(|(value, column)| match value {
                // As Python prints them.
                serde_json::Value::Bool(true) => "True".into(),
                serde_json::Value::Bool(false) => "False".into(),
                _ => value_text(column.kind, value),
            })
            .collect();
        text.push_str(&values.join("\t"));
    }
    text.push('\n');
    text
}
