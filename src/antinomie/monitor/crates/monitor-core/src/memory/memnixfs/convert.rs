// SPDX-License-Identifier: GPL-3.0-only
//! MemNixFS's files as result tables in the format the Memory tab already
//! reads (`output.jsonl`: a `columns` line, then one `{"d":0,"v":[...]}` line
//! per row): its JSON exports, its text reports and the list of the files it
//! recovered.
use super::super::{Column, ColumnKind};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::Path,
};

/// Most of one exported file that is read.
const FILE_MAX_SIZE: u64 = 128 * 1024 * 1024;
/// Rows a result keeps; more are cut and the run says so.
pub(super) const ROW_MAX_COUNT: usize = 500_000;
/// Longest text line kept whole, in octets.
const LINE_MAX_LEN: usize = 8192;
/// Recovered files listed, and hashed up to this size each.
const FILE_HASH_MAX_SIZE: u64 = 64 * 1024 * 1024;

/// A finished table: its row count, and why rows are missing.
pub(super) struct Converted {
    pub rows: u64,
    pub notes: Vec<String>,
}

fn write_header(out: &mut impl Write, columns: &[Column]) -> Result<(), String> {
    let line = serde_json::json!({ "columns": columns });
    writeln!(out, "{line}").map_err(|e| format!("result: {e}"))
}

fn write_row(out: &mut impl Write, values: &[Value]) -> Result<(), String> {
    let line = serde_json::json!({ "d": 0, "v": values });
    writeln!(out, "{line}").map_err(|e| format!("result: {e}"))
}

fn column(name: &str, kind: ColumnKind) -> Column {
    Column {
        name: name.into(),
        kind,
    }
}

/// A JSON array of objects as a table. Columns named in `preferred` come
/// first, the others follow in alphabetical order; a column is numeric or
/// boolean only when every value in it is.
pub(super) fn json_table(
    input: &Path,
    output: &mut impl Write,
    preferred: &[&str],
) -> Result<Converted, String> {
    let file = File::open(input).map_err(|e| format!("{}: {e}", input.display()))?;
    let mut text = Vec::new();
    file.take(FILE_MAX_SIZE + 1)
        .read_to_end(&mut text)
        .map_err(|e| format!("{}: {e}", input.display()))?;
    if text.len() as u64 > FILE_MAX_SIZE {
        return Err("the exported JSON is larger than 128 MiB".into());
    }
    let value: Value = serde_json::from_slice(&text)
        .map_err(|e| format!("MemNixFS wrote JSON that cannot be read: {e}"))?;
    let Value::Array(items) = value else {
        return Err("MemNixFS wrote JSON that is not a list of records".into());
    };
    let mut notes = Vec::new();
    let mut names: Vec<String> = preferred.iter().map(|name| (*name).to_owned()).collect();
    let mut extra: Vec<String> = Vec::new();
    for item in items.iter().take(ROW_MAX_COUNT) {
        let Value::Object(map) = item else {
            return Err("MemNixFS wrote a record that is not an object".into());
        };
        for key in map.keys() {
            if !names.contains(key) && !extra.contains(key) {
                extra.push(key.clone());
            }
        }
    }
    extra.sort();
    names.extend(extra);
    let rows: Vec<_> = items.iter().take(ROW_MAX_COUNT).collect();
    // Preferred names that no record has are not columns, unless nothing
    // was found (the empty table still shows what it would hold).
    if !rows.is_empty() {
        names.retain(|name| {
            rows.iter()
                .any(|row| row.as_object().is_some_and(|map| map.contains_key(name)))
        });
    }
    let kind_of = |name: &String| {
        let mut kind = None;
        for row in &rows {
            let kind_here = match row.get(name) {
                None | Some(Value::Null) => continue,
                Some(Value::Bool(_)) => ColumnKind::Bool,
                Some(Value::Number(number)) if number.is_i64() || number.is_u64() => {
                    ColumnKind::Int
                }
                Some(_) => ColumnKind::Str,
            };
            match kind {
                None => kind = Some(kind_here),
                Some(kind) if kind == kind_here => {}
                Some(_) => return ColumnKind::Str,
            }
        }
        kind.unwrap_or(ColumnKind::Str)
    };
    let columns: Vec<Column> = names
        .iter()
        .map(|name| column(name, kind_of(name)))
        .collect();
    write_header(output, &columns)?;
    for row in &rows {
        let values: Vec<Value> = columns
            .iter()
            .map(|column| match row.get(&column.name) {
                None | Some(Value::Null) => Value::Null,
                Some(value) if column.kind != ColumnKind::Str => value.clone(),
                Some(Value::String(text)) => Value::String(text.clone()),
                Some(other) => Value::String(other.to_string()),
            })
            .collect();
        write_row(output, &values)?;
    }
    if items.len() > ROW_MAX_COUNT {
        notes.push(format!(
            "Only the first {ROW_MAX_COUNT} of {} records are kept.",
            items.len()
        ));
    }
    Ok(Converted {
        rows: rows.len() as u64,
        notes,
    })
}

/// A text report as one column of lines.
pub(super) fn text_table(input: &Path, output: &mut impl Write) -> Result<Converted, String> {
    let file = File::open(input).map_err(|e| format!("{}: {e}", input.display()))?;
    let mut reader = BufReader::new(file.take(FILE_MAX_SIZE));
    write_header(output, &[column("line", ColumnKind::Str)])?;
    let (mut rows, mut cut, mut notes) = (0u64, 0u64, Vec::new());
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader
            .read_until(b'\n', &mut line)
            .map_err(|e| format!("{}: {e}", input.display()))?
            == 0
        {
            break;
        }
        if rows as usize >= ROW_MAX_COUNT {
            cut += 1;
            continue;
        }
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        let long = line.len() > LINE_MAX_LEN;
        line.truncate(LINE_MAX_LEN);
        let mut text = String::from_utf8_lossy(&line).into_owned();
        if long {
            text.push_str(" ...");
        }
        write_row(output, &[Value::String(text)])?;
        rows += 1;
    }
    if cut > 0 {
        notes.push(format!(
            "Only the first {ROW_MAX_COUNT} lines are kept; {cut} more were cut."
        ));
    }
    Ok(Converted { rows, notes })
}

/// The files under `root` (symbolic links are listed, never followed) as a
/// table of path, kind, size and SHA-256.
pub(super) fn files_table(root: &Path, output: &mut impl Write) -> Result<Converted, String> {
    write_header(
        output,
        &[
            column("PATH", ColumnKind::Str),
            column("KIND", ColumnKind::Str),
            column("SIZE", ColumnKind::Int),
            column("SHA-256", ColumnKind::Str),
        ],
    )?;
    let mut entries = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    let mut cut = false;
    while let Some(directory) = pending.pop() {
        let mut children: Vec<_> = fs::read_dir(&directory)
            .map_err(|e| format!("{}: {e}", directory.display()))?
            .flatten()
            .collect();
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let Ok(kind) = child.file_type() else {
                continue;
            };
            if kind.is_dir() {
                pending.push(child.path());
            } else if entries.len() >= ROW_MAX_COUNT {
                cut = true;
            } else {
                entries.push((child.path(), kind));
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut notes = Vec::new();
    for (path, kind) in &entries {
        let relative = path.strip_prefix(root).unwrap_or(path);
        let name = format!("/{}", relative.display());
        let row = if kind.is_symlink() {
            let target = fs::read_link(path).map_or_else(
                |_| String::new(),
                |target| format!("-> {}", target.display()),
            );
            [
                Value::String(name),
                Value::String("symlink".into()),
                Value::Null,
                Value::String(target),
            ]
        } else if kind.is_file() {
            let size = fs::metadata(path).map_or(0, |metadata| metadata.len());
            let hash = (size <= FILE_HASH_MAX_SIZE)
                .then(|| File::open(path).ok())
                .flatten()
                .and_then(|file| crate::storage::sha256_uncached(file).ok())
                .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect());
            [
                Value::String(name),
                Value::String("file".into()),
                Value::from(size),
                hash.map_or(Value::Null, Value::String),
            ]
        } else {
            continue;
        };
        write_row(output, &row)?;
    }
    if cut {
        notes.push(format!(
            "Only the first {ROW_MAX_COUNT} recovered files are listed."
        ));
    }
    Ok(Converted {
        rows: entries.len() as u64,
        notes,
    })
}
