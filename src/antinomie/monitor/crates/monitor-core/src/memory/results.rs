// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Whole-result queries with bounded pages and disk-backed sorting.
use super::{Column, ResultRow, ResultTable, is_absent};
use rusqlite::{Connection, params};
use serde::Deserialize;
use std::{
    fs,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub const RESULT_PAGE_MAX_ROWS: usize = 1024;
const LINE_LIMIT: u64 = 1024 * 1024;
const FILE_LIMIT: u64 = 16 * 1024 * 1024 * 1024;

/// A page from every retained row matching the caller's typed query.
#[derive(Debug)]
pub struct ResultPage {
    pub table: ResultTable,
    pub total: u64,
    pub source_rows: u64,
    pub start: u64,
    pub skipped_lines: u64,
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        // Only this worker's private disposable index directory is removed.
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Deserialize)]
struct Header {
    columns: Vec<Column>,
}
#[derive(Deserialize)]
struct EncodedRow {
    d: u16,
    v: Vec<serde_json::Value>,
}

fn line(reader: &mut impl BufRead, buffer: &mut Vec<u8>) -> Result<usize, String> {
    buffer.clear();
    reader
        .take(LINE_LIMIT + 1)
        .read_until(b'\n', buffer)
        .map_err(|error| error.to_string())?;
    if buffer.len() as u64 > LINE_LIMIT {
        return Err("result line exceeds 1 MiB bound".into());
    }
    Ok(buffer.len())
}

fn key(value: Option<&serde_json::Value>) -> (u8, String, String) {
    use serde_json::Value;
    match value {
        None => (1, String::new(), String::new()),
        Some(value) if is_absent(value) => (1, String::new(), String::new()),
        Some(Value::Number(value)) => {
            let integer = value
                .as_i64()
                .map(i128::from)
                .or_else(|| value.as_u64().map(i128::from));
            if let Some(integer) = integer {
                (
                    0,
                    format!("0{:032x}", (integer as u128) ^ (1_u128 << 127)),
                    String::new(),
                )
            } else {
                let bits = value.as_f64().unwrap_or(0.0).to_bits();
                let ordered = if bits & (1 << 63) == 0 {
                    bits ^ (1 << 63)
                } else {
                    !bits
                };
                (0, format!("1{ordered:016x}"), String::new())
            }
        }
        Some(Value::Bool(value)) => (0, format!("2{}", u8::from(*value)), String::new()),
        Some(Value::String(value)) => (0, format!("3{}", value.to_lowercase()), value.clone()),
        Some(value) => (0, format!("4{value}"), String::new()),
    }
}

/// Query all rows without retaining all result payloads in host memory.
///
/// | Argument | Meaning |
/// |---|---|
/// | `path` | Saved JSONL; never modified. Live files are read to their initial extent. |
/// | `start`, `count` | Matching-row offset and at most 1024 returned rows. |
/// | `sort` | Column index and descending flag; absent cells remain last. |
/// | `cancel` | Worker cancellation, checked while indexing and reading the page. |
/// | `keep` | Typed row predicate, evaluated over all retained rows on the worker. |
pub fn read_result_page_with(
    path: &Path,
    start: u64,
    count: usize,
    sort: Option<(usize, bool)>,
    cancel: &AtomicBool,
    mut keep: impl FnMut(&[Column], &ResultRow) -> bool,
) -> Result<ResultPage, String> {
    let file =
        crate::archive_io::open_regular(path.parent().ok_or("result has no directory")?, path)
            .map_err(|error| error.to_string())?;
    let initial = file.metadata().map_err(|error| error.to_string())?;
    if initial.len() > FILE_LIMIT {
        return Err("result exceeds 16 GiB query limit".into());
    }
    let scratch =
        Scratch(std::env::temp_dir().join(format!("ant-result-{}", crate::storage::unique_id())));
    crate::storage::private_dir(&scratch.0).map_err(|error| error.to_string())?;
    let space = rustix::fs::statvfs(&scratch.0).map_err(|error| error.to_string())?;
    if space.f_bavail.saturating_mul(space.f_frsize)
        < initial.len().saturating_add(64 * 1024 * 1024)
    {
        return Err("insufficient temporary disk space for result index".into());
    }
    let mut connection =
        Connection::open(scratch.0.join("index.sqlite")).map_err(|error| error.to_string())?;
    connection.execute_batch("PRAGMA cache_size=-4096; PRAGMA temp_store=FILE; PRAGMA journal_mode=OFF; CREATE TABLE matched (ordinal INTEGER PRIMARY KEY, offset INTEGER, extent INTEGER, absent INTEGER, sort_key TEXT, tie_key TEXT);").map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(file.take(initial.len()));
    let mut buffer = Vec::new();
    let mut offset = line(&mut reader, &mut buffer)? as u64;
    let header: Header =
        serde_json::from_slice(&buffer).map_err(|error| format!("result columns: {error}"))?;
    if header.columns.len() > 512 {
        return Err("result has more than 512 columns".into());
    }
    if sort.is_some_and(|(column, _)| column >= header.columns.len()) {
        return Err("result sort column is unavailable".into());
    }
    let (mut source_rows, mut total, mut skipped_lines) = (0_u64, 0_u64, 0_u64);
    let transaction = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    {
        let mut insert = transaction
            .prepare("INSERT INTO matched VALUES (?1,?2,?3,?4,?5,?6)")
            .map_err(|error| error.to_string())?;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("result query cancelled".into());
            }
            let extent = line(&mut reader, &mut buffer)?;
            if extent == 0 {
                break;
            }
            if !buffer.iter().all(u8::is_ascii_whitespace) {
                match serde_json::from_slice::<EncodedRow>(&buffer) {
                    Ok(row) => {
                        source_rows += 1;
                        if row.v.len() > 512 {
                            return Err("result row has more than 512 cells".into());
                        }
                        let row = ResultRow {
                            depth: row.d,
                            values: row.v,
                        };
                        if keep(&header.columns, &row) {
                            let (absent, sort_key, tie_key) = sort
                                .map_or((0, String::new(), String::new()), |(column, _)| {
                                    key(row.values.get(column))
                                });
                            insert
                                .execute(params![
                                    i64::try_from(source_rows)
                                        .map_err(|_| "result row count overflow")?,
                                    i64::try_from(offset).map_err(|_| "result offset overflow")?,
                                    i64::try_from(extent)
                                        .map_err(|_| "result line extent overflow")?,
                                    absent,
                                    sort_key,
                                    tie_key
                                ])
                                .map_err(|error| format!("result index: {error}"))?;
                            total += 1;
                        }
                    }
                    Err(_) => skipped_lines += 1,
                }
            }
            offset += extent as u64;
        }
    }
    transaction.commit().map_err(|error| error.to_string())?;
    if cancel.load(Ordering::Relaxed) {
        return Err("result query cancelled".into());
    }
    let order = match sort {
        None => "ordinal ASC",
        Some((_, false)) => "absent ASC, sort_key ASC, tie_key ASC, ordinal ASC",
        Some((_, true)) => "absent ASC, sort_key DESC, tie_key DESC, ordinal ASC",
    };
    let sql = format!("SELECT offset, extent FROM matched ORDER BY {order} LIMIT ?1 OFFSET ?2");
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| error.to_string())?;
    let mut selected = statement
        .query(params![
            count.min(RESULT_PAGE_MAX_ROWS) as i64,
            i64::try_from(start).map_err(|_| "result offset too large")?
        ])
        .map_err(|error| error.to_string())?;
    let mut file =
        crate::archive_io::open_regular(path.parent().ok_or("result has no directory")?, path)
            .map_err(|error| error.to_string())?;
    let current = file.metadata().map_err(|error| error.to_string())?;
    if initial.dev() != current.dev()
        || initial.ino() != current.ino()
        || current.len() < initial.len()
    {
        return Err("result changed while querying".into());
    }
    let mut rows = Vec::new();
    while let Some(record) = selected.next().map_err(|error| error.to_string())? {
        if cancel.load(Ordering::Relaxed) {
            return Err("result query cancelled".into());
        }
        let offset = u64::try_from(record.get::<_, i64>(0).map_err(|error| error.to_string())?)
            .map_err(|_| "negative result offset")?;
        let extent = u64::try_from(record.get::<_, i64>(1).map_err(|error| error.to_string())?)
            .map_err(|_| "negative result extent")?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| error.to_string())?;
        buffer.resize(extent as usize, 0);
        file.read_exact(&mut buffer)
            .map_err(|error| error.to_string())?;
        let row: EncodedRow = serde_json::from_slice(&buffer)
            .map_err(|error| format!("result changed after indexing: {error}"))?;
        rows.push(ResultRow {
            depth: row.d,
            values: row.v,
        });
    }
    Ok(ResultPage {
        table: ResultTable {
            columns: header.columns,
            rows,
            truncated: false,
        },
        total,
        source_rows,
        start,
        skipped_lines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn whole_result_query_finds_late_rows_sorts_exact_integers_and_preserves_partial_source() {
        use std::io::Write;
        let root =
            std::env::temp_dir().join(format!("ant-result-test-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&root).unwrap();
        let path = root.join("output.jsonl");
        let mut output = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        writeln!(
            output,
            "{}",
            json!({"columns":[{"name":"Address","type":"hex"}]})
        )
        .unwrap();
        for index in 0..200_002_u64 {
            writeln!(output, "{}", json!({"d":0,"v":[index]})).unwrap();
        }
        for value in [
            json!(u64::MAX),
            json!(-1_i64),
            json!(u64::MAX - 1),
            json!({"absent":"UnreadableValue"}),
        ] {
            writeln!(output, "{}", json!({"d":1,"v":[value]})).unwrap();
        }
        write!(output, "{{\"d\":0,\"v\":[").unwrap();
        output.flush().unwrap();
        drop(output);
        let size = std::fs::metadata(&path).unwrap().len();
        let cancel = AtomicBool::new(false);
        let page = read_result_page_with(&path, 0, 2, None, &cancel, |_, row| {
            row.values
                .first()
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|value| (200_000..200_002).contains(&value))
        })
        .unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.source_rows, 200_006);
        assert_eq!(page.skipped_lines, 1);
        assert_eq!(page.table.rows[1].values[0], json!(200_001));
        let sorted = read_result_page_with(&path, 0, 4, Some((0, true)), &cancel, |_, row| {
            row.depth == 1
        })
        .unwrap();
        assert_eq!(sorted.total, 4);
        assert_eq!(sorted.table.rows[0].values[0], json!(u64::MAX));
        assert_eq!(sorted.table.rows[1].values[0], json!(u64::MAX - 1));
        assert_eq!(sorted.table.rows[2].values[0], json!(-1));
        assert!(is_absent(&sorted.table.rows[3].values[0]));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size);
        cancel.store(true, Ordering::Relaxed);
        assert!(
            read_result_page_with(&path, 0, 4, None, &cancel, |_, _| true)
                .unwrap_err()
                .contains("cancelled")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
