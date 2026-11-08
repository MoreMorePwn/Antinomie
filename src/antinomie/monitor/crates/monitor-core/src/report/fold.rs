// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Folding repeated rows of an event table for the document formats: a
//! sample that opens `/etc/hosts` 400 times, or reads a dictionary in
//! 4096-byte chunks, is one row with a count and the first and last time, not
//! 400 pages. The JSON keeps every row the index held.
use super::{Table, layout::thousands};

/// Rows of one folded table in the HTML and the PDF.
pub const FOLDED_ROWS: usize = 200;

/// Columns that differ between otherwise identical rows and are left out of
/// the key: the time, and the evidence call number.
fn varies(name: &str) -> bool {
    matches!(name, "Time" | "Evidence")
}

/// `table` with identical rows folded: the key is every column but Time and
/// Evidence; the result has Count, First seen and Last seen in front of the
/// remaining columns. A table without a Time column is returned as it is.
/// The second value is how many rows were folded into others.
pub fn fold_events(table: &Table) -> (Table, u64) {
    let Some(time) = table.columns.iter().position(|name| name == "Time") else {
        return (table.clone(), 0);
    };
    let kept: Vec<usize> = (0..table.columns.len())
        .filter(|&at| !varies(&table.columns[at]))
        .collect();
    struct Group {
        key: Vec<String>,
        first: String,
        last: String,
        count: u64,
        /// The data of the group's first row, with every row's findings.
        data: Option<super::RowData>,
    }
    let mut groups: Vec<Group> = Vec::new();
    let mut index: std::collections::HashMap<Vec<String>, usize> = std::collections::HashMap::new();
    for (at_row, row) in table.rows.iter().enumerate() {
        let data = table.data.get(at_row);
        let key: Vec<String> = kept
            .iter()
            .map(|&at| row.get(at).cloned().unwrap_or_default())
            .collect();
        let when = row.get(time).cloned().unwrap_or_default();
        match index.get(&key) {
            Some(&at) => {
                groups[at].count += 1;
                groups[at].last = when;
                if let (Some(group), Some(data)) = (groups[at].data.as_mut(), data) {
                    for id in &data.finding_refs {
                        if !group.finding_refs.contains(id) {
                            group.finding_refs.push(id.clone());
                        }
                    }
                    if group.time_ms.is_none() {
                        group.time_ms = data.time_ms;
                        group.relative_ms = data.relative_ms;
                    }
                }
            }
            None => {
                index.insert(key.clone(), groups.len());
                groups.push(Group {
                    key,
                    first: when.clone(),
                    last: when,
                    count: 1,
                    data: data.cloned(),
                });
            }
        }
    }
    let folded = (table.rows.len() - groups.len()) as u64;
    let mut columns = vec!["Count".to_owned(), "First seen".into(), "Last seen".into()];
    columns.extend(kept.iter().map(|&at| table.columns[at].clone()));
    let data: Vec<super::RowData> = if table.data.is_empty() {
        Vec::new()
    } else {
        groups
            .iter()
            .map(|group| {
                let mut data = group.data.clone().unwrap_or_default();
                data.count = Some(group.count);
                data
            })
            .collect()
    };
    let rows = groups
        .into_iter()
        .map(|group| {
            let mut row = vec![
                thousands(group.count),
                group.first,
                if group.count > 1 {
                    group.last
                } else {
                    String::new()
                },
            ];
            row.extend(group.key);
            row
        })
        .collect();
    let indicator_columns = table
        .indicator_columns
        .iter()
        .filter_map(|marked| {
            kept.iter()
                .position(|&at| at == marked.column)
                .map(|at| super::IndicatorColumn {
                    column: at + 3,
                    kind: marked.kind,
                })
        })
        .collect();
    (
        Table {
            columns,
            rows,
            omitted: table.omitted,
            indicator_columns,
            data,
        },
        folded,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> Table {
        let row = |time: &str, path: &str, call: &str| {
            vec![
                time.into(),
                path.into(),
                "cat".into(),
                "ok".into(),
                call.into(),
            ]
        };
        Table {
            columns: ["Time", "Path", "Process", "Result", "Evidence"]
                .map(String::from)
                .to_vec(),
            rows: vec![
                row("+0.1 s", "/etc/hosts", "call 1"),
                row("+0.2 s", "/etc/passwd", "call 2"),
                row("+0.3 s", "/etc/hosts", "call 3"),
                row("+0.9 s", "/etc/hosts", "call 4"),
            ],
            omitted: 5,
            indicator_columns: Vec::new(),
            data: Vec::new(),
        }
    }

    #[test]
    fn identical_rows_become_one_with_a_count_and_the_first_and_last_time() {
        let (folded, gone) = fold_events(&table());
        assert_eq!(gone, 2);
        assert_eq!(
            folded.columns[..4],
            ["Count", "First seen", "Last seen", "Path"]
        );
        assert_eq!(folded.rows.len(), 2);
        assert_eq!(folded.rows[0][..4], ["3", "+0.1 s", "+0.9 s", "/etc/hosts"]);
        assert_eq!(folded.rows[1][..3], ["1", "+0.2 s", ""]);
        assert_eq!(folded.omitted, 5, "rows the index dropped stay counted");
    }

    #[test]
    fn a_table_without_a_time_column_is_left_alone() {
        let plain = Table {
            columns: vec!["Path".into()],
            rows: vec![vec!["/a".into()], vec!["/a".into()]],
            ..Table::default()
        };
        let (same, gone) = fold_events(&plain);
        assert_eq!((same.rows.len(), gone), (2, 0));
    }
}
