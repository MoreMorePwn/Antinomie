// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The Files and Network parts of the run report's document: what the run
//! wrote or changed first, then each Files tab folded; endpoints with the
//! name a Tor stand-in stands for, domains, URLs and TLS.
use super::fold::{FOLDED_ROWS, fold_events};
use super::layout::{Block, Builder, Cell, DocTable, thousands};
use super::layout_parts::drop_empty_columns;
use super::{DOCUMENT_ROWS, FileRecord, IndicatorKind, NamedTable, Report, Table, stamp};
use std::collections::BTreeMap;

/// Reserved and private address ranges have no country or organisation.
pub(super) fn reserved(endpoint: &str) -> bool {
    let host = endpoint
        .rsplit_once(':')
        .map_or(endpoint, |(host, _)| host)
        .trim_matches(['[', ']']);
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            let [a, b, ..] = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || (a == 198 && (b == 18 || b == 19))
                || (a == 100 && (64..128).contains(&b))
        }
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => false,
    }
}

impl Builder {
    /// The files the run wrote or changed, one row each: its lifecycle from
    /// the Changed files tab and its reconstruction from File activity.
    fn written_table(&self, records: &[FileRecord], changed: Option<&Table>) -> DocTable {
        let changed_row: BTreeMap<&str, usize> = changed
            .map(|table| {
                let path = table.columns.iter().position(|c| c == "Path");
                table
                    .rows
                    .iter()
                    .enumerate()
                    .filter_map(|(at, row)| Some((row.get(path?)?.as_str(), at)))
                    .rev()
                    .collect()
            })
            .unwrap_or_default();
        let get = |at: Option<usize>, name: &str| -> String {
            let (Some(table), Some(at)) = (changed, at) else {
                return String::new();
            };
            table
                .columns
                .iter()
                .position(|c| c == name)
                .and_then(|c| table.rows[at].get(c))
                .cloned()
                .unwrap_or_default()
        };
        let rows = records
            .iter()
            .take(DOCUMENT_ROWS)
            .map(|record| {
                let at = changed_row.get(record.path.as_str()).copied();
                let mut state = Vec::new();
                if record.created {
                    state.push("created");
                }
                if record.changed {
                    state.push("changed");
                }
                if record.deleted {
                    state.push("deleted");
                }
                let lifecycle = get(at, "Lifecycle");
                let not_captured = record.bytes_not_captured + record.bytes_unknown;
                let process_ref = if record.process_ref.is_empty() {
                    at.and_then(|at| changed?.data.get(at))
                        .map(|d| d.process_ref.clone())
                        .unwrap_or_default()
                } else {
                    record.process_ref.clone()
                };
                vec![
                    Cell::plain(record.path.clone()).with_id(&record.id),
                    Cell::plain(if lifecycle.is_empty() {
                        state.join(", ")
                    } else {
                        lifecycle
                    }),
                    Cell::plain(
                        record
                            .final_size
                            .map_or(String::new(), crate::byte_size::file_size),
                    ),
                    Cell::plain(format!(
                        "{}{}",
                        crate::byte_size::file_size(record.bytes_written),
                        if not_captured > 0 {
                            format!(
                                " ({} not captured)",
                                crate::byte_size::file_size(not_captured)
                            )
                        } else {
                            String::new()
                        }
                    )),
                    Cell::plain(get(at, "Type")),
                    Cell::plain(record.guest_sha256.clone()),
                    Cell::plain(record.reconstruction.clone()),
                    Cell::plain(record.bundle_entry.clone()),
                    Cell::link(self.free(&get(at, "Process")), &process_ref),
                    self.finding_list(&record.finding_refs),
                ]
            })
            .collect();
        let mut table = DocTable {
            columns: [
                "Path",
                "Lifecycle",
                "Size",
                "Written",
                "Type",
                "Guest SHA-256",
                "Reconstruction",
                "In bundle",
                "Process",
                "Findings",
            ]
            .map(String::from)
            .to_vec(),
            rows,
        };
        drop_empty_columns(&mut table, &["Type", "In bundle", "Process", "Findings"]);
        table
    }

    /// Files: what the run wrote or changed first, then each Files tab in
    /// [`super::refs::FILE_TAB_ORDER`] with identical rows folded; the empty tabs in one line.
    pub(super) fn files_section(&mut self, report: &Report) {
        if report.files.is_none() && report.file_activity.is_none() {
            return;
        }
        let tabs: Vec<&NamedTable> = {
            let mut tabs: Vec<&NamedTable> =
                report.files.iter().flat_map(|f| f.tabs.iter()).collect();
            tabs.sort_by_key(|tab| super::refs::file_tab_rank(&tab.name));
            tabs
        };
        let changed = tabs
            .iter()
            .find(|tab| tab.name == "Changed files")
            .map(|tab| &tab.table);
        let mut blocks = Vec::new();
        let mut empty: Vec<String> = Vec::new();
        match &report.file_activity {
            Some(records) if !records.is_empty() => {
                blocks.push(Block::Sub {
                    title: format!("Written or changed ({})", thousands(records.len() as u64)),
                    id: "files-written".into(),
                });
                blocks.push(Block::Table(self.written_table(records, changed)));
                if records.len() > DOCUMENT_ROWS {
                    blocks.push(Block::Note(format!(
                        "{} more files are in the JSON export.",
                        records.len() - DOCUMENT_ROWS
                    )));
                }
            }
            Some(_) if changed.is_none_or(|t| t.rows.is_empty()) => {
                empty.push("Written or changed".into());
            }
            _ => {}
        }
        let merged = report.file_activity.as_ref().is_some_and(|r| !r.is_empty());
        for named in tabs {
            if named.name == "Changed files" && merged {
                continue;
            }
            let total = named.table.rows.len() as u64 + named.table.omitted;
            if total == 0 {
                empty.push(named.name.clone());
                continue;
            }
            // Times as the document writes them, before identical rows fold.
            let mut timed = named.table.clone();
            if let Some(time) = timed.columns.iter().position(|c| c == "Time") {
                for (row, d) in timed.rows.iter_mut().zip(&named.table.data) {
                    if (d.time_ms.is_some() || d.relative_ms.is_some())
                        && let Some(cell) = row.get_mut(time)
                    {
                        *cell = stamp(d.relative_ms, d.time_ms);
                    }
                }
            }
            let (folded, gone) = if named.name == "Changed files" {
                (timed, 0)
            } else {
                fold_events(&timed)
            };
            blocks.push(Block::sub(format!("{} ({})", named.name, thousands(total))));
            let shown = folded.rows.len().min(FOLDED_ROWS);
            let rows: Vec<usize> = (0..shown).collect();
            blocks.push(Block::Table(self.linked(&folded, &rows)));
            let mut said = Vec::new();
            if gone > 0 {
                said.push(format!(
                    "{} repeated rows are folded into the count of the row they repeat.",
                    thousands(gone)
                ));
            }
            if folded.rows.len() > shown {
                said.push(format!(
                    "The first {shown} of {} distinct rows are shown.",
                    thousands(folded.rows.len() as u64)
                ));
            }
            if named.table.omitted > 0 {
                said.push(format!(
                    "{} more matching rows were not kept by the index.",
                    thousands(named.table.omitted)
                ));
            }
            if !said.is_empty() {
                said.push("The JSON export keeps every row the index held.".into());
                blocks.push(Block::Note(said.join(" ")));
            }
        }
        if !empty.is_empty() {
            blocks.push(Block::Note(format!("Empty: {}.", empty.join(", "))));
        }
        let title = if report.files.is_some() {
            "Files"
        } else {
            "File activity and reconstruction"
        };
        self.section("files", title, blocks);
    }

    /// Endpoints (with the name a Tor stand-in address stands for), Domains,
    /// URLs and TLS; the empty ones in one line.
    pub(super) fn network_blocks(&self, tabs: &[NamedTable]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let mut empty = Vec::new();
        for named in tabs {
            let total = named.table.rows.len() as u64 + named.table.omitted;
            if total == 0 {
                empty.push(named.name.clone());
                continue;
            }
            blocks.push(Block::sub(format!("{} ({})", named.name, thousands(total))));
            let rows: Vec<usize> = (0..named.table.rows.len().min(DOCUMENT_ROWS)).collect();
            let mut table = self.linked(&named.table, &rows);
            if named.name == "Endpoints" {
                self.stands_for(&named.table, &rows, &mut table);
            }
            blocks.push(Block::Table(table));
            if let Some(note) = Builder::cut_note(&named.table) {
                blocks.push(Block::Note(note));
            }
        }
        if !empty.is_empty() {
            blocks.push(Block::Note(format!("Empty: {}.", empty.join(", "))));
        }
        if blocks.is_empty() {
            blocks.push(Block::Note("No network activity was recorded.".into()));
        }
        blocks
    }

    /// A Stands for column after Endpoint: the name the run's DNS answers
    /// handed a Tor stand-in address out for.
    fn stands_for(&self, source: &Table, rows: &[usize], table: &mut DocTable) {
        let names: Vec<String> = rows
            .iter()
            .map(|&at| {
                let endpoint = source.data.get(at).map_or("", |d| d.endpoint.as_str());
                self.stand_ins.get(endpoint).cloned().unwrap_or_default()
            })
            .collect();
        if names.iter().all(String::is_empty) {
            return;
        }
        table.columns.insert(1, "Stands for".into());
        for (row, name) in table.rows.iter_mut().zip(names) {
            let to = self.reg.domain(&name);
            row.insert(
                1,
                Cell::link(self.value(Some(IndicatorKind::Domain), &name), &to),
            );
        }
    }
}
