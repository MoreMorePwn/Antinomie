// SPDX-License-Identifier: GPL-3.0-only
//! Loading a saved plugin result and showing it as a table.
use super::*;

impl MemoryView {
    pub(super) fn open_run(&mut self, id: Option<String>) {
        if self.selected_run != id {
            self.sort = None;
            self.filter.clear();
        }
        self.selected_run = id.clone();
        self.selected_row = None;
        self.show_log = false;
        self.result = None;
        let Some(run) = id.and_then(|id| self.runs.iter().find(|run| run.id == id).cloned()) else {
            self.cancel_result_load();
            return;
        };
        if self.jobs.iter().any(|job| job.run.id == run.id) {
            self.cancel_result_load();
            return;
        }
        self.request_result(ResultRequest {
            vm_id: self.dump().map(|dump| dump.vm_id.clone()),
            boot_id: self.dump().and_then(|dump| dump.boot_id.clone()),
            run_id: run.id.clone(),
            source: run.output(),
            query: self.filter.clone(),
            sort: self.sort,
            start: 0,
        });
    }

    pub(super) fn cancel_result_load(&mut self) {
        if let Some(load) = &self.loading {
            load.cancel.store(true, Ordering::Relaxed);
        }
        self.pending_result = None;
    }

    fn request_result(&mut self, request: ResultRequest) {
        if self.pending_result.as_ref() == Some(&request) {
            return;
        }
        if self
            .loading
            .as_ref()
            .is_some_and(|load| load.request == request && !load.cancel.load(Ordering::Relaxed))
        {
            return;
        }
        if let Some(load) = &self.loading {
            load.cancel.store(true, Ordering::Relaxed);
        }
        self.pending_result = Some(request);
        self.selected_row = None;
        self.start_result_load();
    }

    pub(super) fn start_result_load(&mut self) {
        if self.loading.is_some() {
            return;
        }
        let Some(request) = self.pending_result.take() else {
            return;
        };
        let Some(run) = self
            .runs
            .iter()
            .find(|run| run.id == request.run_id)
            .cloned()
        else {
            return;
        };
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker_request = request.clone();
        match std::thread::Builder::new()
            .name("memory-result-query".into())
            .spawn(move || {
                let result = load_result(run, &worker_request, &worker_cancel);
                let _ = sender.send(result);
            }) {
            Ok(_) => {
                self.loading = Some(ResultLoad {
                    request,
                    cancel,
                    receiver,
                })
            }
            Err(error) => self.status = Some((format!("Cannot start result query: {error}"), true)),
        }
    }

    pub(super) fn result_view(&mut self, ui: &mut egui::Ui, dump: &MemoryDump, font_size: f32) {
        let Some(run_id) = self.selected_run.clone() else {
            empty_state(ui, "Run a plugin.");
            return;
        };
        if let Some(job) = self.jobs.iter().find(|job| job.run.id == run_id) {
            running_job(ui, job, dump);
            return;
        }
        if self
            .result
            .as_ref()
            .is_none_or(|result| result.run.id != run_id)
        {
            self.unloaded_result(ui, &run_id);
            return;
        }
        let request = self.result_request(ui);
        if let Some(request) = request {
            self.request_result(request);
        }
        if self.loading.is_some() {
            let mut cancel = false;
            ui.horizontal_wrapped(|ui| {
                crate::theme::spinner(ui);
                ui.label("Querying every retained row…");
                cancel = ui.button("Cancel query").clicked();
            });
            if cancel {
                self.cancel_result_load();
                if let Some(result) = &self.result {
                    self.filter.clone_from(&result.filter);
                    self.sort = result.sort;
                }
            }
        }
        if self.result.is_none() {
            return;
        }
        self.result_head(ui, font_size);
        self.result_notices(ui, font_size);
        self.result_body(ui, font_size);
    }
}

/// The next order after a click on `column`'s header.
pub(super) fn next_sort(sort: Option<Sort>, column: usize) -> Option<Sort> {
    match sort {
        Some(Sort {
            column: current,
            descending: false,
        }) if current == column => Some(Sort {
            column,
            descending: true,
        }),
        Some(Sort {
            column: current,
            descending: true,
        }) if current == column => None,
        _ => Some(Sort {
            column,
            descending: false,
        }),
    }
}

pub(super) fn value_color(kind: ColumnKind, value: &serde_json::Value) -> egui::Color32 {
    if value.is_null() || value.get("absent").is_some() {
        return theme::muted();
    }
    match kind {
        ColumnKind::Hex | ColumnKind::Bin => theme::value(ValueKind::Pointer),
        ColumnKind::Int => theme::value(ValueKind::Number),
        ColumnKind::Bool => theme::value(ValueKind::Flags),
        ColumnKind::Bytes | ColumnKind::Disasm => theme::value(ValueKind::Text),
        ColumnKind::Time => theme::muted(),
        ColumnKind::Str => theme::text(),
    }
}

/// The tree branches of the shown rows, a tree of the rows a filter left.
pub(super) fn result_branches(
    table: &ResultTable,
    shown: &[usize],
) -> Vec<crate::tree_lines::Prefix> {
    crate::tree_lines::prefixes(
        &shown
            .iter()
            .map(|&row| usize::from(table.rows[row].depth))
            .collect::<Vec<_>>(),
    )
}

pub(super) fn load_result(
    run: PluginRun,
    request: &ResultRequest,
    cancel: &AtomicBool,
) -> LoadedResult {
    let annotation = antinomie_monitor_core::annotations::load(&run.dir);
    let mut record = plugin_result_record(&run, annotation.as_ref().ok());
    add_dump_identity(
        &mut record,
        request.vm_id.as_deref(),
        request.boot_id.as_deref(),
    );
    let mut compiled = None;
    let mut names = Vec::new();
    let mut filter_error = None;
    let page = memory::read_result_page_with(
        &request.source,
        request.start,
        RESULT_PAGE_LEN,
        request.sort.map(|sort| (sort.column, sort.descending)),
        cancel,
        |columns, row| {
            if compiled.is_none() {
                names = column_fields(columns);
                let fields = result_fields(&names, columns);
                let query = crate::query::compile_table(&request.query, &fields);
                filter_error = query.error.clone();
                compiled = Some(query);
            }
            compiled.as_ref().is_some_and(|query| {
                let mut values = result_row(&names, columns, row);
                values.extend(record.iter().cloned());
                query.keep_table(&values)
            })
        },
    );
    let (table, total, source_rows, start, skipped_lines) = match page {
        Ok(page) => (
            Ok(page.table),
            page.total,
            page.source_rows,
            page.start,
            page.skipped_lines,
        ),
        Err(error) => (Err(error), 0, 0, request.start, 0),
    };
    let mut data = Vec::new();
    let mut log = match std::fs::File::open(run.log()) {
        Ok(file) => match file.take(RESULT_LOG_SIZE + 1).read_to_end(&mut data) {
            Ok(_) => {
                let truncated = data.len() as u64 > RESULT_LOG_SIZE;
                data.truncate(RESULT_LOG_SIZE as usize);
                let mut text = String::from_utf8_lossy(&data).into_owned();
                if truncated {
                    text.push_str("\nLog preview truncated at 2 MiB; open the result directory for the complete log.");
                }
                text
            }
            Err(error) => format!("Cannot read retained log: {error}"),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => format!("Cannot read retained log: {error}"),
    };
    if let Err(error) = annotation {
        log.push_str(&format!("\nAnnotation unavailable: {error}"));
    }
    let shown: Vec<usize> = table
        .as_ref()
        .map(|table| (0..table.rows.len()).collect())
        .unwrap_or_default();
    let branches = match (&table, request.sort) {
        (Ok(table), None) => result_branches(table, &shown),
        _ => Vec::new(),
    };
    let has_files = std::fs::read_dir(run.files())
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    LoadedResult {
        run,
        table,
        shown,
        branches,
        filter: request.query.clone(),
        filter_error,
        sort: request.sort,
        text: None,
        log,
        has_files,
        total,
        source_rows,
        start,
        skipped_lines,
        record,
    }
}

pub(super) fn column_fields(columns: &[ResultColumn]) -> Vec<String> {
    let mut used = std::collections::BTreeSet::from(["depth".to_owned()]);
    columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let mut name: String = column
                .name
                .to_lowercase()
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() || ch == '_' {
                        ch
                    } else {
                        '_'
                    }
                })
                .collect();
            if name.is_empty()
                || name.starts_with(|ch: char| ch.is_ascii_digit())
                || matches!(
                    name.as_str(),
                    "and" | "or" | "not" | "contains" | "in" | "exists" | "missing" | "lower"
                )
            {
                name = format!("column_{index}_{name}");
            }
            let base = name.clone();
            let mut suffix = 0;
            while !used.insert(name.clone()) {
                name = format!("{base}_{index}_{suffix}");
                suffix += 1;
            }
            name
        })
        .collect()
}

pub(super) fn result_fields<'a>(
    names: &'a [String],
    columns: &'a [ResultColumn],
) -> Vec<crate::query::FieldSpec<'a>> {
    let mut fields = vec![crate::query::FieldSpec::number(
        "depth",
        "Result tree depth",
    )];
    fields.extend(crate::query::LABEL_FIELDS);
    fields.extend(
        names
            .iter()
            .zip(columns)
            .map(|(name, column)| crate::query::FieldSpec {
                name,
                detail: &column.name,
                kind: match column.kind {
                    ColumnKind::Int | ColumnKind::Hex | ColumnKind::Bin => "integer",
                    ColumnKind::Bool => "boolean",
                    _ => "text",
                },
            }),
    );
    fields
}

pub(super) fn result_row<'a>(
    names: &'a [String],
    columns: &[ResultColumn],
    row: &memory::ResultRow,
) -> Vec<(&'a str, crate::query::RowValue)> {
    use crate::query::RowValue;
    let mut values = vec![("depth", RowValue::Number(i128::from(row.depth)))];
    values.extend(
        names
            .iter()
            .zip(columns)
            .enumerate()
            .map(|(index, (name, column))| {
                let value = row.values.get(index);
                let value = match value {
                    None | Some(serde_json::Value::Null) => RowValue::Missing,
                    Some(value) if value.get("absent").is_some() => RowValue::Missing,
                    Some(value) => match column.kind {
                        ColumnKind::Int | ColumnKind::Hex | ColumnKind::Bin => value
                            .as_i64()
                            .map(i128::from)
                            .or_else(|| value.as_u64().map(i128::from))
                            .or_else(|| {
                                value.as_str().and_then(|text| {
                                    text.strip_prefix("0x").map_or_else(
                                        || text.parse().ok(),
                                        |text| i128::from_str_radix(text, 16).ok(),
                                    )
                                })
                            })
                            .map_or(RowValue::Missing, RowValue::Number),
                        ColumnKind::Bool => {
                            value.as_bool().map_or(RowValue::Missing, RowValue::Bool)
                        }
                        _ => RowValue::Text(memory::value_text(column.kind, value)),
                    },
                };
                (name.as_str(), value)
            }),
    );
    values
}

/// One row as tab-separated text.
pub(super) fn row_text(columns: &[ResultColumn], row: &memory::ResultRow) -> String {
    row.values
        .iter()
        .zip(columns)
        .map(|(value, column)| memory::value_text(column.kind, value))
        .collect::<Vec<_>>()
        .join("\t")
}

/// The result as tab-separated text, with its column names.
pub(super) fn result_tsv(columns: &[ResultColumn], table: &ResultTable, rows: &[usize]) -> String {
    let mut text = columns
        .iter()
        .map(|column| column.name.as_str())
        .collect::<Vec<_>>()
        .join("\t");
    for &index in rows {
        let row = &table.rows[index];
        text.push('\n');
        text.push_str(&"  ".repeat(row.depth as usize));
        text.push_str(
            &row.values
                .iter()
                .zip(columns)
                .map(|(value, column)| memory::value_text(column.kind, value))
                .collect::<Vec<_>>()
                .join("\t"),
        );
    }
    text
}

/// Tabs to the next multiple of 8 columns, as a terminal shows them.
pub(super) fn expand_tabs(line: &str) -> String {
    let mut out = String::with_capacity(line.len() + 16);
    let mut column = 0;
    for ch in line.chars() {
        if ch == '\t' {
            let next = (column / 8 + 1) * 8;
            out.extend(std::iter::repeat_n(' ', next - column));
            column = next;
        } else {
            out.push(ch);
            column += 1;
        }
    }
    out
}

/// Initial column widths from the header and the first rows' values.
pub(super) fn column_widths(table: &ResultTable, char_width: f32) -> Vec<f32> {
    table
        .columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let longest = table
                .rows
                .iter()
                .take(200)
                .map(|row| {
                    row.values.get(index).map_or(0, |value| {
                        memory::value_text(column.kind, value).chars().count()
                    }) + if index == 0 {
                        row.depth as usize * crate::tree_lines::CELL_CHARS + 1
                    } else {
                        0
                    }
                })
                .max()
                .unwrap_or(0)
                .max(column.name.chars().count());
            (longest.clamp(4, 48) as f32 + 2.0) * char_width
        })
        .collect()
}
