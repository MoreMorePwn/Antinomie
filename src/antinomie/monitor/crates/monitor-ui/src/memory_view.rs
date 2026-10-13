//! The Memory tab: RAM dumps of a VM and their analysis with Volatility 3,
//! in the manner of Volatility Workbench. Pick a dump, pick a plugin and its
//! options, run it; every run is saved with its dump and listed beside it, so
//! an earlier result opens again without running the plugin again.
use crate::{
    network_view::{capture_row, format_date},
    theme::{self, ValueKind},
};
use antinomie_monitor_core::{
    memory::{
        self, community, Column as ResultColumn, ColumnKind, DumpProgress, MemoryDump, OptionKind,
        Os, PluginCatalog, PluginInfo, PluginRun, ResultTable, RunHandle, RunState, Volatility,
    },
    BaseSummary, VmConfig,
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc, Mutex,
    },
    time::Duration,
};

/// Rows of one result loaded for display.
const RESULT_PAGE_LEN: usize = 1024;
const RESULT_LOG_SIZE: u64 = 2 * 1024 * 1024;

pub(crate) enum MemoryAction {
    /// Dump the running VM's RAM.
    Dump,
    /// Install Volatility 3 (Tools → Analysis tools).
    InstallVolatility,
    /// Look up symbol tables online for dumps without one (a setting).
    OnlineSymbols(bool),
}

pub(crate) struct MemoryContext<'a> {
    pub vm: Option<&'a VmConfig>,
    /// Where new dumps and imports of this VM go, and every recording
    /// directory to list dumps from.
    pub recordings: Option<&'a Path>,
    pub recording_roots: &'a [PathBuf],
    /// The VM is running (a dump can be taken).
    pub running: bool,
    pub dumping: Option<&'a DumpProgress>,
    /// A dump request is on its way to the backend.
    pub pending: bool,
    pub data_dir: &'a Path,
    /// Volatility 3 is installed, or being installed.
    pub volatility_installed: bool,
    pub volatility_installing: bool,
    pub bases: &'a [BaseSummary],
    pub font_size: f32,
    /// Symbol tables of dumps without one are looked up online.
    pub online_symbols: bool,
    /// curl, for catalog plugin downloads.
    pub curl: &'a Path,
}

enum Catalog {
    Unknown,
    Loading(Receiver<Result<(Volatility, PluginCatalog), String>>),
    Ready(Volatility, PluginCatalog),
    Failed(String),
}

struct LoadedResult {
    run: PluginRun,
    table: Result<ResultTable, String>,
    /// Indices of the rows the filter keeps, in the chosen order.
    shown: Vec<usize>,
    filter: String,
    filter_error: Option<String>,
    sort: Option<Sort>,
    /// The shown rows as Volatility prints them, made when first viewed.
    text: Option<Vec<String>>,
    log: String,
    total: u64,
    source_rows: u64,
    start: u64,
    skipped_lines: u64,
    record: Vec<(&'static str, crate::query::RowValue)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResultRequest {
    vm_id: Option<String>,
    boot_id: Option<String>,
    run_id: String,
    source: PathBuf,
    query: String,
    sort: Option<Sort>,
    start: u64,
}

struct ResultLoad {
    request: ResultRequest,
    cancel: Arc<AtomicBool>,
    receiver: Receiver<LoadedResult>,
}

/// A result ordered by one column (header clicks: ascending, descending, as
/// Volatility gave it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sort {
    column: usize,
    descending: bool,
}

/// The next order after a click on `column`'s header.
fn next_sort(sort: Option<Sort>, column: usize) -> Option<Sort> {
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

/// A catalog plugin being downloaded.
struct PluginInstall {
    /// Received and total octets.
    progress: Arc<Mutex<(u64, u64)>>,
    cancel: Arc<AtomicBool>,
    done: Receiver<Result<(), String>>,
}

/// The import form.
struct Import {
    path: String,
    os: Os,
    /// Directory of the installed base whose symbol table goes with it.
    base: Option<PathBuf>,
    picker: Option<Child>,
    error: Option<String>,
}

pub(crate) struct MemoryView {
    dumps: Vec<MemoryDump>,
    dumps_for: Option<Vec<PathBuf>>,
    dumping_seen: bool,
    selected: Option<String>,
    runs: Vec<PluginRun>,
    selected_run: Option<String>,
    jobs: Vec<RunHandle>,
    catalog: Catalog,
    plugin: Option<String>,
    search: String,
    /// Option values typed per plugin.
    values: BTreeMap<String, Vec<(String, String)>>,
    show_deprecated: bool,
    result: Option<LoadedResult>,
    loading: Option<ResultLoad>,
    pending_result: Option<ResultRequest>,
    filter: String,
    /// Index of the selected row in the loaded result.
    selected_row: Option<usize>,
    show_log: bool,
    /// The result as Volatility's text instead of a table.
    text_view: bool,
    /// Order of the open result.
    sort: Option<Sort>,
    /// Plugins of this system are listed (the dump's system until changed).
    list_os: Option<(String, Os)>,
    import: Option<Import>,
    confirm_delete: Option<String>,
    status: Option<(String, bool)>,
    catalog_open: bool,
    installs: BTreeMap<String, PluginInstall>,
    catalog_status: Option<(String, bool)>,
    /// System of each installed catalog plugin, by its folder name.
    community_os: BTreeMap<String, Os>,
    /// Installed catalog plugins, read when the catalog opens or changes.
    catalog_installed: Option<Vec<community::Installed>>,
    hide_list: bool,
}

impl Default for MemoryView {
    fn default() -> Self {
        Self {
            dumps: Vec::new(),
            dumps_for: None,
            dumping_seen: false,
            selected: None,
            runs: Vec::new(),
            selected_run: None,
            jobs: Vec::new(),
            catalog: Catalog::Unknown,
            plugin: None,
            search: String::new(),
            values: BTreeMap::new(),
            show_deprecated: false,
            result: None,
            loading: None,
            pending_result: None,
            filter: String::new(),
            selected_row: None,
            show_log: false,
            text_view: false,
            sort: None,
            list_os: None,
            import: None,
            confirm_delete: None,
            status: None,
            catalog_open: false,
            installs: BTreeMap::new(),
            catalog_status: None,
            community_os: BTreeMap::new(),
            catalog_installed: None,
            hide_list: false,
        }
    }
}

impl Drop for MemoryView {
    fn drop(&mut self) {
        if let Some(load) = &self.loading {
            load.cancel.store(true, Ordering::Relaxed);
        }
        for job in &self.jobs {
            job.cancel();
        }
        for install in self.installs.values() {
            install.cancel.store(true, Ordering::Relaxed);
        }
        if let Some(mut child) = self.import.as_mut().and_then(|import| import.picker.take()) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn format_size(bytes: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    match bytes {
        0..1_048_576 => format!("{:.1} KiB", bytes as f64 / 1024.0),
        1_048_576..1_073_741_824 => format!("{:.1} MiB", bytes as f64 / 1_048_576.0),
        _ => format!("{:.1} GiB", bytes as f64 / GIB),
    }
}

fn format_elapsed(ms: u64) -> String {
    if ms < 60_000 {
        format!("{:.1} s", ms as f64 / 1000.0)
    } else {
        format!("{} min {} s", ms / 60_000, ms / 1000 % 60)
    }
}

/// The time of day (UTC) of a date-time.
fn clock(ms: u64) -> String {
    let date = format_date(ms / 1000);
    date.split_whitespace().nth(1).unwrap_or(&date).to_owned()
}

fn dump_title(dump: &MemoryDump) -> String {
    if dump.imported {
        dump.file.file_name().map_or_else(
            || "Imported dump".into(),
            |name| name.to_string_lossy().into_owned(),
        )
    } else {
        format_date(dump.started_ms / 1000)
            .trim_end_matches(" UTC")
            .to_owned()
    }
}

fn dump_detail(dump: &MemoryDump) -> String {
    let size = dump.bytes.map(format_size).unwrap_or_else(|| "…".into());
    if let Some(error) = &dump.error {
        return format!("Failed: {error}");
    }
    if dump.missing() {
        return format!("{size} · file missing");
    }
    if dump.imported {
        format!("Imported · {size} · {}", dump.system)
    } else {
        format!("{size} · {}", dump.system)
    }
}

/// The run's options in a short form.
fn args_summary(run: &PluginRun) -> String {
    run.args.join(" ")
}

fn run_detail(run: &PluginRun, job: Option<&memory::Progress>) -> String {
    if let Some(progress) = job {
        return if progress.step.is_empty() {
            "Running…".into()
        } else {
            format!("{:.0}% {}", progress.percent, progress.step)
        };
    }
    let took = run
        .finished_ms
        .map(|end| format_elapsed(end.saturating_sub(run.started_ms)))
        .unwrap_or_default();
    match run.state {
        RunState::Running => "Did not finish (the app closed)".into(),
        RunState::Finished => format!("{} · {} rows · {took}", clock(run.started_ms), run.rows),
        RunState::Cancelled => format!("{} · cancelled", clock(run.started_ms)),
        RunState::Failed => format!(
            "{} · failed: {}",
            clock(run.started_ms),
            run.error.as_deref().unwrap_or("see its messages")
        ),
    }
}

fn value_color(kind: ColumnKind, value: &serde_json::Value) -> egui::Color32 {
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

fn load_result(run: PluginRun, request: &ResultRequest, cancel: &AtomicBool) -> LoadedResult {
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
    let shown = table
        .as_ref()
        .map(|table| (0..table.rows.len()).collect())
        .unwrap_or_default();
    LoadedResult {
        run,
        table,
        shown,
        filter: request.query.clone(),
        filter_error,
        sort: request.sort,
        text: None,
        log,
        total,
        source_rows,
        start,
        skipped_lines,
        record,
    }
}

fn column_fields(columns: &[ResultColumn]) -> Vec<String> {
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

fn result_fields<'a>(
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

fn result_row<'a>(
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
fn row_text(columns: &[ResultColumn], row: &memory::ResultRow) -> String {
    row.values
        .iter()
        .zip(columns)
        .map(|(value, column)| memory::value_text(column.kind, value))
        .collect::<Vec<_>>()
        .join("\t")
}

/// The result as tab-separated text, with its column names.
fn result_tsv(columns: &[ResultColumn], table: &ResultTable, rows: &[usize]) -> String {
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

fn open_directory(path: &Path) -> Result<(), String> {
    let mut child = Command::new("xdg-open")
        .arg(path)
        .spawn()
        .map_err(|error| format!("Open folder: {error}"))?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

impl MemoryView {
    pub(crate) fn open_dump(&mut self, directory: &std::path::Path) {
        self.select(
            directory
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
        );
        self.dumps_for = None;
    }
    fn scan(&mut self, roots: &[PathBuf]) {
        self.dumps = memory::list(roots);
        self.dumps_for = Some(roots.to_vec());
        if self
            .selected
            .as_ref()
            .is_none_or(|id| !self.dumps.iter().any(|dump| &dump.id == id))
        {
            let first = self
                .dumps
                .iter()
                .find(|dump| dump.complete())
                .or(self.dumps.first());
            self.select(first.map(|dump| dump.id.clone()));
        } else {
            // A run link can select an ID before this refreshed list contains it.
            self.reload_runs();
            let selected = self
                .selected_run
                .clone()
                .filter(|id| self.runs.iter().any(|run| &run.id == id))
                .or_else(|| self.runs.first().map(|run| run.id.clone()));
            self.open_run(selected);
        }
    }

    fn select(&mut self, id: Option<String>) {
        if self.selected == id && self.dumps_for.is_some() && !self.runs.is_empty() {
            return;
        }
        self.selected = id;
        self.status = None;
        self.reload_runs();
        let newest = self.runs.first().map(|run| run.id.clone());
        self.open_run(newest);
    }

    fn dump(&self) -> Option<&MemoryDump> {
        let id = self.selected.as_ref()?;
        self.dumps.iter().find(|dump| &dump.id == id)
    }

    fn reload_runs(&mut self) {
        self.runs = self.dump().map(MemoryDump::runs).unwrap_or_default();
    }

    fn open_run(&mut self, id: Option<String>) {
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

    fn cancel_result_load(&mut self) {
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

    fn start_result_load(&mut self) {
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

    fn poll(&mut self, ctx: &egui::Context, data_dir: &Path) {
        let finished = self
            .loading
            .as_ref()
            .and_then(|load| match load.receiver.try_recv() {
                Ok(result) => Some(Ok(result)),
                Err(mpsc::TryRecvError::Disconnected) => Some(Err(
                    "Result query worker stopped without a result".to_owned(),
                )),
                Err(mpsc::TryRecvError::Empty) => None,
            });
        if let Some(finished) = finished {
            if let Some(load) = self.loading.take() {
                if !load.cancel.load(Ordering::Relaxed)
                    && self.pending_result.is_none()
                    && self.selected_run.as_ref() == Some(&load.request.run_id)
                {
                    match finished {
                        Ok(result) => {
                            self.result = Some(result);
                            self.selected_row = None;
                        }
                        Err(error) => self.status = Some((error, true)),
                    }
                }
            }
            self.start_result_load();
        }
        if self
            .loading
            .as_ref()
            .is_some_and(|load| Some(&load.request.run_id) != self.selected_run.as_ref())
        {
            self.cancel_result_load();
        }
        let listed = match &self.catalog {
            Catalog::Loading(receiver) => receiver.try_recv().ok(),
            _ => None,
        };
        if let Some(listed) = listed {
            self.community_os = community::installed(&memory::plugins_dir(data_dir))
                .into_iter()
                .map(|installed| (installed.plugin.id, installed.plugin.os))
                .collect();
            self.catalog = match listed {
                Ok((volatility, plugins)) => Catalog::Ready(volatility, plugins),
                Err(error) => Catalog::Failed(error),
            };
        }
        if matches!(self.catalog, Catalog::Unknown) {
            let (sender, receiver) = mpsc::channel();
            let data_dir = data_dir.to_path_buf();
            std::thread::spawn(move || {
                let loaded = Volatility::locate(&data_dir).and_then(|volatility| {
                    let plugins = volatility.plugins()?;
                    Ok((volatility, plugins))
                });
                let _ = sender.send(loaded);
            });
            self.catalog = Catalog::Loading(receiver);
        }
        let mut installed = Vec::new();
        self.installs
            .retain(|id, install| match install.done.try_recv() {
                Ok(result) => {
                    installed.push((id.clone(), result));
                    false
                }
                Err(mpsc::TryRecvError::Empty) => true,
                Err(mpsc::TryRecvError::Disconnected) => false,
            });
        for (id, result) in installed {
            self.catalog_status = Some(match result {
                Ok(()) => (format!("{id} installed: its plugins are listed"), false),
                Err(error) => (format!("{id}: {error}"), true),
            });
            // List the plugins again, with the new ones.
            self.catalog = Catalog::Unknown;
            self.catalog_installed = None;
        }
        if !self.installs.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
        let mut finished = Vec::new();
        self.jobs.retain(|job| match job.progress().finished {
            Some(run) => {
                finished.push(run);
                false
            }
            None => true,
        });
        if !self.jobs.is_empty()
            || self.loading.is_some()
            || matches!(self.catalog, Catalog::Loading(_))
        {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
        for run in finished {
            self.reload_runs();
            if self.selected_run.as_deref() == Some(run.id.as_str()) {
                self.open_run(Some(run.id.clone()));
            }
            self.status = Some(match run.state {
                RunState::Finished => (
                    format!("{} finished: {} rows", run.short_name(), run.rows),
                    false,
                ),
                RunState::Cancelled => (format!("{} cancelled", run.short_name()), false),
                // The open result shows why; others say it here.
                _ if self.selected_run.as_deref() == Some(run.id.as_str()) => {
                    (format!("{} failed", run.short_name()), true)
                }
                _ => (
                    format!(
                        "{} failed: {}",
                        run.short_name(),
                        run.error.as_deref().unwrap_or("see its messages")
                    ),
                    true,
                ),
            });
        }
    }

    /// Volatility was installed or removed: list its plugins again.
    fn check_catalog(&mut self, installed: bool) {
        let ready = matches!(self.catalog, Catalog::Ready(..));
        let failed = matches!(self.catalog, Catalog::Failed(_));
        if (installed && failed) || (!installed && ready) {
            self.catalog = Catalog::Unknown;
        }
    }

    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        cx: MemoryContext<'_>,
    ) -> Option<MemoryAction> {
        let dumping = cx.dumping.is_some();
        if self
            .dumps_for
            .as_deref()
            .is_none_or(|roots| roots != cx.recording_roots)
            || self.dumping_seen != dumping
        {
            self.scan(cx.recording_roots);
            self.dumping_seen = dumping;
            let fresh = self
                .dumps
                .first()
                .filter(|newest| {
                    !dumping
                        && newest.complete()
                        && !newest.imported
                        && newest.finished_ms.is_some_and(|end| end + 5_000 > now_ms())
                })
                .map(|newest| newest.id.clone());
            if fresh.is_some() {
                self.select(fresh);
            }
        }
        if dumping {
            ui.ctx().request_repaint_after(Duration::from_millis(250));
        }
        self.check_catalog(cx.volatility_installed);
        self.poll(ui.ctx(), cx.data_dir);
        self.poll_picker();

        let mut action = None;
        self.list_toolbar(ui);
        if !self.hide_list {
            egui::SidePanel::left("memory_dumps")
                .resizable(true)
                .default_width(240.0)
                .width_range(180.0..=480.0)
                .frame(egui::Frame::new().inner_margin(egui::Margin {
                    right: 8,
                    ..Default::default()
                }))
                .show_inside(ui, |ui| {
                    action = self.dump_list(ui, &cx);
                });
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                left: 10,
                ..Default::default()
            }))
            .show_inside(ui, |ui| {
                if let Some(next) = self.analysis(ui, &cx) {
                    action = Some(next);
                }
            });
        self.import_window(ui.ctx(), &cx);
        self.catalog_window(ui.ctx(), &cx);
        action
    }

    fn list_toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add(
                    egui::Button::new(egui_phosphor::regular::SIDEBAR_SIMPLE)
                        .frame(false)
                        .selected(!self.hide_list),
                )
                .on_hover_text(if self.hide_list {
                    "Show the dump list"
                } else {
                    "Hide the dump list"
                })
                .clicked()
            {
                self.hide_list = !self.hide_list;
            }
            match self.dump() {
                Some(dump) => {
                    ui.label(
                        RichText::new(dump_title(dump))
                            .strong()
                            .color(theme::heading()),
                    );
                }
                None => {
                    ui.colored_label(theme::muted(), "No dump open");
                }
            }
        });
    }

    fn dump_list(&mut self, ui: &mut egui::Ui, cx: &MemoryContext<'_>) -> Option<MemoryAction> {
        let mut action = None;
        ui.horizontal(|ui| {
            theme::section(ui, "Memory dumps");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(egui::Button::new(egui_phosphor::regular::ARROW_CLOCKWISE).frame(false))
                    .on_hover_text("Refresh the list")
                    .clicked()
                {
                    self.scan(cx.recording_roots);
                }
            });
        });
        let why = if cx.vm.is_none() {
            Some("Select a VM")
        } else if !cx.running {
            Some("Start the VM to dump its memory")
        } else if cx.dumping.is_some() {
            Some("A dump is being written")
        } else {
            None
        };
        let full = egui::vec2(ui.available_width(), 0.0);
        if ui
            .add_enabled(
                why.is_none() && !cx.pending,
                egui::Button::new(format!("{} Dump memory", egui_phosphor::regular::MEMORY))
                    .min_size(full),
            )
            .on_hover_text(
                "Write the VM's RAM to a dump for analysis. The VM pauses while it is \
                 written (seconds to minutes, by RAM size and disk speed) and then continues.",
            )
            .on_disabled_hover_text(why.unwrap_or("Waiting for the VM"))
            .clicked()
        {
            action = Some(MemoryAction::Dump);
        }
        if ui
            .add_enabled(
                cx.vm.is_some() && cx.recordings.is_some(),
                egui::Button::new(format!(
                    "{} Import dump…",
                    egui_phosphor::regular::FILE_ARROW_UP
                ))
                .min_size(full),
            )
            .on_hover_text(
                "Analyse a dump made elsewhere (raw, LiME, ELF core, crash dump, VMware or \
                 VirtualBox memory, hibernation file). The file stays where it is.",
            )
            .on_disabled_hover_text("Select a VM: imported dumps are kept with its recordings")
            .clicked()
            && self.import.is_none()
        {
            self.import = Some(Import {
                path: String::new(),
                os: Os::Linux,
                base: None,
                picker: None,
                error: None,
            });
        }
        ui.add_space(2.0);
        let mut fields = crate::query::LABEL_FIELDS.to_vec();
        fields.extend(crate::query::CAPTURE_FIELDS);
        fields.extend([
            crate::query::FieldSpec::text("name", "Displayed dump name"),
            crate::query::FieldSpec::text("state", "Dump state"),
            crate::query::FieldSpec::text("os", "Guest operating system"),
            crate::query::FieldSpec::text("system", "Recorded guest system"),
            crate::query::FieldSpec::number("size", "Dump size in octets"),
            crate::query::FieldSpec::number("ram_mib", "Configured RAM in MiB"),
            crate::query::FieldSpec::boolean("imported", "Imported dump"),
            crate::query::FieldSpec::boolean("symbols", "Retained symbol table"),
        ]);
        let annotations: Vec<_> = self
            .dumps
            .iter()
            .map(|dump| crate::evidence::annotation(ui, &dump.dir))
            .collect();
        let tags: Vec<_> = annotations
            .iter()
            .flatten()
            .flat_map(|value| value.tags.iter().cloned())
            .collect();
        let filter = crate::query::table_filter(
            ui,
            "memory-dump-history",
            "Filter memory dumps",
            &fields,
            &tags,
        );
        let filter_id = ui.id().with(("table-filter", "memory-dump-history"));
        let shown: Vec<_> = self
            .dumps
            .iter()
            .enumerate()
            .filter(|(index, dump)| {
                filter.keep_table(&memory_dump_row(dump, annotations[*index].as_ref()))
            })
            .map(|(_, dump)| dump)
            .collect();
        ui.weak(format!("{} / {} dumps", shown.len(), self.dumps.len()));
        if self
            .selected
            .as_ref()
            .is_some_and(|selected| !shown.iter().any(|dump| &dump.id == selected))
        {
            self.selected = None;
            self.selected_run = None;
            self.result = None;
        }
        let mut select = None;
        let mut delete = None;
        let font_size = cx.font_size;
        egui::ScrollArea::vertical()
            .id_salt("memory_dump_list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                if let Some(progress) = cx.dumping {
                    let fraction = progress.completed as f32 / progress.total.max(1) as f32;
                    capture_row(
                        ui,
                        false,
                        (
                            &format!("{} Writing dump", egui_phosphor::regular::RECORD),
                            theme::error(),
                        ),
                        &format!(
                            "{:.0}% of {} · VM paused",
                            fraction * 100.0,
                            format_size(progress.total)
                        ),
                        font_size,
                    );
                    ui.add(egui::ProgressBar::new(fraction).desired_height(4.0));
                }
                for dump in shown {
                    if cx
                        .dumping
                        .is_some_and(|progress| progress.dump.id == dump.id)
                    {
                        continue;
                    }
                    let selected = self.selected.as_ref() == Some(&dump.id);
                    let color = if dump.error.is_some() {
                        theme::error()
                    } else {
                        theme::text()
                    };
                    let title = crate::evidence::title(ui, &dump.dir, &dump_title(dump));
                    let row =
                        capture_row(ui, selected, (&title, color), &dump_detail(dump), font_size)
                            .on_hover_text(format!(
                                "{}\n{}{}",
                                dump.path().display(),
                                dump.boot_id
                                    .as_ref()
                                    .map(|boot| format!("Boot {boot}\n"))
                                    .unwrap_or_default(),
                                if dump.symbols {
                                    "Symbol table of its base included"
                                } else {
                                    "No symbol table: Volatility looks for one itself"
                                }
                            ));
                    if row.clicked() {
                        select = Some(dump.id.clone());
                    }
                    row.context_menu(|ui| {
                        crate::evidence::menu(ui, &dump.dir);
                        let annotation = crate::evidence::annotation(ui, &dump.dir);
                        crate::query::table_row_menu(
                            ui,
                            filter_id,
                            &memory_dump_row(dump, annotation.as_ref()),
                        );
                        ui.separator();
                        if ui.button("Open folder").clicked() {
                            if let Err(error) = open_directory(&dump.dir) {
                                self.status = Some((error, true));
                            }
                            ui.close_menu();
                        }
                        if ui.button("Copy path").clicked() {
                            ui.ctx().copy_text(dump.path().display().to_string());
                            ui.close_menu();
                        }
                        ui.separator();
                        let label = if dump.imported {
                            "Remove from list (keeps the file)"
                        } else {
                            "Delete dump and results"
                        };
                        if ui
                            .button(RichText::new(label).color(theme::error()))
                            .clicked()
                        {
                            delete = Some(dump.id.clone());
                            ui.close_menu();
                        }
                    });
                }
                if self.dumps.is_empty() && cx.dumping.is_none() {
                    ui.add_space(4.0);
                    ui.colored_label(theme::muted(), "No memory dumps for this VM");
                }
            });
        if let Some(id) = select {
            self.select(Some(id));
        }
        if let Some(id) = delete {
            self.confirm_delete = Some(id);
        }
        self.delete_window(ui.ctx(), cx);
        action
    }

    fn delete_window(&mut self, ctx: &egui::Context, cx: &MemoryContext<'_>) {
        let Some(id) = self.confirm_delete.clone() else {
            return;
        };
        let Some(dump) = self.dumps.iter().find(|dump| dump.id == id).cloned() else {
            self.confirm_delete = None;
            return;
        };
        let mut open = true;
        let mut done = false;
        egui::Window::new("Delete memory dump")
            .id(egui::Id::new("memory_delete"))
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.label(format!("{} — {}", dump_title(&dump), dump_detail(&dump)));
                let runs = dump.runs().len();
                ui.colored_label(
                    theme::muted(),
                    if dump.imported {
                        format!("Its {runs} saved results are deleted; the imported file stays.")
                    } else {
                        format!("The dump file and its {runs} saved results are deleted.")
                    },
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Delete").color(theme::palette().primary_text),
                            )
                            .fill(theme::error()),
                        )
                        .clicked()
                    {
                        if let Err(error) = memory::delete(&dump) {
                            self.status = Some((error, true));
                        }
                        done = true;
                    }
                    if ui.button("Cancel").clicked() {
                        done = true;
                    }
                });
            });
        if done || !open || ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.confirm_delete = None;
            ctx.request_repaint();
            if done {
                self.scan(cx.recording_roots);
            }
        }
    }

    fn analysis(&mut self, ui: &mut egui::Ui, cx: &MemoryContext<'_>) -> Option<MemoryAction> {
        let mut action = None;
        let Some(dump) = self.dump().cloned() else {
            empty_state(
                ui,
                if cx.vm.is_none() {
                    "Select a VM to see its memory dumps."
                } else if cx.running {
                    "Dump the VM's memory, then pick a Volatility plugin to run on it. \
                     Every result is saved with its dump."
                } else {
                    "Start the VM and dump its memory, or import a dump made elsewhere. \
                     Volatility 3 then analyses it: processes, open files, network \
                     connections, kernel modules, injected code and more."
                },
            );
            return None;
        };
        ui.add_space(2.0);
        let failed = match &self.catalog {
            Catalog::Failed(error) => Some(error.clone()),
            _ => None,
        };
        match &self.catalog {
            Catalog::Ready(..) => {}
            Catalog::Loading(_) | Catalog::Unknown => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.colored_label(theme::muted(), "Listing Volatility plugins…");
                });
            }
            Catalog::Failed(_) => {
                let error = failed.unwrap_or_default();
                egui::Frame::new()
                    .fill(theme::raised())
                    .corner_radius(4.0)
                    .inner_margin(8.0)
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(egui_phosphor::regular::WARNING).color(theme::warn()),
                            );
                            if cx.volatility_installed {
                                ui.label(error.as_str());
                                if ui.button("Try again").clicked() {
                                    self.catalog = Catalog::Unknown;
                                }
                            } else if cx.volatility_installing {
                                ui.spinner();
                                ui.label("Installing Volatility 3…");
                            } else {
                                ui.label(
                                    "Memory analysis runs Volatility 3 on the system Python 3. \
                                     Install it once (about 5 MB, pinned release):",
                                );
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new("Install Volatility 3")
                                                .color(theme::palette().primary_text),
                                        )
                                        .fill(theme::primary()),
                                    )
                                    .clicked()
                                {
                                    action = Some(MemoryAction::InstallVolatility);
                                }
                            }
                        });
                    });
            }
        }
        if !dump.complete() {
            ui.add_space(8.0);
            ui.colored_label(
                theme::muted(),
                dump.error
                    .as_deref()
                    .unwrap_or("This dump is still being written."),
            );
            return action;
        }
        if let Some(next) = self.plugin_bar(ui, &dump, cx) {
            action = Some(next);
        }
        if let Some((message, error)) = &self.status {
            ui.colored_label(
                if *error {
                    theme::error()
                } else {
                    theme::muted()
                },
                message,
            );
        }
        ui.add_space(4.0);
        egui::SidePanel::left("memory_runs")
            .resizable(true)
            .default_width(230.0)
            .width_range(170.0..=420.0)
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                right: 8,
                ..Default::default()
            }))
            .show_inside(ui, |ui| self.run_list(ui, cx.font_size));
        egui::CentralPanel::default()
            .frame(egui::Frame::new())
            .show_inside(ui, |ui| self.result_view(ui, &dump, cx.font_size));
        action
    }

    fn plugin_bar(
        &mut self,
        ui: &mut egui::Ui,
        dump: &MemoryDump,
        cx: &MemoryContext<'_>,
    ) -> Option<MemoryAction> {
        let (data_dir, font_size) = (cx.data_dir, cx.font_size);
        let Catalog::Ready(volatility, catalog) = &self.catalog else {
            return None;
        };
        let mut action = None;
        let plugins = &catalog.plugins;
        let failures = &catalog.failures;
        let mut reload = false;
        let list_os = match &self.list_os {
            Some((id, os)) if id == &dump.id => *os,
            _ => dump.os,
        };
        let community_os = &self.community_os;
        // A catalog plugin's system is in its manifest; others' in their name.
        let os_of = |plugin: &PluginInfo| {
            plugin.os().or_else(|| {
                plugin
                    .community
                    .then(|| plugin.name.split('.').next())
                    .flatten()
                    .and_then(|id| community_os.get(id).copied())
            })
        };
        let applies = |plugin: &&PluginInfo| {
            os_of(plugin).is_none_or(|os| os == list_os)
                && !matches!(
                    plugin.name.as_str(),
                    "configwriter.ConfigWriter"
                        | "layerwriter.LayerWriter"
                        | "frameworkinfo.FrameworkInfo"
                )
        };
        if self.plugin.as_ref().is_none_or(|name| {
            !plugins
                .iter()
                .any(|plugin| &plugin.name == name && applies(&plugin))
        }) {
            let default = format!("{}.pslist.PsList", list_os.prefix());
            self.plugin = plugins
                .iter()
                .find(|plugin| plugin.name == default)
                .or_else(|| plugins.iter().find(applies))
                .map(|plugin| plugin.name.clone());
        }
        let current = self
            .plugin
            .as_ref()
            .and_then(|name| plugins.iter().find(|plugin| &plugin.name == name))
            .cloned()?;
        let mut chosen = None;
        let mut run = None;
        let mut chosen_os = None;
        ui.horizontal(|ui| {
            for os in Os::ALL {
                if ui
                    .selectable_label(list_os == os, os.label())
                    .on_hover_text(format!("List the plugins for {} dumps", os.label()))
                    .clicked()
                {
                    chosen_os = Some(os);
                }
            }
            if list_os != dump.os {
                ui.label(RichText::new(egui_phosphor::regular::WARNING).color(theme::warn()))
                    .on_hover_text(format!(
                        "This dump is {}: {} plugins will not find what they look for",
                        dump.os.label(),
                        list_os.label()
                    ));
            }
            ui.separator();
            ui.label(RichText::new("Plugin").color(theme::muted()));
            egui::ComboBox::from_id_salt("memory_plugin")
                .width(360.0)
                .height(480.0)
                .selected_text(RichText::new(&current.name).font(theme::mono(font_size - 1.0)))
                .show_ui(ui, |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text("Search plugins")
                            .desired_width(f32::INFINITY),
                    )
                    .request_focus();
                    ui.checkbox(&mut self.show_deprecated, "Show deprecated names");
                    ui.separator();
                    let needle = self.search.trim().to_lowercase();
                    let mut group = String::new();
                    // Volatility's own plugins, then the community folder's.
                    let ordered = plugins
                        .iter()
                        .filter(|plugin| !plugin.community)
                        .chain(plugins.iter().filter(|plugin| plugin.community));
                    for plugin in ordered.filter(applies) {
                        if plugin.deprecated() && !self.show_deprecated {
                            continue;
                        }
                        if !needle.is_empty()
                            && !plugin.name.to_lowercase().contains(&needle)
                            && !plugin.help.to_lowercase().contains(&needle)
                        {
                            continue;
                        }
                        let area = if plugin.community {
                            let os = os_of(plugin).map_or("generic", Os::prefix);
                            format!("community · {os}")
                        } else {
                            plugin_area(&plugin.name)
                        };
                        if area != group {
                            group = area.clone();
                            ui.add_space(2.0);
                            ui.label(RichText::new(area).small().color(theme::heading()));
                        }
                        let selected = plugin.name == current.name;
                        if ui
                            .selectable_label(
                                selected,
                                RichText::new(&plugin.name).font(theme::mono(font_size - 1.0)),
                            )
                            .on_hover_text(&plugin.help)
                            .clicked()
                        {
                            chosen = Some(plugin.name.clone());
                        }
                    }
                });
            let running = self
                .jobs
                .iter()
                .any(|job| job.run.dump_id == dump.id && job.run.plugin == current.name);
            if ui
                .add_enabled(
                    !running,
                    egui::Button::new(
                        RichText::new(format!("{} Run", egui_phosphor::regular::PLAY))
                            .color(theme::palette().primary_text),
                    )
                    .fill(theme::primary()),
                )
                .on_hover_text("Run the plugin on this dump; the result is saved with it")
                .on_disabled_hover_text("This plugin is already running on this dump")
                .clicked()
            {
                let values = self.values.get(&current.name).cloned().unwrap_or_default();
                run = Some(memory::plugin_args(&current, &values));
            }
            ui.menu_button(egui_phosphor::regular::GEAR, |ui| {
                ui.set_max_width(440.0);
                let mut online = cx.online_symbols;
                if ui
                    .checkbox(&mut online, "Look up symbol tables online")
                    .changed()
                {
                    action = Some(MemoryAction::OnlineSymbols(online));
                }
                ui.label(
                    RichText::new(format!(
                        "For Linux and macOS dumps without a symbol table of their own (imported \
                         dumps): after Volatility's folders, the table of the dump's kernel is \
                         looked up by its banner in {} on GitHub, about 11,000 distribution \
                         kernels, and kept in Volatility's cache. Dumps of Antinomie's VMs carry \
                         their base's table and stay offline.",
                        memory::ONLINE_SYMBOLS_NAME
                    ))
                    .color(theme::muted()),
                );
            })
            .response
            .on_hover_text("Memory analysis options");
            let community = plugins.iter().filter(|plugin| plugin.community).count();
            let label = if failures.is_empty() {
                format!(
                    "{} Community ({community})",
                    egui_phosphor::regular::PUZZLE_PIECE
                )
            } else {
                format!(
                    "{} Community ({community}, {} failed)",
                    egui_phosphor::regular::PUZZLE_PIECE,
                    failures.len()
                )
            };
            ui.menu_button(label, |ui| {
                ui.set_max_width(420.0);
                if !failures.is_empty() {
                    ui.colored_label(theme::error(), "Failed to load:");
                    for failure in failures {
                        ui.label(
                            RichText::new(failure.trim_start_matches("volatility3.plugins."))
                                .font(theme::mono(font_size - 2.0))
                                .color(theme::error()),
                        );
                    }
                }
                ui.separator();
                if ui
                    .button(format!(
                        "{} Plugin catalog…",
                        egui_phosphor::regular::STOREFRONT
                    ))
                    .on_hover_text("Download community plugins checked for this Volatility")
                    .clicked()
                {
                    self.catalog_open = true;
                    ui.close_menu();
                }
                if ui.button("Open community plugins folder").clicked() {
                    let dir = memory::plugins_dir(data_dir);
                    let opened = std::fs::create_dir_all(&dir)
                        .map_err(|error| format!("{}: {error}", dir.display()))
                        .and_then(|()| open_directory(&dir));
                    if let Err(error) = opened {
                        self.status = Some((error, true));
                    }
                    ui.close_menu();
                }
                if ui
                    .button("Reload plugin list")
                    .on_hover_text("After adding, changing or removing plugins")
                    .clicked()
                {
                    reload = true;
                    ui.close_menu();
                }
            });
            // Truncated: a long description must not widen the tab.
            ui.add(egui::Label::new(RichText::new(&current.help).color(theme::muted())).truncate())
                .on_hover_text(&current.help);
        });
        if !current.options.is_empty() {
            let values = self.values.entry(current.name.clone()).or_default();
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                for option in &current.options {
                    let at = match values.iter().position(|(name, _)| name == &option.name) {
                        Some(at) => at,
                        None => {
                            values.push((option.name.clone(), String::new()));
                            values.len() - 1
                        }
                    };
                    let value = &mut values[at].1;
                    let help = if option.help.is_empty() {
                        option.flag()
                    } else {
                        format!("{}\n{}", option.flag(), option.help)
                    };
                    match option.kind {
                        OptionKind::Bool => {
                            let mut on = value == "true";
                            if ui
                                .checkbox(&mut on, option.name.replace('_', " "))
                                .on_hover_text(help)
                                .changed()
                            {
                                *value = if on { "true".into() } else { String::new() };
                            }
                        }
                        OptionKind::Choice => {
                            ui.label(option.name.replace('_', " ")).on_hover_text(&help);
                            egui::ComboBox::from_id_salt(("memory_choice", &option.name))
                                .selected_text(if value.is_empty() {
                                    "default".to_owned()
                                } else {
                                    value.clone()
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(value, String::new(), "default");
                                    for choice in &option.choices {
                                        ui.selectable_value(value, choice.clone(), choice);
                                    }
                                });
                        }
                        _ => {
                            ui.label(option.name.replace('_', " ")).on_hover_text(&help);
                            let hint = match option.kind {
                                OptionKind::List => "values, comma-separated".to_owned(),
                                _ => option
                                    .default
                                    .as_ref()
                                    .map(|value| value.to_string())
                                    .unwrap_or_default(),
                            };
                            ui.add(
                                egui::TextEdit::singleline(value)
                                    .hint_text(hint)
                                    .font(egui::TextStyle::Monospace)
                                    .margin(theme::TEXT_EDIT_MARGIN)
                                    .desired_width(if option.kind == OptionKind::Int {
                                        90.0
                                    } else {
                                        170.0
                                    }),
                            )
                            .on_hover_text(help);
                        }
                    }
                }
            });
        }
        if let Some(name) = chosen {
            self.plugin = Some(name);
            self.search.clear();
        }
        if let Some(os) = chosen_os {
            self.list_os = Some((dump.id.clone(), os));
        }
        if reload {
            self.catalog = Catalog::Unknown;
            return action;
        }
        match run {
            Some(Ok(args)) => {
                match volatility.start(dump, &current.name, args, cx.online_symbols) {
                    Ok(job) => {
                        let id = job.run.id.clone();
                        self.jobs.push(job);
                        self.reload_runs();
                        self.selected_run = Some(id);
                        self.result = None;
                        self.status = None;
                    }
                    Err(error) => self.status = Some((error, true)),
                }
            }
            Some(Err(error)) => self.status = Some((error, true)),
            None => {}
        }
        action
    }

    fn run_list(&mut self, ui: &mut egui::Ui, font_size: f32) {
        theme::section(ui, "Results");
        let mut fields = crate::query::LABEL_FIELDS.to_vec();
        fields.extend([
            crate::query::FieldSpec::text("name", "Displayed plugin result name"),
            crate::query::FieldSpec::text("plugin", "Full plugin name"),
            crate::query::FieldSpec::text("state", "Plugin result state"),
            crate::query::FieldSpec::text("args", "Plugin arguments"),
            crate::query::FieldSpec::number("rows", "Retained result rows"),
            crate::query::FieldSpec::number("exit_code", "Tool exit code"),
        ]);
        let annotations: Vec<_> = self
            .runs
            .iter()
            .map(|run| crate::evidence::annotation(ui, &run.dir))
            .collect();
        let tags: Vec<_> = annotations
            .iter()
            .flatten()
            .flat_map(|value| value.tags.iter().cloned())
            .collect();
        let filter = crate::query::table_filter(
            ui,
            "memory-plugin-history",
            "Filter plugin results",
            &fields,
            &tags,
        );
        let filter_id = ui.id().with(("table-filter", "memory-plugin-history"));
        let shown: Vec<_> = self
            .runs
            .iter()
            .enumerate()
            .filter(|(index, run)| {
                filter.keep_table(&plugin_run_row(run, annotations[*index].as_ref()))
            })
            .map(|(_, run)| run)
            .collect();
        ui.weak(format!("{} / {} results", shown.len(), self.runs.len()));
        if self
            .selected_run
            .as_ref()
            .is_some_and(|selected| !shown.iter().any(|run| &run.id == selected))
        {
            self.selected_run = None;
            self.result = None;
        }
        let mut open = None;
        let mut delete = None;
        let mut rerun = None;
        egui::ScrollArea::vertical()
            .id_salt("memory_run_list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                for run in shown {
                    let job = self.jobs.iter().find(|job| job.run.id == run.id);
                    let progress = job.map(RunHandle::progress);
                    let color = match (job, run.state) {
                        (Some(_), _) => theme::info(),
                        (None, RunState::Failed) => theme::error(),
                        (None, RunState::Cancelled | RunState::Running) => theme::muted(),
                        (None, RunState::Finished) => theme::text(),
                    };
                    let mut title = run.short_name().to_owned();
                    if !run.args.is_empty() {
                        title.push(' ');
                        title.push_str(&args_summary(run));
                    }
                    let title = crate::evidence::title(ui, &run.dir, &title);
                    let row = capture_row(
                        ui,
                        self.selected_run.as_ref() == Some(&run.id),
                        (&title, color),
                        &run_detail(run, progress.as_ref()),
                        font_size,
                    )
                    .on_hover_text(format!(
                        "{} {}\nStarted {}{}",
                        run.plugin,
                        args_summary(run),
                        format_date(run.started_ms / 1000),
                        if run.symbols_online.is_some() {
                            format!(
                                "\nSymbol table looked up online ({})",
                                memory::ONLINE_SYMBOLS_NAME
                            )
                        } else {
                            String::new()
                        }
                    ));
                    if row.clicked() {
                        open = Some(run.id.clone());
                    }
                    row.context_menu(|ui| {
                        crate::evidence::menu(ui, &run.dir);
                        let annotation = crate::evidence::annotation(ui, &run.dir);
                        crate::query::table_row_menu(
                            ui,
                            filter_id,
                            &plugin_run_row(run, annotation.as_ref()),
                        );
                        ui.separator();
                        if let Some(job) = job {
                            if ui.button("Cancel run").clicked() {
                                job.cancel();
                                ui.close_menu();
                            }
                            return;
                        }
                        if ui
                            .button("Set up again")
                            .on_hover_text("Choose this plugin with these options")
                            .clicked()
                        {
                            rerun = Some(run.clone());
                            ui.close_menu();
                        }
                        if ui.button("Open its folder").clicked() {
                            if let Err(error) = open_directory(&run.dir) {
                                self.status = Some((error, true));
                            }
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .button(RichText::new("Delete result").color(theme::error()))
                            .clicked()
                        {
                            delete = Some(run.clone());
                            ui.close_menu();
                        }
                    });
                    if let Some(progress) = &progress {
                        ui.add(
                            egui::ProgressBar::new(progress.percent / 100.0).desired_height(3.0),
                        );
                    }
                }
                if self.runs.is_empty() {
                    ui.colored_label(theme::muted(), "No results yet: pick a plugin and Run");
                }
            });
        if let Some(run) = delete {
            if let Err(error) = memory::delete_run(&run) {
                self.status = Some((error, true));
            }
            self.reload_runs();
            if self.selected_run.as_ref() == Some(&run.id) {
                let newest = self.runs.first().map(|run| run.id.clone());
                self.open_run(newest);
            }
        }
        if let Some(run) = rerun {
            self.plugin = Some(run.plugin.clone());
            if let Catalog::Ready(_, catalog) = &self.catalog {
                self.values
                    .insert(run.plugin.clone(), args_values(&run, &catalog.plugins));
            }
        }
        if let Some(id) = open {
            self.open_run(Some(id));
        }
    }

    fn result_view(&mut self, ui: &mut egui::Ui, dump: &MemoryDump, font_size: f32) {
        let Some(run_id) = self.selected_run.clone() else {
            empty_state(
                ui,
                "Pick a plugin and Run it: its result appears here and is saved with this dump.",
            );
            return;
        };
        if let Some(job) = self.jobs.iter().find(|job| job.run.id == run_id) {
            let progress = job.progress();
            ui.add_space(12.0);
            ui.vertical_centered(|ui| {
                ui.spinner();
                ui.label(format!(
                    "Running {} on {}",
                    job.run.plugin,
                    dump_title(dump)
                ));
                ui.colored_label(
                    theme::muted(),
                    if progress.step.is_empty() {
                        "Starting Volatility…".to_owned()
                    } else {
                        format!("{:.0}% {}", progress.percent, progress.step)
                    },
                );
                ui.add(egui::ProgressBar::new(progress.percent / 100.0).desired_width(320.0));
                if ui.button("Cancel").clicked() {
                    job.cancel();
                }
            });
            return;
        }
        if self
            .result
            .as_ref()
            .is_none_or(|result| result.run.id != run_id)
        {
            let mut cancel = false;
            let mut retry = false;
            ui.horizontal(|ui| {
                if self.loading.is_some() {
                    ui.spinner();
                    ui.colored_label(theme::muted(), "Loading the result…");
                    cancel = ui.button("Cancel query").clicked();
                } else {
                    ui.label("Result not loaded.");
                    retry = ui.button("Load result").clicked();
                }
            });
            if cancel {
                self.cancel_result_load();
            }
            if retry {
                self.open_run(Some(run_id.clone()));
            }
            return;
        }
        let mut request = None;
        if let Some(result) = self.result.as_ref() {
            if let Ok(table) = &result.table {
                let annotation = crate::evidence::annotation(ui, &result.run.dir);
                let mut record = plugin_result_record(&result.run, annotation.as_ref());
                add_dump_identity(
                    &mut record,
                    self.dump().map(|dump| dump.vm_id.as_str()),
                    self.dump().and_then(|dump| dump.boot_id.as_deref()),
                );
                let tags: &[String] = annotation
                    .as_ref()
                    .map_or(&[], |annotation| annotation.tags.as_slice());
                let names = column_fields(&table.columns);
                let fields = result_fields(&names, &table.columns);
                crate::query::filter_edit_fields(
                    ui,
                    &mut self.filter,
                    "Filter result fields",
                    ui.available_width(),
                    &fields,
                    tags,
                );
                let compiled = crate::query::compile_table(&self.filter, &fields);
                if let Some(error) = compiled.error {
                    ui.colored_label(
                        theme::warn(),
                        format!("{error} · showing the last valid filter"),
                    );
                } else {
                    crate::query::remember_valid_filter(ui, &self.filter);
                    if result.filter != self.filter
                        || result.sort != self.sort
                        || result.record != record
                    {
                        request = Some(ResultRequest {
                            vm_id: self.dump().map(|dump| dump.vm_id.clone()),
                            boot_id: self.dump().and_then(|dump| dump.boot_id.clone()),
                            run_id: result.run.id.clone(),
                            source: result.run.output(),
                            query: self.filter.clone(),
                            sort: self.sort,
                            start: 0,
                        });
                    }
                }
                let page_count = result.total.div_ceil(RESULT_PAGE_LEN as u64).max(1);
                let page_number = result.start / RESULT_PAGE_LEN as u64 + 1;
                let mut start = None;
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            self.loading.is_none() && result.start > 0,
                            egui::Button::new("Previous"),
                        )
                        .clicked()
                    {
                        start = Some(result.start.saturating_sub(RESULT_PAGE_LEN as u64));
                    }
                    ui.label(format!(
                        "Page {page_number}/{page_count} · {} matching / {} retained rows",
                        result.total, result.source_rows
                    ));
                    if ui
                        .add_enabled(
                            self.loading.is_none()
                                && result.start + (table.rows.len() as u64) < result.total,
                            egui::Button::new("Next"),
                        )
                        .clicked()
                    {
                        start = Some(result.start + RESULT_PAGE_LEN as u64);
                    }
                    if ui
                        .add_enabled(self.loading.is_none(), egui::Button::new("Refresh"))
                        .clicked()
                    {
                        start = Some(result.start);
                    }
                });
                if let Some(start) = start {
                    request = Some(ResultRequest {
                        vm_id: self.dump().map(|dump| dump.vm_id.clone()),
                        boot_id: self.dump().and_then(|dump| dump.boot_id.clone()),
                        run_id: result.run.id.clone(),
                        source: result.run.output(),
                        query: result.filter.clone(),
                        sort: result.sort,
                        start,
                    });
                }
                if result.skipped_lines > 0 {
                    ui.colored_label(
                        theme::warn(),
                        format!(
                            "{} incomplete or invalid saved lines were unavailable",
                            result.skipped_lines
                        ),
                    );
                }
            } else if ui.button("Retry result").clicked() {
                request = Some(ResultRequest {
                    vm_id: self.dump().map(|dump| dump.vm_id.clone()),
                    boot_id: self.dump().and_then(|dump| dump.boot_id.clone()),
                    run_id: result.run.id.clone(),
                    source: result.run.output(),
                    query: self.filter.clone(),
                    sort: self.sort,
                    start: 0,
                });
            }
        }
        if let Some(request) = request {
            self.request_result(request);
        }
        if self.loading.is_some() {
            let mut cancel = false;
            ui.horizontal_wrapped(|ui| {
                ui.spinner();
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
        let Some(result) = self.result.as_mut() else {
            return;
        };
        if let Some(error) = &result.filter_error {
            ui.colored_label(theme::warn(), error);
        }
        let mut status = None;
        // The controls keep their size; the title takes what is left.
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.toggle_value(&mut self.show_log, "Messages")
                    .on_hover_text("Volatility's messages for this run");
                ui.selectable_value(&mut self.text_view, true, "Text")
                    .on_hover_text("The result as Volatility prints it");
                ui.selectable_value(&mut self.text_view, false, "Table")
                    .on_hover_text("Columns colored by type; click a column name to sort");
                ui.separator();
                let files = std::fs::read_dir(result.run.files())
                    .map(|mut entries| entries.next().is_some())
                    .unwrap_or(false);
                if files
                    && ui
                        .button(format!("{} Files", egui_phosphor::regular::FOLDER_OPEN))
                        .on_hover_text("Open the files this run wrote")
                        .clicked()
                {
                    if let Err(error) = open_directory(&result.run.files()) {
                        status = Some(error);
                    }
                }
                if let Ok(table) = &result.table {
                    if ui
                        .button(format!("{} Copy", egui_phosphor::regular::COPY))
                        .on_hover_text(if self.text_view {
                            "Copy this page as Volatility's text"
                        } else {
                            "Copy this page as tab-separated text"
                        })
                        .clicked()
                    {
                        ui.ctx().copy_text(if self.text_view {
                            memory::result_text(table, &result.shown)
                        } else {
                            result_tsv(&table.columns, table, &result.shown)
                        });
                    }
                }
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    let mut title = egui::text::LayoutJob::default();
                    let mono = theme::mono(font_size - 1.0);
                    title.append(
                        &result.run.plugin,
                        0.0,
                        egui::TextFormat::simple(mono.clone(), theme::heading()),
                    );
                    if !result.run.args.is_empty() {
                        title.append(
                            &args_summary(&result.run),
                            8.0,
                            egui::TextFormat::simple(mono, theme::value(ValueKind::Flags)),
                        );
                    }
                    if let Ok(table) = &result.table {
                        let rows = format!("{} rows on this page", table.rows.len());
                        title.append(
                            &rows,
                            10.0,
                            egui::TextFormat::simple(
                                egui::TextStyle::Body.resolve(ui.style()),
                                theme::muted(),
                            ),
                        );
                    }
                    let hover = title.text.clone();
                    ui.add(egui::Label::new(title).truncate())
                        .on_hover_text(hover);
                });
            })
        });
        if let Some(error) = status {
            self.status = Some((error, true));
        }
        if result.run.state == RunState::Failed {
            ui.add(
                egui::Label::new(
                    RichText::new(result.run.error.as_deref().unwrap_or("Volatility failed"))
                        .color(theme::error()),
                )
                .wrap(),
            );
            self.show_log = true;
        }
        if self.show_log {
            egui::TopBottomPanel::bottom("memory_log")
                .resizable(true)
                .default_height(140.0)
                .show_inside(ui, |ui| {
                    egui::ScrollArea::both()
                        .id_salt("memory_log_text")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            let text = if result.log.trim().is_empty() {
                                "No messages"
                            } else {
                                result.log.as_str()
                            };
                            ui.label(
                                RichText::new(text)
                                    .font(theme::mono(font_size - 2.0))
                                    .color(theme::muted()),
                            );
                        });
                });
        }
        let table = match &result.table {
            Ok(table) => table,
            Err(error) => {
                // A failed run's reason is shown above.
                if result.run.state != RunState::Failed {
                    ui.colored_label(theme::muted(), format!("No result saved: {error}"));
                }
                return;
            }
        };
        if table.columns.is_empty() {
            ui.colored_label(theme::muted(), "The plugin wrote no result.");
            return;
        }
        if table.rows.is_empty() {
            ui.colored_label(
                theme::muted(),
                if result.source_rows == 0 {
                    "The plugin saved no result rows."
                } else {
                    "No retained row matches the filter."
                },
            );
        }
        let mono = theme::mono(font_size - 1.0);
        if self.text_view {
            let lines = result.text.get_or_insert_with(|| {
                memory::result_text(table, &result.shown)
                    .lines()
                    .map(str::to_owned)
                    .collect()
            });
            let line_height = ui.fonts(|fonts| fonts.row_height(&mono)) + 2.0;
            egui::Frame::new()
                .fill(theme::bg())
                .corner_radius(4.0)
                .inner_margin(egui::Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    egui::ScrollArea::both()
                        .id_salt(("memory_result_text", &result.run.id))
                        .auto_shrink([false, false])
                        .show_rows(ui, line_height, lines.len(), |ui, range| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            for line in &lines[range] {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(expand_tabs(line)).font(mono.clone()),
                                    )
                                    .extend(),
                                );
                            }
                        });
                });
            return;
        }
        let char_width = ui.fonts(|fonts| fonts.glyph_width(&mono, '0'));
        let row_height = theme::row_height(font_size);
        let widths = column_widths(table, char_width);
        let total: f32 = widths.iter().sum();
        // Wider than the panel: every column keeps its width and the table
        // scrolls sideways; otherwise the last column takes the rest.
        let fits = total <= ui.available_width();
        let indent = 14.0;
        // Sorted rows lose their tree: shown flat.
        let nested = result.sort.is_none();
        let selected_row = self.selected_row;
        let mut clicked_row = None;
        let mut clicked_header = None;
        egui::ScrollArea::horizontal()
            .id_salt(("memory_result_wide", &result.run.id))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let mut builder = TableBuilder::new(ui)
                    .id_salt(("memory_result", &result.run.id))
                    .striped(true)
                    .resizable(true)
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .max_scroll_height(f32::INFINITY)
                    .min_scrolled_height(0.0)
                    .auto_shrink([false, false]);
                for (index, width) in widths.iter().enumerate() {
                    builder = if index + 1 == widths.len() && fits {
                        builder.column(
                            Column::remainder()
                                .at_least(width.min(char_width * 12.0))
                                .clip(true),
                        )
                    } else {
                        builder.column(
                            Column::initial(*width)
                                .at_least(char_width * 4.0)
                                .clip(true),
                        )
                    };
                }
                builder
                    .header(row_height + 4.0, |mut header| {
                        for (index, column) in table.columns.iter().enumerate() {
                            header.col(|ui| {
                                let arrow = match result.sort {
                                    Some(sort) if sort.column == index && sort.descending => {
                                        format!(" {}", egui_phosphor::regular::CARET_DOWN)
                                    }
                                    Some(sort) if sort.column == index => {
                                        format!(" {}", egui_phosphor::regular::CARET_UP)
                                    }
                                    _ => String::new(),
                                };
                                let response = ui
                                    .add(
                                        egui::Label::new(
                                            RichText::new(format!("{}{arrow}", column.name))
                                                .strong()
                                                .color(theme::heading()),
                                        )
                                        .truncate()
                                        .sense(egui::Sense::click()),
                                    )
                                    .on_hover_text(
                                        "Sort: ascending, descending, then as Volatility gave it",
                                    )
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                                if response.clicked() {
                                    clicked_header = Some(index);
                                }
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(row_height, result.shown.len(), |mut row| {
                            let row_index = result.shown[row.index()];
                            let data = &table.rows[row_index];
                            row.set_selected(selected_row == Some(row_index));
                            for (index, (value, column)) in
                                data.values.iter().zip(&table.columns).enumerate()
                            {
                                row.col(|ui| {
                                    if nested && index == 0 && data.depth > 0 {
                                        ui.add_space(f32::from(data.depth) * indent);
                                        ui.label(
                                            RichText::new("└")
                                                .font(mono.clone())
                                                .color(theme::line()),
                                        );
                                    }
                                    let text = memory::value_text(column.kind, value);
                                    let mut label = RichText::new(&text)
                                        .font(mono.clone())
                                        .color(value_color(column.kind, value));
                                    if value.get("absent").is_some() {
                                        label = label.italics();
                                    }
                                    let response = ui.add(
                                        egui::Label::new(label)
                                            .truncate()
                                            .sense(egui::Sense::click()),
                                    );
                                    if response.clicked() {
                                        clicked_row = Some(row_index);
                                    }
                                    response.context_menu(|ui| {
                                        if ui.button("Copy value").clicked() {
                                            ui.ctx().copy_text(text.clone());
                                            ui.close_menu();
                                        }
                                        if ui.button("Copy row").clicked() {
                                            ui.ctx().copy_text(row_text(&table.columns, data));
                                            ui.close_menu();
                                        }
                                        let names = column_fields(&table.columns);
                                        let mut values = result_row(&names, &table.columns, data);
                                        values.extend(result.record.iter().cloned());
                                        if let Some((field, value)) = values.get(index + 1) {
                                            crate::query::value_menu(
                                                ui,
                                                field,
                                                value,
                                                &mut self.filter,
                                            );
                                        }
                                        ui.menu_button("Filter result metadata", |ui| {
                                            for (field, value) in &result.record {
                                                ui.menu_button(*field, |ui| {
                                                    crate::query::value_menu(
                                                        ui,
                                                        field,
                                                        value,
                                                        &mut self.filter,
                                                    )
                                                });
                                            }
                                        });
                                    });
                                });
                            }
                            if row.response().clicked() {
                                clicked_row = Some(row_index);
                            }
                        });
                    });
            });
        if clicked_row.is_some() {
            self.selected_row = clicked_row;
        }
        if let Some(column) = clicked_header {
            self.sort = next_sort(self.sort, column);
        }
    }

    /// The Details panel while it follows the Memory tab: every value of the
    /// selected result row, in full.
    pub(crate) fn details(&mut self, ui: &mut egui::Ui, font_size: f32) {
        let row = self.result.as_ref().and_then(|result| {
            let table = result.table.as_ref().ok()?;
            let row = table.rows.get(self.selected_row?)?;
            Some((
                result.run.plugin.clone(),
                table.columns.clone(),
                row.clone(),
            ))
        });
        let Some((plugin, columns, row)) = row else {
            ui.add_space(6.0);
            ui.colored_label(
                theme::muted(),
                "Select a row of a Volatility result to see all its values here",
            );
            return;
        };
        let mono = theme::mono(font_size - 1.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(&plugin)
                    .font(mono.clone())
                    .color(theme::heading()),
            );
            if ui
                .button(format!("{} Copy row", egui_phosphor::regular::COPY))
                .clicked()
            {
                ui.ctx().copy_text(row_text(&columns, &row));
            }
        });
        egui::ScrollArea::vertical()
            .id_salt("memory_row_details")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("memory_row_grid")
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for (value, column) in row.values.iter().zip(&columns) {
                            ui.label(RichText::new(&column.name).color(theme::muted()));
                            let text = memory::value_text(column.kind, value);
                            let response = ui.add(
                                egui::Label::new(
                                    RichText::new(&text)
                                        .font(mono.clone())
                                        .color(value_color(column.kind, value)),
                                )
                                .wrap()
                                .sense(egui::Sense::click()),
                            );
                            response.context_menu(|ui| {
                                if ui.button("Copy value").clicked() {
                                    ui.ctx().copy_text(text.clone());
                                    ui.close_menu();
                                }
                            });
                            ui.end_row();
                        }
                    });
            });
    }

    fn import_window(&mut self, ctx: &egui::Context, cx: &MemoryContext<'_>) {
        let Some(import) = self.import.as_mut() else {
            return;
        };
        let mut open = true;
        let mut close = false;
        let mut done = None;
        let with_symbols: Vec<&BaseSummary> = cx
            .bases
            .iter()
            .filter(|base| base.directory.join(memory_symbols_file()).is_file())
            .collect();
        egui::Window::new("Import memory dump")
            .id(egui::Id::new("memory_import"))
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                egui::Grid::new("memory_import_grid")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Dump file");
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut import.path)
                                    .hint_text("/path/to/memory.raw")
                                    .font(egui::TextStyle::Monospace)
                                    .margin(theme::TEXT_EDIT_MARGIN)
                                    .desired_width(320.0),
                            );
                            if ui
                                .add_enabled(import.picker.is_none(), egui::Button::new("Browse…"))
                                .on_disabled_hover_text("The file chooser is open")
                                .clicked()
                            {
                                match Command::new("zenity")
                                    .args(["--file-selection", "--title=Choose a memory dump"])
                                    .stdout(Stdio::piped())
                                    .stderr(Stdio::null())
                                    .spawn()
                                {
                                    Ok(child) => import.picker = Some(child),
                                    Err(error) => {
                                        import.error = Some(format!("File chooser (zenity): {error}"))
                                    }
                                }
                            }
                        });
                        ui.end_row();
                        ui.label("System");
                        ui.horizontal(|ui| {
                            for os in Os::ALL {
                                ui.selectable_value(&mut import.os, os, os.label());
                            }
                        });
                        ui.end_row();
                        ui.label("Symbol table");
                        ui.add_enabled_ui(import.os == Os::Linux, |ui| {
                            let automatic = if cx.online_symbols {
                                "Find it: Volatility's folders, then online"
                            } else {
                                "Find it in Volatility's folders"
                            };
                            let selected = import
                                .base
                                .as_ref()
                                .and_then(|dir| with_symbols.iter().find(|base| &base.directory == dir))
                                .map_or(automatic.to_owned(), |base| base_choice(base));
                            egui::ComboBox::from_id_salt("memory_import_symbols")
                                .width(360.0)
                                .selected_text(selected)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut import.base, None, automatic);
                                    for base in cx.bases {
                                        let has = with_symbols
                                            .iter()
                                            .any(|other| other.directory == base.directory);
                                        ui.add_enabled_ui(has, |ui| {
                                            ui.selectable_value(
                                                &mut import.base,
                                                Some(base.directory.clone()),
                                                base_choice(base),
                                            )
                                            .on_disabled_hover_text(
                                                "Built before Antinomie 0.4.0: its kernel has no \
                                                 symbol table. Download the 0.4.0 base for one.",
                                            );
                                        });
                                    }
                                });
                        });
                        ui.end_row();
                    });
                ui.colored_label(
                    theme::muted(),
                    match import.os {
                        Os::Windows => "Windows symbols are downloaded from Microsoft's symbol server when a plugin first needs them.",
                        Os::Linux => "Linux dumps need the symbol table of their exact kernel: pick the base a dump of an Antinomie VM was taken from; for other machines, Volatility finds distribution kernels' tables.",
                        Os::Mac => "macOS dumps need a symbol table for their kernel in Volatility's symbol folders.",
                    },
                );
                if let Some(error) = &import.error {
                    ui.colored_label(theme::error(), error);
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let ready = !import.path.trim().is_empty();
                    if ui
                        .add_enabled(
                            ready,
                            egui::Button::new(RichText::new("Import").color(theme::palette().primary_text))
                                .fill(theme::primary()),
                        )
                        .clicked()
                    {
                        let path = crate::folders::user_path(&import.path);
                        let symbols = import.base.as_ref().and_then(|dir| {
                            with_symbols
                                .iter()
                                .find(|base| &base.directory == dir)
                                .map(|base| (dir.join(memory_symbols_file()), base.label.clone()))
                        });
                        match (cx.recordings, cx.vm) {
                            (Some(recordings), Some(vm)) => match memory::import(
                                recordings,
                                vm,
                                &path,
                                import.os,
                                symbols.as_ref().map(|(path, label)| (path.as_path(), label.clone())),
                            ) {
                                Ok(dump) => done = Some(dump.id),
                                Err(error) => import.error = Some(error),
                            },
                            _ => import.error = Some("Select a VM first".into()),
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if done.is_some()
            || close
            || !open
            || ctx.input(|input| input.key_pressed(egui::Key::Escape))
        {
            ctx.request_repaint();
            if let Some(mut child) = self.import.take().and_then(|import| import.picker) {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        if let Some(id) = done {
            self.scan(cx.recording_roots);
            self.select(Some(id));
        }
    }

    fn catalog_window(&mut self, ctx: &egui::Context, cx: &MemoryContext<'_>) {
        if !self.catalog_open {
            return;
        }
        let plugins_dir = memory::plugins_dir(cx.data_dir);
        let installed = self
            .catalog_installed
            .get_or_insert_with(|| community::installed(&plugins_dir))
            .clone();
        let entries = community::catalog();
        let mut open = true;
        let mut install = None;
        let mut remove = None;
        egui::Window::new("Community plugin catalog")
            .id(egui::Id::new("memory_plugin_catalog"))
            .collapsible(false)
            .resizable(true)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.screen_rect().center())
            .default_width(680.0)
            .default_height(560.0)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "Volatility 3 plugins by other authors. Each is downloaded from its \
                             author's repository at the commit listed and checked against its \
                             SHA-256; Antinomie only applies the compatibility edits shown. They \
                             are ordinary Python and run as you, outside any sandbox: read the \
                             source before installing.",
                        )
                        .color(theme::muted()),
                    )
                    .wrap(),
                );
                if let Some((message, error)) = &self.catalog_status {
                    ui.colored_label(
                        if *error {
                            theme::error()
                        } else {
                            theme::good()
                        },
                        message,
                    );
                }
                ui.add_space(6.0);
                let entries = match &entries {
                    Ok(entries) => entries,
                    Err(error) => {
                        ui.colored_label(theme::error(), error);
                        return;
                    }
                };
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for plugin in entries {
                            let present = installed.iter().find(|i| i.plugin.id == plugin.id);
                            egui::Frame::new()
                                .fill(theme::raised())
                                .corner_radius(6.0)
                                .inner_margin(egui::Margin::symmetric(12, 10))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(RichText::new(&plugin.name).strong());
                                        ui.colored_label(
                                            theme::muted(),
                                            format!("by {}", plugin.author),
                                        );
                                        ui.label(
                                            RichText::new(plugin.os.label())
                                                .small()
                                                .color(theme::value(ValueKind::Name)),
                                        );
                                        ui.label(
                                            RichText::new(&plugin.license)
                                                .small()
                                                .color(theme::value(ValueKind::Flags)),
                                        );
                                    });
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&plugin.summary).color(theme::text()),
                                        )
                                        .wrap(),
                                    );
                                    ui.label(
                                        RichText::new(format!(
                                            "{} {}",
                                            egui_phosphor::regular::CHECK_CIRCLE,
                                            plugin.tested
                                        ))
                                        .small()
                                        .color(theme::muted()),
                                    );
                                    for caveat in &plugin.caveats {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(format!(
                                                    "{} {caveat}",
                                                    egui_phosphor::regular::WARNING
                                                ))
                                                .small()
                                                .color(theme::warn()),
                                            )
                                            .wrap(),
                                        );
                                    }
                                    for need in &plugin.requires {
                                        ui.label(
                                            RichText::new(format!("Needs {need}"))
                                                .small()
                                                .color(theme::warn()),
                                        );
                                    }
                                    for file in &plugin.files {
                                        for edit in &file.edits {
                                            ui.label(
                                                RichText::new(format!(
                                                    "Compatibility edit in {}: {} → {}",
                                                    file.to, edit.find, edit.replace
                                                ))
                                                .small()
                                                .font(theme::mono(cx.font_size - 3.0))
                                                .color(theme::muted()),
                                            );
                                        }
                                    }
                                    ui.add_space(4.0);
                                    ui.horizontal(|ui| {
                                        if let Some(job) = self.installs.get(&plugin.id) {
                                            let (got, total) =
                                                *job.progress.lock().expect("install progress");
                                            ui.add(
                                                egui::ProgressBar::new(
                                                    got as f32 / total.max(1) as f32,
                                                )
                                                .desired_width(160.0),
                                            );
                                            if ui.button("Cancel").clicked() {
                                                job.cancel.store(true, Ordering::Relaxed);
                                            }
                                        } else if let Some(present) = present {
                                            if present.outdated(entries)
                                                && ui.button("Update").clicked()
                                            {
                                                install = Some(plugin.clone());
                                            }
                                            ui.colored_label(theme::good(), "Installed");
                                            if ui.button("Remove").clicked() {
                                                remove = Some(plugin.id.clone());
                                            }
                                        } else if ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new(format!(
                                                        "{} Install",
                                                        egui_phosphor::regular::DOWNLOAD_SIMPLE
                                                    ))
                                                    .color(theme::palette().primary_text),
                                                )
                                                .fill(theme::primary()),
                                            )
                                            .clicked()
                                        {
                                            install = Some(plugin.clone());
                                        }
                                        ui.hyperlink_to(
                                            format!(
                                                "Source {}",
                                                egui_phosphor::regular::ARROW_SQUARE_OUT
                                            ),
                                            plugin.source_url(),
                                        )
                                        .on_hover_text(
                                            format!(
                                                "{} at commit {}",
                                                plugin.repo,
                                                &plugin.commit[..12]
                                            ),
                                        );
                                        ui.colored_label(
                                            theme::muted(),
                                            format_size(plugin.size()),
                                        );
                                    });
                                });
                            ui.add_space(8.0);
                        }
                    });
            });
        if let Some(plugin) = install {
            let progress = Arc::new(Mutex::new((0, plugin.size())));
            let cancel = Arc::new(AtomicBool::new(false));
            let (sender, done) = mpsc::channel();
            let (curl, staging) = (
                cx.curl.to_path_buf(),
                antinomie_monitor_core::analysis_tools::tools_dir(cx.data_dir).join(".downloads"),
            );
            let (shared, stop, id) = (progress.clone(), cancel.clone(), plugin.id.clone());
            std::thread::spawn(move || {
                let result = community::install(
                    &curl,
                    &plugins_dir,
                    &staging,
                    &plugin,
                    &stop,
                    |got, total| {
                        if let Ok(mut progress) = shared.lock() {
                            *progress = (got, total);
                        }
                    },
                );
                let _ = sender.send(result);
            });
            self.catalog_status = None;
            self.installs.insert(
                id,
                PluginInstall {
                    progress,
                    cancel,
                    done,
                },
            );
        }
        if let Some(id) = remove {
            self.catalog_status = Some(
                match community::remove(&memory::plugins_dir(cx.data_dir), &id) {
                    Ok(()) => (format!("{id} removed"), false),
                    Err(error) => (error, true),
                },
            );
            self.catalog_installed = None;
            self.catalog = Catalog::Unknown;
        }
        if !open || ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.catalog_open = false;
            self.catalog_installed = None;
            ctx.request_repaint();
        }
    }

    fn poll_picker(&mut self) {
        let Some(import) = self.import.as_mut() else {
            return;
        };
        let Some(child) = import.picker.as_mut() else {
            return;
        };
        let Ok(Some(status)) = child.try_wait() else {
            return;
        };
        let mut child = import.picker.take().expect("picker is running");
        let mut text = String::new();
        if let (true, Some(stdout)) = (status.success(), child.stdout.take()) {
            use std::io::Read;
            let _ = stdout.take(8192).read_to_string(&mut text);
        }
        // Already exited (try_wait reaped it); this only collects the status.
        let _ = child.wait();
        let path = text.trim_end_matches('\n');
        if !path.is_empty() {
            import.path = path.to_owned();
        }
    }
}

/// A base in the symbol table list: its name and the version it is for.
fn base_choice(base: &BaseSummary) -> String {
    match &base.min_app_version {
        Some(version) => format!("{} · Antinomie {version}", base.label),
        None => base.label.clone(),
    }
}

/// Tabs to the next multiple of 8 columns, as a terminal shows them.
fn expand_tabs(line: &str) -> String {
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

fn memory_symbols_file() -> &'static str {
    antinomie_monitor_core::storage::SYMBOLS_FILE
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_millis() as u64)
}

/// The plugin's group in the picker: its OS and module (`linux.malware`).
fn plugin_area(name: &str) -> String {
    let parts: Vec<&str> = name.split('.').collect();
    match parts.as_slice() {
        [os, "malware" | "tracing" | "graphics" | "registry", ..] => format!("{os} · {}", parts[1]),
        [os, _, _, ..] if Os::ALL.iter().any(|known| known.prefix() == *os) => (*os).to_owned(),
        _ => "generic".to_owned(),
    }
}

/// Option values of a saved run, to set the same run up again.
fn args_values(run: &PluginRun, plugins: &[PluginInfo]) -> Vec<(String, String)> {
    let Some(plugin) = plugins.iter().find(|plugin| plugin.name == run.plugin) else {
        return Vec::new();
    };
    let mut values: Vec<(String, String)> = Vec::new();
    let mut current: Option<&memory::PluginOption> = None;
    for arg in &run.args {
        if let Some(option) = plugin.options.iter().find(|option| &option.flag() == arg) {
            current = Some(option);
            if option.kind == OptionKind::Bool {
                values.push((option.name.clone(), "true".into()));
                current = None;
            }
            continue;
        }
        if let Some(option) = current {
            match values.iter_mut().find(|(name, _)| name == &option.name) {
                Some((_, value)) => {
                    value.push_str(", ");
                    value.push_str(arg);
                }
                None => values.push((option.name.clone(), arg.clone())),
            }
        }
    }
    values
}

/// Initial column widths from the header and the first rows' values.
fn column_widths(table: &ResultTable, char_width: f32) -> Vec<f32> {
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
                        row.depth as usize * 2 + 2
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

/// A muted hint centered near the top of an empty area.
fn empty_state(ui: &mut egui::Ui, text: &str) {
    ui.add_space(12.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(560.0);
        ui.label(
            RichText::new(egui_phosphor::regular::MEMORY)
                .size(28.0)
                .color(theme::muted()),
        );
        ui.add(egui::Label::new(RichText::new(text).color(theme::muted())).wrap());
    });
}

fn memory_dump_row(
    dump: &MemoryDump,
    annotation: Option<&antinomie_monitor_core::annotations::Annotation>,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue;

    let mut row = crate::query::label_row(
        &dump.id,
        annotation.map_or("", |value| &value.name),
        &dump.path().display().to_string(),
        annotation.map_or(&[], |value| value.tags.as_slice()),
    );
    row.extend([
        ("capture.kind", RowValue::Text("memory".into())),
        (
            "capture.started_ms",
            RowValue::Number(i128::from(dump.started_ms)),
        ),
        (
            "capture.ended_ms",
            dump.finished_ms.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "capture.size",
            dump.bytes.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        ("capture.complete", RowValue::Bool(dump.complete())),
        (
            "capture.state",
            RowValue::Text(
                if dump.error.is_some() {
                    "failed"
                } else if dump.finished_ms.is_some() {
                    "finished"
                } else {
                    "writing"
                }
                .into(),
            ),
        ),
        ("entry.kind", RowValue::Text("memory".into())),
        ("entry.complete", RowValue::Bool(dump.complete())),
        (
            "entry.time_ms",
            RowValue::Number(i128::from(dump.started_ms)),
        ),
        (
            "entry.size",
            dump.bytes.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        ("vm.id", RowValue::Text(dump.vm_id.clone())),
        (
            "boot.id",
            dump.boot_id
                .as_ref()
                .map_or(RowValue::Missing, |value| RowValue::Text(value.clone())),
        ),
        (
            "entry.state",
            RowValue::Text(
                if dump.error.is_some() {
                    "failed"
                } else if dump.finished_ms.is_some() {
                    "finished"
                } else {
                    "writing"
                }
                .into(),
            ),
        ),
        (
            "name",
            RowValue::Text(
                annotation
                    .filter(|value| !value.name.is_empty())
                    .map_or_else(|| dump_title(dump), |value| value.name.clone()),
            ),
        ),
        (
            "state",
            RowValue::Text(
                if dump.error.is_some() {
                    "failed"
                } else if dump.finished_ms.is_some() {
                    "finished"
                } else {
                    "writing"
                }
                .into(),
            ),
        ),
        ("os", RowValue::Text(format!("{:?}", dump.os))),
        ("system", RowValue::Text(dump.system.clone())),
        (
            "size",
            dump.bytes.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        ("ram_mib", RowValue::Number(i128::from(dump.ram_mib))),
        ("imported", RowValue::Bool(dump.imported)),
        ("symbols", RowValue::Bool(dump.symbols)),
    ]);

    row
}

fn add_dump_identity(
    row: &mut Vec<(&'static str, crate::query::RowValue)>,
    vm_id: Option<&str>,
    boot_id: Option<&str>,
) {
    if let Some(vm_id) = vm_id {
        row.push(("vm.id", crate::query::RowValue::Text(vm_id.to_owned())));
    }
    if let Some(boot_id) = boot_id {
        row.push(("boot.id", crate::query::RowValue::Text(boot_id.to_owned())));
    }
}

fn plugin_result_record(
    run: &PluginRun,
    annotation: Option<&antinomie_monitor_core::annotations::Annotation>,
) -> Vec<(&'static str, crate::query::RowValue)> {
    plugin_run_row(run, annotation)
        .into_iter()
        .filter(|(field, _)| {
            crate::query::LABEL_FIELDS
                .iter()
                .any(|spec| spec.name == *field)
        })
        .collect()
}

fn plugin_run_row(
    run: &PluginRun,
    annotation: Option<&antinomie_monitor_core::annotations::Annotation>,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue;

    let mut row = crate::query::label_row(
        &run.id,
        annotation.map_or("", |value| &value.name),
        &run.dir.display().to_string(),
        annotation.map_or(&[], |value| value.tags.as_slice()),
    );
    row.extend([
        ("entry.kind", RowValue::Text("volatility".into())),
        ("entry.state", RowValue::Text(format!("{:?}", run.state))),
        (
            "entry.complete",
            RowValue::Bool(run.state == RunState::Finished),
        ),
        (
            "entry.time_ms",
            RowValue::Number(i128::from(run.started_ms)),
        ),
        ("run.id", RowValue::Text(run.id.clone())),
        (
            "name",
            RowValue::Text(
                annotation
                    .filter(|value| !value.name.is_empty())
                    .map_or_else(|| run.short_name().to_owned(), |value| value.name.clone()),
            ),
        ),
        ("plugin", RowValue::Text(run.plugin.clone())),
        ("state", RowValue::Text(format!("{:?}", run.state))),
        ("args", RowValue::Text(run.args.join(" "))),
        ("rows", RowValue::Number(i128::from(run.rows))),
        (
            "exit_code",
            run.exit_code.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
    ]);

    row
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_result_column_gets_a_distinct_parseable_filter_keyword() {
        let columns: Vec<_> = ["X", "X", "X_1_0", "Depth", "and", "lower", "1st", ""]
            .into_iter()
            .map(|name| ResultColumn {
                name: name.into(),
                kind: ColumnKind::Int,
            })
            .collect();
        let names = column_fields(&columns);
        assert_eq!(
            names
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            columns.len()
        );
        let fields = result_fields(&names, &columns);
        let row = memory::ResultRow {
            depth: 0,
            values: (0..columns.len())
                .map(|index| serde_json::json!(index))
                .collect(),
        };
        let values = result_row(&names, &columns, &row);
        for (index, name) in names.iter().enumerate() {
            let query = crate::query::compile_table(&format!("{name} == {index}"), &fields);
            assert!(query.error.is_none(), "{name}: {:?}", query.error);
            assert!(query.keep_table(&values), "{name}");
        }
    }

    #[test]
    fn plugins_are_grouped_by_system_and_module() {
        assert_eq!(plugin_area("linux.pslist.PsList"), "linux");
        assert_eq!(
            plugin_area("linux.malware.malfind.Malfind"),
            "linux · malware"
        );
        assert_eq!(
            plugin_area("windows.registry.hivelist.HiveList"),
            "windows · registry"
        );
        assert_eq!(plugin_area("yarascan.YaraScan"), "generic");
    }

    #[test]
    fn saved_runs_set_their_options_up_again() {
        let plugin: PluginInfo = serde_json::from_str(
            r#"{"name":"linux.pslist.PsList","options":[
                {"name":"pid","kind":"list","element":"int"},
                {"name":"threads","kind":"bool"}]}"#,
        )
        .unwrap();
        let run = PluginRun {
            plugin: plugin.name.clone(),
            args: vec!["--pid".into(), "1".into(), "42".into(), "--threads".into()],
            ..PluginRun::default()
        };
        let values = args_values(&run, std::slice::from_ref(&plugin));
        assert_eq!(
            values,
            [
                ("pid".to_owned(), "1, 42".to_owned()),
                ("threads".into(), "true".into())
            ]
        );
        assert_eq!(memory::plugin_args(&plugin, &values).unwrap(), run.args);
        assert!(args_values(&run, &[]).is_empty());
    }

    #[test]
    fn results_copy_as_tab_separated_text_with_tree_indent() {
        let table = ResultTable {
            columns: vec![
                ResultColumn {
                    name: "PID".into(),
                    kind: ColumnKind::Int,
                },
                ResultColumn {
                    name: "COMM".into(),
                    kind: ColumnKind::Str,
                },
            ],
            rows: vec![
                memory::ResultRow {
                    depth: 0,
                    values: vec![1.into(), "init".into()],
                },
                memory::ResultRow {
                    depth: 1,
                    values: vec![42.into(), "sh".into()],
                },
            ],
            truncated: false,
        };
        assert_eq!(
            result_tsv(&table.columns, &table, &[0, 1]),
            "PID\tCOMM\n1\tinit\n  42\tsh"
        );
    }

    #[test]
    fn column_clicks_sort_up_then_down_then_back() {
        let up = next_sort(None, 2);
        assert_eq!(
            up,
            Some(Sort {
                column: 2,
                descending: false
            })
        );
        let down = next_sort(up, 2);
        assert!(down.is_some_and(|sort| sort.descending));
        assert_eq!(next_sort(down, 2), None);
        assert_eq!(next_sort(down, 0).map(|sort| sort.column), Some(0));
    }

    #[test]
    fn result_worker_filters_beyond_old_prefix_and_sorts_entire_retained_source() {
        use std::io::Write;
        let root = std::env::temp_dir().join(format!(
            "antinomie-paged-memory-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("result.jsonl");
        let mut output = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        writeln!(output, "{{\"columns\":[{{\"name\":\"PID\",\"type\":\"int\"}},{{\"name\":\"COMM\",\"type\":\"str\"}}]}}").unwrap();
        for index in 0..200_005 {
            writeln!(
                output,
                "{{\"d\":0,\"v\":[{index},\"{}\"]}}",
                if index == 200_004 {
                    "beyond-prefix"
                } else {
                    "row"
                }
            )
            .unwrap();
        }
        output.flush().unwrap();
        let run = PluginRun {
            id: "run-one".into(),
            dir: root.clone(),
            ..Default::default()
        };
        antinomie_monitor_core::annotations::save(
            &root,
            &antinomie_monitor_core::annotations::Annotation {
                name: "Renamed plugin result".into(),
                tags: vec!["needs review".into()],
            },
        )
        .unwrap();
        let cancel = AtomicBool::new(false);
        let mut request = ResultRequest {
            vm_id: None,
            boot_id: None,
            run_id: run.id.clone(),
            source: path.clone(),
            query: "comm == \"beyond-prefix\" && tag == \"needs review\" && entry.name == \"Renamed plugin result\"".into(),
            sort: None,
            start: 0,
        };
        let loaded = load_result(run.clone(), &request, &cancel);
        assert!(loaded.filter_error.is_none());
        assert_eq!(
            (loaded.total, loaded.source_rows, loaded.start),
            (1, 200_005, 0)
        );
        assert_eq!(
            loaded.table.as_ref().unwrap().rows[0].values[0],
            serde_json::json!(200_004)
        );
        request.query.clear();
        request.sort = Some(Sort {
            column: 0,
            descending: true,
        });
        request.start = 1024;
        let loaded = load_result(run, &request, &cancel);
        assert_eq!(loaded.table.as_ref().unwrap().rows.len(), 1024);
        assert_eq!(
            loaded.table.as_ref().unwrap().rows[0].values[0],
            serde_json::json!(200_004 - 1024)
        );
        assert_eq!(
            (loaded.total, loaded.source_rows, loaded.start),
            (200_005, 200_005, 1024)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn text_view_expands_tabs_like_a_terminal() {
        assert_eq!(expand_tabs("PID\tCOMM"), "PID     COMM");
        assert_eq!(expand_tabs("12345678\tx"), "12345678        x");
    }
}
