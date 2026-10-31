// SPDX-License-Identifier: GPL-3.0-only
//! The Memory tab: RAM dumps of a VM and their analysis with Volatility 3 or
//! MemNixFS, in the manner of Volatility Workbench. Pick a dump, pick a
//! plugin and its options (or a MemNixFS report), run it; every run is saved
//! with its dump and listed beside it, so an earlier result opens again
//! without running the plugin again.
use crate::{
    network_view::{capture_row, format_date},
    theme::{self, ValueKind},
};
use antinomie_monitor_core::{
    memory::{
        self, community, Analyzer, Column as ResultColumn, ColumnKind, DumpProgress, MemoryDump,
        OptionKind, Os, PluginCatalog, PluginInfo, PluginRun, ResultTable, RunHandle, RunState,
        Volatility,
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

mod catalog;
mod dumps;
mod memnixfs;
mod plugins;
mod results;

use self::{dumps::*, memnixfs::Engine, plugins::*, results::*};

/// Rows of one result loaded for display.
const RESULT_PAGE_LEN: usize = 1024;
const RESULT_LOG_SIZE: u64 = 2 * 1024 * 1024;

pub(crate) enum MemoryAction {
    /// Dump the running VM's RAM.
    Dump,
    /// Install Volatility 3 (Tools → Analysis tools).
    InstallVolatility,
    /// Install MemNixFS (Tools → Analysis tools).
    InstallMemNixFs,
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
    /// MemNixFS is installed, or being installed.
    pub memnixfs_installed: bool,
    pub memnixfs_installing: bool,
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
    /// The tree branches in front of each of `shown`; none when sorted.
    branches: Vec<crate::tree_lines::Prefix>,
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
    /// Which backend the next Run uses.
    analyzer: Analyzer,
    engine: Engine,
    /// The MemNixFS report chosen (its name).
    report: Option<String>,
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
            analyzer: Analyzer::default(),
            engine: Engine::Unknown,
            report: None,
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

impl MemoryView {
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
            || matches!(self.engine, Engine::Loading(_))
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
        self.check_engine(cx.memnixfs_installed);
        self.poll(ui.ctx(), cx.data_dir);
        self.poll_engine(cx.data_dir);
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
}

#[cfg(test)]
mod tests;
