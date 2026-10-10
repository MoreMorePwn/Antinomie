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
        self, Column as ResultColumn, ColumnKind, DumpProgress, MemoryDump, OptionKind, Os,
        PluginInfo, PluginRun, ResultTable, RunHandle, RunState, Volatility,
    },
    BaseSummary, VmConfig,
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::Duration,
};

/// Rows of one result loaded for display.
const RESULT_LIMIT: usize = 200_000;

pub(crate) enum MemoryAction {
    /// Dump the running VM's RAM.
    Dump,
    /// Install Volatility 3 (Tools → Analysis tools).
    InstallVolatility,
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
}

enum Catalog {
    Unknown,
    Loading(Receiver<Result<(Volatility, Vec<PluginInfo>), String>>),
    Ready(Volatility, Vec<PluginInfo>),
    Failed(String),
}

struct LoadedResult {
    run: PluginRun,
    table: Result<ResultTable, String>,
    /// Indices of the rows the filter keeps.
    shown: Vec<usize>,
    filter: String,
    log: String,
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
    loading: Option<(String, Receiver<LoadedResult>)>,
    filter: String,
    /// Index of the selected row in the loaded result.
    selected_row: Option<usize>,
    show_log: bool,
    import: Option<Import>,
    confirm_delete: Option<String>,
    status: Option<(String, bool)>,
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
            filter: String::new(),
            selected_row: None,
            show_log: false,
            import: None,
            confirm_delete: None,
            status: None,
        }
    }
}

impl Drop for MemoryView {
    fn drop(&mut self) {
        for job in &self.jobs {
            job.cancel();
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

fn load_result(run: PluginRun) -> LoadedResult {
    let table = memory::read_result(&run.output(), RESULT_LIMIT);
    let log = std::fs::read_to_string(run.log()).unwrap_or_default();
    let shown = table
        .as_ref()
        .map(|table| (0..table.rows.len()).collect())
        .unwrap_or_default();
    LoadedResult {
        run,
        table,
        shown,
        filter: String::new(),
        log,
    }
}

fn filter_rows(result: &mut LoadedResult, filter: &str) {
    if result.filter == filter {
        return;
    }
    result.filter = filter.to_owned();
    let Ok(table) = &result.table else {
        return;
    };
    let needle = filter.trim().to_lowercase();
    result.shown = (0..table.rows.len())
        .filter(|&index| {
            needle.is_empty()
                || table.rows[index]
                    .values
                    .iter()
                    .zip(&table.columns)
                    .any(|(value, column)| {
                        memory::value_text(column.kind, value)
                            .to_lowercase()
                            .contains(&needle)
                    })
        })
        .collect();
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
        }
    }

    fn select(&mut self, id: Option<String>) {
        if self.selected == id && self.dumps_for.is_some() && !self.runs.is_empty() {
            return;
        }
        self.selected = id;
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
        self.selected_run = id.clone();
        self.selected_row = None;
        self.show_log = false;
        let Some(run) = id.and_then(|id| self.runs.iter().find(|run| run.id == id).cloned()) else {
            self.result = None;
            self.loading = None;
            return;
        };
        if self.jobs.iter().any(|job| job.run.id == run.id) {
            self.result = None;
            self.loading = None;
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let id = run.id.clone();
        std::thread::spawn(move || {
            let _ = sender.send(load_result(run));
        });
        self.loading = Some((id, receiver));
    }

    fn poll(&mut self, ctx: &egui::Context, data_dir: &Path) {
        let loaded = self
            .loading
            .as_ref()
            .and_then(|(id, receiver)| Some((id.clone(), receiver.try_recv().ok()?)));
        if let Some((id, mut result)) = loaded {
            if Some(&id) == self.selected_run.as_ref() {
                let filter = self.filter.clone();
                result.filter = "\u{0}".into();
                filter_rows(&mut result, &filter);
                self.result = Some(result);
            }
            self.loading = None;
        }
        let listed = match &self.catalog {
            Catalog::Loading(receiver) => receiver.try_recv().ok(),
            _ => None,
        };
        if let Some(listed) = listed {
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
        egui::CentralPanel::default()
            .frame(egui::Frame::new())
            .show_inside(ui, |ui| {
                if let Some(next) = self.analysis(ui, &cx) {
                    action = Some(next);
                }
            });
        self.import_window(ui.ctx(), &cx);
        action
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
                 written (a few seconds per GiB) and then continues.",
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
                for dump in &self.dumps {
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
                    let row = capture_row(
                        ui,
                        selected,
                        (&dump_title(dump), color),
                        &dump_detail(dump),
                        font_size,
                    )
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
        self.plugin_bar(ui, &dump, cx.font_size);
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

    fn plugin_bar(&mut self, ui: &mut egui::Ui, dump: &MemoryDump, font_size: f32) {
        let Catalog::Ready(volatility, plugins) = &self.catalog else {
            return;
        };
        let applies = |plugin: &&PluginInfo| {
            plugin.os().is_none_or(|os| os == dump.os)
                && !matches!(
                    plugin.name.as_str(),
                    "configwriter.ConfigWriter"
                        | "layerwriter.LayerWriter"
                        | "frameworkinfo.FrameworkInfo"
                )
        };
        if self
            .plugin
            .as_ref()
            .is_none_or(|name| !plugins.iter().any(|plugin| &plugin.name == name))
        {
            let default = format!("{}.pslist.PsList", dump.os.prefix());
            self.plugin = plugins
                .iter()
                .find(|plugin| plugin.name == default)
                .or_else(|| plugins.iter().find(applies))
                .map(|plugin| plugin.name.clone());
        }
        let Some(current) = self
            .plugin
            .as_ref()
            .and_then(|name| plugins.iter().find(|plugin| &plugin.name == name))
            .cloned()
        else {
            return;
        };
        let mut chosen = None;
        let mut run = None;
        ui.horizontal(|ui| {
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
                    for plugin in plugins.iter().filter(applies) {
                        if plugin.deprecated() && !self.show_deprecated {
                            continue;
                        }
                        if !needle.is_empty()
                            && !plugin.name.to_lowercase().contains(&needle)
                            && !plugin.help.to_lowercase().contains(&needle)
                        {
                            continue;
                        }
                        let area = plugin_area(&plugin.name);
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
            ui.colored_label(theme::muted(), &current.help)
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
        match run {
            Some(Ok(args)) => match volatility.start(dump, &current.name, args) {
                Ok(job) => {
                    let id = job.run.id.clone();
                    self.jobs.push(job);
                    self.reload_runs();
                    self.selected_run = Some(id);
                    self.result = None;
                    self.status = None;
                }
                Err(error) => self.status = Some((error, true)),
            },
            Some(Err(error)) => self.status = Some((error, true)),
            None => {}
        }
    }

    fn run_list(&mut self, ui: &mut egui::Ui, font_size: f32) {
        theme::section(ui, "Results");
        let mut open = None;
        let mut delete = None;
        let mut rerun = None;
        egui::ScrollArea::vertical()
            .id_salt("memory_run_list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                for run in &self.runs {
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
                    let row = capture_row(
                        ui,
                        self.selected_run.as_ref() == Some(&run.id),
                        (&title, color),
                        &run_detail(run, progress.as_ref()),
                        font_size,
                    )
                    .on_hover_text(format!(
                        "{} {}\nStarted {}",
                        run.plugin,
                        args_summary(run),
                        format_date(run.started_ms / 1000)
                    ));
                    if row.clicked() {
                        open = Some(run.id.clone());
                    }
                    row.context_menu(|ui| {
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
            if let Catalog::Ready(_, plugins) = &self.catalog {
                self.values
                    .insert(run.plugin.clone(), args_values(&run, plugins));
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
        if self.loading.is_some()
            || self
                .result
                .as_ref()
                .is_none_or(|result| result.run.id != run_id)
        {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.colored_label(theme::muted(), "Loading the result…");
            });
            return;
        }
        let filter = self.filter.clone();
        let Some(result) = self.result.as_mut() else {
            return;
        };
        filter_rows(result, &filter);
        let mut status = None;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(&result.run.plugin)
                    .font(theme::mono(font_size - 1.0))
                    .color(theme::heading()),
            );
            if !result.run.args.is_empty() {
                ui.label(
                    RichText::new(args_summary(&result.run))
                        .font(theme::mono(font_size - 1.0))
                        .color(theme::value(ValueKind::Flags)),
                );
            }
            if let Ok(table) = &result.table {
                ui.colored_label(
                    theme::muted(),
                    if result.shown.len() == table.rows.len() {
                        format!("{} rows", table.rows.len())
                    } else {
                        format!("{} of {} rows", result.shown.len(), table.rows.len())
                    },
                );
                if table.truncated {
                    ui.colored_label(theme::warn(), format!("(first {RESULT_LIMIT} shown)"));
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.toggle_value(&mut self.show_log, "Messages")
                    .on_hover_text("Volatility's messages for this run");
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
                        .on_hover_text("Copy the shown rows as tab-separated text")
                        .clicked()
                    {
                        ui.ctx()
                            .copy_text(result_tsv(&table.columns, table, &result.shown));
                    }
                }
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text(format!("{} Filter rows", egui_phosphor::regular::FUNNEL))
                        .margin(theme::TEXT_EDIT_MARGIN)
                        .desired_width(200.0),
                );
            });
        });
        if let Some(error) = status {
            self.status = Some((error, true));
        }
        if result.run.state == RunState::Failed {
            ui.colored_label(
                theme::error(),
                result.run.error.as_deref().unwrap_or("Volatility failed"),
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
                ui.colored_label(theme::muted(), format!("No result saved: {error}"));
                return;
            }
        };
        if table.columns.is_empty() {
            ui.colored_label(theme::muted(), "The plugin wrote no result.");
            return;
        }
        if table.rows.is_empty() {
            ui.colored_label(theme::muted(), "The plugin found nothing in this dump.");
        }
        let mono = theme::mono(font_size - 1.0);
        let char_width = ui.fonts(|fonts| fonts.glyph_width(&mono, '0'));
        let row_height = theme::row_height(font_size);
        let widths = column_widths(table, char_width);
        let total: f32 = widths.iter().sum();
        // Wider than the panel: every column keeps its width and the table
        // scrolls sideways; otherwise the last column takes the rest.
        let fits = total <= ui.available_width();
        let indent = 14.0;
        let selected_row = self.selected_row;
        let mut clicked_row = None;
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
                        for column in &table.columns {
                            header.col(|ui| {
                                ui.label(
                                    RichText::new(&column.name).strong().color(theme::heading()),
                                );
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
                                    if index == 0 && data.depth > 0 {
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
                                        if ui.button("Filter on this value").clicked() {
                                            self.filter = text.clone();
                                            ui.close_menu();
                                        }
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
                            let selected = import
                                .base
                                .as_ref()
                                .and_then(|dir| with_symbols.iter().find(|base| &base.directory == dir))
                                .map_or("Let Volatility find one", |base| base.label.as_str());
                            egui::ComboBox::from_id_salt("memory_import_symbols")
                                .width(320.0)
                                .selected_text(selected)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut import.base, None, "Let Volatility find one");
                                    for base in &with_symbols {
                                        ui.selectable_value(
                                            &mut import.base,
                                            Some(base.directory.clone()),
                                            &base.label,
                                        );
                                    }
                                });
                        });
                        ui.end_row();
                    });
                ui.colored_label(
                    theme::muted(),
                    match import.os {
                        Os::Windows => "Windows symbols are downloaded from Microsoft's symbol server when a plugin first needs them.",
                        Os::Linux => "Linux dumps need the symbol table of their exact kernel: pick the base the dump was taken from.",
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut loaded = LoadedResult {
            run: PluginRun::default(),
            table: Ok(table),
            shown: vec![0, 1],
            filter: String::new(),
            log: String::new(),
        };
        filter_rows(&mut loaded, "SH");
        assert_eq!(loaded.shown, vec![1]);
        filter_rows(&mut loaded, "");
        assert_eq!(loaded.shown, vec![0, 1]);
    }
}
