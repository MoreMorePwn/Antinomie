// SPDX-License-Identifier: GPL-3.0-only
//! Library › Samples: every sample in the library as one flat list, latest
//! run first. A sample is identified by its SHA-256, so the same bytes by two
//! routes are one row with two origins. Lineage (a file with two parents, 500
//! re-executions of one binary) is not drawn here: the list only counts
//! parents and children.
use super::*;
use antinomie_monitor_core::samples::{
    Library, LibraryCheck, RunStats, SampleRecord, SeenRun, Tag, Verification,
};
use std::{
    collections::BTreeMap,
    sync::mpsc::{self, Receiver},
};

mod add;
mod custody_all;
mod custody_parts;
mod detail;
mod export;
mod list;
mod picker;
mod promote;
mod viewer;

/// One list row: a library sample with what the list shows of its runs,
/// tags and lineage.
pub(super) struct Row {
    pub(super) record: SampleRecord,
    pub(super) tags: Vec<Tag>,
    pub(super) runs: RunStats,
    pub(super) parents: usize,
    pub(super) children: usize,
    /// The archive is on disk (Verify all reads it back).
    pub(super) archived: bool,
}

type Loaded = Result<Vec<Row>, String>;
type Verified = Result<(Vec<(String, Verification)>, LibraryCheck), String>;

/// How a run's root ended, as the run list says it.
fn exit_label(run: &RunSummary) -> String {
    if matches!(run.state, RunState::Running | RunState::StopRequested) {
        "Running".into()
    } else {
        history::root_exit(run)
    }
}

/// Read the library, first noting every run of a library sample in the
/// recordings of all VMs: the list counts runs across VMs.
fn load(options: BackendOptions, vms: Vec<(String, String)>) -> Loaded {
    let mut library = Library::open(&options.data_dir)?;
    let mut seen = Vec::new();
    for (vm_id, vm_name) in vms {
        let Ok(runs) = antinomie_monitor_core::recording::list_vm_runs(&options, &vm_id) else {
            continue;
        };
        for run in runs {
            let Some(sample) = &run.request.sample else {
                continue;
            };
            seen.push(SeenRun {
                sha256: sample.sha256.clone(),
                vm_id: run.vm_id.clone(),
                vm_name: vm_name.clone(),
                run_id: run.id.clone(),
                started_ms: run.started_ms,
                exit: exit_label(&run),
                directory: run.directory.display().to_string(),
            });
        }
    }
    library.index_runs(&seen)?;
    let mut tags = library.all_tags()?;
    let mut stats = library.run_stats()?;
    let lineage = library.lineage_counts()?;
    let mut rows: Vec<Row> = library
        .list()?
        .into_iter()
        .map(|record| {
            let (parents, children) = lineage.get(&record.sha256).copied().unwrap_or_default();
            Row {
                archived: record.removed_ms.is_none()
                    && library
                        .archive_path(&record.sha256)
                        .is_ok_and(|path| path.is_file()),
                tags: tags.remove(&record.sha256).unwrap_or_default(),
                runs: stats.remove(&record.sha256).unwrap_or_default(),
                parents,
                children,
                record,
            }
        })
        .filter(|row| row.record.removed_ms.is_none())
        .collect();
    // Latest run first; a sample never run goes by when it was added.
    rows.sort_by_key(|row| {
        std::cmp::Reverse(
            row.runs
                .latest
                .as_ref()
                .and_then(|run| run.started_ms)
                .unwrap_or(row.record.added_ms),
        )
    });
    Ok(rows)
}

#[derive(Default)]
pub(super) struct SamplesPage {
    rows: Vec<Row>,
    loaded: bool,
    loading: Option<Receiver<Loaded>>,
    /// Something changed: read the library again.
    stale: bool,
    error: Option<String>,
    query: String,
    tags_open: bool,
    tag_filter: BTreeSet<Tag>,
    roots_only: bool,
    selected: Option<String>,
    /// Archives that did not verify, by SHA-256, with why.
    problems: BTreeMap<String, String>,
    verifying: Option<Receiver<Verified>>,
    /// A line under the toolbar: what the last action did, and whether it failed.
    notice: Option<(String, bool)>,
    confirm_remove: Option<String>,
    add: Option<add::AddDialog>,
    /// The sample whose tags are being edited, with the picker.
    editing: Option<(String, String, picker::TagPicker)>,
    /// The open sample window; the list shows when there is none.
    detail: Option<detail::Detail>,
    /// A run the sample window asked to open in its own VM.
    open_run: Option<OpenRun>,
    /// The file viewer window.
    viewer: Option<viewer::Viewer>,
    /// Add to Samples… for a file of a run.
    promote: Option<promote::Promote>,
    /// Export custody record… for the open sample.
    export: Option<export::ExportDialog>,
    /// The custody log across every sample; shows instead of the list.
    custody_all: Option<custody_all::CustodyAll>,
}

/// A run to open in a panel of the VM it belongs to: the VM is selected and
/// its history read first, so the panel finds the run.
pub(super) struct OpenRun {
    vm_id: String,
    run_id: String,
    panel: crate::workspace::Panel,
    /// Scope Syscall Trace to this filter once the run is selected.
    trace_filter: Option<String>,
    started: std::time::Instant,
    listed: bool,
}

impl SamplesPage {
    /// Read the library again at the next frame.
    pub(super) fn refresh(&mut self) {
        self.stale = true;
        self.refresh_detail();
    }

    pub(super) fn count(&self) -> usize {
        self.rows.len()
    }

    /// The Add file… dialog, with `path` filled in (the Explorer's Add to
    /// Samples).
    pub(super) fn open_add(&mut self, path: Option<&std::path::Path>) {
        self.add = Some(add::AddDialog::new(path, false));
    }

    /// The file the chooser returned for the Add file… dialog.
    pub(super) fn chosen(&mut self, path: &std::path::Path) {
        if let Some(dialog) = &mut self.add {
            dialog.set_path(path);
        }
    }

    fn start_load(&mut self, ctx: &egui::Context, options: &BackendOptions, vms: &[VmConfig]) {
        if self.loading.is_some() {
            return;
        }
        self.stale = false;
        let (sender, receiver) = mpsc::channel();
        let options = options.clone();
        let vms: Vec<(String, String)> = vms
            .iter()
            .map(|vm| (vm.id.clone(), vm.name.clone()))
            .collect();
        let wake = ctx.clone();
        match std::thread::Builder::new()
            .name("samples-list".into())
            .spawn(move || {
                let _ = sender.send(load(options, vms));
                wake.request_repaint();
            }) {
            Ok(_) => self.loading = Some(receiver),
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn poll(&mut self) {
        if let Some(receiver) = &self.loading {
            if let Ok(result) = receiver.try_recv() {
                self.loading = None;
                self.loaded = true;
                match result {
                    Ok(rows) => {
                        self.rows = rows;
                        self.error = None;
                    }
                    Err(error) => self.error = Some(error),
                }
            }
        }
        if let Some(receiver) = &self.verifying {
            if let Ok(result) = receiver.try_recv() {
                self.verifying = None;
                self.notice = Some(match result {
                    Ok((results, custody)) => {
                        self.problems = results
                            .iter()
                            .filter_map(|(sha256, result)| match result {
                                Verification::Matches => None,
                                Verification::Missing => {
                                    Some((sha256.clone(), "the archive is missing".to_owned()))
                                }
                                Verification::Mismatch(error) => {
                                    Some((sha256.clone(), error.clone()))
                                }
                            })
                            .collect();
                        let bad = self.problems.len();
                        (
                            format!(
                                "Read back {} archives: {}; {}",
                                results.len(),
                                if bad == 0 {
                                    "every SHA-256 matches".to_owned()
                                } else {
                                    format!("{bad} did not verify")
                                },
                                custody.summary()
                            ),
                            bad > 0 || !custody.ok(),
                        )
                    }
                    Err(error) => (format!("Verify all: {error}"), true),
                });
                self.stale = true;
            }
        }
    }

    fn start_verify(&mut self, ctx: &egui::Context, data_dir: &std::path::Path) {
        if self.verifying.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let data_dir = data_dir.to_path_buf();
        let wake = ctx.clone();
        match std::thread::Builder::new()
            .name("samples-verify".into())
            .spawn(move || {
                let _ = sender.send(Library::open(&data_dir).and_then(|mut l| {
                    let archives = l.verify_all()?;
                    Ok((archives, l.custody_check_all()?))
                }));
                wake.request_repaint();
            }) {
            Ok(_) => self.verifying = Some(receiver),
            Err(error) => self.notice = Some((error.to_string(), true)),
        }
    }
}

impl MonitorApp {
    /// Open `run` in `panel` of its VM: select the VM and read its history if
    /// it is not the selected one, then select the run. Syscall Trace takes
    /// `trace_filter` as its filter.
    pub(super) fn open_sample_run(
        &mut self,
        run: &RunSummary,
        panel: crate::workspace::Panel,
        trace_filter: Option<String>,
    ) {
        self.samples_page.open_run = Some(OpenRun {
            vm_id: run.vm_id.clone(),
            run_id: run.id.clone(),
            panel,
            trace_filter,
            started: std::time::Instant::now(),
            listed: false,
        });
    }

    /// Carry out the run the sample window asked to open, a step per frame
    /// until the VM's history has it (or the wait ends).
    pub(super) fn advance_run_open(&mut self) {
        let Some(open) = self.samples_page.open_run.as_ref() else {
            return;
        };
        let (vm_id, run_id) = (open.vm_id.clone(), open.run_id.clone());
        if self.selected.as_ref() != Some(&vm_id) {
            self.selected = Some(vm_id);
            self.clear_history();
            self.select_run(None);
            self.refresh_history();
            if let Some(open) = &mut self.samples_page.open_run {
                open.listed = true;
            }
            return;
        }
        if self.run(&run_id).is_some() {
            let Some(open) = self.samples_page.open_run.take() else {
                return;
            };
            self.select_run(Some(run_id));
            self.focus_panel = Some(open.panel);
            if let Some(filter) = open.trace_filter {
                self.scope_trace(filter);
            }
            return;
        }
        if let Some(open) = &mut self.samples_page.open_run {
            if !open.listed {
                open.listed = true;
                self.refresh_history();
            } else if open.started.elapsed() > std::time::Duration::from_secs(20) {
                self.samples_page.open_run = None;
                self.report_error("The run could not be found in its VM's history".into());
            }
        }
    }

    /// The sidebar count of the Samples row.
    pub(super) fn samples_count(&self) -> usize {
        self.samples_page.count()
    }

    /// The Samples page body.
    pub(super) fn samples_page(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.samples_page.poll();
        if !self.samples_page.loaded && self.samples_page.loading.is_none()
            || self.samples_page.stale
        {
            let vms = self.snapshot.vms.clone();
            self.samples_page.start_load(&ctx, &self.options, &vms);
        }
        if self.samples_page.detail.is_some() {
            self.detail_view(ui);
        } else if self.samples_page.custody_all.is_some() {
            self.custody_all_view(ui);
        } else {
            self.list_view(ui);
        }
        self.samples_dialogs(&ctx);
    }

    /// The custody log across every sample.
    fn custody_all_view(&mut self, ui: &mut egui::Ui) {
        let font = self.settings.font_size;
        let data_dir = self.options.data_dir.clone();
        let Some(view) = &mut self.samples_page.custody_all else {
            return;
        };
        match view.show(ui, &data_dir, font) {
            custody_all::Outcome::None => {}
            custody_all::Outcome::Back => self.samples_page.custody_all = None,
            custody_all::Outcome::Open(sha256) => {
                self.samples_page.custody_all = None;
                self.samples_page.selected = Some(sha256.clone());
                self.samples_page.open_custody(&sha256);
            }
        }
    }

    /// The windows over the page: Add file, Edit tags, Remove.
    fn samples_dialogs(&mut self, ctx: &egui::Context) {
        let mut refresh = false;
        if let Some(dialog) = &mut self.samples_page.export {
            dialog.show(ctx, &self.options.data_dir);
            refresh = std::mem::take(&mut dialog.wrote);
            if !dialog.open {
                self.samples_page.export = None;
            }
        }
        if let Some(dialog) = &mut self.samples_page.promote {
            dialog.show(ctx);
            refresh = std::mem::take(&mut dialog.added);
            if !dialog.open {
                self.samples_page.promote = None;
            }
        }
        if refresh {
            self.samples_page.refresh();
            if let Some(view) = &mut self.samples_page.custody_all {
                view.refresh();
            }
        }
        if let Some(viewer) = &mut self.samples_page.viewer {
            viewer.show(ctx);
            if !viewer.open {
                self.samples_page.viewer = None;
            }
        }
        let known_custom = self.known_custom_tags();
        if let Some(dialog) = &mut self.samples_page.add {
            let can_choose = self.folder_picker.available();
            match dialog.show(ctx, &self.options.data_dir, can_choose, &known_custom) {
                add::Outcome::None => {}
                add::Outcome::Close => self.samples_page.add = None,
                add::Outcome::ChooseFile => {
                    if let Err(error) = self.folder_picker.choose(FolderTarget {
                        generation: 0,
                        kind: FolderKind::SampleFile,
                    }) {
                        self.report_error(format!("Add file: {error}"));
                    }
                }
                add::Outcome::Added(added) => {
                    let removed = self
                        .samples_page
                        .add
                        .take()
                        .is_some_and(|dialog| dialog.delete_original());
                    self.samples_page.selected = Some(added.sha256);
                    self.samples_page.notice = Some((
                        match (added.new, removed) {
                            (true, true) => "Added to Samples; the original was deleted".into(),
                            (true, false) => "Added to Samples".into(),
                            (false, true) => {
                                "Already in Samples: origin added; the original was deleted".into()
                            }
                            (false, false) => "Already in Samples: origin added".into(),
                        },
                        false,
                    ));
                    self.samples_page.refresh();
                }
            }
        }
        self.edit_tags_window(ctx, &known_custom);
        self.remove_window(ctx);
    }

    /// The custom tags in the library, for the picker to offer again.
    fn known_custom_tags(&self) -> Vec<Tag> {
        let mut seen = BTreeSet::new();
        for row in &self.samples_page.rows {
            for tag in &row.tags {
                if tag.kind == antinomie_monitor_core::samples::TagKind::Custom {
                    seen.insert(tag.clone());
                }
            }
        }
        seen.into_iter().collect()
    }

    fn edit_tags_window(&mut self, ctx: &egui::Context, known_custom: &[Tag]) {
        let Some((sha256, name, picker)) = &mut self.samples_page.editing else {
            return;
        };
        let mut open = true;
        let mut save = false;
        let mut cancel = false;
        crate::widgets::window(format!("Edit tags: {name}"))
            .id(egui::Id::new("samples_edit_tags"))
            .open(&mut open)
            .default_width(480.0)
            .resizable(false)
            .show(ctx, |ui| {
                picker.show(ui, &[], known_custom);
                crate::widgets::footer(ui, |ui| {
                    save = ui.button("Save").clicked();
                    cancel = ui.button("Cancel").clicked();
                });
            });
        if save {
            let tags = picker.tags();
            let sha256 = sha256.clone();
            let result = Library::open(&self.options.data_dir)
                .and_then(|mut library| library.set_tags(&sha256, &tags));
            self.samples_page.notice = Some(match result {
                Ok(()) => ("Tags saved".into(), false),
                Err(error) => (error, true),
            });
            self.samples_page.editing = None;
            self.samples_page.refresh();
        } else if cancel || !open {
            self.samples_page.editing = None;
        }
    }

    fn remove_window(&mut self, ctx: &egui::Context) {
        let Some(sha256) = self.samples_page.confirm_remove.clone() else {
            return;
        };
        let name = self
            .samples_page
            .rows
            .iter()
            .find(|row| row.record.sha256 == sha256)
            .map_or_else(|| sha256.clone(), |row| row.record.name.clone());
        let mut open = true;
        let mut remove = false;
        let mut cancel = false;
        crate::widgets::window("Remove sample")
            .id(egui::Id::new("samples_remove"))
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(format!("Delete the archive of {name}?"));
                ui.weak("Its hash, origins, tags and events stay; adding the same file again restores it.");
                crate::widgets::footer(ui, |ui| {
                    remove = ui.button("Remove").clicked();
                    cancel = ui.button("Cancel").clicked();
                });
            });
        if remove {
            let result = Library::open(&self.options.data_dir)
                .and_then(|mut library| library.remove(&sha256));
            self.samples_page.notice = Some(match result {
                Ok(()) => ("Archive removed".into(), false),
                Err(error) => (error, true),
            });
            self.samples_page.confirm_remove = None;
            self.samples_page.refresh();
        } else if cancel || !open {
            self.samples_page.confirm_remove = None;
        }
    }
}

#[cfg(test)]
impl SamplesPage {
    pub(super) fn show_tag_filter(&mut self, on: bool) {
        self.tags_open = on;
    }
    pub(super) fn edit_tags_of(&mut self, sha256: &str, name: &str, tags: &[Tag]) {
        self.editing = Some((sha256.into(), name.into(), picker::TagPicker::with(tags)));
    }
    pub(super) fn is_loaded(&self) -> bool {
        self.loaded
    }
    pub(super) fn rows(&self) -> &[Row] {
        &self.rows
    }
    pub(super) fn set_query(&mut self, query: &str) {
        self.query = query.into();
    }
    pub(super) fn toggle_tag(&mut self, tag: Tag) {
        if !self.tag_filter.remove(&tag) {
            self.tag_filter.insert(tag);
        }
    }
    pub(super) fn clear_tags(&mut self) {
        self.tag_filter.clear();
    }
    pub(super) fn set_roots_only(&mut self, on: bool) {
        self.roots_only = on;
    }
    pub(super) fn add_open(&self) -> bool {
        self.add.is_some()
    }
    pub(super) fn add_ready(&self) -> bool {
        self.add.as_ref().is_some_and(add::AddDialog::ready)
    }
    pub(super) fn delete_original_ticked(&self) -> bool {
        self.add
            .as_ref()
            .is_some_and(add::AddDialog::delete_original)
    }
    pub(super) fn tick_delete_original(&mut self) {
        if let Some(dialog) = &mut self.add {
            dialog.tick_delete_original();
        }
    }
    pub(in crate::app) fn open_custody_all(&mut self) {
        self.custody_all = Some(custody_all::CustodyAll::new());
    }
    pub(in crate::app) fn custody_all_mut(&mut self) -> Option<&mut custody_all::CustodyAll> {
        self.custody_all.as_mut()
    }
    pub(in crate::app) fn custody_all_ref(&self) -> Option<&custody_all::CustodyAll> {
        self.custody_all.as_ref()
    }
    pub(in crate::app) fn export_ref(&self) -> Option<&export::ExportDialog> {
        self.export.as_ref()
    }
    pub(in crate::app) fn export_mut(&mut self) -> Option<&mut export::ExportDialog> {
        self.export.as_mut()
    }
    pub(super) fn notice_text(&self) -> Option<&str> {
        self.notice.as_ref().map(|(text, _)| text.as_str())
    }
}
