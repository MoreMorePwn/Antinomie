// SPDX-License-Identifier: MIT
//! Compare the open entry (the open view or a saved dump) with a reference:
//! the installed base image, a saved checkpoint, another dump or the open
//! view. The sandboxed reader walks both images and lists the added, deleted
//! and changed entries; a rename is a deletion and an addition.
//!
//! A diff is block evidence: it says what differs between two disk images,
//! not which process changed it. Triage › Changed files holds the other kind,
//! the changes the kernel was observed making in one run. Where a path is in
//! both, each side links to the other and says which kind it is.
use super::*;
use crate::theme;
use antinomie_monitor_core::disks::{
    reader::{DiffEntry, DiffReason, DiffResults, DiffStatus, DiskEntry},
    DiskSourceSpec,
};
use std::sync::Arc;

/// Rows of the diff list the viewport draws.
const ROW_HEIGHT: f32 = 20.0;
/// The id of the paths a diff lists, shared with the Triage details.
pub(crate) const PATHS_KEY: &str = "disk-diff-paths";
/// The id of a path Triage asks the Disks tab to show.
pub(crate) const JUMP_KEY: &str = "disk-diff-jump";

/// What the open entry is compared with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Against {
    Dump(String),
    /// The open Current disk view.
    View,
    /// A source the backend flattens into a reference image.
    Source(DiskSourceSpec),
}

pub(super) enum Stage {
    /// The backend is flattening the reference; `seen` once its job showed.
    Reference {
        seen: bool,
    },
    Running,
    Done(Box<DiffResults>),
    Failed(String),
}

#[derive(Default)]
pub(super) struct Filter {
    pub status: Option<DiffStatus>,
    pub text: String,
    /// Hide changes whose only reasons are time, mode or owner.
    pub hide_metadata: bool,
}

pub(super) struct Diff {
    pub against: Against,
    /// "Base image", "Disk at before-run", a dump's title, "Current disk".
    pub label: String,
    pub stage: Stage,
    pub filter: Filter,
    /// Indexes into the results, after the filter.
    pub shown: Vec<usize>,
    pub dirty: bool,
    /// Index into the results.
    pub selected: Option<usize>,
    pub scroll_to: Option<usize>,
    /// A path to select when the results arrive (from Triage).
    pub reveal: Option<String>,
    pub worker: Option<worker::Worker>,
}

impl Diff {
    pub(super) fn new(against: Against, label: String, stage: Stage) -> Self {
        Self {
            against,
            label,
            stage,
            filter: Filter::default(),
            shown: Vec::new(),
            dirty: true,
            selected: None,
            scroll_to: None,
            reveal: None,
            worker: None,
        }
    }

    pub(super) fn results(&self) -> Option<&DiffResults> {
        match &self.stage {
            Stage::Done(results) => Some(results),
            _ => None,
        }
    }

    pub(super) fn entry(&self) -> Option<&DiffEntry> {
        self.results()
            .zip(self.selected)
            .and_then(|(results, index)| results.entries.get(index))
    }

    /// Recompute which entries pass the filter. Not per frame: when the
    /// filter or the results change.
    pub(super) fn refilter(&mut self) {
        self.dirty = false;
        let Some(results) = self.results() else {
            self.shown.clear();
            return;
        };
        let needle = self.filter.text.trim().to_lowercase();
        self.shown = results
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                self.filter
                    .status
                    .is_none_or(|status| entry.status == status)
                    && (needle.is_empty() || entry.path.to_lowercase().contains(&needle))
                    && !(self.filter.hide_metadata
                        && entry.status == DiffStatus::Changed
                        && entry.reasons.iter().all(|reason| {
                            matches!(
                                reason,
                                DiffReason::Time | DiffReason::Mode | DiffReason::Owner
                            )
                        }))
            })
            .map(|(index, _)| index)
            .collect();
    }

    /// Select the entry with this path, if the results have it.
    pub(super) fn select_path(&mut self, path: &str) -> bool {
        let Some(index) = self
            .results()
            .and_then(|results| results.entries.iter().position(|entry| entry.path == path))
        else {
            return false;
        };
        if self.filter.status.is_some() || !self.filter.text.is_empty() {
            self.filter = Filter::default();
            self.refilter();
        }
        self.selected = Some(index);
        self.scroll_to = self.shown.iter().position(|shown| *shown == index);
        true
    }
}

/// Take the diff's paths off the shared data Triage reads.
pub(super) fn withdraw_paths(ctx: &egui::Context) {
    ctx.data_mut(|data| {
        data.remove::<Arc<std::collections::BTreeSet<String>>>(egui::Id::new(PATHS_KEY))
    });
}

/// The path as Triage and the diff both spell it: absolute, no `//`, no
/// trailing `/`. `None` for a relative or empty path.
pub(crate) fn normalize_guest_path(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    Some(format!("/{}", parts.join("/")))
}

fn status_color(status: DiffStatus) -> egui::Color32 {
    match status {
        DiffStatus::Added => theme::good(),
        DiffStatus::Deleted => theme::error(),
        DiffStatus::Changed => theme::warn(),
    }
}

fn reasons_text(reasons: &[DiffReason]) -> String {
    reasons
        .iter()
        .map(|reason| reason.label())
        .collect::<Vec<_>>()
        .join(", ")
}

impl DiskView {
    /// Start comparing the open entry with `against`.
    pub(super) fn start_compare(
        &mut self,
        ctx: &egui::Context,
        cx: &DiskContext<'_>,
        against: Against,
    ) {
        if self.bound.is_none() {
            return;
        }
        self.close_diff(ctx);
        let (label, image) = match &against {
            Against::Dump(id) => match self.dumps.iter().find(|row| &row.dump.id == id) {
                Some(row) => (dumps::dump_title(&row.dump), Some(row.image.clone())),
                None => return,
            },
            Against::View => match cx.current_disk {
                Some(view) => (view.source.kind.label(), Some(view.image.clone())),
                None => return,
            },
            // A reference already read for this source is reused: a source
            // never changes while the VM is off.
            Against::Source(source) => (
                self.source_name(source),
                cx.reference
                    .filter(|reference| reference.source.kind.spec().as_ref() == Some(source))
                    .map(|reference| reference.image.clone()),
            ),
        };
        match image {
            Some(image) => {
                let mut diff = Diff::new(against, label, Stage::Running);
                self.start_diff_worker(ctx, &mut diff, &image);
                self.diff = Some(diff);
            }
            None => {
                let Against::Source(source) = &against else {
                    return;
                };
                self.action = Some(DiskAction::Reference(source.clone()));
                self.wait_for(false);
                self.diff = Some(Diff::new(against, label, Stage::Reference { seen: false }));
            }
        }
    }

    fn start_diff_worker(&mut self, ctx: &egui::Context, diff: &mut Diff, reference: &Path) {
        let Some(bound) = &self.bound else {
            diff.stage = Stage::Failed("no entry is open".into());
            return;
        };
        match worker::Worker::start(
            ctx.clone(),
            "disk-diff",
            bound.image.clone(),
            Some(reference.to_path_buf()),
            bound.extract_dir.clone(),
        ) {
            Ok(mut worker) => {
                let token = self.token(Purpose::Diff);
                worker.send(worker::Job {
                    token,
                    request: DiskRequest::Diff,
                    place: None,
                });
                diff.worker = Some(worker);
                diff.stage = Stage::Running;
            }
            Err(error) => diff.stage = Stage::Failed(error),
        }
    }

    /// Follow the backend's reference image, the diff worker and a
    /// reveal asked for by Triage. Once per frame; no filesystem calls.
    pub(super) fn diff_sync(&mut self, ctx: &egui::Context, cx: &DiskContext<'_>) {
        let Some(mut diff) = self.diff.take() else {
            return;
        };
        if let Stage::Reference { seen } = &mut diff.stage {
            let Against::Source(source) = diff.against.clone() else {
                self.diff = Some(diff);
                return;
            };
            let job = cx
                .job
                .is_some_and(|job| job.purpose == DiskJobPurpose::Reference);
            *seen |= job;
            let ready = cx
                .reference
                .filter(|reference| reference.source.kind.spec().as_ref() == Some(&source));
            if let Some(reference) = ready {
                let image = reference.image.clone();
                self.start_diff_worker(ctx, &mut diff, &image);
            } else if !job && cx.job.is_none() && (*seen || self.waiting.is_none()) {
                diff.stage = Stage::Failed(
                    "The reference disk could not be read; the Activity log says why.".into(),
                );
            }
        }
        if diff.dirty {
            diff.refilter();
        }
        self.diff = Some(diff);
    }

    /// The reader answered the comparison.
    pub(super) fn diff_finished(
        &mut self,
        ctx: &egui::Context,
        reply: Result<DiffResults, String>,
    ) {
        let Some(diff) = self.diff.as_mut() else {
            return;
        };
        diff.worker = None;
        match reply {
            Ok(results) => {
                let paths: std::collections::BTreeSet<String> = results
                    .entries
                    .iter()
                    .filter(|entry| entry.kind() != DiskEntryKind::Dir)
                    .filter_map(|entry| normalize_guest_path(&entry.path))
                    .collect();
                ctx.data_mut(|data| data.insert_temp(egui::Id::new(PATHS_KEY), Arc::new(paths)));
                diff.stage = Stage::Done(Box::new(results));
                diff.dirty = true;
                diff.refilter();
                if let Some(path) = diff.reveal.take() {
                    diff.select_path(&path);
                }
            }
            Err(error) => diff.stage = Stage::Failed(error),
        }
        self.sync_diff_selection();
    }

    /// Stop a comparison and forget its results.
    pub(super) fn close_diff(&mut self, ctx: &egui::Context) {
        if self.diff.take().is_some() {
            withdraw_paths(ctx);
            self.purposes
                .retain(|_, purpose| !matches!(purpose, Purpose::Diff));
            self.selection = None;
        }
    }

    /// Open a finished diff of the open entry without a reader (tests).
    #[cfg(test)]
    pub(crate) fn show_diff_for_test(&mut self, ctx: &egui::Context, results: DiffResults) {
        self.diff = Some(Diff::new(
            Against::Source(DiskSourceSpec::Base),
            "Base image".into(),
            Stage::Running,
        ));
        self.diff_finished(ctx, Ok(results));
    }

    /// The path selected in the diff (tests).
    #[cfg(test)]
    pub(crate) fn diff_selected_path_for_test(&self) -> Option<String> {
        self.diff
            .as_ref()
            .and_then(|diff| diff.entry())
            .map(|entry| entry.path.clone())
    }

    /// Show the entry with this path in the diff (from Triage). The diff is
    /// not started here: only an open comparison can reveal.
    pub(crate) fn reveal_diff(&mut self, path: &str) -> bool {
        let Some(diff) = self.diff.as_mut() else {
            return false;
        };
        let found = diff.select_path(path);
        if !found && diff.results().is_none() {
            diff.reveal = Some(path.to_owned());
        }
        self.sync_diff_selection();
        found || self.diff.as_ref().is_some_and(|diff| diff.reveal.is_some())
    }

    /// The Details follow the diff's selection: an entry that exists in the
    /// open image is selected there too (Extract works on it).
    pub(super) fn sync_diff_selection(&mut self) {
        let Some(entry) = self.diff.as_ref().and_then(|diff| diff.entry()).cloned() else {
            return;
        };
        if entry.after.is_some() && entry.kind() != DiskEntryKind::Dir {
            self.tree.reveal(&entry.path);
            self.select(entry.path);
        } else {
            self.selection = None;
        }
    }

    /// "Compare with…": the references that can be offered now.
    pub(super) fn compare_menu(&mut self, ui: &mut egui::Ui, cx: &DiskContext<'_>) {
        if self.bound.is_none() {
            return;
        }
        let backend_ready = cx.vm.is_some()
            && cx.vm_off
            && cx.job.is_none()
            && !cx.other_job
            && self.waiting.is_none();
        let why = if backend_ready {
            ""
        } else {
            "Needs the VM to be off and no other disk job running"
        };
        let selected_dump = self.selected_dump().map(|row| row.dump.id.clone());
        let mut chosen = None;
        ui.menu_button("Compare with…", |ui| {
            ui.add_enabled_ui(backend_ready, |ui| {
                if ui
                    .button("Installed base image")
                    .on_hover_text("What the VM's disk was created from")
                    .on_disabled_hover_text(why)
                    .clicked()
                {
                    chosen = Some(Against::Source(DiskSourceSpec::Base));
                }
                for checkpoint in source::offered(&self.checkpoints) {
                    if ui
                        .button(format!(
                            "Checkpoint {}",
                            source::checkpoint_label(checkpoint)
                        ))
                        .on_disabled_hover_text(why)
                        .clicked()
                    {
                        chosen = Some(Against::Source(DiskSourceSpec::Checkpoint(
                            checkpoint.id.clone(),
                        )));
                    }
                }
            });
            ui.separator();
            if selected_dump.is_some()
                && ui
                    .add_enabled(
                        cx.current_disk.is_some(),
                        egui::Button::new("The open view"),
                    )
                    .on_disabled_hover_text("Open the current disk (or a checkpoint) first")
                    .clicked()
            {
                chosen = Some(Against::View);
            }
            for row in &self.dumps {
                if !row.browsable() || selected_dump.as_deref() == Some(row.dump.id.as_str()) {
                    continue;
                }
                if ui
                    .button(format!("Dump {}", dumps::dump_title(&row.dump)))
                    .clicked()
                {
                    chosen = Some(Against::Dump(row.dump.id.clone()));
                }
            }
        });
        if let Some(against) = chosen {
            ui.close_menu();
            self.start_compare(ui.ctx(), cx, against);
        }
    }

    /// The diff in place of the tree.
    pub(super) fn diff_pane(&mut self, ui: &mut egui::Ui, cx: &DiskContext<'_>) {
        let title = self.entry_title();
        let triage = self.triage_paths.clone();
        let Some(diff) = self.diff.as_mut() else {
            return;
        };
        let mut close = false;
        let mut cancel_job = false;
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(format!("Changes in {title} since {}", diff.label))
                    .strong()
                    .color(theme::heading()),
            );
            if ui.button("Close diff").clicked() {
                close = true;
            }
        });
        let needs_cancel = match &diff.stage {
            Stage::Reference { .. } => {
                ui.horizontal(|ui| {
                    theme::spinner(ui);
                    let percent = cx.job.and_then(|job| match job.stage {
                        antinomie_monitor_core::disks::DiskJobStage::Converting { percent } => {
                            Some(percent)
                        }
                        _ => None,
                    });
                    ui.colored_label(
                        theme::muted(),
                        match percent {
                            Some(percent) => {
                                format!("Reading {}… {percent:.0} %", diff.label)
                            }
                            None => format!("Reading {}…", diff.label),
                        },
                    );
                });
                true
            }
            Stage::Running => {
                ui.horizontal(|ui| {
                    theme::spinner(ui);
                    ui.colored_label(theme::muted(), "Comparing the two images…");
                });
                true
            }
            Stage::Failed(error) => {
                crate::activity::error(ui, error);
                false
            }
            Stage::Done(_) => false,
        };
        if needs_cancel && ui.button("Cancel").clicked() {
            // The reference job, if the backend runs one; the reader is
            // stopped by closing the diff.
            if matches!(diff.stage, Stage::Reference { .. }) {
                cancel_job = true;
            }
            close = true;
        }
        if close {
            if cancel_job {
                self.action = Some(DiskAction::Cancel);
            }
            self.close_diff(ui.ctx());
            return;
        }
        let Some(results) = diff.results() else {
            return;
        };
        let (added, deleted, changed, scanned) = (
            results.added,
            results.deleted,
            results.changed,
            results.scanned,
        );
        let (truncated, timed_out, unreadable, listed) = (
            results.truncated,
            results.timed_out,
            results.unreadable,
            results.entries.len(),
        );
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(theme::good(), format!("+{added} added"));
            ui.colored_label(theme::error(), format!("−{deleted} deleted"));
            ui.colored_label(theme::warn(), format!("~{changed} changed"));
            ui.colored_label(theme::muted(), format!("· {scanned} entries compared"));
        });
        if truncated {
            crate::activity::warning(
                ui,
                format!(
                    "Only the first {listed} differences are listed; the totals count all of them."
                ),
            );
        }
        if timed_out {
            crate::activity::warning(
                ui,
                "The comparison reached its time or entry limit; later paths were not compared.",
            );
        }
        if unreadable > 0 {
            crate::activity::warning(
                ui,
                format!("{unreadable} folder(s) could not be read on one side and were skipped."),
            );
        }
        let mut changed_filter = false;
        ui.horizontal_wrapped(|ui| {
            for (label, status) in [
                ("All", None),
                ("Added", Some(DiffStatus::Added)),
                ("Deleted", Some(DiffStatus::Deleted)),
                ("Changed", Some(DiffStatus::Changed)),
            ] {
                if ui
                    .selectable_label(diff.filter.status == status, label)
                    .clicked()
                {
                    diff.filter.status = status;
                    changed_filter = true;
                }
            }
            changed_filter |= ui
                .add(
                    egui::TextEdit::singleline(&mut diff.filter.text)
                        .desired_width(200.0)
                        .hint_text("path contains"),
                )
                .changed();
            changed_filter |= ui
                .checkbox(
                    &mut diff.filter.hide_metadata,
                    "Hide time, mode and owner only",
                )
                .changed();
        });
        if changed_filter {
            diff.dirty = true;
        }
        ui.add(
            egui::Label::new(
                egui::RichText::new(
                    "Block evidence: these paths differ between two disk images. It does not say \
                     which process changed them; Triage › Changed files lists the changes \
                     observed in a run.",
                )
                .color(theme::muted()),
            )
            .wrap(),
        );
        ui.add_space(2.0);
        let shown = diff.shown.clone();
        let mut clicked = None;
        let scroll_to = diff.scroll_to.take();
        let selected = diff.selected;
        let Some(results) = diff.results() else {
            return;
        };
        let mut area = egui::ScrollArea::vertical()
            .id_salt("disk_diff_rows")
            .auto_shrink([false, false]);
        if let Some(position) = scroll_to {
            area = area
                .vertical_scroll_offset((position as f32 * ROW_HEIGHT - 2.0 * ROW_HEIGHT).max(0.0));
        }
        area.show_rows(ui, ROW_HEIGHT, shown.len(), |ui, range| {
            for position in range {
                let index = shown[position];
                let entry = &results.entries[index];
                let linked =
                    normalize_guest_path(&entry.path).is_some_and(|path| triage.contains(&path));
                let mut text = format!("{}  {}", entry.status.badge(), display_name(&entry.path));
                if !entry.reasons.is_empty() {
                    text.push_str(&format!("   [{}]", reasons_text(&entry.reasons)));
                }
                if linked {
                    text.push_str("   ◆ in Triage");
                }
                let label = egui::RichText::new(text)
                    .monospace()
                    .color(status_color(entry.status));
                if ui
                    .selectable_label(selected == Some(index), label)
                    .on_hover_text(if linked {
                        "Also listed in Triage › Changed files for the selected run"
                    } else {
                        ""
                    })
                    .clicked()
                {
                    clicked = Some(index);
                }
            }
        });
        if let Some(index) = clicked {
            if let Some(diff) = self.diff.as_mut() {
                diff.selected = Some(index);
            }
            self.sync_diff_selection();
        }
    }

    /// The name of the open entry, for the diff's heading.
    fn entry_title(&self) -> String {
        match self.bound.as_ref().map(|bound| &bound.what) {
            Some(What::Current(view)) => view.source.kind.label(),
            _ => self
                .selected_dump()
                .map(|row| dumps::dump_title(&row.dump))
                .unwrap_or_else(|| "this image".into()),
        }
    }

    /// The Details block of the selected difference: both sides, and the
    /// link to Triage.
    pub(super) fn diff_details(&mut self, ui: &mut egui::Ui, entry: &DiffEntry) {
        theme::section(ui, "Disk difference");
        egui::Grid::new("disk_diff_details")
            .num_columns(3)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                for (label, value) in [
                    ("Path", display_name(&entry.path)),
                    (
                        "Difference",
                        match entry.status {
                            DiffStatus::Added => "Added since the reference".to_string(),
                            DiffStatus::Deleted => "Deleted since the reference".to_string(),
                            DiffStatus::Changed => {
                                format!("Changed: {}", reasons_text(&entry.reasons))
                            }
                        },
                    ),
                ] {
                    ui.label(egui::RichText::new(label).color(theme::muted()));
                    ui.add(egui::Label::new(egui::RichText::new(value).monospace()).wrap());
                    ui.label("");
                    ui.end_row();
                }
                ui.label("");
                ui.label(egui::RichText::new("Before (reference)").color(theme::muted()));
                ui.label(egui::RichText::new("After (this image)").color(theme::muted()));
                ui.end_row();
                let side = |entry: &Option<DiskEntry>, field: &dyn Fn(&DiskEntry) -> String| {
                    entry.as_ref().map_or_else(|| "—".to_string(), field)
                };
                type Field<'a> = (&'a str, Box<dyn Fn(&DiskEntry) -> String>);
                let numeric = self.settings.numeric_modes;
                let fields: Vec<Field<'_>> = vec![
                    ("Type", Box::new(|e| e.kind.label().to_string())),
                    ("Size", Box::new(|e| format!("{} bytes", e.size))),
                    (
                        "Mode",
                        Box::new(move |e| {
                            if numeric {
                                mode_numeric(e.mode)
                            } else {
                                mode_rwx(e.kind, e.mode)
                            }
                        }),
                    ),
                    ("Owner", Box::new(|e| format!("{}:{}", e.uid, e.gid))),
                    (
                        "Modified",
                        Box::new(|e| {
                            u64::try_from(e.mtime)
                                .ok()
                                .map(crate::time_format::local_seconds)
                                .unwrap_or_else(|| "Unavailable".into())
                        }),
                    ),
                    (
                        "Link target",
                        Box::new(|e| {
                            e.link_target
                                .as_deref()
                                .map(display_name)
                                .unwrap_or_else(|| "—".into())
                        }),
                    ),
                ];
                for (label, field) in &fields {
                    ui.label(egui::RichText::new(*label).color(theme::muted()));
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(side(&entry.before, field.as_ref())).monospace(),
                        )
                        .wrap(),
                    );
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(side(&entry.after, field.as_ref())).monospace(),
                        )
                        .wrap(),
                    );
                    ui.end_row();
                }
            });
        ui.add_space(4.0);
        let linked =
            normalize_guest_path(&entry.path).is_some_and(|path| self.triage_paths.contains(&path));
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(
                theme::muted(),
                "Block evidence: the path differs between the two images.",
            );
            if linked {
                ui.colored_label(
                    theme::good(),
                    "The selected run's Changed files (observed operations) lists it too.",
                );
                if ui.button("Show in Triage › Changed files").clicked() {
                    self.action = Some(DiskAction::ShowInTriage(entry.path.clone()));
                }
            } else {
                ui.colored_label(theme::muted(), "Not in the selected run's Changed files.");
            }
        });
        ui.add_space(6.0);
    }
}
