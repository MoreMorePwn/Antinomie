// SPDX-License-Identifier: MIT
//! The saved dumps of the entries list: scanning the recordings, the rows
//! with their badges and menus, and the record filter.
//!
//! The list is scanned when the selected VM's recording folders change, when
//! a disk job starts or ends, when an open view is kept, and on Refresh: never
//! per frame. Whether an imported image moved is checked in the same scan.
use super::*;
use crate::{
    evidence,
    network_view::{capture_row, format_date},
    query::{self, RowValue},
    theme,
};
use antinomie_monitor_core::disks::{
    dump::{self, DiskImageFormat},
    export::ExportFormat,
    DiskJobPurpose, DiskJobStage, Ext4State,
};

/// One listed dump, with what the scan found out about its file.
pub(super) struct Row {
    pub dump: DiskDump,
    /// Where its image is, resolved at the scan.
    pub image: PathBuf,
    /// An imported image that is no longer where it was.
    pub missing: bool,
}

impl Row {
    fn new(dump: DiskDump) -> Self {
        Self {
            image: dump.path(),
            missing: dump.missing(),
            dump,
        }
    }

    /// The image can be opened by this version.
    pub(super) fn browsable(&self) -> bool {
        self.dump.complete() && self.dump.format == DiskImageFormat::RawExt4 && !self.missing
    }
}

/// What a scan was taken for; when it changes, the list is read again.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ScanKey {
    job: Option<DiskJobPurpose>,
    kept: Option<String>,
    waiting: bool,
}

/// The default name of a dump: its start time, or an imported file's name.
pub(super) fn dump_title(dump: &DiskDump) -> String {
    if dump.imported {
        dump.file.file_name().map_or_else(
            || "Imported image".into(),
            |name| name.to_string_lossy().into_owned(),
        )
    } else {
        format_date(dump.started_ms / 1000)
            .trim_end_matches(" UTC")
            .to_owned()
    }
}

fn dump_detail(row: &Row) -> String {
    let dump = &row.dump;
    if let Some(error) = &dump.error {
        return format!("Failed: {error}");
    }
    if dump.finished_ms.is_none() {
        return "incomplete".into();
    }
    if row.missing {
        return "file moved".into();
    }
    if dump.format != DiskImageFormat::RawExt4 {
        return "made by a newer version".into();
    }
    let mut parts = vec![dump.fs_state.label().to_owned()];
    if dump.imported {
        parts.push("imported".into());
    }
    parts.push(format!(
        "{} of {}",
        format_size(dump.allocated_size.unwrap_or(dump.logical_size)),
        format_size(dump.logical_size)
    ));
    if dump.sha256.is_some() {
        parts.push("SHA-256".into());
    }
    parts.join(" · ")
}

fn dump_fields() -> Vec<query::FieldSpec<'static>> {
    let mut fields = query::LABEL_FIELDS.to_vec();
    fields.extend(query::CAPTURE_FIELDS);
    fields.extend([
        query::FieldSpec::text("name", "Displayed dump name"),
        query::FieldSpec::text("state", "Dump state: finished, failed or writing"),
        query::FieldSpec::text("fs_state", "Filesystem state: clean or not_clean"),
        query::FieldSpec::text("system", "Recorded guest system"),
        query::FieldSpec::text("vm", "Name of the VM it was taken from"),
        query::FieldSpec::number("size", "Allocated size in octets"),
        query::FieldSpec::number("logical_size", "Virtual disk size in octets"),
        query::FieldSpec::boolean("imported", "Imported image"),
        query::FieldSpec::boolean("hashed", "A SHA-256 is recorded"),
    ]);
    fields
}

fn dump_row(
    dump: &DiskDump,
    annotation: Option<&antinomie_monitor_core::annotations::Annotation>,
) -> Vec<(&'static str, RowValue)> {
    let state = if dump.error.is_some() {
        "failed"
    } else if dump.finished_ms.is_some() {
        "finished"
    } else {
        "writing"
    };
    let mut row = query::label_row(
        &dump.id,
        annotation.map_or("", |value| &value.name),
        &dump.path().display().to_string(),
        annotation.map_or(&[], |value| value.tags.as_slice()),
    );
    let size = dump
        .allocated_size
        .map_or(RowValue::Missing, |size| RowValue::Number(i128::from(size)));
    row.extend([
        ("capture.kind", RowValue::Text("disk".into())),
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
        ("capture.size", size.clone()),
        ("capture.complete", RowValue::Bool(dump.complete())),
        ("capture.state", RowValue::Text(state.into())),
        ("entry.kind", RowValue::Text("disk".into())),
        ("entry.complete", RowValue::Bool(dump.complete())),
        (
            "entry.time_ms",
            RowValue::Number(i128::from(dump.started_ms)),
        ),
        ("entry.size", size.clone()),
        ("entry.state", RowValue::Text(state.into())),
        ("vm.id", RowValue::Text(dump.vm_id.clone())),
        (
            "name",
            RowValue::Text(
                annotation
                    .filter(|value| !value.name.is_empty())
                    .map_or_else(|| dump_title(dump), |value| value.name.clone()),
            ),
        ),
        ("state", RowValue::Text(state.into())),
        (
            "fs_state",
            RowValue::Text(
                match dump.fs_state {
                    Ext4State::Unknown => "unknown",
                    Ext4State::Clean => "clean",
                    Ext4State::NotClean => "not_clean",
                }
                .into(),
            ),
        ),
        ("system", RowValue::Text(dump.system.clone())),
        ("vm", RowValue::Text(dump.vm_name.clone())),
        ("size", size),
        (
            "logical_size",
            RowValue::Number(i128::from(dump.logical_size)),
        ),
        ("imported", RowValue::Bool(dump.imported)),
        ("hashed", RowValue::Bool(dump.sha256.is_some())),
    ]);
    row
}

impl DiskView {
    /// Read the dumps of these recording folders.
    pub(super) fn scan(&mut self, roots: &[PathBuf]) {
        self.dumps = dump::list(roots).into_iter().map(Row::new).collect();
        self.dumps_for = Some(roots.to_vec());
        self.drop_missing_entry();
    }

    /// An entry that is not in the list any more selects the Current disk.
    fn drop_missing_entry(&mut self) {
        if let Entry::Dump(id) = &self.entry {
            if !self.dumps.iter().any(|row| &row.dump.id == id) {
                self.entry = Entry::Current;
            }
        }
    }

    /// Scan again when the recordings may have changed under the tab.
    pub(super) fn scan_when_needed(&mut self, cx: &DiskContext<'_>) {
        let key = ScanKey {
            job: cx.job.map(|job| job.purpose),
            kept: cx.current_disk.and_then(|view| view.kept_as.clone()),
            waiting: self.waiting.is_some(),
        };
        if self
            .dumps_for
            .as_deref()
            .is_none_or(|roots| roots != cx.recording_roots)
            || self.scan_key != key
        {
            self.scan_key = key;
            self.scan(cx.recording_roots);
        }
    }

    /// Why a new dump cannot be taken now, for the button's tooltip.
    pub(super) fn dump_blocked(&self, cx: &DiskContext<'_>) -> Option<String> {
        if cx.vm.is_none() {
            return Some("Select a VM".into());
        }
        if !cx.vm_off {
            return Some("Dumping needs the VM to be off".into());
        }
        if cx.job.is_some() || cx.other_job {
            return Some("Another disk job is running".into());
        }
        if self.waiting.is_some() {
            return Some("A request is on its way".into());
        }
        let Some(measure) = cx.measure else {
            return Some("Measuring the disk…".into());
        };
        measure.error.clone().or_else(|| measure.quota_error())
    }

    /// Why the open view cannot be kept now.
    pub(super) fn keep_blocked(&self, cx: &DiskContext<'_>) -> Option<String> {
        let view = cx.current_disk?;
        if view.kept_as.is_some() {
            return Some("This view is already kept as a dump".into());
        }
        if cx.job.is_some() || cx.other_job {
            return Some("Another disk job is running".into());
        }
        if self.waiting.is_some() {
            return Some("A request is on its way".into());
        }
        let ceiling = cx.measure.map_or(0, |measure| measure.quota);
        antinomie_monitor_core::disks::quota_error(view.allocated_size, ceiling)
    }

    /// Ask for a dump; the button of the list and of the measure card.
    pub(super) fn dump_button(&mut self, ui: &mut egui::Ui, cx: &DiskContext<'_>, full: bool) {
        let blocked = self.dump_blocked(cx);
        let mut button =
            egui::Button::new(format!("{} Dump disk", egui_phosphor::regular::HARD_DRIVES));
        if full {
            button = button.min_size(egui::vec2(ui.available_width(), 0.0));
        }
        let response = ui
            .add_enabled(blocked.is_none(), button)
            .on_hover_text(
                "Flatten the VM's current disk into a standalone sparse image kept with its \
                 recordings",
            )
            .on_disabled_hover_text(blocked.clone().unwrap_or_default());
        if response.clicked() {
            self.wait_for(false);
            self.action = Some(DiskAction::Dump);
        }
    }

    /// The saved dumps with their filter, newest first.
    pub(super) fn dump_list(&mut self, ui: &mut egui::Ui, cx: &DiskContext<'_>) {
        let fields = dump_fields();
        let annotations: Vec<_> = self
            .dumps
            .iter()
            .map(|row| evidence::annotation(ui, &row.dump.dir))
            .collect();
        let tags: Vec<_> = annotations
            .iter()
            .flatten()
            .flat_map(|value| value.tags.iter().cloned())
            .collect();
        let filter = query::table_filter(
            ui,
            "disk-dump-history",
            "name contains debian",
            &fields,
            &tags,
        );
        let filter_id = ui.id().with(("table-filter", "disk-dump-history"));
        let shown: Vec<usize> = (0..self.dumps.len())
            .filter(|&index| {
                filter.keep_table(&dump_row(
                    &self.dumps[index].dump,
                    annotations[index].as_ref(),
                ))
            })
            .collect();
        ui.weak(format!("{} / {} dumps", shown.len(), self.dumps.len()));
        let mut select = None;
        let mut menu: Option<RowMenu> = None;
        let font_size = cx.font_size;
        egui::ScrollArea::vertical()
            .id_salt("disk_dump_list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                if let Some(job) = cx.job.filter(|job| {
                    matches!(job.purpose, DiskJobPurpose::Dump | DiskJobPurpose::Keep)
                }) {
                    self.writing_row(ui, job, font_size);
                }
                for &index in &shown {
                    let row = &self.dumps[index];
                    let dump = &row.dump;
                    let selected = self.entry == Entry::Dump(dump.id.clone());
                    let color = if dump.error.is_some() {
                        theme::error()
                    } else if !row.browsable() {
                        theme::muted()
                    } else {
                        theme::text()
                    };
                    let mut title = evidence::title(ui, &dump.dir, &dump_title(dump));
                    if dump.fs_state == Ext4State::NotClean {
                        title = format!("{} {title}", egui_phosphor::regular::WARNING);
                    }
                    let response =
                        capture_row(ui, selected, (&title, color), &dump_detail(row), font_size)
                            .on_hover_text(format!(
                                "{}\n{} · {}",
                                row.image.display(),
                                dump.vm_name,
                                dump.system
                            ));
                    if response.clicked() {
                        select = Some(dump.id.clone());
                    }
                    response.context_menu(|ui| {
                        if let Some(choice) =
                            self.row_menu(ui, index, filter_id, annotations[index].as_ref())
                        {
                            menu = Some(choice);
                        }
                    });
                }
                if self.dumps.is_empty() && cx.job.is_none() {
                    ui.add_space(4.0);
                    ui.colored_label(theme::muted(), "No disk dumps for this VM");
                }
            });
        if let Some(id) = select {
            self.entry = Entry::Dump(id);
        }
        if let Some(choice) = menu {
            self.row_choice(ui.ctx(), choice, cx);
        }
    }

    fn writing_row(&self, ui: &mut egui::Ui, job: &DiskJobProgress, font_size: f32) {
        let (label, fraction) = match &job.stage {
            DiskJobStage::Measuring => ("measuring…".to_string(), None),
            DiskJobStage::Converting { percent } => {
                (format!("writing… {percent:.0} %"), Some(percent / 100.0))
            }
            DiskJobStage::Hashing { done, total } => {
                let fraction = *done as f32 / (*total).max(1) as f32;
                (
                    format!("hashing… {:.0} %", fraction * 100.0),
                    Some(fraction),
                )
            }
            DiskJobStage::Finalizing => ("finishing…".to_string(), None),
        };
        let title = if job.purpose == DiskJobPurpose::Keep {
            format!("{} Keeping the view", egui_phosphor::regular::RECORD)
        } else {
            format!("{} Writing dump", egui_phosphor::regular::RECORD)
        };
        capture_row(ui, false, (&title, theme::error()), &label, font_size);
        if let Some(fraction) = fraction {
            ui.add(egui::ProgressBar::new(fraction.clamp(0.0, 1.0)).desired_height(4.0));
        }
    }

    /// The right-click menu of a row. Returns the choice, if one was made.
    fn row_menu(
        &self,
        ui: &mut egui::Ui,
        index: usize,
        filter_id: egui::Id,
        annotation: Option<&antinomie_monitor_core::annotations::Annotation>,
    ) -> Option<RowMenu> {
        let row = &self.dumps[index];
        let dump = &row.dump;
        let mut choice = None;
        evidence::menu(ui, &dump.dir);
        query::table_row_menu(ui, filter_id, &dump_row(dump, annotation));
        ui.separator();
        if ui.button("Copy path").clicked() {
            choice = Some(RowMenu::CopyPath(index));
            ui.close_menu();
        }
        let busy = self.saving_image.is_some();
        let saveable = row.browsable() && !busy;
        for format in [ExportFormat::SparseRaw, ExportFormat::Qcow2] {
            if ui
                .add_enabled(
                    saveable,
                    egui::Button::new(format!("Save image to host… ({})", format.label())),
                )
                .on_disabled_hover_text("Needs a finished dump, and no other save running")
                .clicked()
            {
                choice = Some(RowMenu::Save(index, format));
                ui.close_menu();
            }
        }
        if ui
            .add_enabled(
                row.browsable() && self.verify.is_none(),
                egui::Button::new("Verify SHA-256"),
            )
            .on_disabled_hover_text("Needs a finished dump, and no other check running")
            .clicked()
        {
            choice = Some(RowMenu::Verify(index));
            ui.close_menu();
        }
        let blocked = self.delete_blocked_id(&dump.id);
        if crate::evidence_delete::menu_item(ui, blocked.as_deref()) {
            choice = Some(RowMenu::Delete(index));
        }
        choice
    }

    /// Why a dump cannot be deleted now.
    pub(super) fn delete_blocked_id(&self, id: &str) -> Option<String> {
        if self.open_kept.as_deref() == Some(id) {
            return Some("The open Current disk view reads this dump: close the view first".into());
        }
        if self
            .saving_image
            .as_ref()
            .is_some_and(|saving| saving.id == id)
        {
            return Some("Its image is being saved to the host".into());
        }
        None
    }

    fn row_choice(&mut self, ctx: &egui::Context, choice: RowMenu, cx: &DiskContext<'_>) {
        match choice {
            RowMenu::CopyPath(index) => {
                ctx.copy_text(self.dumps[index].image.display().to_string());
            }
            RowMenu::Save(index, format) => {
                let dump = self.dumps[index].dump.clone();
                let qemu_img = cx.qemu_img.to_path_buf();
                self.start_save_image(ctx, &dump, &qemu_img, format);
            }
            RowMenu::Verify(index) => {
                let row = &self.dumps[index];
                let (dump, image) = (row.dump.clone(), row.image.clone());
                self.start_verify(ctx, &dump, image);
            }
            RowMenu::Delete(index) => {
                self.action = Some(DiskAction::Delete(Box::new(self.dumps[index].dump.clone())));
            }
        }
    }

    /// The deleted dump is gone from the list.
    pub(crate) fn forget_dump(&mut self, directory: &Path) {
        self.dumps.retain(|row| row.dump.dir != directory);
        self.drop_missing_entry();
        self.verified
            .retain(|id, _| self.dumps.iter().any(|row| &row.dump.id == id));
        // Rescan on the next frame: other dumps may have changed too.
        self.dumps_for = None;
    }

    /// The dump of the selected entry.
    pub(super) fn selected_dump(&self) -> Option<&Row> {
        let Entry::Dump(id) = &self.entry else {
            return None;
        };
        self.dumps.iter().find(|row| &row.dump.id == id)
    }
}

/// A choice from a row's right-click menu, by index into the list.
pub(super) enum RowMenu {
    CopyPath(usize),
    Save(usize, ExportFormat),
    Verify(usize),
    Delete(usize),
}
