// SPDX-License-Identifier: GPL-3.0-only
//! Delete run…: the dialog that lists the run's artifacts, each with its
//! kind and short SHA-256, and asks for each whether to keep it in Samples or
//! delete it. The last artifact of its kind that the sample has starts as
//! Keep, everything else as Delete. The files are read, moved and removed on
//! a thread; a run that is still running is refused.
use super::*;
use crate::widgets::{self, table, Tone};
use antinomie_monitor_core::samples::{
    delete_run, plan_run_deletion, ArtifactKind, ArtifactPlace, DeletedRun, RunPlan, RunPlanItem,
};
use std::collections::{BTreeMap, BTreeSet};

type Planned = Result<RunPlan, String>;
type Done = Result<DeletedRun, String>;

enum Stage {
    /// Reading the run's files and their hashes.
    Planning(Receiver<Planned>),
    Ready(RunPlan),
    Working(Receiver<Done>),
    Failed(String),
}

/// The open dialog.
pub(super) struct DeleteRun {
    sample: String,
    vm_name: String,
    run_id: String,
    number: usize,
    started: String,
    /// Artifacts of the same kind the sample has in other runs.
    others: BTreeMap<ArtifactKind, usize>,
    /// Keep (true) or delete (false), by item key; the defaults until changed.
    keep: BTreeMap<String, bool>,
    stage: Stage,
    open: bool,
}

/// What the dialog asks of the page.
pub(super) enum Outcome {
    None,
    Confirm(BTreeSet<String>),
}

impl DeleteRun {
    fn item_keep(&self, item: &RunPlanItem) -> bool {
        self.keep
            .get(&item.key)
            .copied()
            .unwrap_or_else(|| self.others.get(&item.kind).copied().unwrap_or(0) == 0)
    }

    fn wanted(&self, plan: &RunPlan) -> BTreeSet<String> {
        plan.items
            .iter()
            .filter(|item| item.choosable() && self.item_keep(item))
            .map(|item| item.key.clone())
            .collect()
    }

    fn poll(&mut self) -> Option<Done> {
        match &self.stage {
            Stage::Planning(receiver) => {
                if let Ok(result) = receiver.try_recv() {
                    self.stage = match result {
                        Ok(plan) => Stage::Ready(plan),
                        Err(error) => Stage::Failed(error),
                    };
                }
            }
            Stage::Working(receiver) => {
                if let Ok(result) = receiver.try_recv() {
                    return Some(result);
                }
            }
            _ => {}
        }
        None
    }

    /// One frame; the page deals with what comes back.
    fn show(&mut self, ctx: &egui::Context, font: f32) -> Outcome {
        let mut outcome = Outcome::None;
        let mut open = self.open;
        let busy = matches!(self.stage, Stage::Planning(_) | Stage::Working(_));
        widgets::window(format!("Delete run {}", self.number))
            .id(egui::Id::new("samples_delete_run"))
            .open(&mut open)
            .default_width(640.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} on {} · {}",
                            self.sample, self.vm_name, self.started
                        ))
                        .color(theme::muted()),
                    );
                });
                match &self.stage {
                    Stage::Planning(_) => {
                        ui.horizontal(|ui| {
                            theme::spinner(ui);
                            ui.label("Reading the run's files…");
                        });
                    }
                    Stage::Working(_) => {
                        ui.horizontal(|ui| {
                            theme::spinner(ui);
                            ui.label("Deleting the run…");
                        });
                    }
                    Stage::Failed(error) => {
                        ui.colored_label(theme::error(), error);
                    }
                    Stage::Ready(_) => {}
                }
                let plan = match std::mem::replace(&mut self.stage, Stage::Failed(String::new())) {
                    Stage::Ready(plan) => plan,
                    other => {
                        self.stage = other;
                        widgets::footer(ui, |ui| {
                            if ui.add_enabled(!busy, egui::Button::new("Close")).clicked() {
                                self.open = false;
                            }
                        });
                        return;
                    }
                };
                self.rows(ui, &plan, font);
                let (frees, keeps) = self.totals(&plan);
                widgets::footer_split(
                    ui,
                    |ui| {
                        ui.label(
                            RichText::new(format!(
                                "Frees {} · keeps {}",
                                crate::values::file_size(frees),
                                crate::values::file_size(keeps)
                            ))
                            .color(theme::muted()),
                        );
                    },
                    |ui| {
                        let delete = egui::Button::new(
                            RichText::new(format!("Delete run {}", self.number))
                                .color(theme::error()),
                        );
                        if ui.add(delete).clicked() {
                            outcome = Outcome::Confirm(self.wanted(&plan));
                        }
                        if ui.button("Cancel").clicked() {
                            self.open = false;
                        }
                    },
                );
                if matches!(self.stage, Stage::Failed(_)) {
                    self.stage = Stage::Ready(plan);
                }
            });
        if !open {
            self.open = false;
        }
        outcome
    }

    fn totals(&self, plan: &RunPlan) -> (u64, u64) {
        let (mut frees, mut keeps) = (0, 0);
        for item in plan.items.iter().filter(|item| item.choosable()) {
            if self.item_keep(item) {
                keeps += item.size;
            } else if item.place == ArtifactPlace::InFolder {
                frees += item.size;
            }
        }
        (frees, keeps)
    }

    fn rows(&mut self, ui: &mut egui::Ui, plan: &RunPlan, font: f32) {
        if plan.items.is_empty() {
            ui.add_space(6.0);
            ui.label(RichText::new("This run has no artifacts.").color(theme::muted()));
            return;
        }
        ui.horizontal(|ui| {
            if ui.small_button("Keep all").clicked() {
                for item in plan.items.iter().filter(|item| item.choosable()) {
                    self.keep.insert(item.key.clone(), true);
                }
            }
            if ui.small_button("Delete all").clicked() {
                for item in plan.items.iter().filter(|item| item.choosable()) {
                    self.keep.insert(item.key.clone(), false);
                }
            }
        });
        table::begin(ui);
        egui_extras::TableBuilder::new(ui)
            .id_salt("samples_delete_run_rows")
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(egui_extras::Column::auto().at_least(180.0))
            .column(egui_extras::Column::auto().at_least(70.0))
            .column(egui_extras::Column::remainder().at_least(160.0).clip(true))
            .column(egui_extras::Column::auto().at_least(150.0))
            .max_scroll_height(320.0)
            .header(table::header_height(font), |mut header| {
                for title in ["Artifact", "Size", "For this sample", ""] {
                    header.col(|ui| table::head(ui, title));
                }
            })
            .body(|body| {
                body.rows(table::row_height(font) + 6.0, plan.items.len(), |mut row| {
                    let item = &plan.items[row.index()];
                    let others = self.others.get(&item.kind).copied().unwrap_or(0);
                    row.col(|ui| {
                        ui.label(RichText::new(item.title()).strong());
                        if !item.context.is_empty() {
                            ui.label(RichText::new(&item.context).color(theme::muted()));
                        }
                    });
                    row.col(|ui| {
                        ui.label(if item.size > 0 {
                            crate::values::file_size(item.size)
                        } else {
                            "–".to_owned()
                        });
                    });
                    row.col(|ui| {
                        if !item.choosable() {
                            return;
                        }
                        let word = item.kind.plural();
                        if others == 0 {
                            widgets::chip(
                                ui,
                                format!(
                                    "the last {} of {}",
                                    word.trim_end_matches('s'),
                                    self.sample
                                ),
                                Tone::Error,
                            );
                        } else {
                            ui.label(
                                RichText::new(format!(
                                    "{others} other {} of {}",
                                    if others == 1 {
                                        word.trim_end_matches('s')
                                    } else {
                                        word
                                    },
                                    self.sample
                                ))
                                .color(theme::muted()),
                            );
                        }
                    });
                    row.col(|ui| match item.place {
                        ArtifactPlace::InFolder | ArtifactPlace::Outside => {
                            let mut keep = self.item_keep(item);
                            let second = if item.place == ArtifactPlace::InFolder {
                                "Delete"
                            } else {
                                "Leave"
                            };
                            let changed = widgets::segmented(
                                ui,
                                [
                                    (true, widgets::TabItem::new("Keep")),
                                    (false, widgets::TabItem::new(second)),
                                ],
                                &mut keep,
                            );
                            if changed {
                                self.keep.insert(item.key.clone(), keep);
                            }
                            if item.place == ArtifactPlace::Outside {
                                ui.label(RichText::new("stays in the VM").color(theme::muted()))
                                    .on_hover_text(
                                        "Delete it from Memory or Network; only the run's own files are deleted here",
                                    );
                            }
                        }
                        ArtifactPlace::WithVm => {
                            ui.label(RichText::new("Stays with the VM").color(theme::muted()));
                        }
                        ArtifactPlace::InRecord => {
                            ui.label(
                                RichText::new("Stays in the sample record").color(theme::muted()),
                            );
                        }
                    });
                });
            });
    }
}

impl MonitorApp {
    /// Whether a run is still running: it cannot be deleted then.
    pub(in crate::app) fn sample_run_live(&self, run: &RunSummary) -> bool {
        self.snapshot
            .runs
            .iter()
            .any(|live| live.id == run.id && live_state(&live.state))
    }

    /// Open the Delete run… dialog for `run` (number `number` of the sample).
    pub(super) fn start_delete_run(
        &mut self,
        ctx: &egui::Context,
        data: &detail::Data,
        number: usize,
        run: &RunSummary,
    ) {
        let mut others = BTreeMap::new();
        for output in data
            .outputs()
            .iter()
            .filter(|output| output.number != number && output.is_present())
        {
            *others.entry(output.kind.core()).or_insert(0usize) += 1;
        }
        let (sender, receiver) = mpsc::channel();
        let options = self.options.clone();
        let (sha, vm, id) = (
            data.record.sha256.clone(),
            run.vm_id.clone(),
            run.id.clone(),
        );
        let wake = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("samples-delete-plan".into())
            .spawn(move || {
                let _ = sender.send(plan_run_deletion(&options, &sha, &vm, &id));
                wake.request_repaint();
            });
        let stage = match spawned {
            Ok(_) => Stage::Planning(receiver),
            Err(error) => Stage::Failed(error.to_string()),
        };
        self.samples_page.delete_run = Some(DeleteRun {
            sample: data.record.name.clone(),
            vm_name: run
                .environment
                .as_ref()
                .map(|environment| environment.vm_name.clone())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| run.vm_id.clone()),
            run_id: run.id.clone(),
            number,
            started: crate::time_format::unix_ms(run.started_ms),
            others,
            keep: BTreeMap::new(),
            stage,
            open: true,
        });
    }

    /// The dialog, and what it started.
    pub(super) fn delete_run_window(&mut self, ctx: &egui::Context) {
        let font = self.settings.font_size;
        let Some(dialog) = &mut self.samples_page.delete_run else {
            return;
        };
        let finished = dialog.poll();
        let outcome = dialog.show(ctx, font);
        if let Some(result) = finished {
            match result {
                Ok(done) => {
                    let notice = format!(
                        "Run {} deleted: {} kept, {} deleted",
                        dialog.number, done.kept, done.deleted
                    );
                    self.samples_page.notice = Some((notice, false));
                    self.samples_page.delete_run = None;
                    self.samples_page.refresh();
                    self.refresh_history();
                }
                Err(error) => dialog.stage = Stage::Failed(error),
            }
            return;
        }
        if let (Outcome::Confirm(keep), Stage::Ready(_)) = (outcome, &dialog.stage) {
            let live = self
                .snapshot
                .runs
                .iter()
                .any(|run| run.id == dialog.run_id && live_state(&run.state));
            let Stage::Ready(plan) =
                std::mem::replace(&mut dialog.stage, Stage::Failed(String::new()))
            else {
                return;
            };
            let (sender, receiver) = mpsc::channel();
            let options = self.options.clone();
            let vm_name = dialog.vm_name.clone();
            let wake = ctx.clone();
            dialog.stage = match std::thread::Builder::new()
                .name("samples-delete-run".into())
                .spawn(move || {
                    let _ = sender.send(delete_run(&options, &plan, &keep, &vm_name, live));
                    wake.request_repaint();
                }) {
                Ok(_) => Stage::Working(receiver),
                Err(error) => Stage::Failed(error.to_string()),
            };
            return;
        }
        if !dialog.open && !matches!(dialog.stage, Stage::Working(_)) {
            self.samples_page.delete_run = None;
        }
    }
}

/// A run that is running (or being stopped) cannot be deleted.
fn live_state(state: &RunState) -> bool {
    matches!(
        *state,
        RunState::Running | RunState::StopRequested | RunState::TerminalClosed
    )
}

#[cfg(test)]
impl SamplesPage {
    /// Where the dialog is: planning, ready, working or failed (with why).
    pub(in crate::app) fn delete_run_stage(&self) -> Option<String> {
        self.delete_run.as_ref().map(|dialog| match &dialog.stage {
            Stage::Planning(_) => "planning".to_owned(),
            Stage::Ready(_) => "ready".to_owned(),
            Stage::Working(_) => "working".to_owned(),
            Stage::Failed(why) => format!("failed: {why}"),
        })
    }

    /// The rows: title, whether the analyst can choose, and whether it is kept.
    pub(in crate::app) fn delete_run_rows(&self) -> Vec<(String, bool, bool)> {
        let Some(dialog) = &self.delete_run else {
            return Vec::new();
        };
        let Stage::Ready(plan) = &dialog.stage else {
            return Vec::new();
        };
        plan.items
            .iter()
            .map(|item| (item.title(), item.choosable(), dialog.item_keep(item)))
            .collect()
    }

    pub(in crate::app) fn delete_run_set_all(&mut self, keep: bool) {
        if let Some(dialog) = &mut self.delete_run {
            if let Stage::Ready(plan) = &dialog.stage {
                for item in plan.items.iter().filter(|item| item.choosable()) {
                    dialog.keep.insert(item.key.clone(), keep);
                }
            }
        }
    }
}

#[cfg(test)]
impl MonitorApp {
    /// Press Delete run in the open dialog.
    pub(in crate::app) fn confirm_delete_run(&mut self) {
        let Some(dialog) = &mut self.samples_page.delete_run else {
            return;
        };
        let Stage::Ready(plan) = std::mem::replace(&mut dialog.stage, Stage::Failed(String::new()))
        else {
            return;
        };
        let keep = dialog.wanted(&plan);
        let (sender, receiver) = mpsc::channel();
        let options = self.options.clone();
        let vm_name = dialog.vm_name.clone();
        let _ = sender.send(delete_run(&options, &plan, &keep, &vm_name, false));
        dialog.stage = Stage::Working(receiver);
    }
}

#[cfg(test)]
impl MonitorApp {
    /// Choose Delete run… on run `number` of the open sample.
    pub(in crate::app) fn start_delete_run_for_test(&mut self, ctx: &egui::Context, number: usize) {
        let Some(data) = self
            .samples_page
            .detail
            .as_ref()
            .and_then(|detail| detail.data.clone())
        else {
            return;
        };
        if let Some(entry) = data.runs.iter().find(|entry| entry.number == number) {
            let run = entry.run.clone();
            self.start_delete_run(ctx, &data, number, &run);
        }
    }
}
