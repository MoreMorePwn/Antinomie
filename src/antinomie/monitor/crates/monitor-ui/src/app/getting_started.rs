// SPDX-License-Identifier: MIT
//! Help > Getting started: the window frame, when it opens and the work it
//! queues. Each step reuses the existing window's code and plumbing; see
//! `steps` for what a step shows.
use super::*;
use crate::getting_started::{self as walkthrough, Facts, Status, Step};
use antinomie_monitor_core::dependencies::Dependency;

mod steps;

/// A VM that does not appear within this time is reported as not created.
const VM_WAIT: Duration = Duration::from_secs(20);

impl MonitorApp {
    /// Open the window (Help > Getting started, or the first launch). It
    /// reads the host again, so what is already installed shows as done.
    pub(super) fn open_getting_started(&mut self) {
        let state = &mut self.getting_started;
        state.open = true;
        state.step = self.settings.getting_started.remembered_step();
        state.catalog_requested = false;
        state.vm_error = None;
        state.base_error = None;
        state.tool_error = None;
        state.draft = None;
        state.rules_chosen = None;
        self.dependencies.recheck_quietly(&self.options);
        self.rules_ui.reload(&self.options.data_dir);
    }

    /// Each frame: apply the first-launch rule once, then move the queued
    /// work (tool installs, rule packs, a VM being created) along.
    pub(super) fn getting_started_tick(&mut self) {
        let state = &self.getting_started;
        if !state.decided && state.snapshot_seen && !self.snapshot.bases_checking {
            self.getting_started.decided = true;
            if self
                .settings
                .getting_started
                .opens_on_launch(self.snapshot.vms.len(), self.snapshot.bases.len())
            {
                self.settings.getting_started.seen = true;
                self.open_getting_started();
            }
        }
        self.pump_tool_queue();
        self.pump_rule_queue();
        if let Some((started, before)) = self.getting_started.vm_pending {
            if self.snapshot.vms.len() > before {
                self.getting_started.vm_pending = None;
                self.settings.getting_started.unskip(Step::Vm);
            } else if started.elapsed() > VM_WAIT {
                self.getting_started.vm_pending = None;
                self.getting_started.vm_error =
                    Some("The VM was not created; the Activity panel has the reason".into());
            }
        }
    }

    /// Install the queued tools one after another.
    fn pump_tool_queue(&mut self) {
        if let Some(id) = &self.getting_started.tool_inflight {
            match &self.snapshot.tool_install {
                Some(install) if install.id == *id && install.finished => {}
                _ => return,
            }
            self.getting_started.tool_inflight = None;
        }
        while let Some(id) = self.getting_started.tool_queue.pop_front() {
            let missing = self
                .snapshot
                .analysis_tools
                .iter()
                .any(|tool| tool.id == id && !tool.available());
            if !missing {
                continue;
            }
            if let Err(error) = self.dependencies.require_dependencies(&[Dependency::Curl]) {
                self.getting_started.tool_error = Some(error);
                self.getting_started.tool_queue.clear();
            } else {
                // The dependency check above is the only reason a tool
                // install is refused; a lost backend ends the queue.
                self.send(Command::InstallTool { id: id.clone() });
                if self.backend_disconnected {
                    self.getting_started.tool_queue.clear();
                } else {
                    self.getting_started.tool_inflight = Some(id);
                }
            }
            break;
        }
    }

    /// Install the queued rule packs one after another, on the Rule manager's
    /// own worker.
    fn pump_rule_queue(&mut self) {
        if self.getting_started.rule_queue.is_empty() || self.rules_ui.is_busy() {
            return;
        }
        let outbound = self.settings.outbound_catalog;
        let Some(id) = self.getting_started.rule_queue.pop_front() else {
            return;
        };
        if !self
            .rules_ui
            .install_offer(&self.options.data_dir, outbound, &id)
        {
            self.getting_started.rule_queue.clear();
        }
    }

    pub(super) fn getting_started_facts(&self) -> Facts {
        use crate::rules_window::first_run::ENGINES;
        let ready = self.rules_ui.engines_with_packs();
        Facts {
            bases: self.snapshot.bases.len(),
            vms: self.snapshot.vms.len(),
            dependencies_ready: self
                .dependencies
                .report()
                .map(|report| !report.has_missing()),
            tools_total: self.snapshot.analysis_tools.len(),
            tools_missing: self
                .snapshot
                .analysis_tools
                .iter()
                .filter(|tool| !tool.available())
                .count(),
            rule_engines: self
                .rules_ui
                .is_loaded()
                .then(|| ENGINES.iter().filter(|(id, _)| ready.contains(*id)).count()),
        }
    }

    pub(super) fn getting_started_window(&mut self, ctx: &egui::Context) {
        if !self.getting_started.open {
            return;
        }
        let facts = self.getting_started_facts();
        let mut open = true;
        let mut go = None;
        let mut skip = false;
        let mut finish = false;
        egui::Window::new("Getting started")
            .id(Dialog::GettingStarted.window_id())
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_size([780.0, 560.0])
            .min_width(560.0)
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    for step in Step::ALL {
                        let status = walkthrough::status(step, &facts, &self.settings.getting_started);
                        let (glyph, color) = match status {
                            Status::Done => (egui_phosphor::regular::CHECK_CIRCLE, theme::good()),
                            Status::Skipped => (egui_phosphor::regular::MINUS_CIRCLE, theme::muted()),
                            Status::Pending => (egui_phosphor::regular::CIRCLE, theme::text()),
                        };
                        if ui
                            .selectable_label(
                                self.getting_started.step == step,
                                RichText::new(format!("{glyph} {}", step.title())).color(color),
                            )
                            .on_hover_text(status.word())
                            .clicked()
                        {
                            go = Some(step);
                        }
                    }
                });
                ui.separator();
                let height = (ctx.screen_rect().height() * 0.6).clamp(200.0, 520.0);
                egui::ScrollArea::vertical()
                    .id_salt("getting_started_step")
                    .max_height(height)
                    .auto_shrink([false, true])
                    .show(ui, |ui| self.getting_started_step(ui, &facts));
                dialog_footer(ui, |ui| {
                    let step = self.getting_started.step;
                    if ui.add_enabled(step != Step::Base, egui::Button::new("Back")).clicked() {
                        go = Some(step.previous());
                    }
                    if step == Step::Finish {
                        finish = ui.add(primary_button("Finish")).clicked();
                    } else {
                        if ui.add(primary_button("Next")).clicked() {
                            go = Some(step.next());
                        }
                        skip = ui
                            .button("Skip this step")
                            .on_hover_text("Skipped steps stay available here and in the summary")
                            .clicked();
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.checkbox(
                            &mut self.settings.getting_started.dont_show,
                            "Don't show again",
                        )
                        .on_hover_text("It opens by itself only on the first launch; Help > Getting started always reopens it");
                    });
                });
            });
        let step = self.getting_started.step;
        if skip {
            self.settings.getting_started.skip(step);
            go = Some(step.next());
        }
        if let Some(step) = go {
            self.getting_started.step = step;
        }
        if finish {
            self.settings.getting_started.finished = true;
            open = false;
        }
        self.settings.getting_started.step = self.getting_started.step.id().into();
        self.getting_started.open = open;
    }
}
