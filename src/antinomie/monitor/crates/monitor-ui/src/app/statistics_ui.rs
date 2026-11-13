// SPDX-License-Identifier: GPL-3.0-only
//! The Statistics window's place in the app: which run or capture it shows,
//! and what a click on a number does to the Syscall Trace (ANT-T0477).
use super::*;
use crate::statistics::{AppView, Facts, Navigate, Target};

impl MonitorApp {
    /// The run or capture the app has selected, as the window needs it.
    pub(super) fn statistics_target(&self) -> Option<Target> {
        if let Some(capture) = self.selected_capture_summary() {
            let state = format!("{:?}", capture.state);
            return Some(Target {
                id: capture.id.clone(),
                label: format!("capture {}", short_id(&capture.id)),
                vm: capture.vm_id.clone(),
                boot: capture.boot_id.clone(),
                directory: capture.directory.clone(),
                capture: true,
                root_cookie: 0,
                live: matches!(capture.state, CaptureState::Active | CaptureState::Unknown),
                facts: Facts::of_capture(capture, &state, &captures::scope(&capture.scope)),
            });
        }
        let run = self.selected_vm_run()?;
        let state = run_state_text::run_status(run);
        Some(Target {
            id: run.id.clone(),
            label: format!("run {}", short_id(&run.id)),
            vm: run.vm_id.clone(),
            boot: run.boot_id.clone(),
            directory: run.directory.clone(),
            capture: false,
            root_cookie: run.root_task_cookie,
            live: run.state.is_live(),
            facts: Facts::of_run(run, &state),
        })
    }

    /// Draw the Statistics window and do what its clicks ask. Called every frame.
    pub(super) fn show_statistics(&mut self, ctx: &egui::Context) {
        self.statistics.restore(
            self.settings.statistics_window,
            self.settings.statistics_popped,
        );
        let target = if self.statistics.open {
            self.statistics_target()
        } else {
            None
        };
        let hidden = self.settings.hidden_trace_categories.clone();
        let trace_filter = self.applied_filter.clone();
        let data_dir = self.options.data_dir.clone();
        let view = AppView {
            target,
            trace_filter: &trace_filter,
            hidden: &hidden,
            data_dir: &data_dir,
        };
        let asked = self.statistics.show(ctx, &view);
        if let Some((size, popped)) = self.statistics.take_saved() {
            self.settings.statistics_window = size;
            self.settings.statistics_popped = popped;
        }
        for navigate in asked {
            match navigate {
                Navigate::Filter(filter) => self.scope_trace(filter),
                Navigate::ShowGroup { group, filter } => {
                    self.settings
                        .hidden_trace_categories
                        .retain(|g| *g != group);
                    self.scope_trace(filter);
                }
                Navigate::Call(key) => self.jump_triage_call(key),
                Navigate::RunHistory => self.show_panel_asked(Panel::RunHistory),
            }
        }
    }
}

fn short_id(id: &str) -> &str {
    &id[..id.len().min(8)]
}
