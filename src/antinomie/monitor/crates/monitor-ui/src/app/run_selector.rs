// SPDX-License-Identifier: MIT
//! Program-run dropdown shared by the Triage and syscall trace views.
//!
//! Every view that offers the dropdown reads and writes `selected_run`, so a
//! choice made in one view (or in Run history) shows in all of them.
use super::*;

/// How one view presents the shared run dropdown.
pub(super) struct RunSelector {
    /// Distinct widget id; two views can be docked at the same time.
    pub(super) id_salt: &'static str,
    /// Entry that clears the selection (the live trace), if the view has one.
    pub(super) clear_label: Option<&'static str>,
    /// Text shown while the selection is not one of the listed runs.
    pub(super) empty_text: &'static str,
    /// Longest the closed dropdown may grow.
    pub(super) max_width: f32,
    pub(super) hover: &'static str,
}

impl MonitorApp {
    /// Program runs of the selected VM, newest first. These are listing
    /// copies without analysis rows (see `history::listed`); the dropdowns
    /// draw every frame. `selected_triage_run` returns the complete run.
    pub(super) fn triage_runs(&self) -> Vec<RunSummary> {
        let mut runs = BTreeMap::new();
        for run in self.snapshot.runs.iter().chain(&self.history) {
            if Some(&run.vm_id) == self.selected.as_ref() && run.root_task_cookie != 0 {
                runs.entry(run.id.clone())
                    .or_insert_with(|| super::history::listed(run));
            }
        }
        let mut runs: Vec<_> = runs.into_values().collect();
        runs.sort_by(|a, b| {
            b.started_ms
                .cmp(&a.started_ms)
                .then_with(|| b.id.cmp(&a.id))
        });
        runs
    }

    /// The complete selected run of the selected VM, analysis included.
    pub(super) fn selected_triage_run(&self) -> Option<RunSummary> {
        let id = self.selected_run.as_ref()?;
        self.snapshot
            .runs
            .iter()
            .chain(&self.history)
            .find(|run| {
                &run.id == id
                    && Some(&run.vm_id) == self.selected.as_ref()
                    && run.root_task_cookie != 0
            })
            .cloned()
    }

    /// Draws the dropdown over `runs`. A changed choice goes through
    /// `select_run`, so archive loading stays on the archive worker. Returns
    /// whether the selection changed.
    pub(super) fn show_run_selector(
        &mut self,
        ui: &mut egui::Ui,
        runs: &[RunSummary],
        view: &RunSelector,
    ) -> bool {
        let mut selected = self.selected_run.clone();
        let text = match runs.iter().find(|run| Some(&run.id) == selected.as_ref()) {
            Some(run) => run_selector_label(run),
            None => match (view.clear_label, &selected) {
                (Some(label), None) => label.into(),
                _ => view.empty_text.into(),
            },
        };
        egui::ComboBox::from_id_salt(view.id_salt)
            .selected_text(text)
            .width(ui.available_width().min(view.max_width))
            .show_ui(ui, |ui| {
                if let Some(label) = view.clear_label {
                    ui.selectable_value(&mut selected, None, label);
                }
                for run in runs {
                    ui.selectable_value(
                        &mut selected,
                        Some(run.id.clone()),
                        run_selector_label(run),
                    );
                }
            })
            .response
            .on_hover_text(view.hover);
        let changed = selected != self.selected_run;
        if changed {
            self.select_run(selected);
            self.capture_tab = false;
        }
        changed
    }

    /// The dropdown at the top of the syscall trace: the live trace, then the
    /// recorded runs. Hidden while the VM has no runs.
    pub(super) fn show_trace_run_selector(&mut self, ui: &mut egui::Ui) {
        let runs = self.triage_runs();
        if runs.is_empty() {
            return;
        }
        let view = RunSelector {
            id_salt: "trace-run-selector",
            clear_label: Some(if self.selected_capture.is_some() {
                "Observation capture"
            } else {
                "Live trace"
            }),
            empty_text: "Program run not listed",
            max_width: 420.0,
            hover: "Program run whose syscalls are shown. Live trace follows the running VM.",
        };
        self.show_run_selector(ui, &runs, &view);
    }
}

pub(super) fn run_selector_label(run: &RunSummary) -> String {
    format!(
        "{}  {}  [{}]",
        crate::time_format::unix_ms(run.started_ms),
        run.request.path,
        run.id.chars().take(8).collect::<String>()
    )
}
