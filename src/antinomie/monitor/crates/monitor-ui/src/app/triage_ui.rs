// SPDX-License-Identifier: MIT
//! Run selection and evidence navigation for the native triage pane.
use super::*;

impl MonitorApp {
    pub(super) fn triage_runs(&self) -> Vec<RunSummary> {
        let mut runs = BTreeMap::new();
        for run in self.snapshot.runs.iter().chain(&self.history) {
            if Some(&run.vm_id) == self.selected.as_ref() && run.root_task_cookie != 0 {
                runs.entry(run.id.clone()).or_insert_with(|| run.clone());
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

    pub(super) fn show_triage(&mut self, ui: &mut egui::Ui) {
        let runs = self.triage_runs();
        let mut selected = self.selected_run.clone();
        let label = runs
            .iter()
            .find(|run| Some(&run.id) == selected.as_ref())
            .map(triage_run_label)
            .unwrap_or_else(|| "Select a program run".into());
        egui::ComboBox::from_id_salt("triage-run-selector")
            .selected_text(label)
            .width(ui.available_width().min(720.0))
            .show_ui(ui, |ui| {
                for run in &runs {
                    ui.selectable_value(&mut selected, Some(run.id.clone()), triage_run_label(run));
                }
            }).response.on_hover_text("Network evidence is captured VM traffic during the selected run, without proven process ownership.");
        if selected != self.selected_run {
            self.select_run(selected);
            self.capture_tab = false;
        }
        let Some(run) = runs
            .into_iter()
            .find(|run| Some(&run.id) == self.selected_run.as_ref())
        else {
            self.triage
                .tick(ui.ctx(), crate::triage::TriageInput::empty());
            ui.weak("Choose a program run above or in Run history.");
            return;
        };
        let owned_pcap = self.owned_triage_pcap();
        if !run.request.capture_network {
            ui.colored_label(
                theme::warn(),
                "Capture network was disabled for this run; network evidence may be unavailable.",
            );
        }
        if owned_pcap.is_none() {
            ui.colored_label(
                theme::warn(),
                "No network capture is available for this run.",
            );
        }
        if let Some(error) = &run.recording_error {
            ui.colored_label(theme::warn(), format!("Recording incomplete: {error}"));
        }
        if let Some(error) = &self.archive_error {
            ui.colored_label(theme::warn(), error);
        }
        let live = self.invocations();
        // A loaded archive page can be from an observation capture or a query;
        // never let its process rows replace the selected run's full index.
        let invocations: Vec<_> = live
            .into_iter()
            .filter(|call| {
                crate::trace::representative(call)
                    .is_some_and(|event| event.root_task_cookie == run.root_task_cookie)
            })
            .collect();
        let input = crate::triage::TriageInput {
            analysis: run.analysis.as_ref(),
            invocations: &invocations,
            vm_id: Some(&run.vm_id),
            boot_id: Some(&run.boot_id),
            run_id: Some(&run.id),
            archive: Some(&run.directory),
            pcap: owned_pcap.as_ref().map(|owned| owned.0.as_path()),
            pcap_open: owned_pcap.as_ref().is_some_and(|owned| owned.1),
            clock_anchor: run.clock_anchor,
            started_ms: run.started_ms,
            root_cookie: run.root_task_cookie,
            run_finished: !self.live_history_run(&run),
            #[cfg(test)]
            packets: &[],
            #[cfg(test)]
            frames: None,
        };
        self.triage.set_address_lookup(self.settings.address_lookup);
        *self.triage.detection_settings() = self.settings.triage_detection.clone();
        self.triage.set_rules(
            &self.options.data_dir,
            self.settings.automatic_detection,
            &self.rules_summary,
            self.rules_generation,
        );
        if self.triage.take_rule_manager() {
            self.rules_open = true;
        }
        let jump = self.triage.show(ui, input);
        self.settings.triage_detection = self.triage.detection_settings().clone();
        self.settings.triage_detection.rules_root.clear();
        if self.triage.take_details_focus(ui.ctx()) {
            self.details_follow.chose(&Panel::Triage);
            self.focus_panel = Some(Panel::Details);
        }
        self.apply_triage_navigation(jump);
    }

    pub(super) fn show_triage_details(&mut self, ui: &mut egui::Ui) {
        let jump = self.triage.details(ui);
        self.apply_triage_navigation(jump);
    }

    fn apply_triage_navigation(&mut self, jump: Option<trace::InvocationKey>) {
        if let Some(call_id) = jump {
            self.jump_triage_call(call_id);
        }
        if let Some(frame_number) = self.triage.take_packet_jump() {
            let capture = self.triage.take_packet_capture();
            if let Err(error) = self.jump_triage_packet_capture(frame_number, capture) {
                self.status = error.clone();
                self.log("ERROR", error);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn jump_triage_packet(&mut self, frame: u64) -> Result<(), String> {
        self.jump_triage_packet_capture(frame, None)
    }

    fn jump_triage_packet_capture(
        &mut self,
        frame: u64,
        capture: Option<PathBuf>,
    ) -> Result<(), String> {
        let run = self
            .selected_run
            .as_deref()
            .and_then(|id| self.run(id))
            .ok_or("Select a program run first")?;
        if self.selected_capture.is_some()
            || self.selected.as_ref() != Some(&run.vm_id)
            || run.root_task_cookie == 0
        {
            return Err("Packet evidence requires one selected program run".into());
        }
        let path = if let Some(path) = capture {
            let owned = antinomie_monitor_core::RunArtifacts::load(&run.directory)?.is_some_and(
                |artifacts| {
                    artifacts.run_id == run.id
                        && artifacts.vm_id == run.vm_id
                        && artifacts.boot_id == run.boot_id
                        && artifacts.network_captures.contains(&path)
                },
            );
            let shared = self
                .owned_triage_pcap()
                .is_some_and(|capture| capture.0 == path);
            if !owned && !shared {
                return Err("The evidence packet is not owned by this run".into());
            }
            path
        } else {
            self.owned_triage_pcap()
                .ok_or("This run has no packet capture for the selected evidence")?
                .0
        };
        self.network_view.open(Some(path));
        self.network_view.jump_to_evidence(frame)?;
        self.focus_panel = Some(Panel::Network);
        Ok(())
    }

    pub(super) fn jump_triage_call(&mut self, key: trace::InvocationKey) {
        self.selected_process = None;
        self.archive_selected = true;
        self.filter = format!(
            "stream.id == {} && process.cookie == {} && call.id == {}",
            key.0, key.1, key.2
        );
        self.applied_filter.clone_from(&self.filter);
        self.reset_trace_selection();
        // Reveal exact evidence without overwriting saved category preferences.
        self.trace_evidence = Some(key);
        self.request_page(0);
        self.selected_event = Some(key);
        self.focus_trace();
    }
}

fn triage_run_label(run: &RunSummary) -> String {
    format!(
        "{}  {}  [{}]",
        crate::time_format::unix_ms(run.started_ms),
        run.request.path,
        run.id.chars().take(8).collect::<String>()
    )
}
