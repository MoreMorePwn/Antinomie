// SPDX-License-Identifier: GPL-3.0-only
//! Run selection and evidence navigation for the native triage pane.
use super::run_selector::RunSelector;
use super::*;

impl MonitorApp {
    pub(super) fn show_triage(&mut self, ui: &mut egui::Ui) {
        let runs = self.triage_runs();
        let view = RunSelector {
            id_salt: "triage-run-selector",
            clear_label: None,
            empty_text: "Select a program run",
            max_width: 720.0,
            hover: "Network evidence is captured VM traffic during the selected run, without proven process ownership.",
        };
        self.show_run_selector(ui, &runs, &view);
        let Some(run) = self.selected_triage_run() else {
            self.triage
                .tick(ui.ctx(), crate::triage::TriageInput::empty());
            ui.weak("Choose a program run above or in Run history.");
            return;
        };
        let owned_pcap = self.owned_triage_pcap();
        if !run.request.capture_network {
            crate::activity::warning(
                ui,
                "Capture network was disabled for this run; network evidence may be unavailable.",
            );
        }
        if owned_pcap.is_none() {
            crate::activity::warning(ui, "No network capture is available for this run.");
        }
        crate::run_recording::show(ui, &run);
        if let Some(error) = &self.archive_error {
            crate::activity::warning(ui, error);
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
            current_boot: self.snapshot.active_vm.as_deref() == Some(run.vm_id.as_str())
                && self.snapshot.boot_id.as_deref() == Some(run.boot_id.as_str()),
        };
        self.triage.set_address_lookup(self.settings.address_lookup);
        self.configure_detection();
        self.triage
            .set_tools_dir(&antinomie_monitor_core::analysis_tools::tools_dir(
                &self.options.data_dir,
            ));
        self.triage.set_data_dir(&self.options.data_dir);
        self.triage.set_curl(&self.options.curl);
        if self.triage.take_rule_manager() {
            self.open_library(crate::workspace::LibraryPage::Rules);
        }
        if self.triage.take_open_datasets() {
            self.open_library(crate::workspace::LibraryPage::Rules);
            self.rules_ui.show_ioc();
        }
        let jump = self.triage.show(ui, input);
        self.settings.triage_detection = self.triage.detection_settings().clone();
        self.settings.triage_detection.rules_root.clear();
        if self.triage.take_details_focus(ui.ctx()) {
            self.details_follow.chose(&Panel::Triage);
            self.focus_panel = Some(Panel::Details);
        }
        if let Some(input) = self.triage.take_open_input(ui.ctx()) {
            self.open_scanned_input(input);
        }
        self.apply_triage_navigation(ui.ctx(), jump);
    }

    /// Opens a scanned input where it is viewed best.
    pub(super) fn open_scanned_input(&mut self, input: crate::triage::OpenInput) {
        use crate::triage::OpenInput;
        match input {
            OpenInput::StaticAnalysis => {
                self.selected_analysis = None;
                self.focus_panel = Some(Panel::StaticAnalysis);
            }
            OpenInput::Capture(path) => {
                self.network_view.open(Some(path));
                self.focus_panel = Some(Panel::Network);
            }
            OpenInput::Core(path) => {
                self.core_view.open(&path);
                self.focus_panel = Some(Panel::CoreDump);
            }
            OpenInput::Memory(directory) => {
                self.memory_view.open_dump(&directory);
                self.focus_panel = Some(Panel::Memory);
            }
            OpenInput::Folder(directory) => super::widgets::open_directory(&directory),
        }
    }

    pub(super) fn show_triage_details(&mut self, ui: &mut egui::Ui) {
        let jump = self.triage.details(ui);
        self.apply_triage_navigation(ui.ctx(), jump);
    }

    pub(super) fn apply_triage_navigation(
        &mut self,
        ctx: &egui::Context,
        jump: Option<trace::InvocationKey>,
    ) {
        if let Some(call_id) = jump {
            self.jump_triage_call(call_id);
        }
        if let Some(path) = self.triage.take_disk_jump(ctx) {
            if self.disk_view.reveal_diff(&path) {
                self.focus_panel = Some(Panel::Disks);
            }
        }
        if self.triage.take_open_packets() {
            if let Err(error) = self.open_triage_packets() {
                self.status = error.clone();
                self.log("ERROR", error);
            }
        }
        if let Some(filter) = self.triage.take_trace_scope() {
            self.scope_trace(filter);
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

    /// Open Packets: the run's own capture, no frame chosen.
    fn open_triage_packets(&mut self) -> Result<(), String> {
        let path = self.triage_packet_path(None)?;
        self.network_view.open(Some(path));
        self.focus_panel = Some(Panel::Network);
        Ok(())
    }

    fn jump_triage_packet_capture(
        &mut self,
        frame: u64,
        capture: Option<PathBuf>,
    ) -> Result<(), String> {
        let path = self.triage_packet_path(capture)?;
        self.network_view.open(Some(path));
        self.network_view.jump_to_evidence(frame)?;
        self.focus_panel = Some(Panel::Network);
        Ok(())
    }

    /// The capture a Triage packet request may open: the named one when this
    /// run owns it, else the run's own.
    fn triage_packet_path(&self, capture: Option<PathBuf>) -> Result<PathBuf, String> {
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
        Ok(path)
    }

    /// Show one process in Trace: the trace filter is set to `filter`.
    fn scope_trace(&mut self, filter: String) {
        self.selected_process = None;
        self.archive_selected = true;
        self.filter = filter;
        self.applied_filter.clone_from(&self.filter);
        self.reset_trace_selection();
        self.request_page(0);
        self.focus_trace();
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
