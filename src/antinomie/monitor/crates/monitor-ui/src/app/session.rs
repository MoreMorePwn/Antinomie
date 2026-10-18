// SPDX-License-Identifier: MIT
//! Backend commands and the notifications they produce.
use super::*;

impl MonitorApp {
    pub(super) fn send(&mut self, command: Command) {
        self.send_request(command);
    }

    /// Return the accepted request identity for workflows waiting on completion.
    pub(super) fn send_request(&mut self, command: Command) -> Option<u64> {
        let vm_snapshot = matches!(
            &command,
            Command::RefreshVmSnapshots { .. }
                | Command::CreateVmSnapshot { .. }
                | Command::RestoreVmSnapshot { .. }
                | Command::RenameVmSnapshot { .. }
                | Command::DeleteVmSnapshot { .. }
                | Command::ReconnectTransport
        );
        if let Err(error) = self
            .dependencies
            .require(&command, &self.options, &self.snapshot)
        {
            self.dependencies.open = true;
            if vm_snapshot {
                self.vm_snapshots.result = Some((false, error.clone()));
            }
            self.status = error.clone();
            self.log("ERROR", error);
            return None;
        }
        let launch = matches!(&command, Command::Execute(_));
        let observer = matches!(
            &command,
            Command::AttachProcess { .. } | Command::CaptureAll | Command::StopCapture { .. }
        );
        let process_list = matches!(&command, Command::ListProcesses { .. });
        let core_capture = matches!(&command, Command::DumpProcessCore { .. });
        let sample = matches!(&command, Command::UploadSample { .. });
        let network = matches!(
            &command,
            Command::StartNetworkCapture | Command::StopNetworkCapture
        );
        let admission = if launch {
            self.launch_admission()
        } else {
            Ok(())
        };
        if let Err(error) = admission {
            self.status = error.clone();
            self.log("ERROR", error);
            return None;
        }
        #[cfg(test)]
        if self.submitted.len() < 1024 {
            self.submitted.push(command.clone());
        }
        let mut failure = None;
        let mut accepted = None;
        if let Some(backend) = &self.backend {
            match backend.send(command) {
                Ok(id) => {
                    accepted = Some(id);
                    if vm_snapshot {
                        self.vm_snapshots.pending = Some(id);
                        self.vm_snapshots.result = None;
                    }
                    if observer {
                        self.pending_observer = Some(id);
                    }
                    if core_capture {
                        self.pending_core = Some(id);
                    }
                    if process_list {
                        self.process_picker.pending = Some(id);
                    }
                    if network {
                        self.pending_network = Some(id);
                    }
                    if launch {
                        self.pending_launch = Some(id);
                    }
                    if sample {
                        self.samples.sent(id);
                    }
                    self.status = "Request queued".into();
                }
                Err(error) => {
                    self.status = error.clone();
                    failure = Some(error);
                }
            }
        }
        if let Some(error) = failure {
            if vm_snapshot {
                self.vm_snapshots.result = Some((false, error.clone()));
            }
            self.log("ERROR", error);
        }
        #[cfg(test)]
        if self.backend.is_none() {
            accepted = Some(self.submitted.len() as u64);
        }
        accepted
    }

    /// Makes `snapshot` the current one, noting what changed for the Activity log.
    pub(super) fn accept_snapshot(
        &mut self,
        snapshot: Snapshot,
        activity: &mut Vec<(&'static str, String)>,
    ) {
        if snapshot.state != self.snapshot.state {
            activity.push(("INFO", format!("Session {:?}", snapshot.state)));
        }
        if snapshot.last_error != self.snapshot.last_error {
            if let Some(error) = &snapshot.last_error {
                activity.push(("ERROR", error.clone()));
            }
        }
        if snapshot.health.persistence_error != self.snapshot.health.persistence_error {
            if let Some(error) = &snapshot.health.persistence_error {
                activity.push(("ERROR", format!("Saving stopped: {error}")));
            }
        }
        if snapshot.health.ui_dropped > self.snapshot.health.ui_dropped {
            for terminal in self.terminals.values_mut() {
                terminal.dirty = true;
            }
        }
        let new_run = snapshot.runs.iter().any(|run| {
            run_in_live_session(&snapshot, run) && !self.terminals.contains_key(&run.id)
        });
        sync_runs(&mut self.terminals, &snapshot);
        if new_run {
            self.pending_launch = None;
        }
        if let Some(capture) = self
            .selected_capture_summary()
            .filter(|capture| {
                !snapshot
                    .captures
                    .iter()
                    .any(|current| current.id == capture.id)
            })
            .cloned()
        {
            if !self
                .capture_history
                .iter()
                .any(|saved| saved.id == capture.id)
            {
                if self.capture_history.len() >= CAPTURE_HISTORY_LIMIT {
                    self.capture_history.remove(0);
                }
                self.capture_history.push(capture);
            }
        }
        self.follow_runs(&snapshot);
        self.snapshot = snapshot;
    }

    pub(super) fn drain(&mut self) {
        if let Some((target, result)) = self.folder_picker.poll() {
            match result {
                Ok(Some(path)) => match target.kind {
                    FolderKind::BaseImport => {
                        self.import_directory = path.to_string_lossy().into_owned()
                    }
                    FolderKind::Disk if target.generation == self.draft_generation => {
                        self.draft.disk_root = Some(path)
                    }
                    FolderKind::Recording if target.generation == self.draft_generation => {
                        self.draft.recording_root = Some(path)
                    }
                    FolderKind::UploadFile => self.accept_upload_file(target.generation, path),
                    FolderKind::ExplorerRoot
                        if target.generation == self.explorer_browser.generation =>
                    {
                        self.settings.explorer_root = Some(path.clone());
                        self.settings.explorer_collapsed = false;
                        self.explorer_browser.reset(path);
                    }
                    _ => {}
                },
                Err(error) => {
                    self.status = format!("Host folder: {error}");
                    self.log("ERROR", self.status.clone());
                }
                _ => {}
            }
        }
        let mut activity = Vec::new();
        // A sample sent into the guest that is to run next.
        let mut launch_sample = None;
        let mut upload_result = None;
        let mut analysis_changed = false;
        let was_offline = self.trace_archive_directory().is_some();
        let mut incoming = Vec::new();
        if let Some(backend) = &self.backend {
            while incoming.len() < 256 {
                let Some(notification) = backend.try_recv() else {
                    break;
                };
                incoming.push(notification);
            }
        }
        for notification in incoming {
            match notification {
                Notification::Snapshot(snapshot) => {
                    self.accept_snapshot(snapshot, &mut activity);
                    analysis_changed = true;
                }
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    self.vm_snapshots.complete(id, success, &message);
                    if let Some(run) = self.samples.complete(id, success, &message) {
                        launch_sample = Some(run);
                    }
                    if self
                        .pending_upload
                        .as_ref()
                        .is_some_and(|upload| upload.id == id)
                    {
                        upload_result = Some((id, success));
                    }
                    if self.pending_observer == Some(id) {
                        self.pending_observer = None;
                    }
                    if self.pending_core == Some(id) {
                        self.pending_core = None;
                    }
                    if self.pending_network == Some(id) {
                        self.pending_network = None;
                    }
                    if self.process_picker.pending == Some(id) {
                        self.process_picker.pending = None;
                    }
                    for terminal in self.terminals.values_mut() {
                        if terminal.snapshot_request == Some(id) {
                            terminal.snapshot_request = None;
                            terminal.snapshot_started = None;
                            if !success {
                                terminal.snapshot_error = Some(message.clone());
                            }
                        }
                    }
                    resolve_launch_result(&mut self.pending_launch, id, success);
                    self.status = if success {
                        message
                    } else {
                        format!("Failed: {message}")
                    };
                    if !success || !self.status.starts_with("terminal input accepted") {
                        activity
                            .push((if success { "INFO" } else { "ERROR" }, self.status.clone()));
                    }
                }
                Notification::RunStarted(run) => {
                    self.pending_launch = None;
                    activity.push((
                        "INFO",
                        format!("Started {} (PID {})", run.request.path, run.pid),
                    ));
                    if let Some(current) = self
                        .snapshot
                        .runs
                        .iter_mut()
                        .find(|current| current.id == run.id)
                    {
                        *current = run;
                    } else {
                        self.snapshot.runs.push(run);
                    }
                    sync_runs(&mut self.terminals, &self.snapshot);
                }
                Notification::AnalysisUpdated { run_id, report } => {
                    if let Some(current) = self.analysis_windows.get_mut(&report.id) {
                        current.clone_from(&report);
                    }
                    if let Some(id) = run_id {
                        for run in self.snapshot.runs.iter_mut().chain(self.history.iter_mut()) {
                            if run.id == id {
                                run.analysis = Some(report.clone());
                            }
                        }
                    } else if let Some(current) = self
                        .snapshot
                        .analysis_reports
                        .iter_mut()
                        .find(|current| current.id == report.id)
                    {
                        *current = report;
                    } else {
                        if self.snapshot.analysis_reports.len() >= 8 {
                            self.snapshot.analysis_reports.remove(0);
                        }
                        self.selected_analysis = Some(report.id.clone());
                        self.snapshot.analysis_reports.push(report);
                    }
                }
                Notification::Terminal {
                    run_id,
                    sequence,
                    data,
                    eof,
                } => {
                    if let Some(terminal) = self.terminals.get_mut(&run_id) {
                        terminal.output(sequence, &data, eof);
                    }
                }
                Notification::TerminalScreen {
                    run_id,
                    sequence,
                    rows,
                    cols,
                    data,
                } => {
                    if let Some(terminal) = self.terminals.get_mut(&run_id) {
                        terminal.screen(sequence, rows, cols, &data);
                    }
                }
            }
        }
        if analysis_changed {
            self.refresh_analysis_windows();
        }
        if let Some(gone) = self
            .selected
            .clone()
            .filter(|id| !self.snapshot.vms.iter().any(|vm| &vm.id == id))
        {
            self.selected = None;
            self.forget_deleted_vm(&gone);
        }
        if self.selected.is_none() {
            self.selected = self.snapshot.vms.first().map(|vm| vm.id.clone());
            self.refresh_history();
        }
        for (level, message) in activity {
            self.log(level, message);
        }
        if let Some(run) = launch_sample {
            self.launch_sample(run);
        }
        if let Some((id, success)) = upload_result {
            self.complete_upload(id, success);
        }
        if self
            .pending_upload
            .as_ref()
            .is_some_and(|upload| !upload.intent.same_session(&self.snapshot))
        {
            self.pending_upload = None;
        }
        if !was_offline && self.trace_archive_directory().is_some() {
            self.request_page(0);
        }
        self.refresh_history_when_idle();
    }

    pub(super) fn running(&self) -> bool {
        self.snapshot.state == VmState::Running && self.snapshot.active_vm == self.selected
    }

    pub(super) fn resync_terminals(&mut self) {
        if let Some(backend) = &self.backend {
            for terminal in self.terminals.values_mut() {
                if terminal
                    .snapshot_started
                    .is_some_and(|started| started.elapsed() > Duration::from_secs(5))
                {
                    terminal.snapshot_request = None;
                    terminal.snapshot_started = None;
                    terminal.snapshot_error =
                        Some("Terminal screen reply timed out; reopen to retry".into());
                    self.status =
                        format!("Terminal screen reply timed out for {}", terminal.run.id);
                }
                if terminal.dirty
                    && terminal.snapshot_request.is_none()
                    && terminal.snapshot_error.is_none()
                    && run_in_live_session(&self.snapshot, &terminal.run)
                {
                    match backend.send(Command::TerminalSnapshot {
                        run_id: terminal.run.id.clone(),
                    }) {
                        Ok(id) => {
                            terminal.snapshot_request = Some(id);
                            terminal.snapshot_started = Some(Instant::now());
                        }
                        Err(error) => {
                            terminal.snapshot_error = Some(error.clone());
                            self.status = format!("Terminal resync: {error}");
                        }
                    }
                }
            }
        }
    }

    pub(super) fn update_options(&mut self) {
        self.options.bundle_dir = crate::folders::user_path(&self.settings.bundle);
        self.send(Command::UpdateOptions {
            bundle_dir: crate::folders::user_path(&self.settings.bundle),
            capture_quota_size: u64::from(self.settings.quota_gib) * 1073741824,
            shutdown_timeout_secs: self.settings.timeout,
        });
    }
}

pub(super) fn resolve_launch_result(pending: &mut Option<u64>, id: u64, success: bool) {
    // Success retains the reserved view until RunStarted or the snapshot supplies its run.
    if !success && *pending == Some(id) {
        *pending = None;
    }
}

pub(super) fn sync_runs(terminals: &mut BTreeMap<String, RunTerminal>, snapshot: &Snapshot) {
    for run in &snapshot.runs {
        if let Some(terminal) = terminals.get_mut(&run.id) {
            terminal.run = run.clone();
        } else if run_in_live_session(snapshot, run) {
            if terminals.len() >= TERMINAL_VIEW_LIMIT {
                let reclaim = terminals
                    .iter()
                    .find(|(_, terminal)| {
                        !terminal.open && !run_in_live_session(snapshot, &terminal.run)
                    })
                    .map(|(id, _)| id.clone());
                if let Some(id) = reclaim {
                    terminals.remove(&id);
                }
            }
            if terminals.len() < TERMINAL_VIEW_LIMIT {
                let mut terminal = RunTerminal::new(run.clone());
                terminal.dirty = true;
                terminals.insert(run.id.clone(), terminal);
            }
        }
    }
    for terminal in terminals.values_mut() {
        if terminal.dirty && !run_in_live_session(snapshot, &terminal.run) {
            terminal.begin_replay();
        }
    }
}
