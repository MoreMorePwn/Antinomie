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
        let vm_snapshot_target = match &command {
            Command::RefreshVmSnapshots { vm_id }
            | Command::CreateVmSnapshot { vm_id, .. }
            | Command::RestoreVmSnapshot { vm_id, .. }
            | Command::RenameVmSnapshot { vm_id, .. }
            | Command::DeleteVmSnapshot { vm_id, .. } => Some(vm_id.clone()),
            _ => None,
        };
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
        let launch_request = match &command {
            Command::Execute(request) => Some(request.clone()),
            _ => None,
        };
        let bind_to_session = launch
            || observer
            || process_list
            || core_capture
            || sample
            || network
            || matches!(
                &command,
                Command::Upload { .. } | Command::UploadSample { .. } | Command::ReconnectTransport
            );
        let has_pending_binding = bind_to_session || vm_snapshot_target.is_some();
        if has_pending_binding && self.pending_sessions.len() >= PENDING_SESSION_LIMIT {
            self.status =
                "Too many pending VM operations; wait for existing requests to settle".into();
            return None;
        }
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
                        self.pending_launch_context = Some(PendingLaunch {
                            id,
                            vm_id: self.snapshot.active_vm.clone(),
                            boot_id: self.snapshot.boot_id.clone(),
                            request: launch_request.expect("Execute request captured"),
                            runs_before: self
                                .snapshot
                                .runs
                                .iter()
                                .map(|run| run.id.clone())
                                .collect(),
                            preview_run: None,
                        });
                    }
                    if bind_to_session {
                        self.pending_sessions.insert(
                            id,
                            PendingSession {
                                vm_id: self.snapshot.active_vm.clone(),
                                boot_id: self.snapshot.boot_id.clone(),
                                vm_only: false,
                            },
                        );
                    } else if let Some(vm_id) = vm_snapshot_target {
                        self.pending_sessions.insert(
                            id,
                            PendingSession {
                                vm_id: Some(vm_id),
                                boot_id: None,
                                vm_only: true,
                            },
                        );
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
        let launch_confirmed = self.pending_launch_context.as_ref().is_some_and(|pending| {
            snapshot.runs.iter().any(|run| {
                snapshot
                    .active_vm
                    .as_ref()
                    .is_none_or(|active_vm| active_vm == &run.vm_id)
                    && snapshot
                        .boot_id
                        .as_ref()
                        .is_none_or(|boot_id| boot_id == &run.boot_id)
                    && pending.vm_id.as_deref() == Some(run.vm_id.as_str())
                    && pending.boot_id.as_deref() == Some(run.boot_id.as_str())
                    && requests_match(&pending.request, &run.request)
                    && (pending.preview_run.as_deref() == Some(run.id.as_str())
                        || !pending.runs_before.contains(&run.id))
            })
        });
        if launch_confirmed {
            if let Some(pending) = self.pending_launch_context.as_ref() {
                self.pending_sessions.remove(&pending.id);
            }
            self.pending_launch = None;
            self.pending_launch_context = None;
        }
        self.reconcile_pending_sessions(&snapshot);
        if snapshot.state != self.snapshot.state {
            activity.push(("INFO", format!("Session {:?}", snapshot.state)));
        }
        if snapshot.last_error != self.snapshot.last_error {
            if let Some(error) = &snapshot.last_error {
                activity.push(("ERROR", error.clone()));
                self.error_status_mark = Some(self.status.clone());
            } else {
                self.error_status_mark = None;
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
        sync_runs(&mut self.terminals, &snapshot);
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
        let mut backend_lost = false;
        if let Some(backend) = &self.backend {
            while incoming.len() < 256 {
                match backend.try_recv_status() {
                    Ok(Some(notification)) => incoming.push(notification),
                    Ok(None) => break,
                    Err(_) => {
                        backend_lost = true;
                        break;
                    }
                };
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
                    if self.consume_stale_command_id(id) {
                        continue;
                    }
                    let launch_still_pending = success && self.pending_launch == Some(id);
                    if !launch_still_pending {
                        self.pending_sessions.remove(&id);
                    }
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
                    if !success
                        && self
                            .pending_launch_context
                            .as_ref()
                            .is_some_and(|pending| pending.id == id)
                    {
                        self.pending_launch_context = None;
                    }
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
                    self.accept_run_started(run, &mut activity);
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
        if !was_offline && self.trace_archive_directory().is_some() {
            self.request_page(0);
        }
        if backend_lost {
            self.resolve_backend_disconnect();
        }
        self.retire_unbound_launch();
        self.refresh_history_when_idle();
    }

    fn reconcile_pending_sessions(&mut self, snapshot: &Snapshot) {
        let mut changed = Vec::new();
        for (&id, session) in &mut self.pending_sessions {
            if session.vm_only {
                if !session
                    .vm_id
                    .as_ref()
                    .is_some_and(|vm_id| snapshot.vms.iter().any(|vm| &vm.id == vm_id))
                {
                    changed.push(id);
                }
                continue;
            }
            let vm_changed = session
                .vm_id
                .as_ref()
                .is_some_and(|vm_id| snapshot.active_vm.as_ref() != Some(vm_id));
            let boot_changed = session
                .boot_id
                .as_ref()
                .is_some_and(|boot_id| snapshot.boot_id.as_ref() != Some(boot_id));
            if vm_changed || boot_changed {
                changed.push(id);
            } else {
                if session.vm_id.is_none() {
                    session.vm_id = snapshot.active_vm.clone();
                }
                if session.boot_id.is_none() {
                    session.boot_id = snapshot.boot_id.clone();
                }
            }
        }
        for id in changed {
            self.retire_pending_command(id);
        }
    }

    /// A launch whose VM and boot were never recorded cannot be matched to a
    /// later session; once no VM runs, it can no longer start anything.
    fn retire_unbound_launch(&mut self) {
        let Some(id) = self.pending_launch else {
            return;
        };
        let unbound = !self.pending_sessions.contains_key(&id);
        if unbound && (self.snapshot.state != VmState::Running || self.snapshot.active_vm.is_none())
        {
            self.retire_pending_command(id);
        }
    }

    fn retire_pending_command(&mut self, id: u64) {
        self.pending_sessions.remove(&id);
        self.remember_stale_command_id(id);
        const UNKNOWN: &str = "Operation outcome unknown after the VM or boot session changed; no side effects were retried";
        self.vm_snapshots.complete(id, false, UNKNOWN);
        self.samples.cancel_pending(id, UNKNOWN);
        if self
            .pending_upload
            .as_ref()
            .is_some_and(|pending| pending.id == id)
        {
            self.pending_upload = None;
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
        if self.pending_launch == Some(id) {
            self.pending_launch = None;
            self.pending_launch_context = None;
        }
        for terminal in self.terminals.values_mut() {
            if terminal.snapshot_request == Some(id) {
                terminal.snapshot_request = None;
                terminal.snapshot_started = None;
                terminal.snapshot_error = Some(UNKNOWN.into());
            }
        }
        self.status = UNKNOWN.into();
        self.log("WARN", self.status.clone());
    }

    fn remember_stale_command_id(&mut self, id: u64) {
        if !self.stale_command_ids.contains(&id) {
            if self.stale_command_ids.len() == STALE_COMMAND_LIMIT {
                self.stale_command_ids.pop_front();
            }
            self.stale_command_ids.push_back(id);
        }
    }

    fn consume_stale_command_id(&mut self, id: u64) -> bool {
        if let Some(index) = self.stale_command_ids.iter().position(|stale| *stale == id) {
            self.stale_command_ids.remove(index);
            true
        } else {
            false
        }
    }

    pub(super) fn accept_run_started(
        &mut self,
        run: RunSummary,
        activity: &mut Vec<(&'static str, String)>,
    ) {
        if let Some(pending) = self.pending_launch_context.as_mut() {
            if pending.vm_id.as_deref() == Some(run.vm_id.as_str())
                && pending.boot_id.as_deref() == Some(run.boot_id.as_str())
                && requests_match(&pending.request, &run.request)
            {
                pending.preview_run = Some(run.id.clone());
            }
        }
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

    pub(super) fn resolve_backend_disconnect(&mut self) {
        if self.backend_disconnected {
            return;
        }
        self.backend_disconnected = true;
        self.stale_command_ids.clear();
        let message = "Backend disconnected; pending operation outcomes are unknown. No commands were retried.";
        self.vm_snapshots.pending = None;
        self.vm_snapshots.result = Some((false, message.into()));
        self.pending_upload = None;
        self.pending_launch = None;
        self.pending_launch_context = None;
        self.pending_sessions.clear();
        self.pending_observer = None;
        self.pending_core = None;
        self.pending_network = None;
        self.process_picker.pending = None;
        for terminal in self.terminals.values_mut() {
            if terminal.snapshot_request.take().is_some() {
                terminal.snapshot_started = None;
                terminal.snapshot_error = Some(message.into());
            }
        }
        self.samples.cancel_all_pending(message);
        self.status = message.into();
        self.log("ERROR", message.into());
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
                    if let Some(id) = terminal.snapshot_request.take() {
                        self.pending_sessions.remove(&id);
                        if !self.stale_command_ids.contains(&id) {
                            if self.stale_command_ids.len() == STALE_COMMAND_LIMIT {
                                self.stale_command_ids.pop_front();
                            }
                            self.stale_command_ids.push_back(id);
                        }
                    }
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
                    && self.pending_sessions.len() < PENDING_SESSION_LIMIT
                {
                    match backend.send(Command::TerminalSnapshot {
                        run_id: terminal.run.id.clone(),
                    }) {
                        Ok(id) => {
                            self.pending_sessions.insert(
                                id,
                                PendingSession {
                                    vm_id: self.snapshot.active_vm.clone(),
                                    boot_id: self.snapshot.boot_id.clone(),
                                    vm_only: false,
                                },
                            );
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

fn requests_match(left: &ExecRequest, right: &ExecRequest) -> bool {
    left.path == right.path
        && left.args == right.args
        && left.cwd == right.cwd
        && left.env == right.env
        && left.uid == right.uid
        && left.gid == right.gid
        && left.analysis == right.analysis
        && left.run_in == right.run_in
        && left.capture_network == right.capture_network
        && left.memory_dump_on_exit == right.memory_dump_on_exit
        && left.core_dump_on_exit == right.core_dump_on_exit
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
