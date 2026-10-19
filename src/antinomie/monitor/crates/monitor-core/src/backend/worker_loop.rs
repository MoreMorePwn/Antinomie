// SPDX-License-Identifier: MIT
//! The worker loop: notifications, tool and catalog polling, base listing.
use super::*;

impl Worker {
    pub(super) fn refresh_locations(&mut self) -> Result<(), String> {
        self.snapshot.bases = crate::locations::installed_bases(&self.options)?;
        self.snapshot.vm_locations = self
            .snapshot
            .vms
            .iter()
            .map(|vm| crate::locations::locations(&self.options, &vm.id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }
    pub(super) fn emit(&mut self, notification: Notification) {
        if matches!(
            &notification,
            Notification::CommandResult { id, .. } if *id > 0
        ) {
            self.complete(notification);
            return;
        }
        if self.sender.try_send(notification).is_err() {
            self.snapshot.health.ui_dropped += 1;
        }
        if let Some(wake) = &self.wake {
            wake();
        }
    }
    fn complete(&mut self, notification: Notification) {
        // Every accepted command holds one admission credit until this result is
        // consumed. The result lane has one slot per credit, so Full is an
        // invariant violation; try_send keeps the sole owner nonblocking.
        match self.completion_sender.try_send(notification) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => self.fail_owner(),
            Err(mpsc::TrySendError::Disconnected(_)) => self.fail_owner(),
        }
        if let Some(wake) = &self.wake {
            wake();
        }
    }
    fn fail_owner(&mut self) {
        self.owner_failed.store(true, Ordering::Release);
        self.closing.store(true, Ordering::Release);
        self.stopping.store(true, Ordering::Release);
    }
    fn release_completion_credit(&mut self) {
        if !self.completion_credits.release() {
            self.fail_owner();
        }
    }
    fn cancel_command(&mut self, id: u64) {
        self.complete(Notification::CommandResult {
            id,
            success: false,
            message: "backend closed before command execution; outcome cancelled".into(),
        });
    }
    fn cancel_queued_commands(&mut self) {
        while let Ok((id, _, _command)) = self.receiver.try_recv() {
            self.cancel_command(id);
        }
    }
    pub(super) fn publish(&mut self) {
        if let Some(session) = &self.session {
            self.snapshot.events = session.history();
            session.update_runs(&mut self.snapshot);
            self.snapshot.process_cores = session
                .manual_cores
                .values()
                .map(|owner| owner.summary.clone())
                .collect();
            self.snapshot.capture_processes = session
                .captures
                .iter()
                .filter(|(_, capture)| capture.summary.state != CaptureState::Finalized)
                .map(|(id, capture)| (id.clone(), capture.processes.list()))
                .collect();
        }
        if let Ok(mut latest) = self.latest_snapshot.lock() {
            *latest = Some(self.snapshot.clone());
        }
        self.last_publish = Instant::now();
        if let Some(wake) = &self.wake {
            wake();
        }
    }
    /// Show the progress of the background flush of stopped boots, and report
    /// what failed when a job ends.
    pub(super) fn poll_flush(&mut self) {
        if let Some(deferred) = self.deferred_flush.take() {
            match self.flusher.spawn(deferred.boot_id.clone(), deferred.steps) {
                Ok(()) => {}
                Err(rejected) => {
                    self.snapshot.last_error =
                        Some(format!("recording flush deferred: {}", rejected.reason));
                    self.deferred_flush = Some(rejected);
                }
            }
        }
        if self.deferred_flush.is_none()
            && self.flusher.can_submit_retired()
            && let Some(session) = self.session.as_mut()
            && !session.flush_queue.is_empty()
        {
            let steps = std::mem::take(&mut session.flush_queue);
            match self.flusher.spawn(session.boot_id.clone(), steps) {
                Ok(()) => {}
                Err(mut rejected) => {
                    rejected.steps.append(&mut session.flush_queue);
                    session.flush_queue = rejected.steps;
                    self.snapshot.last_error = Some(format!(
                        "retired capture flush deferred: {}",
                        rejected.reason
                    ));
                }
            }
        }
        let errors = self.flusher.collect();
        let status = self.flusher.status();
        if !errors.is_empty() {
            self.snapshot.last_error = Some(format!("saving recordings: {}", errors.join("; ")));
        }
        if status != self.snapshot.recording_flush || !errors.is_empty() {
            self.snapshot.recording_flush = status;
            self.publish();
        }
    }
    /// Closing: wait for the background flush, showing its progress.
    fn finish_flush(&mut self) {
        while self.flusher.is_busy() || self.deferred_flush.is_some() {
            self.poll_flush();
            thread::sleep(Duration::from_millis(50));
        }
        self.poll_flush();
    }

    /// Submit finalizers for a sealed boot. The session-start admission check
    /// reserves capacity for this job; if that invariant is ever violated,
    /// retain the complete step list and retry on a later worker pass.
    pub(super) fn submit_sealed_flush(
        &mut self,
        boot_id: String,
        steps: Vec<crate::recording_flush::Step>,
    ) {
        if let Err(mut rejected) = self.flusher.spawn(boot_id, steps) {
            self.snapshot.last_error = Some(format!(
                "final recording flush deferred: {}",
                rejected.reason
            ));
            if let Some(mut pending) = self.deferred_flush.take() {
                pending.steps.append(&mut rejected.steps);
                pending
                    .reason
                    .push_str("; another sealed boot is queued behind it");
                self.deferred_flush = Some(pending);
            } else {
                self.deferred_flush = Some(rejected);
            }
        }
    }
    fn poll_tool(&mut self) {
        let Some(job) = self.tool.as_ref() else {
            return;
        };
        if let (Ok(progress), Some(status)) =
            (job.progress.lock(), self.snapshot.tool_install.as_mut())
        {
            status.stage = progress.0.clone();
            status.received = progress.1;
            status.total = progress.2;
        }
        let finished = match job.done.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => Some(Err("tool installer stopped".into())),
        };
        if let Some(result) = finished {
            self.tool = None;
            if let Some(status) = self.snapshot.tool_install.as_mut() {
                status.finished = true;
                status.stage = if result.is_ok() { "done" } else { "failed" }.into();
                status.error = result.err();
            }
            self.snapshot.analysis_tools = crate::analysis_tools::statuses(&self.options.data_dir);
            self.publish();
        }
    }
    pub(super) fn poll_remote(&mut self) {
        if let Some(receiver) = self.refresh.as_ref() {
            match receiver.try_recv() {
                Ok(result) => {
                    self.refresh = None;
                    self.snapshot.remote_refreshing = false;
                    match result {
                        Ok(catalog) => {
                            self.snapshot.remote_bases =
                                catalog.bases.iter().map(RemoteBase::from).collect();
                            self.catalog = catalog;
                            self.snapshot.remote_error = None;
                        }
                        Err(error) => self.snapshot.remote_error = Some(error),
                    }
                    self.publish();
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.refresh = None;
                    self.snapshot.remote_refreshing = false;
                    self.snapshot.remote_error = Some("catalog worker disconnected".into());
                    self.publish();
                }
            }
        }
        if let Some(job) = self.download.as_ref()
            && let (Ok(progress), Some(status)) =
                (job.progress.lock(), self.snapshot.download.as_mut())
        {
            status.received = progress.0;
            status.installing = progress.1;
        }
        let finished = self
            .download
            .as_ref()
            .and_then(|job| match job.done.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("download worker disconnected".into()))
                }
            });
        if let Some(result) = finished {
            let job = self.download.take().expect("download job present");
            let error = result.err();
            if job.thread.join().is_err() {
                self.snapshot.last_error = Some("download worker panicked".into());
            }
            // A cancel is the user's own action, not an error to flag.
            if let Some(error) = error.as_ref().filter(|e| !e.contains("cancelled")) {
                self.snapshot.last_error = Some(error.clone());
            }
            if let Err(error) = self.refresh_locations() {
                self.snapshot.last_error = Some(error);
            }
            let received = if error.is_none() {
                job.total
            } else {
                self.snapshot
                    .download
                    .as_ref()
                    .map(|status| status.received)
                    .unwrap_or(0)
            };
            self.snapshot.download = Some(DownloadStatus {
                identity: job.identity,
                label: job.label,
                received,
                total: job.total,
                installing: false,
                finished: true,
                error,
            });
            self.publish();
        }
    }
    fn poll_build(&mut self) {
        if let Some(job) = self.build.as_ref() {
            let stage = job
                .stage
                .lock()
                .map(|guard| guard.clone())
                .unwrap_or_default();
            let log: Vec<String> = job
                .log
                .lock()
                .map(|guard| guard.iter().cloned().collect())
                .unwrap_or_default();
            if let Some(status) = self.snapshot.build.as_mut() {
                status.stage = stage;
                status.log = log;
            }
        }
        let finished = self.build.as_ref().and_then(|job| {
            job.done.try_recv().ok().or_else(|| {
                if matches!(job.done.try_recv(), Err(mpsc::TryRecvError::Disconnected)) {
                    Some(Err("build worker disconnected".into()))
                } else {
                    None
                }
            })
        });
        if let Some(result) = finished {
            let job = self.build.take().expect("build job present");
            let error = result.err();
            if let Some(error) = &error {
                self.snapshot.last_error = Some(error.clone());
            }
            if let Err(error) = self.refresh_locations() {
                self.snapshot.last_error = Some(error);
            }
            if let Some(status) = self.snapshot.build.as_mut() {
                status.stage = "done".into();
                status.finished = true;
                status.error = error;
                let _ = job.label;
            }
            self.publish();
        }
    }
    /// List the installed bases, installing a configured bundle directory
    /// when there are none. A base is fully checked the first time only,
    /// which can take seconds, so this runs here and not before the UI.
    fn load_bases(&mut self) {
        let result = (|| -> Result<Vec<BaseSummary>, String> {
            let mut bases = crate::locations::installed_bases(&self.options)?;
            if bases.is_empty() && self.options.bundle_dir.join("bundle.json").is_file() {
                crate::locations::boot_bundle(&self.options, None)?;
                bases = crate::locations::installed_bases(&self.options)?;
            }
            Ok(bases)
        })();
        match result {
            Ok(bases) => self.snapshot.bases = bases,
            Err(error) => self.snapshot.last_error = Some(format!("base images: {error}")),
        }
        self.snapshot.bases_checking = false;
    }
    pub(super) fn run(mut self) {
        storage::mark_transport_thread();
        self.publish();
        self.sweep_disk_scratch();
        self.load_bases();
        for id in self
            .snapshot
            .vms
            .iter()
            .map(|vm| vm.id.clone())
            .collect::<Vec<_>>()
        {
            if let Err(error) = self.refresh_vm_snapshots(&id) {
                self.snapshot.last_error = Some(error);
            }
        }
        self.publish();
        loop {
            if self.closing.load(Ordering::Relaxed) {
                self.end_debug();
                self.cancel_queued_commands();
                if let Some(job) = self.download.as_ref() {
                    job.cancel.store(true, Ordering::Relaxed);
                }
                if let Some(job) = self.build.as_ref() {
                    job.cancel.store(true, Ordering::Relaxed);
                }
                self.finish_evidence_deletes();
                let result = self.stop();
                if let Err(e) = result {
                    self.snapshot.last_error = Some(e);
                }
                self.shutdown_disks();
                if let Some(job) = self.download.take()
                    && job.thread.join().is_err()
                {
                    self.snapshot.last_error = Some("download worker panicked".into());
                }
                self.publish();
                self.finish_flush();
                if let Err(error) = storage::flush_json() {
                    self.snapshot.last_error = Some(format!("saving status files: {error}"));
                    self.publish();
                }
                crate::writer::barrier();
                break;
            }
            // While telemetry is flowing, take waiting commands without
            // sleeping so the next drain pass follows at once.
            self.serve_debug_requests();
            // A debugger's round trips each wait for this loop: poll it closely.
            let mut received = if self
                .session
                .as_ref()
                .is_some_and(|session| session.telemetry_busy)
            {
                self.receiver.try_recv().map_err(|error| match error {
                    mpsc::TryRecvError::Empty => mpsc::RecvTimeoutError::Timeout,
                    mpsc::TryRecvError::Disconnected => mpsc::RecvTimeoutError::Disconnected,
                })
            } else if self.debug.is_active() {
                self.receiver.recv_timeout(Duration::from_millis(1))
            } else {
                self.receiver.recv_timeout(Duration::from_millis(10))
            };
            // Handle every queued command (up to a bound), not one per pass: a
            // busy guest makes each pass slow and the bounded queue would fill.
            // Repeated terminal reads of one run in a batch are answered once.
            let mut handled = 0;
            let mut terminal_reads =
                std::collections::BTreeMap::<String, Result<String, String>>::new();
            let mut disconnected = false;
            loop {
                match received {
                    Ok((id, epoch, command)) => {
                        if self.closing.load(Ordering::Acquire) {
                            self.cancel_command(id);
                            self.cancel_queued_commands();
                            handled += 1;
                            break;
                        }
                        // The deletion runs on its own thread, which answers the
                        // command when it is done; only a refusal answers here.
                        if let Command::DeleteEvidence {
                            vm_id,
                            item,
                            confirmed,
                        } = command
                        {
                            if let Err(message) =
                                self.start_evidence_delete(id, &vm_id, item, confirmed)
                            {
                                self.snapshot.last_error = Some(message.clone());
                                self.emit(Notification::CommandResult {
                                    id,
                                    success: false,
                                    message,
                                });
                            }
                            handled += 1;
                            if handled >= 64 {
                                break;
                            }
                            received = self.receiver.try_recv().map_err(|error| match error {
                                mpsc::TryRecvError::Empty => mpsc::RecvTimeoutError::Timeout,
                                mpsc::TryRecvError::Disconnected => {
                                    mpsc::RecvTimeoutError::Disconnected
                                }
                            });
                            continue;
                        }
                        let quiet = matches!(
                            command,
                            Command::TerminalRead { .. } | Command::TerminalResize { .. }
                        );
                        let terminal_read_run = match &command {
                            Command::TerminalRead { run_id } => Some(run_id.clone()),
                            _ => None,
                        };
                        let repeated = terminal_read_run
                            .as_ref()
                            .and_then(|run_id| terminal_reads.get(run_id).cloned());
                        let result = if let Some(repeated) = repeated {
                            repeated
                        } else {
                            let result = self.command_at_epoch(epoch, command);
                            if let Some(run_id) = terminal_read_run {
                                terminal_reads.insert(run_id, result.clone());
                            }
                            result
                        };
                        let success = result.is_ok();
                        let message = result.unwrap_or_else(|e| e);
                        if success {
                            self.snapshot.last_error = None;
                        } else {
                            self.snapshot.last_error = Some(message.clone());
                        }
                        if quiet && success {
                            self.release_completion_credit();
                        } else {
                            self.emit(Notification::CommandResult {
                                id,
                                success,
                                message,
                            });
                        }
                        handled += 1;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                }
                if handled >= 64 {
                    break;
                }
                received = self.receiver.try_recv().map_err(|error| match error {
                    mpsc::TryRecvError::Empty => mpsc::RecvTimeoutError::Timeout,
                    mpsc::TryRecvError::Disconnected => mpsc::RecvTimeoutError::Disconnected,
                });
            }
            if handled > 0 {
                self.publish();
            }
            if self.session.is_none() && self.debug.is_active() {
                self.end_debug();
            }
            if self.debug.is_active() {
                self.refresh_debug_info();
            }
            if self.closing.load(Ordering::Acquire) {
                continue;
            }
            if disconnected {
                self.closing.store(true, Ordering::Relaxed);
                continue;
            }
            let mut exited = false;
            let mut notice = None;
            if let Some(session) = self.session.as_mut() {
                match session.process.child.try_wait() {
                    Ok(Some(status)) => {
                        exited = true;
                        if !status.success() {
                            self.snapshot.last_error = Some(format!(
                                "QEMU exited {status}; log {}",
                                session.process.runtime_dir.join("qemu.log").display()
                            ));
                        }
                    }
                    // Waiting to reconnect: the transport would only fail again.
                    Ok(None) if self.reconnect.1.is_some() => {}
                    Ok(None) => {
                        if let Err(e) = session.pump(&mut self.snapshot, &self.sender) {
                            if stalled(&e) && self.reconnect.0 < RECONNECT_ATTEMPTS {
                                self.reconnect.1 = Some(Instant::now());
                                notice = Some(format!(
                                    "The guest stopped answering ({e}); reconnecting telemetry…"
                                ));
                            } else {
                                self.snapshot.last_error = Some(e);
                                self.snapshot.state = VmState::Failed;
                            }
                        }
                    }
                    Err(e) => {
                        self.snapshot.last_error = Some(e.to_string());
                        exited = true;
                    }
                }
            }
            if exited {
                // The boot is over; its reconnection attempts end with it.
                self.reconnect = (0, None);
            }
            if !exited
                && self.session.is_some()
                && self.reconnect.1.is_some_and(|at| Instant::now() >= at)
            {
                match self.reconnect_transport() {
                    Ok(message) => {
                        notice = Some(format!("The guest answers again. {message}"));
                        self.snapshot.last_error = None;
                        self.reconnect = (0, None);
                    }
                    Err(error) => {
                        let attempts = self.reconnect.0 + 1;
                        if attempts >= RECONNECT_ATTEMPTS || self.session.is_none() {
                            self.snapshot.last_error = Some(format!(
                                "the guest stopped answering and {attempts} reconnections \
                                 failed: {error}"
                            ));
                            self.snapshot.state = VmState::Failed;
                            self.reconnect = (attempts, None);
                        } else {
                            self.reconnect = (
                                attempts,
                                Some(Instant::now() + Duration::from_secs(1 << attempts)),
                            );
                        }
                    }
                }
                self.publish();
            }
            if let Some(message) = notice {
                // Shown in the status line and the Activity log, like a
                // command's result.
                self.emit(Notification::CommandResult {
                    id: 0,
                    success: true,
                    message,
                });
            }
            // While QEMU writes a memory dump the guest is paused: no guest
            // requests until it runs again.
            let paused = self.snapshot.memory_dump.is_some();
            if let Some(session) = self.session.as_mut().filter(|_| !exited && !paused) {
                if self.snapshot.state == VmState::Running {
                    session.poll_recorder_health(&mut self.snapshot);
                }
                if let Err(error) = session.query_run_status(&mut self.snapshot, &self.sender) {
                    self.snapshot.last_error = Some(error);
                }
                if let Err(error) = session.probe_kernel(&mut self.snapshot, &self.sender) {
                    self.snapshot.last_error = Some(format!("guest info: {error}"));
                }
                session.analysis_tick(&mut self.snapshot, &self.sender);
            }
            if exited {
                if let Some(mut session) = self.session.take() {
                    let steps = session.seal("unexpected-exit", &mut self.snapshot);
                    self.submit_sealed_flush(session.boot_id.clone(), steps);
                }
                if let Err(e) = end_network_capture(&mut self.snapshot) {
                    self.snapshot.last_error = Some(e);
                }
                abandon_memory_dump(&mut self.snapshot);
                self.snapshot.active_vm = None;
                self.snapshot.state = VmState::Stopped;
                self.snapshot.vm_resources = None;
                self.publish();
            }
            let paused = self.snapshot.memory_dump.is_some();
            let automatic_read = self
                .session
                .as_mut()
                .filter(|_| !paused)
                .and_then(|session| {
                    let active: Vec<_> = session
                        .runs
                        .values()
                        .filter(|run| !run.summary.terminal_eof)
                        .map(|run| run.summary.id.clone())
                        .collect();
                    if active.is_empty() {
                        None
                    } else {
                        let id = active[session.terminal_cursor % active.len()].clone();
                        session.terminal_cursor = session.terminal_cursor.wrapping_add(1);
                        Some(id)
                    }
                });
            if let Some(run_id) = automatic_read
                && let Some(session) = self.session.as_mut()
                && let Err(error) = session.read_terminal(
                    &run_id,
                    &mut self.snapshot,
                    &self.sender,
                    Duration::from_millis(100),
                )
            {
                self.snapshot.last_error = Some(error);
            }
            if let Some(job) = &mut self.keyboard {
                if self.snapshot.boot_id.as_ref() != Some(&job.boot_id)
                    || self.snapshot.state != VmState::Running
                {
                    job.cancel();
                }
                if let Some(result) = job.poll() {
                    self.keyboard = None;
                    let success = result.is_ok();
                    let message = result.unwrap_or_else(|error| error);
                    if !success {
                        self.snapshot.last_error = Some(message.clone());
                    }
                    self.emit(Notification::CommandResult {
                        id: 0,
                        success,
                        message,
                    });
                }
            }
            self.poll_remote();
            self.poll_build();
            self.poll_tool();
            self.check_network_capture();
            self.check_guest_resources();
            self.check_resources();
            self.check_process_cores();
            self.check_manual_cores();
            self.check_memory_dump();
            self.poll_disk_job();
            self.host_analysis_tick();
            self.check_run_artifacts();
            self.poll_flush();
            self.poll_evidence_deletes();
            if self.last_publish.elapsed() >= Duration::from_millis(250)
                && (self.session.is_some()
                    || self.refresh.is_some()
                    || self.download.is_some()
                    || self.build.is_some()
                    || self.tool.is_some()
                    || self.disk_job.is_some())
            {
                self.publish();
            }
        }
    }
}

pub(super) fn begin_base_install(
    progress: &Mutex<(u64, bool)>,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let mut progress = progress
        .lock()
        .map_err(|_| "download progress lock poisoned")?;
    if cancel.load(Ordering::Relaxed) {
        return Err("download cancelled".into());
    }
    progress.1 = true;
    Ok(())
}

/// A kernel named by app version for messages: "for Antinomie 0.2.0 (build
/// 0164…)", "for Antinomie 0.2.0, unversioned build", "for a newer
/// Antinomie" or "from before Antinomie 0.1.0". Revisions stay internal.
pub(super) fn describe_source((revision, source): (Option<u32>, Option<&str>)) -> String {
    let version = revision.and_then(crate::api::first_app_version);
    match (revision, version, source) {
        (None, _, _) => "from before Antinomie 0.1.0".into(),
        (Some(_), None, _) => "for a newer Antinomie".into(),
        (Some(_), Some(version), Some(source)) => {
            format!(
                "for Antinomie {version} (build {}…)",
                &source[..12.min(source.len())]
            )
        }
        (Some(_), Some(version), None) => format!("for Antinomie {version}, unversioned build"),
    }
}
