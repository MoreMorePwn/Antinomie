// SPDX-License-Identifier: MIT
//! Runs, captures and analyses tracked by the session.
use super::*;

const MAX_RETIRED_FLUSH_STEPS: usize = 64;

impl Session {
    pub(super) fn run_cookie(&self, id: &str) -> Result<u64, String> {
        self.runs
            .iter()
            .find(|(_, run)| run.summary.id == id)
            .map(|(cookie, _)| *cookie)
            .ok_or_else(|| "unknown run in this VM boot".into())
    }
    pub(super) fn update_runs(&self, snapshot: &mut Snapshot) {
        snapshot.runs = self.runs.values().map(|run| run.summary.clone()).collect();
    }
    pub(super) fn update_captures(&self, snapshot: &mut Snapshot) {
        snapshot.captures = self
            .captures
            .values()
            .map(|capture| capture.summary.clone())
            .collect();
        snapshot.capture_events.clear();
        let preview = self
            .captures
            .values()
            .find(|capture| capture.summary.state == CaptureState::Active)
            .or_else(|| {
                self.captures
                    .values()
                    .max_by_key(|capture| capture.summary.start_ns.unwrap_or(0))
            });
        if let Some(capture) = preview {
            snapshot.capture_events.insert(
                capture.summary.id.clone(),
                bounded_live_history(capture.assembler.recent(LIVE_HISTORY)),
            );
        }
    }
    pub(super) fn start_capture(
        &mut self,
        options: &BackendOptions,
        scope: CaptureScope,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<String, String> {
        if self.pending_capture_id.is_some() {
            return Err("an earlier capture start has an unknown outcome; restart the VM before another start".into());
        }
        if self
            .captures
            .values()
            .any(|capture| capture.summary.state == CaptureState::Active)
        {
            return Err("stop the active capture before starting another".into());
        }
        let revision = self
            .capture
            .guest_kernel
            .as_ref()
            .and_then(|kernel| kernel.revision)
            .unwrap_or(0);
        if revision < UNLIMITED_CAPTURE_REVISION && self.captures.len() >= OBSERVATION_MAX_COUNT {
            return Err(format!(
                "this base allows {OBSERVATION_MAX_COUNT} captures per VM boot; restart the VM, or use a base for Antinomie 0.2.0 or newer, which has no limit"
            ));
        }
        let retire_needed = self
            .captures
            .len()
            .saturating_sub(OBSERVATION_RETAINED.saturating_sub(1))
            .min(
                self.captures
                    .values()
                    .filter(|capture| capture.summary.state == CaptureState::Stopped)
                    .count(),
            );
        if self.flush_queue.len().saturating_add(retire_needed) > MAX_RETIRED_FLUSH_STEPS {
            return Err(
                "recording finalization queue is full; wait for saved captures before starting another".into(),
            );
        }
        self.retire_captures(snapshot);
        let (opcode, args) = match &scope {
            CaptureScope::Process { root } => {
                if root.boot_id != self.boot_id {
                    return Err(
                        "selected process belongs to a different VM boot; refresh processes".into(),
                    );
                }
                (control::CAPTURE_ATTACH, control::attach_process(root)?)
            }
            CaptureScope::AllUserspace => (control::CAPTURE_ALL, control::header(0)),
        };
        let id = storage::unique_id();
        let summary = CaptureSummary {
            started_ms: None,
            id: id.clone(), vm_id: self.vm.id.clone(), boot_id: self.boot_id.clone(),
            capture_cookie: 0, scope,
            directory: crate::locations::locations(options, &self.vm.id)?.recording_directory.join("captures").join(&id),
            state: CaptureState::Unknown, recording_error: None, start_ns: None, stop_ns: None,
            incomplete_reason: Some("start not acknowledged; capture begins with new admissions only and delivery may be incomplete".into()),
        };
        let mut capture = CaptureSession::new(summary, self.capture.quota())?;
        capture
            .assembler
            .set_event_table(self.vm.transport.event_table as usize);
        if let Some(error) = self.capture.error.clone() {
            capture.storage_error(error);
        }
        self.captures.insert(id.clone(), capture);
        self.pending_capture_id = Some(id.clone());
        self.update_captures(snapshot);
        let request = match self.transport.send(opcode, &args) {
            Ok(request) => request,
            Err(error) => {
                self.pending_capture_id = None;
                if let Some(mut capture) = self.captures.remove(&id) {
                    capture.summary.state = CaptureState::Finalized;
                    capture.summary.incomplete_reason =
                        Some(format!("start was not submitted: {error}"));
                    capture.persist_summary()?;
                }
                self.update_captures(snapshot);
                return Err(error);
            }
        };
        let result = self.wait_reply(request, opcode, snapshot, sender, Duration::from_secs(10));
        if let Err(RequestError::Rejected { message: error, .. }) = &result {
            self.pending_capture_id = None;
            if let Some(mut capture) = self.captures.remove(&id) {
                capture.summary.state = CaptureState::Finalized;
                capture.summary.incomplete_reason =
                    Some(format!("guest rejected capture start: {error}"));
                capture.persist_summary()?;
            }
            self.update_captures(snapshot);
            return Err(error.clone());
        }
        let result = result
            .map_err(RequestError::into_message)
            .and_then(|reply| control::capture_started(&reply));
        match result {
            Ok((cookie, stream)) => {
                if self.captures.iter().any(|(other_id, capture)| {
                    other_id != &id && capture.summary.capture_cookie == cookie
                }) {
                    return Err("capture acknowledgement reused an existing identity; start outcome unknown".into());
                }
                let capture = self
                    .captures
                    .get_mut(&id)
                    .ok_or("missing provisional capture")?;
                if let Err(error) = capture.observe_identity(cookie, stream) {
                    capture.summary.incomplete_reason = Some("capture reply conflicts with pre-acknowledgement telemetry; outcome unknown".into());
                    capture.persist_summary()?;
                    self.update_captures(snapshot);
                    return Err(format!("{error}; outcome unknown"));
                }
                capture.summary.capture_cookie = cookie;
                capture.summary.state = CaptureState::Active;
                capture.summary.incomplete_reason = Some("capture includes new admissions only; transport loss and unresolved observations may leave gaps".into());
                capture.persist_summary()?;
                self.pending_capture_id = None;
                // Read-only status adds the guest admission timestamp. It never
                // retries a start whose side effects might already have occurred.
                if let Ok(reply) = self.request(
                    control::CAPTURE_STATUS,
                    &control::with_session(cookie),
                    snapshot,
                    sender,
                    Duration::from_millis(500),
                ) && let Ok(status) = control::capture_status(&reply, cookie)
                {
                    self.apply_capture_status(&id, status)?;
                }
                self.update_captures(snapshot);
                Ok("capture started; stopping capture will leave programs running".into())
            }
            Err(error) => {
                if let Some(capture) = self.captures.get_mut(&id) {
                    capture.summary.incomplete_reason = Some(format!(
                        "capture start acknowledgement failed: {error}; admission outcome unknown; no automatic retry"
                    ));
                    capture.persist_summary()?;
                }
                self.update_captures(snapshot);
                Err(format!(
                    "{error}; capture start outcome unknown; no automatic retry"
                ))
            }
        }
    }
    /// Keep at most `OBSERVATION_RETAINED` capture archives open: close the
    /// oldest stopped ones, whose late tails then stay in canonical history
    /// only. Active or unacknowledged captures are never closed here.
    fn retire_captures(&mut self, snapshot: &mut Snapshot) {
        while self.captures.len() >= OBSERVATION_RETAINED {
            let Some(id) = self
                .captures
                .iter()
                .filter(|(_, capture)| capture.summary.state == CaptureState::Stopped)
                .min_by_key(|(id, capture)| (capture.summary.capture_cookie, (*id).clone()))
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            if let Some(mut capture) = self.captures.remove(&id) {
                let note = format!(
                    "archive closed after {OBSERVATION_RETAINED} newer captures in this boot; later tails are kept in the VM history only"
                );
                capture.summary.incomplete_reason =
                    Some(match capture.summary.incomplete_reason.take() {
                        Some(reason) => format!("{reason}; {note}"),
                        None => note,
                    });
                // The archive's disk work goes to a flush job (see `seal`).
                capture.begin_finalize();
                let health = snapshot.health.clone();
                self.flush_queue.push((
                    format!("capture {}", id.chars().take(8).collect::<String>()),
                    Box::new(move || capture.complete_finalize(&health)),
                ));
            }
        }
    }
    pub(super) fn apply_capture_status(
        &mut self,
        id: &str,
        status: control::CaptureStatus,
    ) -> Result<(), String> {
        let capture = self
            .captures
            .get_mut(id)
            .ok_or("unknown capture in this VM boot")?;
        let mode = match capture.summary.scope {
            CaptureScope::Process { .. } => 1,
            CaptureScope::AllUserspace => 2,
        };
        if status.cookie == 0
            || status.mode != mode
            || (capture.summary.capture_cookie != 0
                && capture.summary.capture_cookie != status.cookie)
        {
            return Err("capture status does not match archive identity or scope".into());
        }
        capture.summary.capture_cookie = status.cookie;
        capture.summary.state = if status.active {
            CaptureState::Active
        } else {
            CaptureState::Stopped
        };
        capture.summary.start_ns = Some(status.start_ns);
        capture.summary.stop_ns = (!status.active).then_some(status.stop_ns);
        capture.summary.incomplete_reason = Some(if status.active {
            "capture includes new admissions only; losses and unresolved observations may leave gaps"
        } else {
            "admission stopped; already admitted observations may publish late tails until VM finalization"
        }.into());
        capture.persist_summary()?;
        if self.pending_capture_id.as_deref() == Some(id) {
            self.pending_capture_id = None;
        }
        Ok(())
    }
    pub(super) fn analysis_updates(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) {
        for (run_id, report) in self.analysis.updates() {
            if let Some(id) = &run_id {
                if let Some(run) = self.runs.values_mut().find(|r| &r.summary.id == id) {
                    run.summary.analysis = Some(report.clone());
                    if let Err(error) = run.refresh_analysis_metadata() {
                        run.storage_error(format!("analysis metadata accounting: {error}"));
                    }
                    if let Err(error) = run.persist_summary() {
                        run.storage_error(format!("analysis metadata persistence: {error}"));
                    }
                }
            } else {
                if let Some(existing) = snapshot
                    .analysis_reports
                    .iter_mut()
                    .find(|r| r.id == report.id)
                {
                    *existing = report.clone();
                } else {
                    if snapshot.analysis_reports.len() == 8 {
                        snapshot.analysis_reports.remove(0);
                    }
                    snapshot.analysis_reports.push(report.clone());
                }
            }
            let _ = sender.try_send(Notification::AnalysisUpdated { run_id, report });
        }
        self.update_runs(snapshot);
    }
    pub(super) fn analysis_tick(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) {
        match self.analysis.next() {
            Some(crate::analysis::jobs::Action::Read {
                id,
                offset,
                total,
                capacity,
            }) => {
                let result = self.request(
                    control::SPECIMEN_READ,
                    &control::specimen_read(id, offset, capacity),
                    snapshot,
                    sender,
                    Duration::from_millis(100),
                );
                self.analysis.chunk(result, offset, total, capacity);
            }
            Some(crate::analysis::jobs::Action::Release(id)) => {
                if let Err(error) = self.request(
                    control::SPECIMEN_RELEASE,
                    &control::with_session(id),
                    snapshot,
                    sender,
                    Duration::from_millis(100),
                ) {
                    snapshot.last_error = Some(format!(
                        "specimen release failed; guest expiry must reclaim handle {id}: {error}"
                    ));
                }
            }
            None => {}
        }
        self.analysis_updates(snapshot, sender);
    }
    /// Every guest process from `after_pid` on, read page by page and
    /// bounded so a fork storm cannot keep the enumeration going.
    pub(super) fn list_processes(
        &mut self,
        after_pid: u32,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
        timeout: Duration,
    ) -> Result<crate::GuestProcessPage, String> {
        /// Processes listed at most, across pages.
        const PROCESS_LIST_MAX: usize = 4096;
        let mut page: Option<crate::GuestProcessPage> = None;
        let mut next = after_pid;
        loop {
            let reply = self.request(
                control::PROCESS_LIST,
                &control::process_list(next),
                snapshot,
                sender,
                timeout,
            )?;
            let part = control::process_page(&reply, &self.boot_id, next)?;
            next = part.next_pid;
            match page.as_mut() {
                None => page = Some(part),
                Some(page) => {
                    page.next_pid = part.next_pid;
                    page.processes.extend(part.processes);
                }
            }
            if next == 0
                || page
                    .as_ref()
                    .is_some_and(|page| page.processes.len() >= PROCESS_LIST_MAX)
            {
                return page.ok_or_else(|| "empty process list".into());
            }
        }
    }
    pub(super) fn query_run_status(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        if self.run_status_poll.pending.is_some() {
            // Do not grow an unbounded collection of abandoned request IDs. A lost
            // reply leaves status unknown until it arrives or the session recovers.
            return self.drain_replies(snapshot, sender);
        }
        if self.runs.is_empty() || self.last_status_query.elapsed() < Duration::from_millis(100) {
            return Ok(());
        }
        self.last_status_query = Instant::now();
        let cookie = *self
            .runs
            .keys()
            .nth(self.status_cursor % self.runs.len())
            .ok_or("missing run status owner")?;
        self.status_cursor = self.status_cursor.wrapping_add(1);
        let run = self.runs.get(&cookie).ok_or("missing run status owner")?;
        let owner = RunStatusOwner {
            cookie,
            run_id: run.summary.id.clone(),
            generation: run.execution_generation,
        };
        let result = match self
            .transport
            .send(control::RUN_STATUS, &control::with_session(cookie))
        {
            Ok(id) => match self.wait_reply(
                id,
                control::RUN_STATUS,
                snapshot,
                sender,
                Duration::from_millis(100),
            ) {
                Err(RequestError::TimedOut(error)) => {
                    let error = format!(
                        "{error}; run status polling paused until its reply arrives or transport reconnects"
                    );
                    self.run_status_poll
                        .timed_out(id, owner.clone(), error.clone());
                    Err(error)
                }
                result => result.map_err(RequestError::into_message),
            },
            Err(error) => Err(error),
        };
        let result =
            result.and_then(|reply| crate::execution::decode(&reply, cookie, owner.generation));
        match result {
            Ok(execution) => self.apply_run_status(&owner, execution, snapshot),
            Err(error) => {
                let run = self
                    .runs
                    .get_mut(&cookie)
                    .ok_or("missing run status owner")?;
                if !owner.matches(run) {
                    return Err("run status owner or execution generation changed".into());
                }
                let changed = run.summary.execution.take().is_some()
                    || run.summary.state != RunState::Unknown;
                run.summary.state = RunState::Unknown;
                if changed {
                    run.persist_summary()?;
                }
                Err(error)
            }
        }
    }

    pub(super) fn apply_run_status(
        &mut self,
        owner: &RunStatusOwner,
        execution: RunExecution,
        snapshot: &mut Snapshot,
    ) -> Result<(), String> {
        let run = self
            .runs
            .get_mut(&owner.cookie)
            .ok_or("missing run status owner")?;
        if !owner.matches(run) {
            return Err("run status owner or execution generation changed".into());
        }
        if run.summary.execution.as_ref() != Some(&execution) {
            run.execution_generation = execution.generation;
            run.summary.state = crate::execution::state(&execution);
            run.summary.execution = Some(execution);
            run.record_async_loss();
            run.record_tree_completion();
            run.persist_summary()?;
        }
        self.run_status_poll
            .recovered(owner.cookie, &owner.run_id, &mut snapshot.last_error);
        Ok(())
    }
    /// A run whose program tree ended and whose terminal is closed expects no
    /// more telemetry: its event table is dropped, so memory does not grow
    /// with every run of the boot and the live history skips it. Its archive
    /// on disk is complete and is what views read.
    pub(super) fn release_completed_runs(&mut self) {
        for run in self.runs.values_mut() {
            if run.recording_complete() && run.assembler.holds_tables() {
                run.assembler.release_tables();
            }
        }
    }
    pub(super) fn history(&self) -> Vec<EventSummary> {
        canonical_live_history(
            self.assembler.recent(LIVE_HISTORY),
            self.runs
                .values()
                .map(|run| run.assembler.recent(LIVE_HISTORY)),
        )
    }
}

pub(super) fn bounded_live_history(mut events: Vec<EventSummary>) -> Vec<EventSummary> {
    events.sort_by_key(|event| event.timestamp_ns);
    if events.len() > LIVE_HISTORY {
        events.drain(..events.len() - LIVE_HISTORY);
    }
    events
}

pub(super) fn canonical_live_history(
    boot: Vec<EventSummary>,
    runs: impl IntoIterator<Item = Vec<EventSummary>>,
) -> Vec<EventSummary> {
    // Pre-acknowledgement packets remain in the boot archive after assignment;
    // the run copy supplies the artifact paths when both summaries are present.
    let mut unique = BTreeMap::new();
    for event in boot.into_iter().chain(runs.into_iter().flatten()) {
        unique.insert(
            (
                event.stream_id,
                event.task_cookie,
                event.call_id,
                event.event_seq,
                event.phase,
            ),
            event,
        );
    }
    bounded_live_history(unique.into_values().collect())
}
