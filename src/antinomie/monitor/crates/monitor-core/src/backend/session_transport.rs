// SPDX-License-Identifier: MIT
//! Telemetry pumping, load shedding, control requests and terminal output.
use super::*;

impl Session {
    pub(super) fn pump(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        self.transport.poll(0)?;
        // Drain until the guest's rings are empty: they hold only milliseconds
        // of busy telemetry. A time budget still returns control to command
        // handling under continuous telemetry.
        let started = Instant::now();
        self.pre_ack.expire(started);
        let mut drained = 0usize;
        while started.elapsed() < PUMP_BUDGET {
            let Some(packet) = self.transport.read()?.map(<[u8]>::to_vec) else {
                break;
            };
            drained += 1;
            snapshot.health.received_packets = snapshot.health.received_packets.saturating_add(1);
            let header = crate::parser::parse_packet(&packet)
                .ok()
                .map(|(header, _)| header);
            let root = header.as_ref().map_or(0, |header| header.root_task_cookie);
            let capture_cookie = header.as_ref().map_or(0, |header| header.capture_cookie);
            let observer_id = self
                .captures
                .iter()
                .find(|(_, capture)| {
                    capture_cookie != 0 && capture.summary.capture_cookie == capture_cookie
                })
                .map(|(id, _)| id.clone())
                .or_else(|| {
                    (capture_cookie != 0)
                        .then(|| self.pending_capture_id.clone())
                        .flatten()
                });
            // A packet no run owns is saved once: an observing capture that can
            // still save is its archive, so the boot's unassigned archive skips it.
            let held = held_by_capture(
                self.runs.contains_key(&root),
                observer_id.as_ref().and_then(|id| self.captures.get(id)),
            );
            let reserved = self.stored_len();
            let mut saved = if let Some(run) = self.runs.get_mut(&root) {
                if let Some(header) = &header {
                    run.observe_clock(header.timestamp_ns);
                }
                let saved = run
                    .capture
                    .append_with_reserved(&packet, reserved.saturating_sub(run.capture.bytes));
                if !saved && !run.recording_complete() {
                    run.storage_error(
                        run.capture
                            .error
                            .clone()
                            .unwrap_or_else(|| "raw saving stopped".into()),
                    );
                }
                run.assembler.set_storage_limit(
                    run.assembler
                        .stored_len()
                        .saturating_add(self.capture.quota().saturating_sub(
                            reserved + if saved { packet.len() as u64 + 4 } else { 0 },
                        )),
                );
                if let Err(error) = run.assembler.ingest(&packet) {
                    snapshot.health.parser_errors += 1;
                    snapshot.last_error = Some(error.to_string());
                }
                saved
            } else {
                let stored_here = save_unowned(
                    &mut self.capture,
                    &mut self.assembler,
                    held,
                    &packet,
                    reserved,
                );
                if let Err(error) = self.assembler.ingest(&packet) {
                    snapshot.health.parser_errors += 1;
                    snapshot.last_error = Some(error.to_string());
                }
                self.pre_ack
                    .hold(root, self.guest_resources.cookie, &packet, started);
                held || stored_here
            };
            // Observer copies do not contribute to canonical history: the primary
            // run/unassigned assembler above already owns each incoming packet.
            if let Some(id) = observer_id {
                let reserved = self.stored_len();
                if let Some(observer) = self.captures.get_mut(&id) {
                    let identity_was_unknown = observer.summary.capture_cookie == 0;
                    if let Err(error) = observer.observe_identity(
                        capture_cookie,
                        header.as_ref().map_or(0, |header| header.stream_id),
                    ) {
                        observer.storage_error(error);
                        saved = false;
                    } else {
                        if identity_was_unknown && let Err(error) = observer.persist_summary() {
                            observer.storage_error(error);
                        }
                        let copy_saved = observer.capture.append_with_reserved(
                            &packet,
                            reserved.saturating_sub(observer.capture.bytes),
                        );
                        observer.assembler.set_storage_limit(
                            observer.assembler.stored_len().saturating_add(
                                self.capture.quota().saturating_sub(reserved.saturating_add(
                                    if copy_saved {
                                        packet.len() as u64 + 4
                                    } else {
                                        0
                                    },
                                )),
                            ),
                        );
                        match observer.assembler.ingest(&packet) {
                            Ok(Some(event)) => observer.processes.event(&event),
                            Ok(None) => {}
                            Err(error) => {
                                snapshot.health.parser_errors =
                                    snapshot.health.parser_errors.saturating_add(1);
                                snapshot.last_error = Some(error.to_string());
                            }
                        }
                        if let Some(header) = &header {
                            observer.processes.packet(header);
                            if observer.processes.unnamed(header.pid)
                                && let Some(run) = self.runs.get(&root)
                                && run.summary.pid == header.pid
                            {
                                observer
                                    .processes
                                    .name_launched(header.pid, &run.summary.request.path);
                            }
                        }
                        if let Some(error) = observer.assembler.saving_error().map(str::to_owned) {
                            observer.storage_error(error);
                        }
                        if !copy_saved {
                            observer.storage_error(
                                observer
                                    .capture
                                    .error
                                    .clone()
                                    .unwrap_or_else(|| "observer raw saving stopped".into()),
                            );
                        }
                        saved &= copy_saved;
                    }
                }
            }
            self.propagate_saving_failures(root);
            if !saved {
                let error = self
                    .capture
                    .error
                    .clone()
                    .or_else(|| self.runs.values().find_map(|run| run.capture.error.clone()))
                    .unwrap_or_else(|| "capture saving stopped".into());
                self.saving_refused(root, error);
                snapshot.health.storage_dropped_packets =
                    snapshot.health.storage_dropped_packets.saturating_add(1);
            } else {
                self.persisted_packets = self.persisted_packets.saturating_add(1);
            }
        }
        self.telemetry_busy = drained >= BUSY_PACKETS;
        self.flush_raw();
        if self.last_process_save.elapsed() >= Duration::from_secs(2) {
            self.last_process_save = Instant::now();
            for capture in self.captures.values_mut() {
                capture.persist_processes();
            }
        }
        let stats = self.transport.stats()?;
        snapshot.health.attempted = stats.attempted;
        snapshot.health.dropped = stats.dropped;
        snapshot.health.bad_commands = stats.bad_commands;
        snapshot.health.reply_stalls = stats.reply_stalls;
        snapshot.health.transport_health = stats.health;
        snapshot.health.transport_waits = stats.waits;
        snapshot.health.transport_wait_ns = stats.wait_ns;
        snapshot.health.ring_size = stats.ring_size;
        snapshot.health.send_wait_us = stats.send_wait_us;
        snapshot.health.write_backlog = crate::writer::backlog() as u64;
        self.shed_load(stats.wait_ns, &mut snapshot.health)?;
        snapshot.health.persisted_packets = self.persisted_packets;
        self.refresh_storage_health(&mut snapshot.health);
        snapshot.health.parser_evicted_count = self.assembler.evicted_count
            + self
                .runs
                .values()
                .map(|run| run.assembler.evicted_count)
                .sum::<u64>();
        snapshot.health.parser_evicted_count = snapshot.health.parser_evicted_count.saturating_add(
            self.captures
                .values()
                .map(|capture| capture.assembler.evicted_count)
                .sum::<u64>(),
        );
        self.update_captures(snapshot);
        let _ = sender;
        Ok(())
    }
    /// Capture All load shedding: drop instead of waiting while the host is
    /// behind (see [`Shed`]). `wait_ns` is the guest's total send wait.
    pub(super) fn shed_load(&mut self, wait_ns: u64, health: &mut Health) -> Result<(), String> {
        let configured = self.vm.transport.send_wait_us();
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.shed.sampled);
        if elapsed >= Duration::from_millis(500) {
            let waited = wait_ns.saturating_sub(self.shed.sampled_wait_ns);
            self.shed.wait_share = waited as f64 / elapsed.as_nanos().max(1) as f64;
            self.shed.sampled = now;
            self.shed.sampled_wait_ns = wait_ns;
        }
        let capture_all = self.captures.values().any(|capture| {
            capture.summary.scope == CaptureScope::AllUserspace
                && capture.summary.state == CaptureState::Active
        });
        let backlog = crate::writer::backlog();
        if !self.shed.active
            && configured > 0
            && capture_all
            && (backlog > SHED_BACKLOG || self.shed.wait_share > SHED_WAIT_SHARE)
        {
            self.transport.set_send_wait(0)?;
            self.shed = Shed {
                active: true,
                since: now,
                ..self.shed
            };
        } else if self.shed.active
            && (!capture_all
                || (backlog < RESUME_BACKLOG
                    && now.saturating_duration_since(self.shed.since) >= SHED_MIN))
        {
            self.transport.set_send_wait(configured)?;
            self.shed.active = false;
            self.shed.wait_share = 0.0;
        }
        health.shedding = self.shed.active;
        Ok(())
    }
    /// Write the packets the raw captures buffered during a drain pass.
    fn flush_raw(&mut self) {
        let mut failed = None;
        if !self.capture.flush() {
            self.assembler.stop_saving();
            failed = self.capture.error.clone();
        }
        for run in self.runs.values_mut() {
            if !run.capture.flush() {
                let error = run
                    .capture
                    .error
                    .clone()
                    .unwrap_or_else(|| "raw saving stopped".into());
                run.storage_error(error.clone());
                failed.get_or_insert(error);
            }
        }
        for capture in self.captures.values_mut() {
            if !capture.capture.flush() {
                let error = capture
                    .capture
                    .error
                    .clone()
                    .unwrap_or_else(|| "observer raw saving stopped".into());
                capture.storage_error(error.clone());
                failed.get_or_insert(error);
            }
        }
        if let Some(error) = failed {
            self.stop_saving(error);
        }
    }
    pub(super) fn request(
        &mut self,
        opcode: u32,
        args: &[u8],
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        self.request_typed(opcode, args, snapshot, sender, timeout)
            .map_err(RequestError::into_message)
    }
    pub(super) fn request_typed(
        &mut self,
        opcode: u32,
        args: &[u8],
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
        timeout: Duration,
    ) -> Result<Vec<u8>, RequestError> {
        if timeout.is_zero() {
            return Err(RequestError::Failed(
                "guest command deadline exhausted before submission".into(),
            ));
        }
        let id = self
            .transport
            .send(opcode, args)
            .map_err(RequestError::Failed)?;
        self.wait_reply(id, opcode, snapshot, sender, timeout)
    }
    /// Route only explicitly retained status/terminal requests and the kernel probe.
    /// Other replies still have no remaining waiter.
    fn other_reply(
        &mut self,
        reply_id: u64,
        status: i32,
        payload: &[u8],
        awaiting: Option<u64>,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) {
        if self
            .guest_resources
            .reply(reply_id, status, payload, &self.boot_id, Instant::now())
        {
            return;
        }
        if self.kernel_probe_reply(reply_id, status, payload, snapshot) {
            return;
        }
        let runs = &self.runs;
        if let Some(result) = self
            .run_status_poll
            .late_reply(reply_id, status, payload, |owner| {
                runs.get(&owner.cookie)
                    .is_some_and(|run| owner.matches(run))
            })
        {
            if let Err(error) = result
                .and_then(|(owner, execution)| self.apply_run_status(&owner, execution, snapshot))
            {
                snapshot.last_error = Some(format!("late run status: {error}"));
            }
            return;
        }
        if let Some(cookie) = self.late_reads.remove(&reply_id) {
            if let Err(error) = self.apply_terminal_reply(cookie, status, payload, snapshot, sender)
            {
                snapshot.last_error = Some(format!("late terminal read: {error}"));
            }
        } else {
            snapshot.last_error = Some(match awaiting {
                Some(id) => format!("unmatched command reply {reply_id}; awaiting {id}"),
                None => format!("unmatched command reply {reply_id}"),
            });
        }
    }
    /// Advance the kernel probe: send INFO when due and apply waiting replies.
    pub(super) fn probe_kernel(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        match self.kernel_probe {
            KernelProbe::Done => Ok(()),
            KernelProbe::Due(when) => {
                if Instant::now() >= when {
                    // A full request ring only delays identification.
                    self.kernel_probe =
                        match self.transport.send(control::INFO, &control::header(0)) {
                            Ok(id) => KernelProbe::Info(id),
                            Err(_) => KernelProbe::Due(Instant::now() + KERNEL_PROBE_RETRY),
                        };
                }
                Ok(())
            }
            KernelProbe::Info(_) | KernelProbe::Stats(_) => self.drain_replies(snapshot, sender),
        }
    }
    /// Consume a reply that belongs to the kernel probe; false for any other reply.
    fn kernel_probe_reply(
        &mut self,
        reply_id: u64,
        status: i32,
        payload: &[u8],
        snapshot: &mut Snapshot,
    ) -> bool {
        const EOPNOTSUPP: i32 = 95;
        let retry = KernelProbe::Due(Instant::now() + KERNEL_PROBE_RETRY);
        match self.kernel_probe {
            KernelProbe::Info(id) if id == reply_id => {
                self.kernel_probe = if status == 0 {
                    match control::info(payload) {
                        Ok(kernel) => self.kernel_identified(kernel, snapshot),
                        Err(error) => snapshot.last_error = Some(format!("guest info: {error}")),
                    }
                    KernelProbe::Done
                } else if status == -EOPNOTSUPP {
                    match self.transport.send(control::STATS, &control::header(0)) {
                        Ok(id) => KernelProbe::Stats(id),
                        Err(_) => retry,
                    }
                } else {
                    retry
                };
                true
            }
            KernelProbe::Stats(id) if id == reply_id => {
                // INFO is registered before every other opcode: a kernel that
                // answers STATS but not INFO predates revision 9.
                self.kernel_probe = if status == 0 {
                    self.kernel_identified(GuestKernel::default(), snapshot);
                    KernelProbe::Done
                } else {
                    retry
                };
                true
            }
            _ => false,
        }
    }
    fn kernel_identified(&mut self, kernel: GuestKernel, snapshot: &mut Snapshot) {
        let claimed = (
            self.bundle.antinomie_revision,
            self.bundle.antinomie_source.as_deref(),
        );
        let running = (kernel.revision, kernel.source.as_deref());
        if claimed.0.is_some() && claimed != running {
            snapshot.last_error = Some(format!(
                "the running kernel does not match its base: the base was built {}, the kernel is {}",
                describe_source(claimed),
                describe_source(running)
            ));
        } else if kernel
            .revision
            .is_some_and(|revision| revision > APP_REVISION)
        {
            snapshot.last_error = Some(format!(
                "the guest kernel is {}, newer than this app; update Antinomie",
                describe_source(running)
            ));
        }
        self.capture.guest_kernel = Some(kernel.clone());
        snapshot.guest_kernel = Some(kernel);
    }
    /// Apply replies already available without sending a command.
    pub(super) fn drain_replies(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        self.pump(snapshot, sender)?;
        while let Some((reply_id, status, payload)) = self.transport.reply()? {
            self.other_reply(reply_id, status, &payload, None, snapshot, sender);
        }
        Ok(())
    }
    pub(super) fn wait_reply(
        &mut self,
        id: u64,
        opcode: u32,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
        timeout: Duration,
    ) -> Result<Vec<u8>, RequestError> {
        let deadline = Instant::now() + timeout;
        loop {
            self.pump(snapshot, sender).map_err(RequestError::Failed)?;
            while let Some((reply_id, status, payload)) =
                self.transport.reply().map_err(RequestError::Failed)?
            {
                if reply_id != id {
                    self.other_reply(reply_id, status, &payload, Some(id), snapshot, sender);
                    continue;
                }
                if status < 0 {
                    let errno = status
                        .checked_neg()
                        .filter(|errno| (1..=4095).contains(errno))
                        .ok_or_else(|| {
                            RequestError::Failed("invalid guest rejection errno".into())
                        })?;
                    return Err(RequestError::Rejected {
                        status,
                        message: format!(
                            "guest command 0x{opcode:x}: {}",
                            std::io::Error::from_raw_os_error(errno)
                        ),
                    });
                }
                if status != 0 {
                    return Err(RequestError::Failed(format!(
                        "guest command returned unexpected status {status}"
                    )));
                }
                return Ok(payload);
            }
            if self
                .process
                .child
                .try_wait()
                .map_err(|e| RequestError::Failed(e.to_string()))?
                .is_some()
            {
                return Err(RequestError::Failed(VM_EXITED_WAITING_REPLY.into()));
            }
            if Instant::now() >= deadline {
                return Err(RequestError::TimedOut(format!(
                    "guest command {id} timed out; outcome unknown"
                )));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let poll_timeout = remaining.as_millis().min(10) as i32;
            self.transport
                .poll(poll_timeout)
                .map_err(RequestError::Failed)?;
        }
    }
    pub(super) fn finalize(&mut self, state: &str, snapshot: &mut Snapshot) -> Result<(), String> {
        self.seal_manual_cores(state, snapshot);
        self.seal_process_cores(state, snapshot);
        // QEMU has ended (or host ownership is being sealed at a restore boundary).
        // A queued post-exit dump cannot be claimed to have succeeded here.
        for owner in self.run_artifacts.values_mut() {
            if let Some(capture) = owner.network.take() {
                // At VM exit QEMU already closed it; no object-del is necessary.
                if let Err(error) = finish_network_summary(capture) {
                    owner.issue(error.clone());
                    snapshot.last_error = Some(error);
                }
                owner.summary.network_state = RunArtifactState::Interrupted;
                owner.issue(format!(
                    "VM recording ended ({state}) before capture completed"
                ));
            }
            if matches!(
                owner.summary.memory_state,
                RunArtifactState::WaitingForTreeExit
                    | RunArtifactState::Queued
                    | RunArtifactState::InProgress
            ) {
                owner.summary.memory_state = RunArtifactState::Interrupted;
                owner.issue(format!(
                    "VM recording ended ({state}) before post-exit RAM dump completed"
                ));
            }
            if let Err(error) = owner.save() {
                snapshot.last_error = Some(error);
            }
        }
        self.analysis.shutdown();
        self.analysis_updates(snapshot, &mpsc::sync_channel(1).0);
        for cookie in std::mem::take(&mut self.late_reads).into_values() {
            if let Some(run) = self.runs.get_mut(&cookie) {
                run.terminal_reads_unanswered = run.terminal_reads_unanswered.saturating_add(1);
            }
        }
        let cookies: Vec<_> = self.runs.keys().copied().collect();
        for cookie in cookies {
            let available = self.available();
            if let Some(run) = self.runs.get_mut(&cookie)
                && let Err(error) = run.finalize(available, state, &snapshot.health)
            {
                run.storage_error(error.clone());
                snapshot.last_error = Some(error);
            }
        }
        for capture in self.captures.values_mut() {
            if let Err(error) = capture.finalize(&snapshot.health) {
                capture.storage_error(error.clone());
                snapshot.last_error = Some(format!("capture finalization: {error}"));
            }
        }
        self.update_captures(snapshot);
        self.update_runs(snapshot);
        snapshot.events = self.history();
        for event in &mut snapshot.events {
            if !event.complete {
                event
                    .issues
                    .push("run finalized with unresolved capture".into());
            }
        }
        let summaries = storage::atomic_json(
            &self.capture.directory.join("events.json"),
            &snapshot.events,
        );
        if let Err(e) = &summaries {
            self.capture
                .error
                .get_or_insert_with(|| format!("event summaries persistence failed: {e}"));
        }
        self.refresh_storage_health(&mut snapshot.health);
        self.capture.final_health = Some(snapshot.health.clone());
        let manifest = self
            .capture
            .manifest(&self.vm, &self.bundle, &self.disk_bundle, state);
        self.refresh_storage_health(&mut snapshot.health);
        summaries.and(manifest)
    }
    pub(super) fn read_terminal(
        &mut self,
        run_id: &str,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
        timeout: Duration,
    ) -> Result<(), String> {
        let cookie = self.run_cookie(run_id)?;
        let run = self.runs.get(&cookie).ok_or("unknown run")?;
        if run.summary.terminal_eof {
            return Ok(());
        }
        // Debug builds can force short deadlines to exercise late replies.
        #[cfg(debug_assertions)]
        let timeout = std::env::var("ANTINOMIE_TEST_TERMINAL_READ_TIMEOUT_US")
            .ok()
            .and_then(|value| value.parse().ok())
            .map_or(timeout, Duration::from_micros);
        if timeout.is_zero() {
            return Err("guest command deadline exhausted before submission".into());
        }
        let session_id = run.summary.session_id;
        // At most one READ per run is outstanding. While an earlier reply is late,
        // spend this budget waiting for it instead of queueing more reads.
        let deadline = Instant::now() + timeout;
        while self.late_reads.values().any(|&pending| pending == cookie) {
            self.drain_replies(snapshot, sender)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if !self.late_reads.values().any(|&pending| pending == cookie) {
                break;
            }
            if remaining.is_zero() {
                return Ok(());
            }
            self.transport.poll(remaining.as_millis().min(10) as i32)?;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let run = self.runs.get(&cookie).ok_or("unknown run")?;
        if run.summary.terminal_eof || remaining.is_zero() {
            return Ok(());
        }
        let mut args = control::with_session(session_id);
        args.extend(4096u32.to_le_bytes());
        args.extend(0u32.to_le_bytes());
        let id = self.transport.send(control::READ, &args)?;
        match self.wait_reply(id, control::READ, snapshot, sender, remaining) {
            Ok(reply) => self.apply_terminal_reply(cookie, 0, &reply, snapshot, sender),
            Err(RequestError::TimedOut(_)) => {
                // The guest may already have consumed output for this reply; keep
                // the id so the reply is applied when it arrives.
                self.late_reads.insert(id, cookie);
                Ok(())
            }
            Err(RequestError::Failed(error) | RequestError::Rejected { message: error, .. }) => {
                Err(error)
            }
        }
    }
    fn apply_terminal_reply(
        &mut self,
        cookie: u64,
        status: i32,
        reply: &[u8],
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        if status != 0 {
            return Err(format!("terminal read returned status {status}"));
        }
        let flags = u32_at(reply, 0).map_err(|e| e.to_string())?;
        let count = u32_at(reply, 4).map_err(|e| e.to_string())? as usize;
        if reply.len() != 8 + count || count > 4096 || flags & !1 != 0 {
            return Err("invalid terminal read reply".into());
        }
        let available = self.available();
        let run = self.runs.get_mut(&cookie).ok_or("unknown run")?;
        let mut persistence_error = None;
        if count > 0
            && let Err(error) = run.output(&reply[8..], available)
        {
            persistence_error = Some(error);
        }
        let available = available.saturating_sub(if count > 0 { count as u64 * 2 + 5 } else { 0 });
        let eof = flags & 1 != 0;
        if eof && count == 0 {
            run.sequence = run.sequence.saturating_add(1);
        }
        if eof
            && let Err(error) = run
                .eof(available)
                .and_then(|_| run.save_screen(available.saturating_sub(5)))
        {
            persistence_error = Some(error);
        }
        let failure = persistence_error.map(|error| terminal_failure(run, error));
        let sequence = run.sequence;
        let run_id = run.summary.id.clone();
        match failure {
            // A terminal write that fails stops saving for this run only; the boot
            // keeps recording everything else. The first cause stays the one
            // reported.
            Some(TerminalFailure::RunOnly(cause)) => {
                snapshot.health.persistence_error.get_or_insert(cause);
            }
            // Only the quota, which every recording shares, stops the boot.
            Some(TerminalFailure::Quota(cause)) => {
                self.quota_reached(cookie);
                snapshot.health.persistence_error.get_or_insert(cause);
            }
            None => {}
        }
        if (count > 0 || eof)
            && sender
                .try_send(Notification::Terminal {
                    run_id,
                    sequence,
                    data: reply[8..].to_vec(),
                    eof,
                })
                .is_err()
        {
            snapshot.health.ui_dropped = snapshot.health.ui_dropped.saturating_add(1);
        }
        Ok(())
    }
}

/// The VM process ended before the awaited reply could be read.
pub(super) const VM_EXITED_WAITING_REPLY: &str = "VM exited while waiting for command reply";

pub(super) fn decode_stats(reply: &[u8]) -> Result<[u64; 10], String> {
    if reply.len() != 80 {
        return Err("invalid recorder stats length".into());
    }
    let mut counters = [0; 10];
    for (n, value) in counters.iter_mut().enumerate() {
        *value = u64_at(reply, n * 8).map_err(|e| e.to_string())?;
    }
    Ok(counters)
}

pub(super) fn remaining_request_budget(deadline: Instant, maximum: Duration) -> Duration {
    deadline
        .saturating_duration_since(Instant::now())
        .min(maximum)
}
