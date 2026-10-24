// SPDX-License-Identifier: GPL-3.0-only
//! Starting and stopping the VM, and host resource checks.
use super::*;

impl Worker {
    pub(super) fn start(&mut self, id: &str) -> Result<String, String> {
        if self.session.is_some() {
            return Err("only one VM may run at a time".into());
        }
        // Reconnection state belongs to one boot; a new start begins clean.
        self.reconnect = (0, None);
        if self.deferred_flush.is_some() || !self.flusher.can_submit_retired() {
            return Err(
                "recording flush queue is full; wait for saved recordings before starting a VM"
                    .into(),
            );
        }
        let vm = self
            .snapshot
            .vms
            .iter()
            .find(|v| v.id == id)
            .ok_or("unknown VM")?
            .clone();
        storage::validate_vm(&vm)?;
        vm.launch.validate_for(&self.options)?;
        let bundle = crate::locations::boot_bundle(&self.options, vm.base_identity.as_deref())?;
        storage::validate_boot_display(&vm, &bundle)?;
        let dir = storage::vm_dir(&self.options, id)?;
        let disk_bundle: Bundle = storage::read_json(&dir.join("bundle.json"))?;
        disk_bundle.verify_installed()?;
        crate::snapshots::recover_pending(&self.options, &vm)?;
        crate::snapshots::validate_active(&self.options, &vm, &disk_bundle.base_disk)?;
        storage::validate_guest_transition(&disk_bundle, &bundle)?;
        storage::validate_vm_bundle(&self.options, &vm, &disk_bundle)?;
        storage::validate_vm_bundle(&self.options, &vm, &bundle)?;
        if disk_bundle
            .guest
            .as_ref()
            .is_some_and(|guest| guest.requires_credentials)
        {
            crate::guest_account::GuestAccount::load(&dir)?;
        }
        if !bundle.kernel_version.is_empty() && !bundle.kernel_version.starts_with("6.12.94") {
            return Err("boot bundle must use the approved Linux 6.12.94 baseline".into());
        }
        require_supported(bundle.antinomie_revision, bundle.min_app_version.as_deref())?;
        self.snapshot.state = VmState::Starting;
        self.snapshot.active_vm = Some(id.into());
        // An error of an earlier boot (a crash, a late reply) says nothing about this one.
        self.snapshot.last_error = None;
        self.snapshot.health = Health::default();
        self.snapshot.guest_kernel = None;
        self.snapshot.guest_core_limits = None;
        self.snapshot.guest_tracer = None;
        self.snapshot.events.clear();
        self.snapshot.captures.clear();
        self.snapshot.capture_events.clear();
        self.snapshot.process_page = None;
        self.snapshot.process_cores.clear();
        self.snapshot.boot_id = None;
        self.snapshot.stealth_fallbacks.clear();
        self.snapshot.network_capture = None;
        self.publish();
        self.stopping.store(false, Ordering::Relaxed);
        let result = (|| -> Result<Session, String> {
            let boot_id = storage::unique_id();
            let boot_dir = crate::locations::locations(&self.options, id)?
                .recording_directory
                .join("boots")
                .join(&boot_id);
            let process = VmProcess::launch(&self.options, &vm, &bundle)?;
            self.snapshot.serial_log = Some(process.runtime_dir.join("serial.log"));
            self.snapshot
                .stealth_fallbacks
                .clone_from(&process.stealth_fallbacks);
            self.snapshot.boot_id = Some(boot_id.clone());
            let capture_dir = boot_dir.join("unassigned");
            let mut capture =
                RawCapture::new(capture_dir.clone(), self.options.capture_quota_size)?;
            capture.queue_manifest(&vm, &bundle, &disk_bundle, "starting")?;
            self.snapshot.capture_dir = Some(capture_dir.clone());
            let mut assembler =
                Assembler::new(capture_dir.join("objects"), self.options.capture_quota_size)
                    .map_err(|e| e.to_string())?;
            assembler.set_event_table(vm.transport.event_table as usize);
            if let Err(e) = process.verify_ram_layout() {
                capture.queue_manifest(&vm, &bundle, &disk_bundle, "start-failed")?;
                return Err(e);
            }
            let mut transport =
                match Transport::open(&process.ram_path, process.ram_size, process.bootstrap) {
                    Ok(t) => t,
                    Err(e) => {
                        capture.queue_manifest(&vm, &bundle, &disk_bundle, "start-failed")?;
                        return Err(e);
                    }
                };
            // Bases before 0.3.0 cannot wait for room; they keep dropping.
            if let Err(error) = transport.set_send_wait(vm.transport.send_wait_us()) {
                self.snapshot.last_error = Some(format!(
                    "never-drop mode needs a base for Antinomie 0.3.0 or newer ({error})"
                ));
            } else if vm.transport.lossless {
                // The transport thread can pause for seconds while the disk
                // catches up; the guest must keep waiting through that
                // instead of taking the host for gone and dropping.
                let _ = transport.set_host_timeout(LOSSLESS_HOST_TIMEOUT_MS);
            }
            capture.queue_manifest(&vm, &bundle, &disk_bundle, "running")?;
            Ok(Session {
                resources: crate::resources::ResourceSampler::default(),
                guest_resources: crate::guest_resources::Collector::default(),
                kernel_resources: crate::kernel_resources::KernelResources::default(),
                last_resource_check: None,
                analysis: crate::analysis::jobs::Jobs::with_tools(
                    crate::analysis_tools::tools_dir(&self.options.data_dir),
                ),
                transport,
                process,
                capture,
                assembler,
                vm,
                bundle,
                disk_bundle,
                runs: BTreeMap::new(),
                run_artifacts: BTreeMap::new(),
                core_stored_len: 0,
                core_reserved_len: 0,
                manual_cores: BTreeMap::new(),
                manual_record_count: 0,
                captures: BTreeMap::new(),
                pending_capture_id: None,
                boot_id,
                pre_ack: crate::pre_ack::PreAckBuffer::new(self.options.pre_ack),
                quota: crate::quota::QuotaState::default(),
                terminal_cursor: 0,
                late_reads: BTreeMap::new(),
                run_status_poll: RunStatusPoll::default(),
                recorder_poll: recorder_health::RecorderPoll::default(),
                telemetry_busy: false,
                shed: Shed::default(),
                last_process_save: Instant::now(),
                writer_held_since: None,
                network_bytes_done: 0,
                network_bytes: 0,
                last_network_check: Instant::now(),
                last_memory_check: Instant::now(),
                status_cursor: 0,
                last_status_query: Instant::now(),
                persisted_packets: 0,
                kernel_probe: KernelProbe::Due(Instant::now()),
                core_limits: None,
                flush_queue: Vec::new(),
            })
        })();
        match result {
            Ok(session) => {
                self.session = Some(session);
                self.snapshot.state = VmState::Running;
                self.refresh_vm_snapshots(id)?;
                Ok("VM running; transport attached".into())
            }
            Err(e) => {
                self.snapshot.active_vm = None;
                self.snapshot.state = VmState::Failed;
                Err(e)
            }
        }
    }
    pub(super) fn check_resources(&mut self) {
        let Some(session) = self.session.as_mut() else {
            self.snapshot.vm_resources = None;
            return;
        };
        if session
            .last_resource_check
            .is_some_and(|last| last.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        session.last_resource_check = Some(Instant::now());
        let mut sample = session.resources.sample(
            session.process.child.id(),
            &session.vm.id,
            &self.options.data_dir,
        );
        let unavailable = self.reconnect.1.is_some()
            || self.snapshot.memory_dump.is_some()
            || self.snapshot.state != VmState::Running;
        sample.guest = Some(
            if crate::kernel_resources::kernel_produces(self.snapshot.guest_kernel.as_ref()) {
                session
                    .kernel_resources
                    .sample(&session.boot_id, unavailable)
            } else {
                session
                    .guest_resources
                    .sample(&session.boot_id, unavailable)
            },
        );
        self.snapshot.vm_resources = Some(sample);
        self.publish();
    }
    pub(super) fn stop(&mut self) -> Result<(), String> {
        if let Some(job) = self.keyboard.take() {
            let result = job.cancel_and_join();
            self.emit(Notification::CommandResult {
                id: 0,
                success: result.is_ok(),
                message: result.unwrap_or_else(|error| error),
            });
        }
        // A reconnection pending for this boot must not run against the next.
        self.reconnect = (0, None);
        let Some(mut session) = self.session.take() else {
            self.snapshot.active_vm = None;
            self.snapshot.state = VmState::Stopped;
            return Ok(());
        };
        self.snapshot.state = VmState::Stopping;
        self.publish();
        // Never-drop mode ends with the run: a guest shutting down must not
        // wait on a host that is busy finalizing its recordings.
        let _ = session.transport.set_send_wait(0);
        let _ = session.transport.set_host_timeout(0);
        let graphical = session
            .disk_bundle
            .guest
            .as_ref()
            .is_some_and(|guest| guest.graphical);
        let deadline = Instant::now() + shutdown_timeout(self.options.shutdown_timeout, graphical);
        let mut issues = Vec::new();
        let terminal_ids: Vec<_> = session
            .runs
            .values()
            .filter(|run| !run.summary.terminal_eof)
            .map(|run| run.summary.id.clone())
            .collect();
        for run_id in &terminal_ids {
            let budget = remaining_request_budget(deadline, Duration::from_millis(100));
            if budget.is_zero() {
                break;
            }
            if let Err(error) =
                session.read_terminal(run_id, &mut self.snapshot, &self.sender, budget)
            {
                issues.push(format!("final terminal drain: {error}"));
            }
        }
        let stats_requested = Instant::now();
        match session.request(
            control::STATS,
            &control::header(0),
            &mut self.snapshot,
            &self.sender,
            remaining_request_budget(deadline, Duration::from_secs(4)) / 4,
        ) {
            Ok(reply) => {
                if let Ok(counters) = decode_stats(&reply) {
                    session.recorder_poll.observe(
                        stats_requested,
                        counters,
                        &mut self.snapshot.health,
                    );
                }
            }
            Err(e) => issues.push(format!("final recorder stats unavailable: {e}")),
        }
        // A guest that powers off on SHUTDOWN can end QEMU before its
        // acknowledgement is read; the exit status then decides, not the race.
        let mut exited_before_ack = false;
        let shutdown_ack = match session.request(
            control::SHUTDOWN,
            &control::header(0),
            &mut self.snapshot,
            &self.sender,
            remaining_request_budget(deadline, Duration::from_secs(2)),
        ) {
            Ok(reply) => {
                if reply.is_empty() {
                    true
                } else {
                    issues.push("invalid shutdown acknowledgement".into());
                    false
                }
            }
            Err(e) if e == VM_EXITED_WAITING_REPLY => {
                exited_before_ack = true;
                false
            }
            Err(e) => {
                issues.push(e);
                false
            }
        };
        let mut forced = false;
        let mut exit_success = false;
        let mut writeback = Writeback::new(
            Instant::now(),
            shutdown_timeout(self.options.shutdown_timeout, graphical),
        );
        let mut deadline = deadline;
        loop {
            match session.process.child.try_wait() {
                Ok(Some(status)) => {
                    exit_success = status.success();
                    if !exit_success {
                        if exited_before_ack {
                            issues.push(VM_EXITED_WAITING_REPLY.into());
                        }
                        issues.push(format!("QEMU exited with {status}"));
                    }
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    issues.push(e.to_string());
                    forced = true;
                    break;
                }
            }
            if let Err(e) = session.pump(&mut self.snapshot, &self.sender)
                && issues.last() != Some(&e)
            {
                issues.push(e);
            }
            if !terminal_ids.is_empty() {
                let run_id = &terminal_ids[session.terminal_cursor % terminal_ids.len()];
                session.terminal_cursor = session.terminal_cursor.wrapping_add(1);
                let budget = remaining_request_budget(deadline, Duration::from_millis(50));
                if !budget.is_zero()
                    && let Err(error) =
                        session.read_terminal(run_id, &mut self.snapshot, &self.sender, budget)
                    && issues.last() != Some(&error)
                {
                    issues.push(error);
                }
            }
            if self.last_publish.elapsed() >= Duration::from_millis(250) {
                self.snapshot.events = session.history();
                self.publish();
            }
            if writeback.due(Instant::now()) {
                let written = session.process.disk_written();
                deadline = writeback.observe(Instant::now(), written, deadline);
            }
            if Instant::now() >= deadline {
                forced = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        if forced && let Err(e) = session.process.force_stop() {
            issues.push(e);
        }
        if let Err(e) = session.pump(&mut self.snapshot, &self.sender)
            && issues.last() != Some(&e)
        {
            issues.push(format!("final bounded drain unavailable: {e}"));
        }
        let final_state = final_state(forced, shutdown_ack, exited_before_ack, exit_success);
        // Everything left is disk work. It goes to a flush job, so the VM is
        // Stopped now and the host's `fsync`s are not a wait for the user.
        let steps = session.seal(final_state, &mut self.snapshot);
        self.submit_sealed_flush(session.boot_id.clone(), steps);
        if let Err(e) = end_network_capture(&mut self.snapshot) {
            issues.push(e);
        }
        abandon_memory_dump(&mut self.snapshot);
        self.snapshot.active_vm = None;
        self.snapshot.state = VmState::Stopped;
        self.stopping.store(false, Ordering::Relaxed);
        if forced {
            self.snapshot.last_error =
                Some("VM forced off after shutdown timeout; capture marked forced".into());
        }
        if !issues.is_empty() {
            self.snapshot.last_error = Some(issues.join("; "));
        }
        self.publish();
        Ok(())
    }
}

/// How a Stop ended, as recorded in the boot manifest. Only a forced power-off
/// or an exit that was not a successful shutdown is unexpected.
pub(super) fn final_state(
    forced: bool,
    shutdown_acknowledged: bool,
    exited_before_acknowledgement: bool,
    exit_success: bool,
) -> &'static str {
    if forced {
        "forced"
    } else if (shutdown_acknowledged || exited_before_acknowledgement) && exit_success {
        "clean"
    } else {
        "unexpected-exit"
    }
}

pub(super) fn qmp_outcome_unknown(error: &str) -> bool {
    // QMP protocol errors prove command rejection. Transport/read failures
    // may happen after the command executed and cannot authorize deletion.
    !error.starts_with("QMP error:")
}

/// Longest a guest that keeps writing its disk while it powers off is waited
/// for, in all, from the shutdown request.
const WRITEBACK_LIMIT: Duration = Duration::from_secs(300);
/// How often Stop asks QEMU how much the guest has written.
const WRITEBACK_POLL: Duration = Duration::from_secs(1);

/// A guest writes back what its programs left in its page cache before it
/// powers off (`ksys_sync`): after heavy file churn that is hundreds of
/// megabytes, and the host disk the VM's image is on may be busy, so it can
/// take far longer than the shutdown timeout. While the VM's disks are still
/// being written, the deadline moves to a whole timeout after the last write
/// seen, up to [`WRITEBACK_LIMIT`]; a guest that stops writing and does not
/// power off is forced off a timeout later, as before.
struct Writeback {
    started: Instant,
    timeout: Duration,
    next_poll: Instant,
    written: Option<u64>,
}

impl Writeback {
    fn new(started: Instant, timeout: Duration) -> Self {
        Self {
            started,
            timeout,
            next_poll: started,
            written: None,
        }
    }

    fn due(&self, now: Instant) -> bool {
        now >= self.next_poll
    }

    /// The deadline after a sample of the bytes written (`None`: no answer).
    fn observe(&mut self, now: Instant, written: Option<u64>, deadline: Instant) -> Instant {
        self.next_poll = now + WRITEBACK_POLL;
        let progressed =
            matches!((self.written, written), (Some(before), Some(after)) if after > before);
        if written.is_some() {
            self.written = written;
        }
        if progressed {
            deadline.max((now + self.timeout).min(self.started + WRITEBACK_LIMIT))
        } else {
            deadline
        }
    }
}

/// Least time a graphical guest gets to shut down: a loaded desktop session
/// takes longer than a console guest to stop its services.
const GRAPHICAL_SHUTDOWN: Duration = Duration::from_secs(30);

/// How long Stop waits for the guest before forcing the VM off.
fn shutdown_timeout(configured: Duration, graphical: bool) -> Duration {
    if graphical {
        configured.max(GRAPHICAL_SHUTDOWN)
    } else {
        configured
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_guest_still_writing_its_disk_at_power_off_is_waited_for_up_to_a_limit() {
        let start = std::time::Instant::now();
        let second = super::Duration::from_secs(1);
        let timeout = 10 * second;
        let mut writeback = super::Writeback::new(start, timeout);
        let deadline = start + timeout;
        assert!(writeback.due(start));
        // The first answer only sets where the count stands.
        let deadline = writeback.observe(start, Some(100), deadline);
        assert_eq!(deadline, start + timeout);
        assert!(!writeback.due(start + second / 2));
        // Writes go on: a whole timeout after the last one seen.
        let deadline = writeback.observe(start + 9 * second, Some(200), deadline);
        assert_eq!(deadline, start + 19 * second);
        // No answer and no writes keep the deadline.
        let deadline = writeback.observe(start + 10 * second, None, deadline);
        let deadline = writeback.observe(start + 11 * second, Some(200), deadline);
        assert_eq!(deadline, start + 19 * second);
        // Never past the limit.
        let deadline = writeback.observe(start + 299 * second, Some(300), deadline);
        assert_eq!(deadline, start + super::WRITEBACK_LIMIT);
    }

    #[test]
    fn graphical_guests_get_at_least_the_desktop_shutdown_time() {
        let console = Duration::from_secs(10);
        assert_eq!(super::shutdown_timeout(console, false), console);
        assert_eq!(
            super::shutdown_timeout(console, true),
            super::GRAPHICAL_SHUTDOWN
        );
        let long = Duration::from_secs(90);
        assert_eq!(super::shutdown_timeout(long, true), long);
    }
    use super::*;

    #[test]
    fn a_normal_stop_is_clean_whether_or_not_the_acknowledgement_won_the_race() {
        assert_eq!(final_state(false, true, false, true), "clean");
        assert_eq!(final_state(false, false, true, true), "clean");
    }

    #[test]
    fn only_forced_or_failed_exits_are_not_clean() {
        assert_eq!(final_state(true, true, false, true), "forced");
        assert_eq!(final_state(false, false, true, false), "unexpected-exit");
        assert_eq!(final_state(false, true, false, false), "unexpected-exit");
        assert_eq!(final_state(false, false, false, true), "unexpected-exit");
    }
}
