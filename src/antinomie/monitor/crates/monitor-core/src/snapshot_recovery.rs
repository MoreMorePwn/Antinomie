//! Snapshot transactions run on the backend owner. Disk artifacts are owned by
//! the store; restored guest identities live in fresh, immutable archive namespaces.
use super::*;
use crate::{capture_processes::CaptureProcess, snapshots};
use serde::{Deserialize, Serialize};

const RESUME_TIMEOUT_MS: i32 = 10_000;
const RESUME_BOUNDARY: &str = "snapshot/reconnect boundary: parser and terminal presentation restarted; unresolved command outcomes and observation tails are incomplete";

#[derive(Serialize, Deserialize)]
struct HostCheckpoint {
    schema: u32,
    source_boot_id: String,
    boot_bundle_identity: Option<String>,
    disk_bundle_identity: Option<String>,
    runs: Vec<RunSummary>,
    captures: Vec<CaptureCheckpoint>,
}
#[derive(Serialize, Deserialize)]
struct CaptureCheckpoint {
    summary: CaptureSummary,
    stream_id: Option<u64>,
    processes: Vec<CaptureProcess>,
}
impl HostCheckpoint {
    fn validate(&self, vm: &VmConfig, bundle: &Bundle, disk_bundle: &Bundle) -> Result<(), String> {
        if self.schema != 1
            || self.source_boot_id.is_empty()
            || self.source_boot_id.len() > 128
            || self.runs.len() > 4096
            || self.captures.len() > OBSERVATION_RETAINED
            || self.boot_bundle_identity != bundle.base_identity
            || self.disk_bundle_identity != disk_bundle.base_identity
        {
            return Err("host checkpoint schema, identity or context bounds mismatch".into());
        }
        let mut roots = std::collections::BTreeSet::new();
        let mut sessions = std::collections::BTreeSet::new();
        for run in &self.runs {
            if run.vm_id != vm.id
                || run.root_task_cookie == 0
                || run.session_id == 0
                || !roots.insert(run.root_task_cookie)
                || !sessions.insert(run.session_id)
            {
                return Err("host checkpoint contains invalid run identities".into());
            }
        }
        let mut cookies = std::collections::BTreeSet::new();
        for capture in &self.captures {
            if capture.summary.vm_id != vm.id
                || capture.summary.capture_cookie == 0
                || !cookies.insert(capture.summary.capture_cookie)
                || capture.processes.len() > 65_536
                || capture.stream_id == Some(0)
            {
                return Err("host checkpoint contains invalid capture identities or bounds".into());
            }
        }
        Ok(())
    }
}
struct RestoredGuest {
    process: VmProcess,
    transport: Transport,
}
impl Session {
    fn host_checkpoint(&self) -> Result<serde_json::Value, String> {
        serde_json::to_value(HostCheckpoint {
            schema: 1,
            source_boot_id: self.boot_id.clone(),
            boot_bundle_identity: self.bundle.base_identity.clone(),
            disk_bundle_identity: self.disk_bundle.base_identity.clone(),
            runs: self.runs.values().map(|run| run.summary.clone()).collect(),
            captures: self
                .captures
                .values()
                .map(|capture| CaptureCheckpoint {
                    summary: capture.summary.clone(),
                    stream_id: capture.stream_id,
                    processes: capture.processes.list(),
                })
                .collect(),
        })
        .map_err(|error| error.to_string())
    }
    fn restored(
        options: &BackendOptions,
        vm: VmConfig,
        bundle: Bundle,
        disk_bundle: Bundle,
        guest: RestoredGuest,
        checkpoint: HostCheckpoint,
        snapshot_id: Option<&str>,
    ) -> Result<Self, String> {
        let RestoredGuest { process, transport } = guest;
        checkpoint.validate(&vm, &bundle, &disk_bundle)?;
        let boot_id = storage::unique_id();
        let boot_dir = crate::locations::locations(options, &vm.id)?
            .recording_directory
            .join("boots")
            .join(&boot_id);
        let capture_dir = boot_dir.join("unassigned");
        let mut capture = RawCapture::new(capture_dir.clone(), options.capture_quota_size)?;
        let mut assembler = Assembler::new(capture_dir.join("objects"), options.capture_quota_size)
            .map_err(|error| error.to_string())?;
        assembler.set_event_table(vm.transport.event_table as usize);
        capture.manifest(&vm, &bundle, &disk_bundle, "snapshot-resume-pending")?;
        storage::atomic_json(
            &boot_dir.join("resume-boundary.json"),
            &serde_json::json!({
                "format":1, "snapshot_id":snapshot_id, "source_boot_id":checkpoint.source_boot_id,
                "boot_id":boot_id, "issue":RESUME_BOUNDARY,
                "replayed_commands":false, "network_capture_resumed":false
            }),
        )?;
        let mut runs = BTreeMap::new();
        for mut summary in checkpoint.runs {
            let cookie = summary.root_task_cookie;
            if cookie == 0 || summary.session_id == 0 || runs.contains_key(&cookie) {
                return Err("host checkpoint contains duplicate or zero run identities".into());
            }
            summary.id = storage::unique_id();
            summary.vm_id = vm.id.clone();
            summary.boot_id = boot_id.clone();
            summary.directory = boot_dir.join("runs").join(&summary.id);
            summary.analysis = None;
            // Guest RUN_STATUS reconciles execution after the attachment is ready.
            summary.state = RunState::Unknown;
            let mut run = ProgramRun::new(summary, options.capture_quota_size)?;
            run.boot_bundle_identity = bundle.base_identity.clone();
            run.disk_base_identity = disk_bundle.base_identity.clone();
            run.execution_generation = run
                .summary
                .execution
                .as_ref()
                .map_or(0, |execution| execution.generation);
            run.assembler
                .set_event_table(vm.transport.event_table as usize);
            storage::atomic_json(
                &run.summary.directory.join("resume-boundary.json"),
                &serde_json::json!({"issue":RESUME_BOUNDARY}),
            )?;
            runs.insert(cookie, run);
        }
        let mut captures = BTreeMap::new();
        let mut cookies = std::collections::BTreeSet::new();
        for saved in checkpoint.captures {
            let mut summary = saved.summary;
            if summary.capture_cookie == 0
                || !cookies.insert(summary.capture_cookie)
                || saved.processes.len() > 65_536
            {
                return Err(
                    "host checkpoint contains invalid capture identities or process bounds".into(),
                );
            }
            summary.id = storage::unique_id();
            summary.vm_id = vm.id.clone();
            summary.boot_id = boot_id.clone();
            if let CaptureScope::Process { root } = &mut summary.scope {
                root.boot_id = boot_id.clone();
            }
            summary.directory = boot_dir.join("captures").join(&summary.id);
            summary.incomplete_reason = Some(RESUME_BOUNDARY.into());
            let mut capture = CaptureSession::new(summary, options.capture_quota_size)?;
            capture.stream_id = saved.stream_id;
            capture.processes.restore_baseline(saved.processes);
            capture
                .assembler
                .set_event_table(vm.transport.event_table as usize);
            capture.persist_summary()?;
            captures.insert(capture.summary.id.clone(), capture);
        }
        Ok(Self {
            analysis: crate::analysis::jobs::Jobs::with_tools(crate::analysis_tools::tools_dir(
                &options.data_dir,
            )),
            transport,
            process,
            capture,
            assembler,
            vm,
            bundle,
            disk_bundle,
            runs,
            captures,
            pending_capture_id: None,
            boot_id,
            pending: VecDeque::new(),
            pending_len: 0,
            pending_overflow: false,
            terminal_cursor: 0,
            late_reads: BTreeMap::new(),
            last_process_save: Instant::now(),
            network_bytes_done: 0,
            network_bytes: 0,
            last_network_check: Instant::now(),
            last_memory_check: Instant::now(),
            telemetry_busy: false,
            shed: Shed::default(),
            status_cursor: 0,
            last_status_query: Instant::now() - Duration::from_secs(1),
            persisted_packets: 0,
            kernel_probe: KernelProbe::Due(Instant::now()),
        })
    }
    fn forget_unanswered(&mut self) {
        for cookie in std::mem::take(&mut self.late_reads).into_values() {
            if let Some(run) = self.runs.get_mut(&cookie) {
                run.terminal_reads_unanswered = run.terminal_reads_unanswered.saturating_add(1);
            }
        }
        self.pending_capture_id = None;
    }
}
impl Worker {
    pub(super) fn snapshot_vm(&self, id: &str) -> Result<VmConfig, String> {
        self.snapshot
            .vms
            .iter()
            .find(|vm| vm.id == id)
            .cloned()
            .ok_or_else(|| "unknown VM".into())
    }
    pub(super) fn refresh_vm_snapshots(&mut self, id: &str) -> Result<(), String> {
        let vm = self.snapshot_vm(id)?;
        let mut tree = snapshots::list(&self.options, &vm)?;
        let recovery_required = snapshots::recovery_required(&self.options, &vm)?;
        let running = self.snapshot.active_vm.as_deref() == Some(id);
        let mut full = false;
        if running && let Some(session) = self.session.as_mut() {
            // A failed transport can still be reconnected explicitly; never infer readiness.
            full = session.transport.stats().is_ok_and(|stats| stats.abi >= 9);
        }
        let available = (self.session.is_none() || running) && !recovery_required;
        tree.capabilities = VmSnapshotCapabilities {
            can_create_disk: available,
            can_create_full: full && available,
            can_restore: available,
            reason: (!full).then(|| {
                if running {
                    "Full snapshots require a connected guest built for Antinomie 0.5.0 or newer"
                        .into()
                } else {
                    "Start a resume-capable guest to save RAM and CPU state".into()
                }
            }),
        };
        if recovery_required {
            tree.capabilities.reason = Some("Stop and restart this VM to recover the interrupted disk operation before changing snapshots".into());
        } else if !available {
            tree.capabilities.reason = Some("Stop the other VM before changing snapshots".into());
        }
        let saved = snapshots::compatibilities(&self.options, &vm)?;
        let fingerprint = crate::locations::boot_bundle(&self.options, vm.base_identity.as_deref())
            .and_then(|bundle| VmProcess::compatibility_for(&self.options, &vm, &bundle));
        for node in &mut tree.nodes {
            if node.mode == VmSnapshotMode::Full {
                node.compatible = node.compatible
                    && fingerprint.as_ref().is_ok_and(|current| {
                        saved.get(&node.id).and_then(Option::as_ref) == Some(current)
                    });
                if !node.compatible && node.compatibility_note.is_none() {
                    node.compatibility_note = Some(
                        "Resume configuration or artifacts differ; restore by rebooting from disk"
                            .into(),
                    );
                }
            }
        }
        self.snapshot.vm_snapshot_trees.insert(id.to_owned(), tree);
        Ok(())
    }
    fn snapshot_stage(&mut self, vm_id: &str, stage: &str) {
        self.snapshot.vm_snapshot_progress = Some(VmSnapshotProgress {
            vm_id: vm_id.into(),
            stage: stage.into(),
        });
        self.publish();
    }
    pub(super) fn create_vm_snapshot(
        &mut self,
        id: &str,
        request: SnapshotRequest,
    ) -> Result<String, String> {
        let result = self.take_vm_snapshot(id, &request);
        self.snapshot.vm_snapshot_progress = None;
        if let Err(error) = self.refresh_vm_snapshots(id) {
            self.snapshot.last_error = Some(error);
        }
        result.map(|node| format!("Snapshot {} saved", node.name))
    }
    fn take_vm_snapshot(
        &mut self,
        id: &str,
        request: &SnapshotRequest,
    ) -> Result<VmCheckpoint, String> {
        let vm = self.snapshot_vm(id)?;
        let running = self.snapshot.active_vm.as_deref() == Some(id);
        if self.session.is_some() && !running {
            return Err("stop the other VM before saving a snapshot".into());
        }
        if request.mode == VmSnapshotMode::Full && !running {
            return Err("full snapshots require a running guest".into());
        }
        let full = request.mode == VmSnapshotMode::Full;
        if full
            && !self
                .session
                .as_mut()
                .ok_or("VM is stopped")?
                .transport
                .stats()
                .is_ok_and(|stats| stats.abi >= 9)
        {
            return Err("full snapshots require a connected ABI9 guest for Antinomie 0.5.0".into());
        }
        if running && self.snapshot.network_capture.is_some() {
            self.stop_network_capture()?;
        }
        self.snapshot_stage(id, "Preparing checkpoint");
        let consistency = if full {
            VmSnapshotConsistency::Paused
        } else if running {
            VmSnapshotConsistency::CrashConsistent
        } else {
            VmSnapshotConsistency::Stopped
        };
        if full {
            let session = self.session.as_ref().ok_or("VM is stopped")?;
            let checkpoint: HostCheckpoint = serde_json::from_value(session.host_checkpoint()?)
                .map_err(|error| error.to_string())?;
            checkpoint.validate(&vm, &session.bundle, &session.disk_bundle)?;
        }
        let prepared = snapshots::prepare_take(&self.options, &vm, request, consistency)?;
        if !running {
            return snapshots::commit_take(&self.options, &vm, prepared, None, None);
        }
        self.snapshot_stage(
            id,
            if full {
                "Saving disk, RAM and CPU state"
            } else {
                "Saving disk checkpoint"
            },
        );
        let checkpoint_id = prepared.id.clone();
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let was_running = session.process.pause()?;
        if let Err(error) = session.transport.suspend_heartbeats() {
            if was_running {
                session.process.resume()?;
            }
            return Err(error);
        }
        // From suspension through serialization, no transport call may write shared RAM.
        let operation = (|| {
            storage::flush_json();
            crate::writer::barrier();
            let host = if full {
                Some(session.host_checkpoint()?)
            } else {
                None
            };
            let compatibility = if full {
                Some(VmProcess::compatibility_for(
                    &self.options,
                    &vm,
                    &session.bundle,
                )?)
            } else {
                None
            };
            session.process.pivot_disk(&prepared.active_disk)?;
            if full {
                session.process.save_state(
                    prepared
                        .memory_path
                        .as_deref()
                        .ok_or("missing state artifact path")?,
                )?;
            }
            snapshots::commit_take(&self.options, &vm, prepared, compatibility, host)
        })();
        let resume = (|| -> Result<(), String> {
            if full {
                session.forget_unanswered();
                session.transport.begin_resume()?;
                session.process.resume()?;
                let report = session.transport.finish_resume(RESUME_TIMEOUT_MS)?;
                storage::atomic_json(
                    &session
                        .capture
                        .directory
                        .join(format!("snapshot-attachment-{checkpoint_id}.json")),
                    &serde_json::json!({
                        "attachment":report.attachment, "sequence_floor":report.sequence_floor,
                        "discarded_request_bytes":report.discarded_request_bytes,
                        "discarded_reply_bytes":report.discarded_reply_bytes,
                        "unresolved_side_effects_retried":false
                    }),
                )?;
                if !was_running {
                    session.process.pause()?;
                }
            } else {
                if was_running {
                    session.process.resume()?;
                }
                session.transport.resume_heartbeats()?;
            }
            Ok(())
        })();
        if let Err(error) = resume {
            self.snapshot.state = VmState::Failed;
            return Err(format!(
                "checkpoint result {:?}; guest recovery failed: {error}",
                operation.as_ref().err()
            ));
        }
        // Pending journal remains authoritative until the next stopped recovery on failure.
        operation
    }
    pub(super) fn restore_vm_snapshot(
        &mut self,
        id: &str,
        snapshot_id: &str,
        boot_from_disk: bool,
        save_current: Option<SnapshotRequest>,
    ) -> Result<String, String> {
        let result = self.restore_vm_snapshot_inner(id, snapshot_id, boot_from_disk, save_current);
        self.snapshot.vm_snapshot_progress = None;
        if let Err(error) = self.refresh_vm_snapshots(id) {
            self.snapshot.last_error = Some(error);
        }
        result
    }
    fn restore_vm_snapshot_inner(
        &mut self,
        id: &str,
        snapshot_id: &str,
        boot_from_disk: bool,
        save_current: Option<SnapshotRequest>,
    ) -> Result<String, String> {
        let vm = self.snapshot_vm(id)?;
        if self.session.is_some() && self.snapshot.active_vm.as_deref() != Some(id) {
            return Err("stop the other VM before restoring".into());
        }
        // Validate the target before saving or touching current state.
        let tree = snapshots::list(&self.options, &vm)?;
        let node = tree
            .nodes
            .iter()
            .find(|node| node.id == snapshot_id && !node.deleted)
            .ok_or("unknown snapshot")?;
        let resume = node.mode == VmSnapshotMode::Full && !boot_from_disk;
        let bundle = crate::locations::boot_bundle(&self.options, vm.base_identity.as_deref())?;
        let fingerprint = if resume {
            Some(VmProcess::compatibility_for(&self.options, &vm, &bundle)?)
        } else {
            None
        };
        if resume && snapshots::compatibility(&self.options, &vm, snapshot_id)? != fingerprint {
            return Err("full snapshot requires the original QEMU, hardware configuration and kernel; choose disk reboot".into());
        }
        snapshots::preflight_restore(&self.options, &vm, snapshot_id, !resume)?;
        let disk_bundle: Bundle =
            storage::read_json(&storage::vm_dir(&self.options, id)?.join("bundle.json"))?;
        disk_bundle.verify_installed()?;
        let checkpoint = if resume {
            let value = snapshots::host_checkpoint(&self.options, &vm, snapshot_id)?
                .ok_or("snapshot has no host context")?;
            let saved: HostCheckpoint = serde_json::from_value(value)
                .map_err(|error| format!("invalid host checkpoint: {error}"))?;
            saved.validate(&vm, &bundle, &disk_bundle)?;
            Some(saved)
        } else {
            None
        };
        if let Some(request) = save_current {
            self.take_vm_snapshot(id, &request).map_err(|error| {
                format!("current state was not saved: {error}; restore cancelled")
            })?;
        }
        if self.snapshot.network_capture.is_some() {
            self.stop_network_capture()?;
        }
        let prepared = snapshots::prepare_restore(&self.options, &vm, snapshot_id, !resume)?;
        if (prepared.mode == VmSnapshotMode::Full) != resume
            || (resume && prepared.compatibility != fingerprint)
        {
            snapshots::cancel_restore(&self.options, &vm, &prepared)?;
            return Err("restore candidate capability changed".into());
        }
        let _transition = self.begin_guest_transition()?;
        self.snapshot_stage(id, "Preparing snapshot recovery");
        if let Some(mut old) = self.session.take() {
            let finalize = old.finalize("snapshot-branch-sealed", &mut self.snapshot);
            let stop = old.process.force_stop();
            drop(old);
            if let Err(error) = finalize.and(stop) {
                self.snapshot.active_vm = None;
                self.snapshot.state = VmState::Stopped;
                let cleanup = snapshots::cancel_restore(&self.options, &vm, &prepared);
                return Err(format!("{error}; restore cancellation {:?}", cleanup.err()));
            }
        }
        self.snapshot.active_vm = None;
        self.snapshot.state = VmState::Starting;
        let recovery = (|| -> Result<Option<Session>, String> {
            if !resume {
                snapshots::commit_restore(&self.options, &vm, &prepared)?;
                return Ok(None);
            }
            let checkpoint = checkpoint.ok_or("snapshot has no host context")?;
            let effective = vm.clone();
            let process = VmProcess::launch_incoming(
                &self.options,
                &effective,
                &bundle,
                &prepared.active_disk,
            )?;
            process.load_state(
                prepared
                    .memory_path
                    .as_deref()
                    .ok_or("snapshot has no memory state")?,
            )?;
            process.verify_ram_layout()?;
            let transport =
                Transport::open_pending(&process.ram_path, process.ram_size, process.bootstrap)?;
            let mut session = Session::restored(
                &self.options,
                effective,
                bundle,
                disk_bundle,
                RestoredGuest { process, transport },
                checkpoint,
                Some(snapshot_id),
            )?;
            // Namespace exists and request is published before CPUs run. A short
            // handshake run is staged on the candidate child, never the old future.
            session.process.resume()?;
            session.transport.finish_resume(RESUME_TIMEOUT_MS)?;
            session
                .transport
                .set_send_wait(session.vm.transport.send_wait_us())?;
            if session.vm.transport.lossless {
                session
                    .transport
                    .set_host_timeout(LOSSLESS_HOST_TIMEOUT_MS)?;
            }
            session.process.pause()?;
            session.transport.suspend_heartbeats()?;
            snapshots::commit_restore(&self.options, &vm, &prepared)?;
            session.process.resume()?;
            session.transport.resume_heartbeats()?;
            session.capture.manifest(
                &session.vm,
                &session.bundle,
                &session.disk_bundle,
                "snapshot-resumed",
            )?;
            Ok(Some(session))
        })();
        match recovery {
            Ok(Some(session)) => {
                self.snapshot.health = Health::default();
                self.snapshot.events.clear();
                self.snapshot.captures.clear();
                self.snapshot.capture_events.clear();
                self.snapshot.capture_processes.clear();
                self.snapshot.process_page = None;
                self.snapshot.guest_kernel = None;
                self.snapshot.network_capture = None;
                self.snapshot.active_vm = Some(id.into());
                self.snapshot.state = VmState::Running;
                self.snapshot.boot_id = Some(session.boot_id.clone());
                self.snapshot.capture_dir = Some(session.capture.directory.clone());
                self.snapshot.serial_log = Some(session.process.runtime_dir.join("serial.log"));
                session.update_runs(&mut self.snapshot);
                session.update_captures(&mut self.snapshot);
                self.session = Some(session);
                self.stopping.store(false, Ordering::Relaxed);
                Ok("Snapshot resumed in a new recording timeline".into())
            }
            Ok(None) => {
                self.snapshot.state = VmState::Stopped;
                self.start(id)?;
                Ok("Snapshot disk restored; guest booted in a new timeline".into())
            }
            Err(error) => {
                let cleanup = snapshots::cancel_restore(&self.options, &vm, &prepared);
                self.snapshot.active_vm = None;
                self.snapshot.state = VmState::Stopped;
                Err(format!(
                    "snapshot restore failed: {error}; disk branches retained; check snapshot recovery status before restarting; cleanup {:?}",
                    cleanup.err()
                ))
            }
        }
    }
    pub(super) fn reconnect_transport(&mut self) -> Result<String, String> {
        if self.snapshot.network_capture.is_some() {
            self.stop_network_capture()?;
        }
        let _transition = self.begin_guest_transition()?;
        let mut old = self.session.take().ok_or("VM is stopped")?;
        let report = match old.transport.reconnect(RESUME_TIMEOUT_MS) {
            Ok(report) => report,
            Err(error) => {
                self.session = Some(old);
                return Err(error);
            }
        };
        old.forget_unanswered();
        let checkpoint = match old
            .host_checkpoint()
            .and_then(|value| serde_json::from_value(value).map_err(|error| error.to_string()))
        {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.session = Some(old);
                return Err(error);
            }
        };
        if let Err(error) = old.finalize("reconnect-boundary", &mut self.snapshot) {
            self.session = Some(old);
            return Err(error);
        }
        let id = old.vm.id.clone();
        let fresh = match Session::restored(
            &self.options,
            old.vm,
            old.bundle,
            old.disk_bundle,
            RestoredGuest {
                process: old.process,
                transport: old.transport,
            },
            checkpoint,
            None,
        ) {
            Ok(fresh) => fresh,
            Err(error) => {
                self.snapshot.active_vm = None;
                self.snapshot.state = VmState::Stopped;
                return Err(error);
            }
        };
        let receipt = storage::atomic_json(
            &fresh.capture.directory.join("reconnect.json"),
            &serde_json::json!({
                "attachment":report.attachment, "sequence_floor":report.sequence_floor,
                "discarded_request_bytes":report.discarded_request_bytes,
                "discarded_reply_bytes":report.discarded_reply_bytes, "issue":RESUME_BOUNDARY
            }),
        );
        self.snapshot.health = Health::default();
        self.snapshot.events.clear();
        self.snapshot.capture_events.clear();
        self.snapshot.capture_processes.clear();
        self.snapshot.process_page = None;
        self.snapshot.network_capture = None;
        self.snapshot.boot_id = Some(fresh.boot_id.clone());
        self.snapshot.capture_dir = Some(fresh.capture.directory.clone());
        self.snapshot.state = VmState::Running;
        fresh.update_runs(&mut self.snapshot);
        fresh.update_captures(&mut self.snapshot);
        self.session = Some(fresh);
        receipt?;
        self.refresh_vm_snapshots(&id)?;
        Ok("Transport reconnected in a new recording timeline; unresolved commands were not retried".into())
    }
}
