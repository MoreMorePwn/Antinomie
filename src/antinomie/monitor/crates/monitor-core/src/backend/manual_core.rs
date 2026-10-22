// SPDX-License-Identifier: GPL-3.0-only
//! Independent manual capture ownership. Admission is sent once, after a
//! durable nonce journal; uncertain admission is reconciled only by LOOKUP.
use super::{
    core_sink::{Action, Kind, Sink},
    core_stream::{self, Assembled},
    process_core::CoreStatus,
    *,
};
use crate::core_limits::{
    CORE_MAX_SUPPORTED, CoreLimits, CoreOutcome, CoreReason, CoreReasonCode, guest_reason,
};
use crate::{ProcessCoreCapture, ProcessCorePhase, ProcessCoreRequest, core_capture};
use sha2::{Digest, Sha256};
const STATUS: u32 = 0x1060;
const RELEASE: u32 = 0x1062;
const IO_TIMEOUT: Duration = Duration::from_millis(50);
fn terminal(state: u32) -> bool {
    matches!(state, 3..=6)
}
fn missing_lookup(opcode: u32, error: &RequestError) -> bool {
    opcode == control::CORE_LOOKUP && matches!(error, RequestError::Rejected { status: -3, .. })
}
fn new_id() -> String {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{time:020}-{}", storage::unique_id())
}

pub(super) struct Owner {
    pub summary: ProcessCoreCapture,
    sink: Sink,
    initialized: bool,
    admission_sent: bool,
    lookup_required: bool,
    status: Option<CoreStatus>,
    known_absent: bool,
    cancel_requested: bool,
    cancel_sent: bool,
    release_attempted: bool,
    desired: Option<RunArtifactState>,
    generation: u64,
    reserved_len: u64,
    /// Bytes written to disk so far; `summary.stored_size` also counts holes.
    allocated: u64,
    checked: Option<Instant>,
    activity: Instant,
    pub done: bool,
    disk_finished: bool,
    disk_failed: bool,
    /// The copy to the host has been checked against the host disk and quota.
    preflighted: bool,
    copy_started: Option<Instant>,
}
impl Owner {
    fn new(request: ProcessCoreRequest, directory: PathBuf, id: String) -> Self {
        let digest = Sha256::digest(id.as_bytes());
        let nonce = [
            u64::from_le_bytes(digest[..8].try_into().expect("digest extent")),
            u64::from_le_bytes(digest[8..16].try_into().expect("digest extent")),
        ];
        Self {
            summary: ProcessCoreCapture {
                format: 1,
                id,
                vm_id: request.vm_id,
                boot_id: request.target.boot_id.clone(),
                source_run_id: request.source_run_id,
                restored_from_capture_id: None,
                target: request.target,
                directory: directory.clone(),
                file: None,
                state: RunArtifactState::Queued,
                phase: ProcessCorePhase::Admission,
                stored_size: 0,
                guest_size: None,
                sha256: None,
                pause_released: None,
                max_size: request.max_size,
                timeout_ms: request.timeout_ms,
                nonce,
                guest_handle: None,
                guest_status: None,
                issue: None,
                requested_max_size: None,
                guest_max_size: None,
                stored_bytes: None,
                expected_size: None,
                allocated_size: None,
                reason: None,
            },
            sink: Sink::new(directory),
            initialized: false,
            admission_sent: false,
            lookup_required: false,
            status: None,
            known_absent: false,
            cancel_requested: false,
            cancel_sent: false,
            release_attempted: false,
            desired: None,
            generation: 0,
            reserved_len: 0,
            allocated: 0,
            checked: None,
            activity: Instant::now(),
            done: false,
            disk_finished: false,
            disk_failed: false,
            preflighted: false,
            copy_started: None,
        }
    }
    /// The first reason sticks: a later one is usually its consequence.
    fn set_reason(&mut self, code: CoreReasonCode, errno: Option<i32>, text: impl Into<String>) {
        if self.summary.reason.is_none() {
            self.summary.reason = Some(CoreReason::new(code, errno, text));
        }
    }
    /// A terminal guest status is being copied to the host.
    pub(super) fn transferring(&self) -> bool {
        !self.done
            && self.desired.is_none()
            && self.initialized
            && self
                .status
                .as_ref()
                .is_some_and(|status| matches!(status.state, 3 | 4))
    }
    fn issue(&mut self, issue: impl Into<String>) {
        self.summary.issue = Some(issue.into().chars().take(2048).collect());
    }
    fn fail_disk(&mut self, error: String) {
        self.disk_failed = true;
        self.disk_finished = true;
        self.cancel_requested = true;
        self.sink.seal();
        if !self.admission_sent {
            self.known_absent = true;
        }
        self.finish(RunArtifactState::Failed, error);
        self.summary.state = RunArtifactState::Failed;
        self.done = !self.guest_busy();
        self.summary.phase = if self.done {
            ProcessCorePhase::Finished
        } else if self.summary.guest_handle.is_some() {
            ProcessCorePhase::GuestCapture
        } else {
            ProcessCorePhase::UnknownAdmission
        };
    }
    fn finish(&mut self, state: RunArtifactState, issue: impl Into<String>) {
        let issue = issue.into();
        if self.desired == Some(state)
            && (issue.is_empty() || self.summary.issue.as_deref() == Some(&issue))
        {
            return;
        }
        if state != RunArtifactState::Complete {
            self.sink.seal();
        }
        self.desired = Some(state);
        self.generation = self.generation.saturating_add(1);
        self.summary.phase = if self.guest_busy() {
            if self.summary.guest_handle.is_some() {
                ProcessCorePhase::GuestCapture
            } else if self.admission_sent {
                ProcessCorePhase::UnknownAdmission
            } else {
                ProcessCorePhase::Admission
            }
        } else {
            ProcessCorePhase::Seal
        };
        if !issue.is_empty() {
            self.issue(issue);
        }
    }
    fn metadata(&self, final_state: Option<RunArtifactState>) -> Result<serde_json::Value, String> {
        let mut summary = self.summary.clone();
        if let Some(state) = final_state {
            summary.state = state;
            summary.phase = ProcessCorePhase::Finished;
        }
        let mut value = serde_json::to_value(summary).map_err(|error| error.to_string())?;
        value["incomplete"] = (final_state != Some(RunArtifactState::Complete)).into();
        value["copy_ms"] = self
            .copy_started
            .map(|started| started.elapsed().as_millis() as u64)
            .into();
        value["policy"] =
            "native x86-64; resident-only no-fault pages; Linux filtered mappings".into();
        value["progress_limit"] =
            "in-progress metadata is a checkpoint prefix; final size/hash require the durable seal"
                .into();
        Ok(value)
    }
    /// The recording quota ended the copy before the core was whole.
    fn quota_error(&mut self, size: u64) -> String {
        let text = format!(
            "recording quota exhausted during manual core transfer; the core was cut at {} of {size} bytes",
            self.summary.stored_size
        );
        self.set_reason(CoreReasonCode::Quota, None, text.clone());
        text
    }
    pub(super) fn guest_busy(&self) -> bool {
        !self.done
            && !self.known_absent
            && (!self.admission_sent || self.summary.pause_released != Some(true))
    }
    fn snapshot_busy(&self) -> bool {
        self.guest_busy()
            || (!self.done
                && self.cancel_requested
                && !self.release_attempted
                && !self.known_absent)
    }
    pub(super) fn checkpoint(&self) -> Option<ProcessCoreCapture> {
        (!self.done
            && !self.release_attempted
            && self.desired.is_none()
            && self.summary.pause_released == Some(true)
            && self
                .status
                .as_ref()
                .is_some_and(|status| matches!(status.state, 3 | 4)))
        .then(|| self.summary.clone())
    }
    pub(super) fn restored(
        saved: &ProcessCoreCapture,
        vm_id: &str,
        boot_id: &str,
        boot_dir: &std::path::Path,
        run_id: Option<String>,
    ) -> Result<Self, String> {
        validate_saved(saved)?;
        let mut request = ProcessCoreRequest {
            vm_id: vm_id.into(),
            target: saved.target.clone(),
            source_run_id: run_id,
            max_size: saved.max_size,
            timeout_ms: saved.timeout_ms,
        };
        request.target.boot_id = boot_id.into();
        let id = new_id();
        let mut owner = Self::new(request, boot_dir.join("core-captures").join(&id), id);
        owner.summary.restored_from_capture_id = Some(saved.id.clone());
        owner.summary.nonce = saved.nonce;
        owner.summary.guest_handle = saved.guest_handle;
        owner.summary.phase = ProcessCorePhase::GuestCapture;
        owner.admission_sent = true;
        owner.lookup_required = true;
        owner.issue(
            "read-only checkpoint adoption in a fresh recording; no capture request is replayed",
        );
        Ok(owner)
    }
}
pub(super) fn validate_saved(saved: &ProcessCoreCapture) -> Result<(), String> {
    core_capture::validate_request(&ProcessCoreRequest {
        vm_id: saved.vm_id.clone(),
        target: saved.target.clone(),
        source_run_id: saved.source_run_id.clone(),
        max_size: saved.max_size,
        timeout_ms: saved.timeout_ms,
    })?;
    if saved.format != 1
        || saved.id.is_empty()
        || saved.id.len() > 128
        || saved.boot_id != saved.target.boot_id
        || saved.nonce == [0, 0]
        || saved.guest_handle.is_none_or(|id| id == 0)
        || saved.pause_released != Some(true)
        || saved.stored_size > core_capture::LOGICAL_LIMIT
        || saved
            .guest_size
            .is_none_or(|size| size > core_capture::LOGICAL_LIMIT)
    {
        return Err("manual core checkpoint lacks bounded resumed ownership".into());
    }
    Ok(())
}
impl Session {
    pub(super) fn start_manual_core(
        &mut self,
        mut request: ProcessCoreRequest,
    ) -> Result<String, String> {
        core_capture::validate_request(&request)?;
        CoreLimits::check_known(
            self.core_limits,
            u64::from(request.max_size),
            request.timeout_ms,
        )?;
        let limits = self.core_limits.unwrap_or(CoreLimits::LEGACY);
        if request.vm_id != self.vm.id || request.target.boot_id != self.boot_id {
            return Err("manual core target belongs to another VM or boot".into());
        }
        if self
            .manual_cores
            .values()
            .filter(|owner| !owner.done)
            .count()
            + self
                .run_artifacts
                .values()
                .filter(|owner| owner.core.is_some())
                .count()
            >= core_capture::ACTIVE_LIMIT
        {
            return Err("four core acquisitions are already pending; wait or cancel one".into());
        }
        if self.manual_record_count >= core_capture::RECORD_LIMIT {
            return Err("this boot has reached the 4096 manual-core record limit".into());
        }
        if let Some(id) = &request.source_run_id {
            let cookie = self.run_cookie(id)?;
            let run = self.runs.get(&cookie).ok_or("source run is unavailable")?;
            if run.summary.root_task_cookie != request.target.task_cookie
                || run.summary.pid != request.target.tgid
            {
                return Err(
                    "manual core source run does not match the selected leader cookie and PID"
                        .into(),
                );
            }
        }
        if request.source_run_id.is_none() {
            request.source_run_id = self
                .runs
                .values()
                .find(|run| {
                    run.summary.vm_id == request.vm_id
                        && run.summary.boot_id == request.target.boot_id
                        && run.summary.root_task_cookie == request.target.task_cookie
                        && run.summary.pid == request.target.tgid
                })
                .map(|run| run.summary.id.clone());
        }
        let id = new_id();
        let boot_dir = self
            .capture
            .directory
            .parent()
            .ok_or("missing boot directory")?;
        let mut owner = Owner::new(
            request,
            boot_dir.join("core-captures").join(&id),
            id.clone(),
        );
        owner.summary.guest_max_size = Some(limits.max_size);
        self.manual_record_count += 1;
        self.manual_cores.insert(id.clone(), owner);
        Ok(format!(
            "Manual core {id} queued; target resumes before host saving completes"
        ))
    }
    pub(super) fn cancel_manual_core(&mut self, id: &str) -> Result<String, String> {
        let owner = self
            .manual_cores
            .get_mut(id)
            .ok_or("manual core is not owned by this VM boot")?;
        if owner.done {
            return Err("manual core is already sealed".into());
        }
        owner.cancel_requested = true;
        owner.activity = Instant::now();
        owner.set_reason(CoreReasonCode::Canceled, None, "canceled by the user");
        owner.finish(RunArtifactState::Interrupted,"cancellation requested; waiting for guest pause release and retained-prefix durability");
        owner.issue("cancellation requested; waiting for guest pause release and retained-prefix durability");
        Ok("Manual core cancellation queued; specimen is not terminated".into())
    }
    pub(super) fn manual_snapshot_guard(&self) -> Result<(), String> {
        if self.manual_cores.values().any(Owner::snapshot_busy) {
            return Err("wait for manual core admission, process pause release, or canceled-handle cleanup before taking or restoring a VM snapshot".into());
        }
        Ok(())
    }
    fn manual_status(
        &mut self,
        owner: &mut Owner,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<bool, String> {
        let opcode = if owner.lookup_required || owner.summary.guest_handle.is_none() {
            control::CORE_LOOKUP
        } else {
            STATUS
        };
        // Only a status by handle can carry the stored byte count.
        let extended = opcode == STATUS && self.core_limits.is_some_and(|l| l.stored_status);
        let args = if opcode == control::CORE_LOOKUP {
            control::core_lookup(&owner.summary.target, owner.summary.nonce)
        } else {
            control::core_status(
                owner
                    .summary
                    .guest_handle
                    .ok_or("manual core handle missing")?,
                extended,
            )
        };
        let reply = match self.request_typed(opcode, &args, snapshot, sender, IO_TIMEOUT) {
            Ok(reply) => reply,
            Err(RequestError::TimedOut(_))
                if owner.activity.elapsed() < Duration::from_secs(120) =>
            {
                return Ok(false);
            }
            Err(error) if missing_lookup(opcode, &error) => {
                owner.known_absent = true;
                owner.finish(RunArtifactState::Failed,format!("manual capture admission could not be confirmed; capture is not replayed: {}",error.into_message()));
                return Ok(false);
            }
            Err(error) => return Err(error.into_message()),
        };
        let id = u64_at(&reply, 0).map_err(|error| error.to_string())?;
        if owner
            .summary
            .guest_handle
            .is_some_and(|accepted| accepted != id)
        {
            return Err("manual core lookup returned a different accepted handle".into());
        }
        let status = CoreStatus::parse_manual(
            &reply,
            id,
            owner.summary.target.task_cookie,
            owner.summary.target.tgid,
            extended,
        )?;
        if status.size > core_capture::LOGICAL_LIMIT {
            return Err("manual core exceeded the longest extent a guest may report".into());
        }
        owner.summary.guest_handle = Some(id);
        owner.summary.guest_size = terminal(status.state).then_some(status.size);
        owner.summary.pause_released = Some(status.flags & 0x20 != 0);
        owner.summary.guest_status =
            Some(serde_json::to_value(&status).map_err(|error| error.to_string())?);
        if matches!(status.state, 1 | 2) && owner.desired.is_none() {
            owner.summary.phase = ProcessCorePhase::GuestCapture;
            owner.summary.state = RunArtifactState::InProgress;
        }
        owner.lookup_required = false;
        owner.activity = Instant::now();
        owner.status = Some(status);
        Ok(true)
    }
    fn manual_poll_io(&mut self, owner: &mut Owner) -> Result<(), String> {
        let Some(receipt) = owner.sink.poll()? else {
            return Ok(());
        };
        self.core_reserved_len = self.core_reserved_len.saturating_sub(owner.reserved_len);
        let delta = receipt
            .allocated
            .checked_sub(owner.allocated)
            .filter(|delta| *delta <= owner.reserved_len)
            .ok_or("manual core disk receipt exceeds reserved extent")?;
        owner.reserved_len = 0;
        self.core_stored_len = self.core_stored_len.saturating_add(delta);
        owner.allocated = receipt.allocated;
        owner.summary.stored_size = receipt.size;
        owner.summary.sha256 = Some(receipt.sha256);
        if receipt.has_file {
            owner.summary.file = Some(owner.summary.directory.join("process.elf"));
        }
        if receipt.kind == Kind::Init {
            owner.initialized = true;
        }
        owner.summary.allocated_size = Some(owner.allocated);
        if let Err(error) = receipt.result {
            owner.set_reason(CoreReasonCode::HostWrite, None, error.clone());
            owner.initialized = true;
            owner.cancel_requested = true;
            if receipt.kind == Kind::Finish {
                owner.fail_disk(error);
            } else {
                owner.finish(
                    if owner.summary.stored_size > 0 {
                        RunArtifactState::Partial
                    } else {
                        RunArtifactState::Failed
                    },
                    error,
                );
            }
        } else if receipt.kind == Kind::Finish && receipt.generation == owner.generation {
            owner.disk_finished = true;
            owner.summary.state = if owner.disk_failed {
                RunArtifactState::Failed
            } else {
                receipt
                    .final_state
                    .ok_or("manual core final disk state missing")?
            };
            owner.summary.phase = ProcessCorePhase::Finished;
            owner.done = !owner.guest_busy();
        } else {
            owner.activity = Instant::now();
        }
        Ok(())
    }
    fn manual_guest_step(
        &mut self,
        owner: &mut Owner,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        if owner.known_absent {
            return Ok(());
        }
        if !owner.admission_sent {
            if owner.desired.is_some() {
                owner.known_absent = true;
                return Ok(());
            }
            if owner.cancel_requested {
                owner.known_absent = true;
                owner.finish(
                    RunArtifactState::Interrupted,
                    "manual capture canceled before admission",
                );
                return Ok(());
            }
            let request = ProcessCoreRequest {
                vm_id: owner.summary.vm_id.clone(),
                target: owner.summary.target.clone(),
                source_run_id: owner.summary.source_run_id.clone(),
                max_size: owner.summary.max_size,
                timeout_ms: owner.summary.timeout_ms,
            };
            let args = control::core_capture(&request, owner.summary.nonce)?;
            owner.admission_sent = true;
            owner.activity = Instant::now();
            owner.summary.phase = ProcessCorePhase::UnknownAdmission;
            match self.request_typed(
                control::CORE_CAPTURE,
                &args,
                snapshot,
                sender,
                Duration::from_millis(100),
            ) {
                Ok(reply) => {
                    match control::acquisition_bounded(&reply, CORE_MAX_SUPPORTED) {
                        Ok((id, size)) if size > 0 && size == u64::from(owner.summary.max_size) => {
                            owner.summary.guest_handle = Some(id);
                            owner.summary.phase = ProcessCorePhase::GuestCapture;
                        }
                        Ok(_) => return Err("invalid manual core reservation".into()),
                        Err(error) => {
                            if reply.len() == 24
                                && u64_at(&reply, 0).ok() == Some(0)
                                && u64_at(&reply, 8).ok() == Some(0)
                                && u32_at(&reply, 20).ok() == Some(0)
                                && u32_at(&reply, 16)
                                    .is_ok_and(|status| (-4095..=-1).contains(&(status as i32)))
                            {
                                owner.known_absent = true;
                                owner.finish(RunArtifactState::Failed, error);
                            } else {
                                owner.lookup_required = true;
                                owner.issue(format!("malformed admission reply; only nonce lookup is permitted: {error}"));
                            }
                        }
                    }
                }
                Err(RequestError::Rejected { message: error, .. }) => {
                    owner.known_absent = true;
                    owner.finish(RunArtifactState::Failed, error);
                }
                Err(error) => {
                    owner.lookup_required = true;
                    owner.issue(format!(
                        "admission outcome unknown; only read-only lookup is allowed: {}",
                        error.into_message()
                    ));
                }
            }
            return Ok(());
        }
        if owner.status.as_ref().is_none_or(|status| status.state <= 2) || owner.lookup_required {
            self.manual_status(owner, snapshot, sender)?;
        }
        if owner.known_absent {
            return Ok(());
        }
        if owner.cancel_requested
            && !owner.cancel_sent
            && owner.summary.guest_handle.is_some()
            && owner.summary.pause_released != Some(true)
        {
            owner.cancel_sent = true;
            match self.request_typed(control::CORE_CANCEL,&control::with_session(owner.summary.guest_handle.ok_or("manual cancel handle missing")?),snapshot,sender,IO_TIMEOUT) {
                Ok(reply) if reply.is_empty()=>{},Ok(_)=>owner.issue("manual cancel reply malformed; cancellation is not replayed"),Err(error)=>owner.issue(format!("manual cancellation acknowledgement unavailable; cancellation is not replayed: {}",error.into_message())),
            }
            return Ok(());
        }
        let Some(status) = owner.status.as_ref() else {
            return Ok(());
        };
        if status.state <= 2 {
            return Ok(());
        }
        if owner.summary.pause_released != Some(true) {
            return Err("manual terminal core did not prove pause release".into());
        }
        if owner.cancel_requested || owner.desired.is_some() {
            if owner.desired.is_none() {
                owner.finish(
                    RunArtifactState::Interrupted,
                    "manual capture canceled; available host prefix retained",
                );
            }
            return Ok(());
        }
        if matches!(status.state, 5 | 6) {
            owner.finish(
                RunArtifactState::Failed,
                format!(
                    "manual guest capture unavailable/canceled (state {}, status {})",
                    status.state, status.status
                ),
            );
            return Ok(());
        }
        owner.summary.phase = ProcessCorePhase::Transfer;
        owner.summary.state = RunArtifactState::InProgress;
        let status = status.clone();
        let limits = self.core_limits.unwrap_or(CoreLimits::LEGACY);
        if !owner.preflighted {
            owner.preflighted = true;
            owner.copy_started = Some(Instant::now());
            self.manual_preflight(owner, &status)?;
        }
        if owner.summary.stored_size == status.size {
            let complete = status.state == 3 && status.flags & 8 == 0;
            let reason = guest_reason(&CoreOutcome {
                state: status.state,
                status: status.status,
                expected: status.expected_size,
                size: status.size,
                stored: status.stored,
                flags: status.flags,
                budget: u64::from(owner.summary.max_size),
                limits,
            });
            if let Some(reason) = reason {
                owner.summary.reason.get_or_insert(reason);
            }
            let issue = match (&owner.summary.reason, complete) {
                (_, true) => String::new(),
                (Some(reason), false) => reason.text.clone(),
                (None, false) => {
                    "manual capture has omitted resident pages, missing context or a truncated prefix".into()
                }
            };
            owner.finish(
                if complete {
                    RunArtifactState::Complete
                } else {
                    RunArtifactState::Partial
                },
                issue,
            );
            return Ok(());
        }
        let depth = if limits.advertised {
            core_stream::READ_DEPTH
        } else {
            1
        };
        let requests = core_stream::plan(
            owner.summary.stored_size,
            status.size,
            depth,
            self.available(),
        );
        if requests.is_empty() {
            return Err(owner.quota_error(status.size));
        }
        let Some(replies) =
            self.core_read_burst(status.id, &requests, snapshot, sender, owner.activity)?
        else {
            return Ok(());
        };
        let data = match core_stream::assemble(&requests, &replies, status.size)? {
            Assembled::Data(data) => data,
            Assembled::Hole(len) => {
                // Zeros the guest never stored: a sparse range, no quota used.
                owner.sink.submit(Action::Hole {
                    offset: owner.summary.stored_size,
                    len,
                })?;
                owner.reserved_len = 0;
                owner.activity = Instant::now();
                return Ok(());
            }
        };
        let retained = data.len().min(self.available() as usize);
        if retained == 0 {
            return Err(owner.quota_error(status.size));
        }
        if owner.allocated + retained as u64 > u64::from(owner.summary.max_size) {
            return Err("manual core stored more than its requested limit".into());
        }
        if owner.summary.stored_size == 0
            && retained >= 20
            && (&data[..7] != b"\x7fELF\x02\x01\x01"
                || data[16..18] != 4u16.to_le_bytes()
                || data[18..20] != 62u16.to_le_bytes())
        {
            return Err("manual core is not a native Linux x86-64 ELF core".into());
        }
        let cut = retained < data.len();
        let mut data = data;
        data.truncate(retained);
        if owner.sink.submit(Action::Write {
            offset: owner.summary.stored_size,
            data,
            metadata: owner.metadata(None)?,
        })? {
            owner.reserved_len = retained as u64;
            self.core_reserved_len = self.core_reserved_len.saturating_add(owner.reserved_len);
            if cut {
                let text = "recording quota exhausted; retained available manual-core prefix";
                owner.set_reason(CoreReasonCode::Quota, None, text);
                owner.finish(RunArtifactState::Partial, text);
            }
        }
        Ok(())
    }
    /// Before the copy starts: announce what the recording quota will cut and
    /// refuse to start one the host disk cannot hold.
    fn manual_preflight(&mut self, owner: &mut Owner, status: &CoreStatus) -> Result<(), String> {
        let need = status
            .stored
            .unwrap_or_else(|| status.size.min(CoreLimits::LEGACY.max_size));
        owner.summary.stored_bytes = status.stored;
        owner.summary.expected_size = Some(status.expected_size).filter(|&size| size > 0);
        if let Some(text) = core_stream::quota_warning(self.available(), need) {
            owner.set_reason(CoreReasonCode::Quota, None, text.clone());
            owner.issue(text);
        }
        if let Some(text) = core_stream::host_space_refusal(&owner.summary.directory, need) {
            owner.set_reason(CoreReasonCode::HostDisk, None, text.clone());
            return Err(text);
        }
        Ok(())
    }
    fn manual_step(
        &mut self,
        owner: &mut Owner,
        snapshot: &mut Snapshot,
        sender: Option<&SyncSender<Notification>>,
    ) -> Result<(), String> {
        if let Err(error) = self.manual_poll_io(owner) {
            owner.finish(RunArtifactState::Failed, error);
            owner.cancel_requested = true;
        }
        if owner.done {
            return Ok(());
        }
        if !owner.disk_failed && !owner.initialized && !owner.sink.pending() {
            owner.sink.submit(Action::Init {
                metadata: owner.metadata(None)?,
            })?;
            return Ok(());
        }
        if !owner.disk_failed && (!owner.initialized || owner.sink.pending()) {
            return Ok(());
        }
        if let Some(sender) = sender
            && let Err(error) = self.manual_guest_step(owner, snapshot, sender)
        {
            owner.cancel_requested = true;
            owner.finish(
                if owner.summary.stored_size > 0 {
                    RunArtifactState::Partial
                } else {
                    RunArtifactState::Failed
                },
                error,
            );
        }
        if let Some(requested) = owner.desired {
            if owner.guest_busy() {
                return Ok(());
            }
            if !owner.release_attempted
                && let Some(id) = owner.summary.guest_handle
            {
                if let Some(sender) = sender {
                    // STATUS/LOOKUP already matched full ownership and proved parks released.
                    owner.release_attempted = true;
                    match self.request_typed(
                        RELEASE,
                        &control::with_session(id),
                        snapshot,
                        sender,
                        IO_TIMEOUT,
                    ) {
                        Ok(reply) if reply.is_empty() => {}
                        Ok(_) => {
                            owner.issue("manual release reply malformed; cleanup is not replayed")
                        }
                        Err(error) => owner.issue(format!(
                            "manual release outcome unknown; cleanup is not replayed: {}",
                            error.into_message()
                        )),
                    }
                } else {
                    owner.release_attempted = true;
                }
            }
            if owner.disk_finished {
                owner.done = true;
                owner.summary.phase = ProcessCorePhase::Finished;
                return Ok(());
            }
            let state =
                if requested == RunArtifactState::Interrupted && owner.summary.stored_size > 0 {
                    RunArtifactState::Partial
                } else {
                    requested
                };
            owner.summary.phase = ProcessCorePhase::Seal;
            owner.sink.submit(Action::Finish {
                state,
                generation: owner.generation,
                metadata: owner.metadata(Some(state))?,
            })?;
        }
        Ok(())
    }
    pub(super) fn manual_core_tick(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) {
        let selected = self
            .manual_cores
            .iter()
            .filter(|(_, owner)| {
                !owner.done
                    && (owner.sink.pending()
                        || owner.desired.is_some()
                        || !owner.initialized
                        || owner
                            .status
                            .as_ref()
                            .is_some_and(|status| terminal(status.state))
                        || owner
                            .checked
                            .is_none_or(|checked| checked.elapsed() >= Duration::from_millis(250)))
            })
            .min_by_key(|(_, owner)| owner.checked)
            .map(|(id, _)| id.clone());
        let Some(id) = selected else {
            return;
        };
        let Some(mut owner) = self.manual_cores.remove(&id) else {
            return;
        };
        owner.checked = Some(Instant::now());
        if let Err(error) = self.manual_step(&mut owner, snapshot, Some(sender)) {
            snapshot.last_error = Some(error.clone());
            owner.fail_disk(error);
        }
        self.manual_cores.insert(id, owner);
        // Completed records stay on disk; only the latest 64 are kept in memory.
        while self
            .manual_cores
            .values()
            .filter(|owner| owner.done)
            .count()
            > core_capture::LATEST_LIMIT
        {
            let old = self
                .manual_cores
                .iter()
                .find(|(_, owner)| owner.done)
                .map(|(id, _)| id.clone());
            if let Some(id) = old {
                self.manual_cores.remove(&id);
            } else {
                break;
            }
        }
        self.refresh_storage_health(&mut snapshot.health);
    }
    pub(super) fn prepare_manual_reconnect(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        let ids: Vec<_> = self
            .manual_cores
            .iter()
            .filter(|(_, owner)| !owner.done)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let mut owner = self
                .manual_cores
                .remove(&id)
                .ok_or("manual reconnect owner missing")?;
            if !owner.admission_sent {
                owner.cancel_requested = true;
                owner.known_absent = true;
                owner.finish(
                    RunArtifactState::Interrupted,
                    "manual request interrupted before admission at reconnect",
                );
            } else {
                owner.lookup_required = true;
                owner.activity = Instant::now();
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    let checked = self.manual_status(&mut owner, snapshot, sender);
                    if let Err(error) = checked {
                        self.manual_cores.insert(id, owner);
                        return Err(error);
                    }
                    if owner.known_absent || owner.summary.pause_released == Some(true) {
                        break;
                    }
                    if let Some(handle) = owner.summary.guest_handle
                        && !owner.cancel_sent
                    {
                        owner.cancel_sent = true;
                        owner.cancel_requested = true;
                        if let Err(error) = self.request_typed(
                            control::CORE_CANCEL,
                            &control::with_session(handle),
                            snapshot,
                            sender,
                            IO_TIMEOUT,
                        ) {
                            owner.issue(format!(
                                "reattach cancellation unconfirmed; not replayed: {}",
                                error.into_message()
                            ));
                        }
                    }
                    if Instant::now() >= deadline {
                        self.manual_cores.insert(id, owner);
                        return Err("manual reattach could not prove process pause release".into());
                    }
                    if let Err(error) = self.transport.poll(10) {
                        self.manual_cores.insert(id, owner);
                        return Err(error);
                    }
                }
            }
            self.manual_cores.insert(id, owner);
        }
        Ok(())
    }
    pub(super) fn seal_manual_cores(&mut self, boundary: &str, snapshot: &mut Snapshot) {
        let ids: Vec<_> = self
            .manual_cores
            .iter()
            .filter(|(_, owner)| !owner.done)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let Some(mut owner) = self.manual_cores.remove(&id) else {
                continue;
            };
            owner.known_absent = true;
            owner.release_attempted = true;
            owner.cancel_requested = true;
            owner.set_reason(
                CoreReasonCode::Sealed,
                None,
                format!("sealed at {boundary}"),
            );
            owner.finish(
                RunArtifactState::Interrupted,
                format!("manual capture sealed at {boundary}; no admission is replayed"),
            );
            let deadline = Instant::now() + Duration::from_secs(120);
            loop {
                if let Err(error) = self.manual_step(&mut owner, snapshot, None) {
                    owner.summary.state = RunArtifactState::Failed;
                    owner.issue(error.clone());
                    snapshot.last_error = Some(error);
                    break;
                }
                if owner.done {
                    break;
                }
                if Instant::now() >= deadline {
                    owner.summary.state = RunArtifactState::Interrupted;
                    owner.issue("manual disk seal exceeded 120 seconds; old sink remains isolated in its original directory");
                    snapshot.last_error = owner.summary.issue.clone();
                    break;
                }
                if let Err(error) = self.transport.poll(0) {
                    snapshot.last_error = Some(error);
                }
                thread::sleep(Duration::from_millis(5));
            }
            owner.done = true;
            self.manual_cores.insert(id, owner);
        }
        snapshot.process_cores = self
            .manual_cores
            .values()
            .map(|owner| owner.summary.clone())
            .collect();
    }
}
impl Worker {
    pub(super) fn check_manual_cores(&mut self) {
        if self.snapshot.state == VmState::Running
            && self.snapshot.memory_dump.is_none()
            && let Some(session) = self.session.as_mut()
        {
            session.manual_core_tick(&mut self.snapshot, &self.sender);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> ProcessCoreRequest {
        ProcessCoreRequest {
            vm_id: "vm".into(),
            target: crate::GuestProcessIdentity {
                boot_id: "boot".into(),
                task_cookie: 6,
                tgid: 7,
                start_boot_ns: 8,
            },
            ..Default::default()
        }
    }
    fn status(state: u32, flags: u32) -> Vec<u8> {
        let mut wire = vec![0; 80];
        wire[..8].copy_from_slice(&5u64.to_le_bytes());
        wire[8..16].copy_from_slice(&6u64.to_le_bytes());
        wire[48..52].copy_from_slice(&state.to_le_bytes());
        wire[64..68].copy_from_slice(&flags.to_le_bytes());
        wire[68..72].copy_from_slice(&7u32.to_le_bytes());
        if state == 3 {
            wire[32..40].copy_from_slice(&64u64.to_le_bytes());
            wire[40..48].copy_from_slice(&64u64.to_le_bytes());
            wire[72..76].copy_from_slice(&1u32.to_le_bytes());
        }
        wire
    }
    #[test]
    fn manual_wire_has_exact_identity_nonce_policy_and_limits() {
        let encoded = control::core_capture(&request(), [11, 12]).unwrap();
        assert_eq!(encoded.len(), 56);
        assert_eq!(u64_at(&encoded, 8).unwrap(), 6);
        assert_eq!(u64_at(&encoded, 16).unwrap(), 8);
        assert_eq!(u32_at(&encoded, 24).unwrap(), 7);
        assert_eq!(u32_at(&encoded, 28).unwrap(), 64 * 1024 * 1024);
        assert_eq!(u32_at(&encoded, 32).unwrap(), 5000);
        assert_eq!(u32_at(&encoded, 36).unwrap(), 1);
        assert_eq!(u64_at(&encoded, 40).unwrap(), 11);
        assert_eq!(u64_at(&encoded, 48).unwrap(), 12);
        let lookup = control::core_lookup(&request().target, [11, 12]);
        assert_eq!(lookup.len(), 48);
        assert_eq!(u32_at(&lookup, 28).unwrap(), 0);
        assert_eq!(u64_at(&lookup, 32).unwrap(), 11);
        assert_eq!(u64_at(&lookup, 40).unwrap(), 12);
        let mut invalid = request();
        // The wire carries up to the host's absolute bound; the guest's own is checked elsewhere.
        invalid.max_size = 1 << 30;
        assert!(control::core_capture(&invalid, [11, 12]).is_ok());
        invalid.max_size += 1;
        assert!(control::core_capture(&invalid, [11, 12]).is_err());
        invalid.max_size = 64 << 20;
        invalid.timeout_ms = 60_001;
        assert!(control::core_capture(&invalid, [11, 12]).is_err());
    }
    #[test]
    fn only_explicit_lookup_esrch_proves_absence() {
        let missing = RequestError::Rejected {
            status: -3,
            message: "missing".into(),
        };
        assert!(missing_lookup(control::CORE_LOOKUP, &missing));
        assert!(!missing_lookup(STATUS, &missing));
        for error in [
            RequestError::Rejected {
                status: -22,
                message: "invalid".into(),
            },
            RequestError::Rejected {
                status: -95,
                message: "unsupported".into(),
            },
            RequestError::TimedOut("timeout".into()),
            RequestError::Failed("transport".into()),
        ] {
            assert!(!missing_lookup(control::CORE_LOOKUP, &error));
        }
    }
    #[test]
    fn terminal_manual_status_requires_pause_release_and_native_coverage() {
        assert!(CoreStatus::parse_manual(&status(2, 0x50), 5, 6, 7, false).is_ok());
        assert!(CoreStatus::parse_manual(&status(3, 0x76), 5, 6, 7, false).is_ok());
        for flags in [0x56, 0x77, 0x36, 0xf6] {
            assert!(CoreStatus::parse_manual(&status(3, flags), 5, 6, 7, false).is_err());
        }
        for identity in [(4, 6, 7), (5, 9, 7), (5, 6, 8)] {
            assert!(
                CoreStatus::parse_manual(
                    &status(3, 0x76),
                    identity.0,
                    identity.1,
                    identity.2,
                    false
                )
                .is_err()
            );
        }
        let mut invalid = status(3, 0x76);
        invalid[60..64].copy_from_slice(&11u32.to_le_bytes());
        assert!(CoreStatus::parse_manual(&invalid, 5, 6, 7, false).is_err());
        for len in 0..80 {
            assert!(CoreStatus::parse_manual(&invalid[..len], 5, 6, 7, false).is_err());
        }
    }
    #[test]
    fn disk_failure_keeps_guest_cleanup_owned_and_snapshot_guarded() {
        let mut owner = Owner::new(
            request(),
            std::env::temp_dir().join("unused-manual-cleanup"),
            "capture".into(),
        );
        assert!(
            owner.guest_busy(),
            "queued capture also guards the snapshot boundary"
        );
        owner.admission_sent = true;
        owner.summary.guest_handle = Some(5);
        owner.summary.pause_released = Some(false);
        owner.fail_disk("injected fsync failure".into());
        assert_eq!(owner.summary.state, RunArtifactState::Failed);
        assert_eq!(owner.summary.phase, ProcessCorePhase::GuestCapture);
        assert!(!owner.done);
        assert!(owner.guest_busy());
        assert!(owner.cancel_requested);
        owner.summary.pause_released = Some(true);
        assert!(!owner.guest_busy());
        owner.fail_disk("same failure after guest release".into());
        assert!(owner.done);
        assert_eq!(owner.summary.phase, ProcessCorePhase::Finished);
    }
    #[test]
    fn restored_capture_never_replays_admission_or_reuses_original_sink() {
        let root =
            std::env::temp_dir().join(format!("ant-manual-restore-{}", storage::unique_id()));
        let mut original = Owner::new(request(), root.join("original"), "original".into());
        original.summary.guest_handle = Some(5);
        original.summary.guest_size = Some(64);
        original.summary.pause_released = Some(true);
        let restored = Owner::restored(&original.summary, "vm", "fresh-boot", &root, None).unwrap();
        assert!(restored.admission_sent);
        assert!(restored.lookup_required);
        assert_eq!(restored.summary.stored_size, 0);
        assert_eq!(restored.summary.target.boot_id, "fresh-boot");
        assert_eq!(restored.summary.nonce, original.summary.nonce);
        assert_ne!(restored.summary.directory, original.summary.directory);
        assert!(!root.exists());
        original.summary.pause_released = Some(false);
        assert!(validate_saved(&original.summary).is_err());
    }
    #[test]
    fn cancellation_supersedes_a_pending_complete_generation() {
        let mut owner = Owner::new(
            request(),
            std::env::temp_dir().join("unused-manual-generation"),
            "capture".into(),
        );
        owner.admission_sent = true;
        owner.summary.pause_released = Some(true);
        owner.finish(RunArtifactState::Complete, "");
        let generation = owner.generation;
        owner.cancel_requested = true;
        owner.finish(RunArtifactState::Interrupted, "user canceled");
        assert!(owner.generation > generation);
        assert_eq!(owner.desired, Some(RunArtifactState::Interrupted));
    }
    #[test]
    fn canceled_ready_capture_blocks_snapshot_until_pending_disk_job_and_handle_cleanup_settle() {
        let mut owner = Owner::new(
            request(),
            std::env::temp_dir().join("unused-manual-snapshot-cancel"),
            "capture".into(),
        );
        owner.admission_sent = true;
        owner.summary.guest_handle = Some(5);
        owner.summary.guest_size = Some(64);
        owner.summary.pause_released = Some(true);
        owner.status = Some(CoreStatus::parse_manual(&status(3, 0x76), 5, 6, 7, false).unwrap());
        assert!(
            !owner.snapshot_busy(),
            "an ordinary resumed immutable transfer remains snapshot-compatible"
        );
        assert!(owner.checkpoint().is_some());
        let (release, held) = std::sync::mpsc::channel();
        assert!(owner.sink.submit(Action::Hold(held)).unwrap());
        owner.cancel_requested = true;
        owner.finish(
            RunArtifactState::Interrupted,
            "user canceled while disk job pending",
        );
        assert!(!owner.guest_busy(), "the process is already resumed");
        assert!(owner.sink.pending());
        assert!(owner.snapshot_busy());
        assert!(
            owner.checkpoint().is_none(),
            "cancellation must not be replayed as a restored transfer"
        );
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while owner.sink.poll().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            owner.snapshot_busy(),
            "disk completion alone does not reclaim the retained guest reservation"
        );
        owner.release_attempted = true;
        assert!(!owner.snapshot_busy());
    }
}
