// SPDX-License-Identifier: MIT
//! Bounded root-group ELF core acquisition. Immutable guest buffers are read by
//! offset; launch and release side effects are never automatically replayed.
use super::core_sink::{Action, Kind, Sink};
use super::*;

const STATUS: u32 = 0x1060;
const READ: u32 = 0x1061;
const RELEASE: u32 = 0x1062;
const LIMIT: u64 = 64 * 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_millis(50);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct SavedHandle {
    pub source_run_id: String,
    pub core_id: u64,
    pub max_size: u64,
    pub root_cookie: u64,
    pub tgid: u32,
}
impl SavedHandle {
    pub(super) fn validate(&self, run: &RunSummary) -> Result<(), String> {
        if self.source_run_id.is_empty()
            || self.source_run_id.len() > 128
            || self.source_run_id != run.id
            || self.core_id == 0
            || self.max_size == 0
            || self.max_size > LIMIT
            || self.root_cookie == 0
            || self.root_cookie != run.root_task_cookie
            || self.tgid == 0
            || self.tgid != run.pid
            || !run.request.core_dump_on_exit
        {
            return Err(
                "snapshot process-core handle does not match its saved run identity or bounds"
                    .into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct CoreStatus {
    pub(super) id: u64,
    pub(super) root_cookie: u64,
    pub(super) start_ns: u64,
    pub(super) finish_ns: u64,
    pub(super) size: u64,
    pub(super) expected_size: u64,
    pub(super) state: u32,
    pub(super) status: i32,
    pub(super) wait_status: i32,
    pub(super) signal: u32,
    pub(super) flags: u32,
    pub(super) tgid: u32,
    pub(super) thread_count: u32,
}
impl CoreStatus {
    fn parse(reply: &[u8], id: u64, cookie: u64, tgid: u32) -> Result<Self, String> {
        Self::parse_mode(reply, id, cookie, tgid, false)
    }
    pub(super) fn parse_manual(
        reply: &[u8],
        id: u64,
        cookie: u64,
        tgid: u32,
    ) -> Result<Self, String> {
        Self::parse_mode(reply, id, cookie, tgid, true)
    }
    fn parse_mode(
        reply: &[u8],
        id: u64,
        cookie: u64,
        tgid: u32,
        manual: bool,
    ) -> Result<Self, String> {
        if reply.len() != 80 {
            return Err("invalid process-core status length".into());
        }
        let u64 = |offset| u64_at(reply, offset).map_err(|error| error.to_string());
        let u32 = |offset| u32_at(reply, offset).map_err(|error| error.to_string());
        let result = Self {
            id: u64(0)?,
            root_cookie: u64(8)?,
            start_ns: u64(16)?,
            finish_ns: u64(24)?,
            size: u64(32)?,
            expected_size: u64(40)?,
            state: u32(48)?,
            status: u32(52)? as i32,
            wait_status: u32(56)? as i32,
            signal: u32(60)?,
            flags: u32(64)?,
            tgid: u32(68)?,
            thread_count: u32(72)?,
        };
        if id == 0
            || cookie == 0
            || tgid == 0
            || result.id != id
            || result.root_cookie != cookie
            || result.tgid != tgid
            || !(1..=6).contains(&result.state)
            || result.size > LIMIT
            || result.flags & if manual { !0x7f } else { !15 } != 0
            || if manual {
                result.flags & 0x51 != 0x50
                    || result.wait_status != 0
                    || result.signal != 0
                    || (result.state >= 3 && result.flags & 0x20 == 0)
            } else {
                result.flags & 1 == 0
            }
            || result.signal > 64
            || result.thread_count > 256
            || !(-4095..=0).contains(&result.status)
            || u32(76)? != 0
            || (result.finish_ns != 0 && result.finish_ns < result.start_ns)
            || (result.state == 3
                && (result.status != 0
                    || result.expected_size != result.size
                    || result.size < 64
                    || result.flags & 2 == 0
                    || result.thread_count == 0))
        {
            return Err("invalid process-core identity, bounds, state or flags".into());
        }
        Ok(result)
    }
}

pub(super) struct Transfer {
    id: u64,
    max_size: u64,
    cookie: u64,
    tgid: u32,
    run: RunSummary,
    status: Option<CoreStatus>,
    sink: Sink,
    offset: u64,
    sha256: String,
    initialized: bool,
    reserved_len: u64,
    checked: Option<Instant>,
    last_activity: Instant,
    root_exit_observed: Option<Instant>,
    target: Option<(RunArtifactState, String)>,
    finish_generation: u64,
    finalized_generation: Option<u64>,
    artifacts_receipt: Option<storage::JsonReceipt>,
    artifacts_failed: bool,
    released: bool,
    arm_status: i32,
}
impl Transfer {
    fn new(id: u64, max_size: u64, run: &RunSummary) -> Self {
        Self {
            id,
            max_size,
            cookie: run.root_task_cookie,
            tgid: run.pid,
            run: run.clone(),
            status: None,
            sink: Sink::new(run.directory.join("core")),
            offset: 0,
            sha256: String::new(),
            initialized: false,
            reserved_len: 0,
            checked: None,
            last_activity: Instant::now(),
            root_exit_observed: None,
            target: None,
            finish_generation: 0,
            finalized_generation: None,
            artifacts_receipt: None,
            artifacts_failed: false,
            released: id == 0,
            arm_status: 0,
        }
    }
    pub(super) fn armed(reply: &[u8], run: &RunSummary) -> Result<Self, String> {
        let (id, size) =
            control::acquisition(reply).map_err(|error| format!("process-core arm: {error}"))?;
        if size == 0 || size > LIMIT {
            return Err("invalid core reservation size".into());
        }
        Ok(Self::new(id, size, run))
    }
    pub(super) fn failed(reply: &[u8], run: &RunSummary, error: String) -> Self {
        let mut transfer = Self::new(0, LIMIT, run);
        transfer.arm_status = u32_at(reply, 16).map_or(-5, |status| status as i32);
        transfer.finish_request(RunArtifactState::Failed, error);
        transfer
    }
    fn metadata(&self, state: RunArtifactState, issue: Option<&str>) -> serde_json::Value {
        serde_json::json!({"format":1,"run_id":self.run.id,"vm_id":self.run.vm_id,"boot_id":self.run.boot_id,
            "root_task_cookie":self.cookie,"tgid":self.tgid,"guest_handle":self.id,"guest_arm_status":self.arm_status,
            "executable":self.run.request.path,"state":state,"guest_status":self.status,
            "stored_size":self.offset,"sha256":self.sha256,"incomplete":state!=RunArtifactState::Complete,
            "issue":issue,"max_size":self.max_size,"capture_timeout_ms":5000,"publication_generation":self.finish_generation,
            "scope":"native Linux x86-64 root thread group; Linux filtered memory",
            "deadline_limit":"guest page faults and thread rendezvous do not guarantee a strict wall-clock deadline",
            "progress_limit":"in-progress core.json is a checkpoint; stored_size/hash become authoritative after the final durable seal"})
    }
    fn finish_request(&mut self, state: RunArtifactState, issue: String) {
        if self
            .target
            .as_ref()
            .is_some_and(|target| target.0 == state && target.1 == issue)
        {
            return;
        }
        if self.target.is_none() {
            self.last_activity = Instant::now();
        }
        if state != RunArtifactState::Complete {
            self.sink.seal();
        }
        self.target = Some((state, issue));
        self.finish_generation = self.finish_generation.saturating_add(1);
        self.artifacts_receipt = None;
    }
    pub(super) fn checkpoint_handle(&self) -> Option<SavedHandle> {
        (self.id != 0 && self.target.is_none()).then(|| SavedHandle {
            source_run_id: self.run.id.clone(),
            core_id: self.id,
            max_size: self.max_size,
            root_cookie: self.cookie,
            tgid: self.tgid,
        })
    }
    pub(super) fn restored(saved: &SavedHandle, run: &RunSummary) -> Result<Self, String> {
        if saved.core_id == 0
            || saved.root_cookie != run.root_task_cookie
            || saved.tgid != run.pid
            || saved.max_size == 0
            || saved.max_size > LIMIT
        {
            return Err("restored core handle identity mismatch".into());
        }
        Ok(Self::new(saved.core_id, saved.max_size, run))
    }
}
fn queue_artifacts(owner: &RunArtifactOwner) -> Result<(), String> {
    storage::queue_json(&owner.directory.join("artifacts.json"), &owner.summary)
}
fn acknowledged_len(previous: u64, written: u64, reserved: u64) -> Result<u64, String> {
    written
        .checked_sub(previous)
        .filter(|&delta| delta <= reserved)
        .ok_or_else(|| "core disk acknowledgement exceeds its reservation".into())
}
impl Session {
    pub(super) fn core_readonly(
        &mut self,
        opcode: u32,
        args: &[u8],
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
        last_activity: Instant,
    ) -> Result<Option<Vec<u8>>, String> {
        let id = self.transport.send(opcode, args)?;
        match self.wait_reply(id, opcode, snapshot, sender, COMMAND_TIMEOUT) {
            Ok(reply) => Ok(Some(reply)),
            Err(RequestError::TimedOut(_))
                if last_activity.elapsed() < Duration::from_secs(120) =>
            {
                Ok(None)
            }
            Err(error) => Err(error.into_message()),
        }
    }
    fn poll_core_io(
        &mut self,
        owner: &mut RunArtifactOwner,
        core: &mut Transfer,
    ) -> Result<(), String> {
        let Some(receipt) = core.sink.poll()? else {
            return Ok(());
        };
        let reserved = core.reserved_len;
        self.core_reserved_len = self.core_reserved_len.saturating_sub(reserved);
        core.reserved_len = 0;
        let delta = acknowledged_len(core.offset, receipt.size, reserved)?;
        self.core_stored_len = self.core_stored_len.saturating_add(delta);
        owner.core_stored_len = owner.core_stored_len.saturating_add(delta);
        core.offset = receipt.size;
        core.sha256 = receipt.sha256;
        if receipt.has_file {
            owner.summary.core_dump = Some(owner.directory.join("core/process.elf"));
        }
        if receipt.kind == Kind::Init {
            core.initialized = true;
        }
        if let Err(error) = receipt.result {
            owner.issue(error.clone());
            if receipt.kind == Kind::Finish {
                core.target = Some((RunArtifactState::Failed, error));
                core.finalized_generation = Some(core.finish_generation);
            } else {
                core.initialized = true;
                core.finish_request(
                    if core.offset > 0 {
                        RunArtifactState::Partial
                    } else {
                        RunArtifactState::Failed
                    },
                    error,
                );
            }
        } else if receipt.kind == Kind::Finish {
            if receipt.generation == core.finish_generation {
                if let Some(state) = receipt.final_state
                    && let Some(target) = core.target.as_mut()
                {
                    target.0 = state;
                }
                core.finalized_generation = Some(receipt.generation);
            }
        } else {
            core.last_activity = Instant::now();
            queue_artifacts(owner)?;
        }
        Ok(())
    }
    fn advance_core_finish(
        &mut self,
        owner: &mut RunArtifactOwner,
        core: &mut Transfer,
        snapshot: &mut Snapshot,
    ) -> Result<bool, String> {
        let (requested, issue) = core.target.clone().ok_or("core final state missing")?;
        if core.sink.pending() {
            return Ok(false);
        }
        let state = if requested == RunArtifactState::Interrupted && core.offset > 0 {
            RunArtifactState::Partial
        } else {
            requested
        };
        if core.finalized_generation != Some(core.finish_generation) {
            if core.sink.submit(Action::Finish {
                state,
                generation: core.finish_generation,
                metadata: core.metadata(state, Some(&issue)),
            })? {
                owner.summary.core_state = RunArtifactState::InProgress;
            }
            return Ok(false);
        }
        if core.artifacts_receipt.is_none() {
            if !issue.is_empty() {
                owner.issue(issue);
            }
            let mut final_summary = owner.summary.clone();
            final_summary.core_state = if core.artifacts_failed {
                RunArtifactState::Failed
            } else {
                state
            };
            core.artifacts_receipt = Some(storage::queue_json_observed(
                &owner.directory.join("artifacts.json"),
                &final_summary,
            )?);
        }
        match core
            .artifacts_receipt
            .as_ref()
            .ok_or("core artifacts receipt missing")?
            .status()
        {
            storage::JsonWriteStatus::Pending => Ok(false),
            storage::JsonWriteStatus::Complete => {
                owner.summary.core_state = if core.artifacts_failed {
                    RunArtifactState::Failed
                } else {
                    state
                };
                Ok(core.released)
            }
            storage::JsonWriteStatus::Superseded => {
                core.artifacts_receipt = None;
                Ok(false)
            }
            storage::JsonWriteStatus::Failed(error) => {
                owner.summary.core_state = RunArtifactState::Failed;
                owner.issue(format!("core artifacts publication: {error}"));
                snapshot.last_error = Some(error);
                if !core.artifacts_failed {
                    core.artifacts_failed = true;
                    core.artifacts_receipt = None;
                    Ok(false)
                } else {
                    Ok(core.released)
                }
            }
        }
    }
    fn core_pass(
        &mut self,
        cookie: u64,
        owner: &mut RunArtifactOwner,
        core: &mut Transfer,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        if core.cookie != cookie || core.run.boot_id != self.boot_id {
            return Err("process-core owner belongs to a different run or timeline".into());
        }
        if core.sink.pending() || !core.initialized {
            return Ok(());
        }
        if self
            .runs
            .get(&cookie)
            .and_then(|run| run.summary.execution.as_ref())
            .is_some_and(|execution| {
                matches!(
                    execution.root_exit,
                    Some(WaitStatus::Signaled { signal: 9, .. })
                ) || matches!(
                    crate::execution::state(execution),
                    RunState::Finished | RunState::Stopped
                )
            })
        {
            core.root_exit_observed.get_or_insert_with(Instant::now);
        }
        if core.status.as_ref().is_none_or(|status| status.state <= 2) {
            let Some(reply) = self.core_readonly(
                STATUS,
                &control::with_session(core.id),
                snapshot,
                sender,
                core.last_activity,
            )?
            else {
                return Ok(());
            };
            let status = CoreStatus::parse(&reply, core.id, cookie, core.tgid)?;
            if status.size > core.max_size {
                return Err("guest process core exceeds its accepted reservation".into());
            }
            let state = status.state;
            core.status = Some(status);
            core.last_activity = Instant::now();
            if state == 1
                && core
                    .root_exit_observed
                    .is_some_and(|observed| observed.elapsed() >= Duration::from_secs(2))
            {
                return Err("root group ended without starting a core; immediate-kill signals may make capture unavailable".into());
            }
            if state <= 2 {
                return Ok(());
            }
            if state >= 5 {
                return Err(format!(
                    "guest core unavailable or canceled (state {state}, status {})",
                    core.status.as_ref().map_or(0, |status| status.status)
                ));
            }
            owner.summary.core_state = RunArtifactState::InProgress;
            queue_artifacts(owner)?;
        }
        let status = core.status.as_ref().ok_or("core status missing")?;
        if core.offset == status.size {
            let complete = status.state == 3 && status.flags & 8 == 0;
            core.finish_request(
                if complete {
                    RunArtifactState::Complete
                } else {
                    RunArtifactState::Partial
                },
                if complete {
                    String::new()
                } else if status.state == 3 && status.flags & 8 != 0 {
                    "guest saved a complete ELF file with a coverage gap or missing thread context"
                        .into()
                } else {
                    "guest retained an incomplete process core; only its available prefix is saved"
                        .into()
                },
            );
            return Ok(());
        }
        let capacity = (status.size - core.offset)
            .min(u64::from(control::SPECIMEN_CHUNK_SIZE))
            .min(self.available()) as u32;
        if capacity == 0 {
            return Err("recording quota exhausted during process-core transfer".into());
        }
        let total = status.size;
        let args = control::specimen_read(core.id, core.offset, capacity);
        let Some(reply) = self.core_readonly(READ, &args, snapshot, sender, core.last_activity)?
        else {
            return Ok(());
        };
        let chunk = control::specimen_chunk(&reply, core.offset, total, capacity)?;
        let retained_len = chunk.len().min(self.available() as usize);
        if retained_len == 0 {
            return Err("recording quota exhausted during process-core transfer".into());
        }
        let data = &chunk[..retained_len];
        if core.offset == 0
            && data.len() >= 20
            && (&data[..7] != b"\x7fELF\x02\x01\x01"
                || data[16..18] != 4u16.to_le_bytes()
                || data[18..20] != 62u16.to_le_bytes())
        {
            return Err("guest process core is not a native little-endian x86-64 ELF core".into());
        }
        if core.sink.submit(Action::Write {
            offset: core.offset,
            data: data.to_vec(),
            metadata: core.metadata(RunArtifactState::InProgress, None),
        })? {
            core.reserved_len = retained_len as u64;
            self.core_reserved_len = self.core_reserved_len.saturating_add(core.reserved_len);
            if retained_len < chunk.len() {
                core.finish_request(
                    RunArtifactState::Partial,
                    "recording quota exhausted; retained available prefix".into(),
                );
            }
        }
        core.last_activity = Instant::now();
        Ok(())
    }
    fn step_core(
        &mut self,
        cookie: u64,
        owner: &mut RunArtifactOwner,
        core: &mut Transfer,
        snapshot: &mut Snapshot,
        sender: Option<&SyncSender<Notification>>,
    ) -> Result<bool, String> {
        if let Err(error) = self.poll_core_io(owner, core) {
            core.finish_request(
                if core.offset > 0 {
                    RunArtifactState::Partial
                } else {
                    RunArtifactState::Failed
                },
                error,
            );
        }
        if !core.initialized && !core.sink.pending() {
            let state = core
                .target
                .as_ref()
                .map_or(RunArtifactState::WaitingForRootExit, |target| target.0);
            core.sink.submit(Action::Init {
                metadata: core
                    .metadata(state, core.target.as_ref().map(|target| target.1.as_str())),
            })?;
        }
        if core.target.is_none()
            && let Some(sender) = sender
            && let Err(error) = self.core_pass(cookie, owner, core, snapshot, sender)
        {
            core.finish_request(
                if core.offset > 0 {
                    RunArtifactState::Partial
                } else {
                    RunArtifactState::Failed
                },
                error,
            );
        }
        if core.target.is_some() {
            if !core.released {
                if let Some(sender) = sender {
                    match self.release_core(core, snapshot, sender) {
                        Ok(done) => core.released = done,
                        Err(error) => {
                            owner.issue(format!(
                                "core handle cleanup unresolved; release is not replayed: {error}"
                            ));
                            core.released = true;
                        }
                    }
                } else {
                    core.released = true;
                }
            }
            return self.advance_core_finish(owner, core, snapshot);
        }
        Ok(false)
    }
    fn process_core_tick(&mut self, snapshot: &mut Snapshot, sender: &SyncSender<Notification>) {
        let cookie = self
            .run_artifacts
            .iter()
            .filter(|(_, owner)| {
                owner.core.as_ref().is_some_and(|core| {
                    core.sink.pending()
                        || core.target.is_some()
                        || !core.initialized
                        || core.status.as_ref().is_some_and(|status| status.state >= 3)
                        || core
                            .checked
                            .is_none_or(|checked| checked.elapsed() >= Duration::from_millis(250))
                })
            })
            .min_by_key(|(_, owner)| owner.core.as_ref().and_then(|core| core.checked))
            .map(|(&cookie, _)| cookie);
        let Some(cookie) = cookie else {
            return;
        };
        let Some(mut owner) = self.run_artifacts.remove(&cookie) else {
            return;
        };
        let Some(mut core) = owner.core.take() else {
            self.run_artifacts.insert(cookie, owner);
            return;
        };
        core.checked = Some(Instant::now());
        match self.step_core(cookie, &mut owner, &mut core, snapshot, Some(sender)) {
            Ok(false) => owner.core = Some(core),
            Ok(true) => {}
            Err(error) => {
                owner.summary.core_state = RunArtifactState::Failed;
                owner.issue(error.clone());
                snapshot.last_error = Some(error);
                if !core.released {
                    match self.release_core(&core,snapshot,sender) {
                        Ok(true)=>core.released=true,
                        Ok(false)=>owner.issue("core disk failed before cleanup identity could be confirmed; no release replay is attempted".into()),
                        Err(error)=>owner.issue(format!("core disk failure cleanup unresolved: {error}")),
                    }
                }
                core.finish_request(
                    RunArtifactState::Failed,
                    "core disk or metadata operation failed".into(),
                );
                // A disconnected worker/publisher cannot be retried forever.
                if core.sink.pending() {
                    owner.core = Some(core);
                } else if let Err(error) = queue_artifacts(&owner) {
                    snapshot.last_error = Some(format!("core failure publication: {error}"));
                }
            }
        }
        self.run_artifacts.insert(cookie, owner);
        self.refresh_storage_health(&mut snapshot.health);
    }
    fn release_core(
        &mut self,
        core: &Transfer,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<bool, String> {
        let Some(reply) = self.core_readonly(
            STATUS,
            &control::with_session(core.id),
            snapshot,
            sender,
            core.last_activity,
        )?
        else {
            return Ok(false);
        };
        CoreStatus::parse(&reply, core.id, core.cookie, core.tgid)?;
        let reply = self.request(
            RELEASE,
            &control::with_session(core.id),
            snapshot,
            sender,
            COMMAND_TIMEOUT,
        )?;
        if !reply.is_empty() {
            return Err("invalid process-core release reply".into());
        }
        Ok(true)
    }
    pub(super) fn cancel_core(
        &mut self,
        run_id: &str,
        snapshot: &mut Snapshot,
        _sender: &SyncSender<Notification>,
    ) -> Result<String, String> {
        let cookie = self.run_cookie(run_id)?;
        let owner = self
            .run_artifacts
            .get_mut(&cookie)
            .ok_or("unknown run artifacts")?;
        let core = owner
            .core
            .as_mut()
            .ok_or("run has no pending process-core acquisition")?;
        core.last_activity = Instant::now();
        core.finish_request(RunArtifactState::Interrupted,"process-core acquisition canceled by user; retained prefix durability is pending and specimen continues running".into());
        owner.issue(
            "process-core cancellation requested; waiting for bounded disk worker completion"
                .into(),
        );
        if let Err(error) = queue_artifacts(owner) {
            snapshot.last_error = Some(error);
        }
        Ok(
            "process-core cancellation queued; retained prefix will be sealed asynchronously"
                .into(),
        )
    }
    pub(super) fn seal_process_cores(&mut self, boundary: &str, snapshot: &mut Snapshot) {
        let cookies: Vec<_> = self
            .run_artifacts
            .iter()
            .filter(|(_, owner)| owner.core.is_some())
            .map(|(&cookie, _)| cookie)
            .collect();
        for cookie in cookies {
            let Some(mut owner) = self.run_artifacts.remove(&cookie) else {
                continue;
            };
            let Some(mut core) = owner.core.take() else {
                self.run_artifacts.insert(cookie, owner);
                continue;
            };
            core.finish_request(RunArtifactState::Interrupted,format!("process-core acquisition sealed at {boundary}; only checkpoint-validated ownership may be adopted in a new timeline"));
            core.released = true;
            let deadline = Instant::now() + Duration::from_secs(120);
            loop {
                match self.step_core(cookie, &mut owner, &mut core, snapshot, None) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(error) => {
                        owner.summary.core_state = RunArtifactState::Failed;
                        owner.issue(error.clone());
                        snapshot.last_error = Some(error);
                        if let Err(error) = queue_artifacts(&owner) {
                            snapshot.last_error =
                                Some(format!("core boundary failure publication: {error}"));
                        }
                        break;
                    }
                }
                if Instant::now() >= deadline {
                    owner.summary.core_state = RunArtifactState::Interrupted;
                    owner.issue("core disk boundary exceeded 120 seconds; old worker remains sealed in its original directory".into());
                    if let Err(error) = queue_artifacts(&owner) {
                        snapshot.last_error = Some(error);
                    }
                    break;
                }
                // Explicit snapshot/stop boundaries may settle disk durability;
                // keep guest liveness updated while no fresh timeline exists.
                if let Err(error) = self.transport.poll(0) {
                    snapshot.last_error = Some(error);
                }
                thread::sleep(Duration::from_millis(5));
            }
            self.run_artifacts.insert(cookie, owner);
        }
    }
}
impl Worker {
    pub(super) fn check_process_cores(&mut self) {
        if self.snapshot.state == VmState::Running
            && self.snapshot.memory_dump.is_none()
            && let Some(session) = self.session.as_mut()
        {
            session.process_core_tick(&mut self.snapshot, &self.sender);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn status() -> Vec<u8> {
        let mut wire = vec![0; 80];
        wire[0..8].copy_from_slice(&5u64.to_le_bytes());
        wire[8..16].copy_from_slice(&6u64.to_le_bytes());
        wire[48..52].copy_from_slice(&1u32.to_le_bytes());
        wire[64..68].copy_from_slice(&1u32.to_le_bytes());
        wire[68..72].copy_from_slice(&7u32.to_le_bytes());
        wire
    }
    fn run(directory: PathBuf) -> RunSummary {
        RunSummary {
            started_ms: None,
            clock_anchor: None,
            id: "run-one".into(),
            vm_id: "vm-one".into(),
            boot_id: "boot-one".into(),
            session_id: 4,
            root_task_cookie: 6,
            pid: 7,
            request: ExecRequest {
                core_dump_on_exit: true,
                ..Default::default()
            },
            directory,
            terminal_eof: false,
            state: RunState::Running,
            recording_error: None,
            notes: Vec::new(),
            execution: None,
            analysis: None,
        }
    }
    #[test]
    fn rejects_truncation_stale_identity_bounds_and_reserved_flags() {
        let wire = status();
        assert!(CoreStatus::parse(&wire, 5, 6, 7).is_ok());
        for len in 0..80 {
            assert!(CoreStatus::parse(&wire[..len], 5, 6, 7).is_err());
        }
        for identity in [(4, 6, 7), (5, 8, 7), (5, 6, 9)] {
            assert!(CoreStatus::parse(&wire, identity.0, identity.1, identity.2).is_err());
        }
        for offset in [48, 64, 76] {
            let mut bad = wire.clone();
            bad[offset..offset + 4].copy_from_slice(&128u32.to_le_bytes());
            assert!(CoreStatus::parse(&bad, 5, 6, 7).is_err());
        }
        let mut bad = wire;
        bad[32..40].copy_from_slice(&(LIMIT + 1).to_le_bytes());
        assert!(CoreStatus::parse(&bad, 5, 6, 7).is_err());
        let mut bad = status();
        bad[72..76].copy_from_slice(&257u32.to_le_bytes());
        assert!(CoreStatus::parse(&bad, 5, 6, 7).is_err());
    }
    #[test]
    fn partial_write_releases_unused_quota_and_retains_actual_prefix_only() {
        let total_reserved = 100u64;
        let chunk_reserved = 14u64;
        let retained = acknowledged_len(20, 25, chunk_reserved).unwrap();
        let remaining_reservations = total_reserved - chunk_reserved;
        assert_eq!(retained, 5);
        assert_eq!(remaining_reservations + retained, total_reserved - 9);
        assert!(acknowledged_len(20, 35, chunk_reserved).is_err());
        assert!(acknowledged_len(20, 19, chunk_reserved).is_err());
    }
    #[test]
    fn checkpoint_restore_starts_at_zero_in_fresh_namespace_and_rejects_stale_run_binding() {
        let root = std::env::temp_dir().join(format!("ant-core-restore-{}", storage::unique_id()));
        let summary = run(root.join("original"));
        let mut reply = vec![];
        reply.extend(5u64.to_le_bytes());
        reply.extend(LIMIT.to_le_bytes());
        reply.extend([0; 8]);
        let core = Transfer::armed(&reply, &summary).unwrap();
        let saved = core.checkpoint_handle().unwrap();
        saved.validate(&summary).unwrap();
        let mut restored = run(root.join("restored"));
        restored.id = "new-run".into();
        restored.boot_id = "new-boot".into();
        let fresh = Transfer::restored(&saved, &restored).unwrap();
        assert_eq!(fresh.offset, 0);
        assert!(fresh.status.is_none());
        assert!(!root.exists());
        let mut wrong = summary;
        wrong.pid += 1;
        assert!(saved.validate(&wrong).is_err());
        assert!(Transfer::restored(&saved, &wrong).is_err());
    }
    #[test]
    fn guest_arm_rejection_is_explicit_and_never_replays_a_guest_side_effect() {
        let summary = run(std::env::temp_dir().join("unused-core-arm"));
        let mut denied = vec![0; 24];
        denied[16..20].copy_from_slice(&(-28i32).to_le_bytes());
        let error = Transfer::armed(&denied, &summary).err().unwrap();
        let failure = Transfer::failed(&denied, &summary, error);
        assert_eq!(failure.arm_status, -28);
        assert!(failure.released);
        assert!(failure.checkpoint_handle().is_none());
    }
}
