// SPDX-License-Identifier: MIT
//! Session orchestration: the frontend handle, the worker thread that owns the
//! VM, and the session that owns one transport client.
mod completions;
mod core_sink;
mod evidence_delete;
mod guest_resource_control;
mod launch_failure;
mod manual_core;
mod process_core;
mod recorder_health;
mod run_network;
mod saving;
mod session_runs;
mod session_transport;
mod snapshot_recovery;
mod terminal_drain;
mod uploads;
mod worker_artifacts;
mod worker_commands;
mod worker_guest;
mod worker_loop;
mod worker_vm;

use self::{
    completions::*, launch_failure::*, run_network::*, saving::*, session_transport::*,
    terminal_drain::*, uploads::*, worker_artifacts::*, worker_loop::*, worker_vm::*,
};
use crate::{
    api::*,
    build,
    capture::CaptureSession,
    control, distribution,
    observation::{
        CaptureScope, CaptureState, CaptureSummary, OBSERVATION_MAX_COUNT, OBSERVATION_RETAINED,
        UNLIMITED_CAPTURE_REVISION,
    },
    parser::{Assembler, u32_at, u64_at},
    run::ProgramRun,
    storage::{self, Bundle, RawCapture},
    transport::Transport,
    vm::VmProcess,
};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File},
    io::{BufReader, Read, Seek, SeekFrom},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// Commands and UI notifications are bounded. Closing always joins the sole owner.
pub struct Backend {
    commands: SyncSender<(u64, u64, Command)>,
    notifications: Receiver<Notification>,
    completions: Receiver<Notification>,
    completion_credits: Arc<CompletionCredits>,
    admission: Mutex<()>,
    receive_cursor: AtomicUsize,
    thread: Option<JoinHandle<()>>,
    /// Exclusive lifetime ownership protects snapshot journals from another app.
    data_owner: Option<File>,
    closing: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    owner_failed: Arc<AtomicBool>,
    sequence: AtomicU64,
    guest_epoch: Arc<AtomicU64>,
    latest_snapshot: Arc<Mutex<Option<Snapshot>>>,
}
impl Backend {
    fn release_unaccepted_credit(&self) {
        if !self.completion_credits.release() {
            self.owner_failed.store(true, Ordering::Release);
            self.closing.store(true, Ordering::Release);
            self.stopping.store(true, Ordering::Release);
        }
    }

    pub fn new(options: BackendOptions) -> Result<Self, String> {
        Self::start(options, None)
    }

    /// Create an owner that wakes its frontend after publishing results.
    ///
    /// | Argument | Meaning |
    /// |---|---|
    /// | `options` | Owned application/session configuration. |
    /// | `wake` | Nonblocking notification callback; called without snapshot locks. |
    /// | Return | Owner handle, or initialization error; no guest is started. |
    pub fn new_with_wake(
        options: BackendOptions,
        wake: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Self, String> {
        Self::start(options, Some(wake))
    }

    fn start(
        mut options: BackendOptions,
        wake: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<Self, String> {
        storage::migrate_default_data(&options)?;
        storage::private_dir(&options.data_dir).map_err(|e| e.to_string())?;
        options.data_dir = fs::canonicalize(&options.data_dir).map_err(|e| e.to_string())?;
        let data_owner = acquire_data_owner(&options.data_dir)?;
        let vms = storage::load_vms(&options)?;
        let freed = crate::vm::remove_stale_guest_ram(
            &options,
            &vms.iter().map(|vm| vm.id.as_str()).collect::<Vec<_>>(),
        );
        if freed > 0 {
            eprintln!(
                "removed {} MB of guest RAM files left by VMs that were not stopped",
                freed / 1_000_000
            );
        }
        let vm_locations = vms
            .iter()
            .map(|vm| crate::locations::locations(&options, &vm.id))
            .collect::<Result<Vec<_>, _>>()?;
        // Commands are small; room for many keeps a burst (terminal reads
        // during a long disk backpressure wait) from being refused.
        let (commands, receiver) = mpsc::sync_channel(1024);
        let (sender, notifications) = mpsc::sync_channel(64);
        let (completion_sender, completions) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
        let completion_credits = Arc::new(CompletionCredits::default());
        let closing = Arc::new(AtomicBool::new(false));
        let stopping = Arc::new(AtomicBool::new(false));
        let owner_failed = Arc::new(AtomicBool::new(false));
        let (worker_closing, worker_stopping) = (closing.clone(), stopping.clone());
        let worker_owner_failed = owner_failed.clone();
        let worker_completion_credits = completion_credits.clone();
        let latest_snapshot = Arc::new(Mutex::new(None));
        let worker_snapshot = latest_snapshot.clone();
        let guest_epoch = Arc::new(AtomicU64::new(0));
        let worker_epoch = guest_epoch.clone();
        let flusher = crate::recording_flush::Flusher::new()?;
        let analysis_tools = crate::analysis_tools::statuses(&options.data_dir);
        let thread = thread::Builder::new()
            .name("antinomie-transport".into())
            .spawn(move || {
                Worker {
                    options,
                    snapshot: Snapshot {
                        vms,
                        bases_checking: true,
                        vm_locations,
                        analysis_tools,
                        ..Snapshot::default()
                    },
                    receiver,
                    sender,
                    completion_sender,
                    completion_credits: worker_completion_credits,
                    closing: worker_closing,
                    stopping: worker_stopping,
                    owner_failed: worker_owner_failed,
                    session: None,
                    keyboard: None,
                    catalog: distribution::Catalog::default(),
                    refresh: None,
                    download: None,
                    build: None,
                    tool: None,
                    last_publish: Instant::now(),
                    latest_snapshot: worker_snapshot,
                    guest_epoch: worker_epoch,
                    reconnect: (0, None),
                    deferred_flush: None,
                    flusher,
                    wake,
                }
                .run();
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            commands,
            notifications,
            completions,
            completion_credits,
            admission: Mutex::new(()),
            receive_cursor: AtomicUsize::new(0),
            thread: Some(thread),
            data_owner: Some(data_owner),
            closing,
            stopping,
            owner_failed,
            sequence: AtomicU64::new(0),
            guest_epoch,
            latest_snapshot,
        })
    }
    pub fn send(&self, command: Command) -> Result<u64, String> {
        let _admission = self
            .admission
            .lock()
            .map_err(|_| "backend admission gate is unavailable")?;
        if self.thread.is_none() {
            return Err("backend is closed".into());
        }
        if self.owner_failed.load(Ordering::Acquire) {
            return Err("backend owner failed; accepted operation outcomes may be unknown".into());
        }
        if self.closing.load(Ordering::Acquire) {
            return Err("backend is closing".into());
        }
        if let Command::TerminalInput { ref data, .. } = command
            && data.len() > 1024 * 1024
        {
            return Err("terminal input exceeds bounded command size".into());
        }
        validate_snapshot_command(&command)?;
        if let Command::TypeClipboard { ref text, .. } = command
            && text.len() > crate::clipboard::MAX_TEXT_SIZE
        {
            return Err("clipboard input exceeds bounded command size".into());
        }
        if !self.completion_credits.reserve() {
            return Err("backend command completion capacity full".into());
        }
        let epoch = self.guest_epoch.load(Ordering::Acquire);
        if guest_scoped_command(&command) && !epoch.is_multiple_of(2) {
            self.release_unaccepted_credit();
            return Err(
                "guest transition in progress; submit the command after recovery completes".into(),
            );
        }
        let id = match self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        {
            Ok(sequence) => sequence + 1,
            Err(_) => {
                self.release_unaccepted_credit();
                return Err("command id exhausted".into());
            }
        };
        let is_stop = matches!(&command, Command::Stop | Command::Close);
        let is_close = matches!(&command, Command::Close);
        if let Err(error) = self.commands.try_send((id, epoch, command)) {
            self.release_unaccepted_credit();
            return Err(match error {
                TrySendError::Full(_) => String::from("backend command queue full"),
                TrySendError::Disconnected(_) => String::from("backend owner disconnected"),
            });
        }
        if is_stop {
            self.stopping.store(true, Ordering::Release);
        }
        if is_close {
            self.closing.store(true, Ordering::Release);
        }
        Ok(id)
    }
    pub fn try_recv(&self) -> Option<Notification> {
        self.try_recv_status().ok().flatten()
    }

    /// Poll all notification lanes fairly and report when the sole owner has
    /// exited after its queued results and final snapshot have been drained.
    pub fn try_recv_status(&self) -> Result<Option<Notification>, String> {
        const LANES: usize = 3;
        let first = self.receive_cursor.fetch_add(1, Ordering::Relaxed) % LANES;
        let mut both_channels_disconnected = true;
        for offset in 0..LANES {
            match (first + offset) % LANES {
                0 => match self.completions.try_recv() {
                    Ok(notification) => {
                        if matches!(notification, Notification::CommandResult { id, .. } if id > 0)
                            && !self.completion_credits.release()
                        {
                            self.owner_failed.store(true, Ordering::Release);
                            self.closing.store(true, Ordering::Release);
                            self.stopping.store(true, Ordering::Release);
                        }
                        return Ok(Some(notification));
                    }
                    Err(TryRecvError::Disconnected) => {}
                    Err(TryRecvError::Empty) => both_channels_disconnected = false,
                },
                1 => match self.notifications.try_recv() {
                    Ok(notification) => return Ok(Some(notification)),
                    Err(TryRecvError::Disconnected) => {}
                    Err(TryRecvError::Empty) => both_channels_disconnected = false,
                },
                _ => {
                    if let Some(snapshot) = self
                        .latest_snapshot
                        .lock()
                        .ok()
                        .and_then(|mut latest| latest.take())
                    {
                        return Ok(Some(Notification::Snapshot(snapshot)));
                    }
                }
            }
        }
        if both_channels_disconnected {
            Err(if self.owner_failed.load(Ordering::Acquire) {
                "backend owner failed while publishing command results; remaining outcomes are unknown".into()
            } else {
                "backend owner disconnected".into()
            })
        } else {
            Ok(None)
        }
    }
    /// Wait for a notification without treating a quiet, still-running owner as failed.
    ///
    /// | Item | Purpose |
    /// |---|---|
    /// | `timeout` | Maximum channel wait; already queued notifications/snapshots return immediately. |
    /// | `Ok(Some(...))` | Next queued notification, or the latest coalesced snapshot. |
    /// | `Ok(None)` | Wait elapsed without a notification. |
    /// | `Err(...)` | Backend owner disconnected and no final snapshot remains to deliver. |
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Option<Notification>, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(notification) = self.try_recv_status()? {
                return Ok(Some(notification));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self.try_recv_status();
            }
            // Direct session senders still use the typed preview channel. Short
            // slices let completion-only traffic wake a waiter without changing
            // that public sender API.
            let wait = remaining.min(Duration::from_millis(10));
            match self.notifications.recv_timeout(wait) {
                Ok(notification) => return Ok(Some(notification)),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => thread::sleep(wait),
            }
        }
    }

    pub fn shutdown(&mut self) -> Result<(), String> {
        if let Ok(_admission) = self.admission.lock() {
            self.closing.store(true, Ordering::Release);
            self.stopping.store(true, Ordering::Release);
        } else {
            self.closing.store(true, Ordering::Release);
            self.stopping.store(true, Ordering::Release);
        }
        let result = if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| "backend owner thread panicked".into())
        } else {
            Ok(())
        };
        self.data_owner.take();
        result
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn acquire_data_owner(directory: &std::path::Path) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let owner = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(directory.join(".app-owner.lock"))
        .map_err(|error| error.to_string())?;
    if !owner
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("data owner lock must be a regular file".into());
    }
    // A lock just released can still look held for a moment: a process
    // being started elsewhere holds a copy of the file until its exec, which
    // under load can take hundreds of milliseconds. Wait up to two seconds
    // before calling the folder in use.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match rustix::fs::flock(&owner, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(owner),
            Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(format!(
                    "data folder is already in use or cannot be locked: {error}"
                ));
            }
        }
    }
}

/// Guest host-liveness timeout in never-drop mode (the default is 250 ms).
const LOSSLESS_HOST_TIMEOUT_MS: u32 = 10_000;
/// Longest a drain pass runs before the transport thread handles commands.
const PUMP_BUDGET: Duration = Duration::from_millis(20);
/// Packets per drain pass above which the next pass follows without a wait.
const BUSY_PACKETS: usize = 32;
struct Session {
    resources: crate::resources::ResourceSampler,
    guest_resources: crate::guest_resources::Collector,
    kernel_resources: crate::kernel_resources::KernelResources,
    last_resource_check: Option<Instant>,
    analysis: crate::analysis::jobs::Jobs,
    transport: Transport,
    process: VmProcess,
    capture: RawCapture,
    assembler: Assembler,
    vm: VmConfig,
    bundle: Bundle,
    disk_bundle: Bundle,
    runs: BTreeMap<u64, ProgramRun>,
    /// Host-owned side effects keyed by root cookie, independent of terminal EOF.
    run_artifacts: BTreeMap<u64, RunArtifactOwner>,
    /// Retained process-core prefixes, including owners temporarily removed for I/O.
    core_stored_len: u64,
    core_reserved_len: u64,
    manual_cores: BTreeMap<String, manual_core::Owner>,
    manual_record_count: usize,
    captures: BTreeMap<String, CaptureSession>,
    pending_capture_id: Option<String>,
    boot_id: String,
    /// Telemetry of root tasks whose launch the host has not been told about yet.
    pre_ack: crate::pre_ack::PreAckBuffer,
    /// Set once the recording quota is reached; see `crate::quota`.
    quota: crate::quota::QuotaState,
    terminal_cursor: usize,
    /// Terminal READ requests whose deadline passed before their reply arrived,
    /// keyed by request id. The guest answers commands in submission order and
    /// has already consumed the PTY bytes, so a late reply still belongs to its run.
    late_reads: BTreeMap<u64, u64>,
    /// At most one timed-out read-only status poll; no uncertain effects are replayed.
    run_status_poll: RunStatusPoll,
    recorder_poll: recorder_health::RecorderPoll,
    /// When capture process trees were last queued for saving.
    last_process_save: Instant,
    /// Bytes of this boot's network captures (pcaps written by QEMU): the
    /// finished ones, and the running one as last measured. They count
    /// against the recording quota like every other recording.
    network_bytes_done: u64,
    network_bytes: u64,
    last_network_check: Instant,
    last_memory_check: Instant,
    /// The last drain pass found enough telemetry that the next one should
    /// follow without waiting.
    telemetry_busy: bool,
    /// Capture All load shedding (see [`Session::shed_load`]).
    shed: Shed,
    status_cursor: usize,
    last_status_query: Instant,
    persisted_packets: u64,
    kernel_probe: KernelProbe,
    /// Disk work of recordings closed while the boot runs (a retired capture
    /// archive), taken by the worker into a flush job.
    flush_queue: Vec<crate::recording_flush::Step>,
}

/// Correlation survives a poll deadline, but never a new session or run generation.
#[derive(Clone)]
struct RunStatusOwner {
    cookie: u64,
    run_id: String,
    generation: u64,
}

impl RunStatusOwner {
    fn matches(&self, run: &ProgramRun) -> bool {
        self.cookie == run.summary.root_task_cookie
            && self.run_id == run.summary.id
            && self.generation == run.execution_generation
    }
}

#[derive(Default)]
struct RunStatusPoll {
    pending: Option<(u64, RunStatusOwner)>,
    diagnostic: Option<(u64, String, String)>,
}

impl RunStatusPoll {
    fn timed_out(&mut self, id: u64, owner: RunStatusOwner, error: String) {
        self.diagnostic = Some((owner.cookie, owner.run_id.clone(), error));
        self.pending = Some((id, owner));
    }

    /// Return None for unrelated replies, leaving their normal mismatch handling intact.
    fn late_reply(
        &mut self,
        id: u64,
        status: i32,
        payload: &[u8],
        owner_matches: impl FnOnce(&RunStatusOwner) -> bool,
    ) -> Option<Result<(RunStatusOwner, RunExecution), String>> {
        if !self
            .pending
            .as_ref()
            .is_some_and(|(pending_id, _)| *pending_id == id)
        {
            return None;
        }
        let (_, owner) = self.pending.take()?;
        Some((|| {
            if !owner_matches(&owner) {
                return Err("late run status owner or execution generation changed".into());
            }
            if status != 0 {
                return Err(format!(
                    "late run status command {id} returned status {status}"
                ));
            }
            let execution = crate::execution::decode(payload, owner.cookie, owner.generation)?;
            Ok((owner, execution))
        })())
    }

    /// An attachment boundary discards old reply correlation, not diagnostic ownership.
    fn forget_unanswered(&mut self) {
        self.pending = None;
    }

    fn recovered(&mut self, cookie: u64, run_id: &str, last_error: &mut Option<String>) {
        let Some((owned_cookie, owned_run_id, error)) = self.diagnostic.as_ref() else {
            return;
        };
        if *owned_cookie == cookie && owned_run_id == run_id {
            if last_error.as_ref() == Some(error) {
                *last_error = None;
            }
            self.diagnostic = None;
        }
    }
}

struct RunArtifactOwner {
    directory: PathBuf,
    summary: RunArtifacts,
    network: Option<crate::network::NetworkCapture>,
    tree_complete: bool,
    last_network_stop: Option<Instant>,
    core: Option<process_core::Transfer>,
    core_stored_len: u64,
}

impl RunArtifactOwner {
    fn new(run: &RunSummary) -> Self {
        Self {
            directory: run.directory.clone(),
            summary: RunArtifacts {
                run_id: run.id.clone(),
                vm_id: run.vm_id.clone(),
                boot_id: run.boot_id.clone(),
                memory_state: if run.request.memory_dump_on_exit {
                    RunArtifactState::WaitingForTreeExit
                } else {
                    RunArtifactState::Disabled
                },
                core_state: if run.request.core_dump_on_exit {
                    RunArtifactState::WaitingForRootExit
                } else {
                    RunArtifactState::Disabled
                },
                ..RunArtifacts::default()
            },
            network: None,
            tree_complete: false,
            last_network_stop: None,
            core: None,
            core_stored_len: 0,
        }
    }
    /// Queues the summary for the persistence thread: the transport thread
    /// never waits for the `fsync` of a status file. A failure of an earlier
    /// queued copy is returned here; finalization publishes the last one.
    fn save(&self) -> Result<(), String> {
        storage::queue_json(&self.directory.join("artifacts.json"), &self.summary)
            .map_err(|error| format!("run artifacts: {error}"))
    }
    fn issue(&mut self, issue: String) {
        let issue: String = issue.chars().take(1024).collect();
        if self.summary.issues.len() < 16 && !self.summary.issues.contains(&issue) {
            self.summary.issues.push(issue);
        }
    }
    fn observe(&mut self, execution: Option<&RunExecution>) -> bool {
        if self.tree_complete
            || !execution.is_some_and(|execution| {
                matches!(
                    crate::execution::state(execution),
                    RunState::Finished | RunState::Stopped
                )
            })
        {
            return false;
        }
        self.tree_complete = true;
        if self.summary.memory_state == RunArtifactState::WaitingForTreeExit {
            self.summary.memory_state = RunArtifactState::Queued;
        }
        true
    }
}
/// Capture All of a busy guest (a desktop) can produce telemetry faster than
/// the host decodes and saves it. Never-drop sends then make every traced
/// syscall wait for room, up to seconds each, and the guest stops responding.
/// While Capture All runs and the host falls behind, senders drop instead of
/// waiting (each drop is counted as lost telemetry); never-drop returns once
/// the host has caught up.
#[derive(Clone, Copy, Debug)]
struct Shed {
    active: bool,
    since: Instant,
    /// The guest's total send wait at `sampled`, and the share of wall time
    /// it spent waiting since the sample before.
    sampled: Instant,
    sampled_wait_ns: u64,
    wait_share: f64,
}

impl Default for Shed {
    fn default() -> Self {
        Self {
            active: false,
            since: Instant::now(),
            sampled: Instant::now(),
            sampled_wait_ns: 0,
            wait_share: 0.0,
        }
    }
}

/// Shed when this much recording waits for the disk, or the guest's senders
/// together waited this share of the time; resume below the lower backlog.
const SHED_BACKLOG: usize = 64 * 1024 * 1024;
const RESUME_BACKLOG: usize = 16 * 1024 * 1024;
const SHED_WAIT_SHARE: f64 = 0.5;
const SHED_MIN: Duration = Duration::from_secs(2);

/// Progress of the INFO probe that identifies the running guest kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KernelProbe {
    /// Send INFO at this instant.
    Due(Instant),
    /// INFO request in flight.
    Info(u64),
    /// INFO was unsupported; STATS tells a pre-INFO kernel from one still booting.
    Stats(u64),
    Done,
}
/// Retry interval while the guest control service is not yet registered.
const KERNEL_PROBE_RETRY: Duration = Duration::from_secs(1);

/// Events a live view (and a boot's events.json) shows.
const LIVE_HISTORY: usize = 2048;

/// A negative guest reply proves rejection; transport failures may leave unknown side effects.
enum RequestError {
    TimedOut(String),
    Failed(String),
    Rejected { status: i32, message: String },
}

impl RequestError {
    fn into_message(self) -> String {
        match self {
            Self::TimedOut(message) | Self::Failed(message) | Self::Rejected { message, .. } => {
                message
            }
        }
    }
}

struct Worker {
    wake: Option<Arc<dyn Fn() + Send + Sync>>,
    options: BackendOptions,
    snapshot: Snapshot,
    receiver: Receiver<(u64, u64, Command)>,
    sender: SyncSender<Notification>,
    completion_sender: SyncSender<Notification>,
    completion_credits: Arc<CompletionCredits>,
    closing: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    owner_failed: Arc<AtomicBool>,
    session: Option<Session>,
    keyboard: Option<crate::vm::keyboard::Job>,
    /// Last successful remote catalog (full entries for downloads).
    catalog: distribution::Catalog,
    /// In-flight catalog fetch.
    refresh: Option<Receiver<Result<distribution::Catalog, String>>>,
    /// In-flight base download.
    download: Option<DownloadJob>,
    /// In-flight local build.
    build: Option<BuildJob>,
    /// In-flight analysis tool installation.
    tool: Option<ToolJob>,
    last_publish: Instant,
    latest_snapshot: Arc<Mutex<Option<Snapshot>>>,
    guest_epoch: Arc<AtomicU64>,
    /// Automatic reconnection after the guest stopped answering (see
    /// [`stalled`]): failed attempts so far and when to try next.
    reconnect: (u32, Option<Instant>),
    /// Disk work of stopped boots, off this thread (see `crate::recording_flush`).
    deferred_flush: Option<crate::recording_flush::RejectedFlushJob>,
    flusher: crate::recording_flush::Flusher,
}

/// Attempts at reconnecting a guest that stopped answering, before the VM is
/// reported failed; they are spaced 2, 4, 8, 16 s apart.
const RECONNECT_ATTEMPTS: u32 = 5;

/// The transport gave up on a guest whose heartbeat stopped: its vCPUs got no
/// host time (a host under heavy load) or the guest hung. The guest is often
/// fine once it runs again, so the app reconnects instead of failing the VM.
fn stalled(error: &str) -> bool {
    error.starts_with("transport:") && error.contains("(os error 110)")
}

struct ToolJob {
    /// Stage, received and total octets.
    progress: Arc<Mutex<(String, u64, u64)>>,
    cancel: Arc<AtomicBool>,
    done: Receiver<Result<(), String>>,
}

struct DownloadJob {
    identity: String,
    label: String,
    total: u64,
    /// Received octets and whether atomic installation has started.
    progress: Arc<Mutex<(u64, bool)>>,
    cancel: Arc<AtomicBool>,
    done: Receiver<Result<(), String>>,
    thread: JoinHandle<()>,
}

struct BuildJob {
    label: String,
    stage: Arc<Mutex<String>>,
    log: Arc<Mutex<std::collections::VecDeque<String>>>,
    cancel: Arc<AtomicBool>,
    done: Receiver<Result<(), String>>,
}
/// One base build on its worker thread: kit, inputs, then native or QEMU.
struct BuildRun {
    kind: build::Kind,
    profile: &'static str,
    mode: build::BuildMode,
    options: build::BuildOptions,
    data_dir: PathBuf,
    curl: PathBuf,
    output: PathBuf,
    log_path: PathBuf,
    stage: Arc<Mutex<String>>,
    log: Arc<Mutex<VecDeque<String>>>,
    cancel: Arc<AtomicBool>,
}
impl BuildRun {
    fn run(&self) -> Result<(), String> {
        let mut file = File::create(&self.log_path)
            .map_err(|e| format!("{}: {e}", self.log_path.display()))?;
        let mut line = |text: &str| {
            use std::io::Write;
            let _ = writeln!(file, "{text}");
            // The orchestrator's own "done" precedes the install; only the
            // worker's completion marks the build done.
            if let Some(stage) = text.strip_prefix("::stage ")
                && stage.trim() != "done"
                && let Ok(mut guard) = self.stage.lock()
            {
                *guard = stage.trim().to_string();
            }
            if let Ok(mut guard) = self.log.lock() {
                if guard.len() >= 400 {
                    guard.pop_front();
                }
                guard.push_back(text.to_string());
            }
        };
        let result = self.steps(&mut line);
        if let Err(error) = &result {
            line(&format!("::error {error}"));
        }
        result.map_err(|error| format!("{error} (log: {})", self.log_path.display()))
    }
    fn steps(&self, line: &mut impl FnMut(&str)) -> Result<(), String> {
        let root = self.data_dir.join("build");
        storage::private_dir(&root).map_err(|e| e.to_string())?;
        line("::stage prepare");
        let kit = crate::kit::materialize(&root)?;
        line(&format!("build kit {}", kit.display()));
        let mut reported = 0;
        let orig = crate::kit::fetch_orig(
            &self.curl,
            &root.join("inputs"),
            &self.cancel,
            |received, total| {
                let percent = (received * 100).checked_div(total).unwrap_or(0);
                if percent >= reported + 10 {
                    reported = percent - percent % 10;
                    line(&format!("kernel source download {reported}%"));
                }
            },
        )?;
        let job = serde_json::json!({
            "format": 1,
            "profile": self.profile,
            "options": self.options.job_options(self.kind),
            "app_version": APP_VERSION,
        });
        let kernel_cache = crate::kit::kernel_cache(&root, build::kernel_profile(self.kind))?;
        if kernel_cache.is_file() {
            line("the kernel for this app version is cached; only the image is built");
        }
        // Debian images reuse a recent root filesystem with the same answers.
        let image_cache = job["options"]["desktop"]
            .as_str()
            .map(|desktop| crate::kit::image_cache(&root, desktop));
        if image_cache.as_ref().is_some_and(|cache| cache.is_file()) {
            line("a root filesystem for these answers is cached; it is reused if recent");
        }
        match self.mode {
            build::BuildMode::Qemu => {
                line("::stage builder");
                let output = &self.output;
                fs::create_dir_all(output).map_err(|e| format!("{}: {e}", output.display()))?;
                let qemu =
                    build::which("qemu-system-x86_64").ok_or("qemu-system-x86_64 not found")?;
                let qemu_img = build::which("qemu-img").ok_or("qemu-img not found")?;
                crate::builder_vm::QemuBuild {
                    curl: &self.curl,
                    qemu: &qemu,
                    qemu_img: &qemu_img,
                    root: &root,
                    kit: &kit,
                    orig: &orig,
                    job: &job,
                    mirror: &self.options.mirror,
                    proxy: &self.options.proxy,
                    kernel_cache: &kernel_cache,
                    image_cache: image_cache.as_deref(),
                    ccache: &crate::kit::ccache_archive(&root),
                    output,
                    cancel: &self.cancel,
                }
                .run(&mut *line)
            }
            _ => {
                let job_path = root.join("job.json");
                fs::write(
                    &job_path,
                    serde_json::to_vec_pretty(&job).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                let python = build::which("python3").ok_or("python3 not found")?;
                let mut command = std::process::Command::new(python);
                command
                    .arg(kit.join("scripts/build-base.py"))
                    .arg("--job")
                    .arg(&job_path)
                    .arg("--inputs")
                    .arg(root.join("inputs"))
                    .arg("--work")
                    .arg(root.join("work"))
                    .arg("--output")
                    .arg(&self.output)
                    .arg("--kernel-cache")
                    .arg(&kernel_cache)
                    .arg("--ccache")
                    .arg(crate::kit::ccache_dir(&root));
                if let Some(cache) = &image_cache {
                    command.arg("--image-cache").arg(cache);
                }
                build::run_streaming(&mut command, "native build", &self.cancel, &mut *line)
            }
        }?;
        crate::kit::prune_kernel_cache(&kernel_cache);
        line("::stage install");
        Ok(())
    }
}
// Odd epochs fence submissions; the owner closes the boundary on every exit.
struct GuestTransition(Arc<AtomicU64>);
impl Drop for GuestTransition {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

/// Wall clock in milliseconds since the Unix epoch.
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_millis() as u64)
}

#[cfg(test)]
mod stall_tests;
#[cfg(test)]
mod tests;
