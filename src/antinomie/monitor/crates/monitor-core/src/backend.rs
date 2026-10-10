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
    io::Read,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// Commands and UI notifications are bounded. Closing always joins the sole owner.
pub struct Backend {
    commands: SyncSender<(u64, Command)>,
    notifications: Receiver<Notification>,
    thread: Option<JoinHandle<()>>,
    closing: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    sequence: AtomicU64,
    latest_snapshot: Arc<Mutex<Option<Snapshot>>>,
}
impl Backend {
    pub fn new(mut options: BackendOptions) -> Result<Self, String> {
        storage::migrate_default_data(&options)?;
        storage::private_dir(&options.data_dir).map_err(|e| e.to_string())?;
        options.data_dir = fs::canonicalize(&options.data_dir).map_err(|e| e.to_string())?;
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
        let closing = Arc::new(AtomicBool::new(false));
        let stopping = Arc::new(AtomicBool::new(false));
        let (worker_closing, worker_stopping) = (closing.clone(), stopping.clone());
        let latest_snapshot = Arc::new(Mutex::new(None));
        let worker_snapshot = latest_snapshot.clone();
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
                    closing: worker_closing,
                    stopping: worker_stopping,
                    session: None,
                    catalog: distribution::Catalog::default(),
                    refresh: None,
                    download: None,
                    build: None,
                    tool: None,
                    last_publish: Instant::now(),
                    latest_snapshot: worker_snapshot,
                }
                .run();
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            commands,
            notifications,
            thread: Some(thread),
            closing,
            stopping,
            sequence: AtomicU64::new(0),
            latest_snapshot,
        })
    }
    pub fn send(&self, command: Command) -> Result<u64, String> {
        if self.thread.is_none() {
            return Err("backend is closed".into());
        }
        if matches!(command, Command::Stop | Command::Close) {
            self.stopping.store(true, Ordering::Relaxed);
        }
        if matches!(command, Command::Close) {
            self.closing.store(true, Ordering::Relaxed);
        }
        if let Command::TerminalInput { ref data, .. } = command
            && data.len() > 1024 * 1024
        {
            return Err("terminal input exceeds bounded command size".into());
        }
        let id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| "command id exhausted")?
            + 1;
        self.commands.try_send((id, command)).map_err(|e| match e {
            TrySendError::Full(_) => String::from("backend command queue full"),
            TrySendError::Disconnected(_) => String::from("backend owner disconnected"),
        })?;
        Ok(id)
    }
    pub fn try_recv(&self) -> Option<Notification> {
        self.notifications.try_recv().ok().or_else(|| {
            self.latest_snapshot
                .lock()
                .ok()?
                .take()
                .map(Notification::Snapshot)
        })
    }
    pub fn shutdown(&mut self) -> Result<(), String> {
        self.closing.store(true, Ordering::Relaxed);
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| "backend owner thread panicked")?;
        }
        Ok(())
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// Guest host-liveness timeout in never-drop mode (the default is 250 ms).
const LOSSLESS_HOST_TIMEOUT_MS: u32 = 10_000;
/// Longest a drain pass runs before the transport thread handles commands.
const PUMP_BUDGET: Duration = Duration::from_millis(20);
/// Packets per drain pass above which the next pass follows without a wait.
const BUSY_PACKETS: usize = 32;
struct Session {
    analysis: crate::analysis::jobs::Jobs,
    transport: Transport,
    process: VmProcess,
    capture: RawCapture,
    assembler: Assembler,
    vm: VmConfig,
    bundle: Bundle,
    disk_bundle: Bundle,
    runs: BTreeMap<u64, ProgramRun>,
    captures: BTreeMap<String, CaptureSession>,
    pending_capture_id: Option<String>,
    boot_id: String,
    pending: VecDeque<Vec<u8>>,
    pending_len: usize,
    pending_overflow: bool,
    terminal_cursor: usize,
    /// Terminal READ requests whose deadline passed before their reply arrived,
    /// keyed by request id. The guest answers commands in submission order and
    /// has already consumed the PTY bytes, so a late reply still belongs to its run.
    late_reads: BTreeMap<u64, u64>,
    /// When capture process trees were last queued for saving.
    last_process_save: Instant,
    /// The last drain pass found enough telemetry that the next one should
    /// follow without waiting.
    telemetry_busy: bool,
    status_cursor: usize,
    last_status_query: Instant,
    persisted_packets: u64,
    kernel_probe: KernelProbe,
}
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
impl Session {
    fn stored_len(&self) -> u64 {
        self.capture
            .bytes
            .saturating_add(self.assembler.stored_len())
            .saturating_add(self.runs.values().map(ProgramRun::stored_len).sum::<u64>())
            .saturating_add(self.analysis.stored_len())
            .saturating_add(
                self.captures
                    .values()
                    .map(CaptureSession::stored_len)
                    .sum::<u64>(),
            )
    }
    fn available(&self) -> u64 {
        self.capture.quota().saturating_sub(self.stored_len())
    }
    fn refresh_storage_health(&self, health: &mut Health) {
        refresh_storage_health(
            health,
            &self.capture,
            self.assembler
                .stored_len()
                .saturating_add(self.analysis.persisted_len()),
            &self.runs,
        );
        health.persisted_len = health.persisted_len.saturating_add(
            self.captures
                .values()
                .map(CaptureSession::stored_len)
                .sum::<u64>(),
        );
        health.persistence_error = health.persistence_error.clone().or_else(|| {
            self.captures
                .values()
                .find_map(|capture| capture.summary.recording_error.clone())
        });
    }
    fn stop_saving(&mut self, error: String) {
        stop_capture_saving(
            &mut self.capture,
            &mut self.assembler,
            &mut self.runs,
            error.clone(),
        );
        for capture in self.captures.values_mut() {
            capture.storage_error(error.clone());
        }
    }
    fn run_cookie(&self, id: &str) -> Result<u64, String> {
        self.runs
            .iter()
            .find(|(_, run)| run.summary.id == id)
            .map(|(cookie, _)| *cookie)
            .ok_or_else(|| "unknown run in this VM boot".into())
    }
    fn update_runs(&self, snapshot: &mut Snapshot) {
        snapshot.runs = self.runs.values().map(|run| run.summary.clone()).collect();
    }
    fn update_captures(&self, snapshot: &mut Snapshot) {
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
    fn start_capture(
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
        if let Err(RequestError::Rejected(error)) = &result {
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
                if let Err(error) = capture.finalize(&snapshot.health) {
                    snapshot.last_error = Some(format!("capture finalization: {error}"));
                }
            }
        }
    }
    fn apply_capture_status(
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
    fn analysis_updates(&mut self, snapshot: &mut Snapshot, sender: &SyncSender<Notification>) {
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
    fn analysis_tick(&mut self, snapshot: &mut Snapshot, sender: &SyncSender<Notification>) {
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
    fn list_processes(
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
    fn query_run_status(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
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
        let result = self.request(
            control::RUN_STATUS,
            &control::with_session(cookie),
            snapshot,
            sender,
            Duration::from_millis(100),
        );
        let run = self
            .runs
            .get_mut(&cookie)
            .ok_or("missing run status owner")?;
        let result = result
            .and_then(|reply| crate::execution::decode(&reply, cookie, run.execution_generation));
        match result {
            Ok(execution) => {
                if run.summary.execution.as_ref() != Some(&execution) {
                    run.execution_generation = execution.generation;
                    run.summary.state = crate::execution::state(&execution);
                    run.summary.execution = Some(execution);
                    run.persist_summary()?;
                }
                Ok(())
            }
            Err(error) => {
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
    fn history(&self) -> Vec<EventSummary> {
        canonical_live_history(
            self.assembler.recent(LIVE_HISTORY),
            self.runs
                .values()
                .map(|run| run.assembler.recent(LIVE_HISTORY)),
        )
    }
    fn pump(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        self.transport.poll(0)?;
        // Drain until the guest's rings are empty: they hold only milliseconds
        // of busy telemetry. A time budget still returns control to command
        // handling under continuous telemetry.
        let started = Instant::now();
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
            let reserved = self.stored_len();
            let mut saved =
                if let Some(run) = self.runs.get_mut(&root) {
                    let saved = run
                        .capture
                        .append_with_reserved(&packet, reserved.saturating_sub(run.capture.bytes));
                    if !saved {
                        run.storage_error(
                            run.capture
                                .error
                                .clone()
                                .unwrap_or_else(|| "raw saving stopped".into()),
                        );
                    }
                    run.assembler
                        .set_storage_limit(run.assembler.stored_len().saturating_add(
                            self.capture.quota().saturating_sub(
                                reserved + if saved { packet.len() as u64 + 4 } else { 0 },
                            ),
                        ));
                    if let Err(error) = run.assembler.ingest(&packet) {
                        snapshot.health.parser_errors += 1;
                        snapshot.last_error = Some(error.to_string());
                    }
                    saved
                } else {
                    let saved = self
                        .capture
                        .append_with_reserved(&packet, reserved.saturating_sub(self.capture.bytes));
                    if !saved {
                        self.assembler.stop_saving();
                    }
                    self.assembler
                        .set_storage_limit(self.assembler.stored_len().saturating_add(
                            self.capture.quota().saturating_sub(
                                reserved + if saved { packet.len() as u64 + 4 } else { 0 },
                            ),
                        ));
                    if let Err(error) = self.assembler.ingest(&packet) {
                        snapshot.health.parser_errors += 1;
                        snapshot.last_error = Some(error.to_string());
                    }
                    if root != 0 {
                        while self.pending_len + packet.len() > 16 * 1024 * 1024 {
                            if let Some(old) = self.pending.pop_front() {
                                self.pending_len -= old.len();
                                self.pending_overflow = true;
                            } else {
                                break;
                            }
                        }
                        self.pending.push_back(packet.to_vec());
                        self.pending_len += packet.len();
                    }
                    saved
                };
            // Observer copies do not contribute to canonical history: the primary
            // run/unassigned assembler above already owns each incoming packet.
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
            propagate_object_saving_failure(&mut self.capture, &mut self.assembler, &mut self.runs);
            if let Some(error) = self
                .captures
                .values()
                .find_map(|capture| capture.summary.recording_error.clone())
            {
                // Unknown command outcomes are status, not persistence failures.
                self.stop_saving(error);
            }
            if !saved {
                let error = self
                    .capture
                    .error
                    .clone()
                    .or_else(|| self.runs.values().find_map(|run| run.capture.error.clone()))
                    .unwrap_or_else(|| "capture saving stopped".into());
                self.stop_saving(error);
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
    fn request(
        &mut self,
        opcode: u32,
        args: &[u8],
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        if timeout.is_zero() {
            return Err("guest command deadline exhausted before submission".into());
        }
        let id = self.transport.send(opcode, args)?;
        self.wait_reply(id, opcode, snapshot, sender, timeout)
            .map_err(RequestError::into_message)
    }
    /// A reply for an earlier request: a late terminal READ is applied to its run;
    /// anything else has no remaining waiter.
    fn other_reply(
        &mut self,
        reply_id: u64,
        status: i32,
        payload: &[u8],
        awaiting: Option<u64>,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) {
        if self.kernel_probe_reply(reply_id, status, payload, snapshot) {
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
    fn probe_kernel(
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
    fn drain_replies(
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
    fn wait_reply(
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
                    return Err(RequestError::Rejected(format!(
                        "guest command 0x{opcode:x}: {}",
                        std::io::Error::from_raw_os_error(-status)
                    )));
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
                return Err(RequestError::Failed(
                    "VM exited while waiting for command reply".into(),
                ));
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
    fn finalize(&mut self, state: &str, snapshot: &mut Snapshot) -> Result<(), String> {
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
    fn read_terminal(
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
            Err(RequestError::Failed(error) | RequestError::Rejected(error)) => Err(error),
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
        let sequence = run.sequence;
        let run_id = run.summary.id.clone();
        if let Some(error) = persistence_error {
            self.stop_saving(error.clone());
            snapshot.health.persistence_error = Some(error);
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

/// Events a live view (and a boot's events.json) shows.
const LIVE_HISTORY: usize = 2048;
fn bounded_live_history(mut events: Vec<EventSummary>) -> Vec<EventSummary> {
    events.sort_by_key(|event| event.timestamp_ns);
    if events.len() > LIVE_HISTORY {
        events.drain(..events.len() - LIVE_HISTORY);
    }
    events
}

fn canonical_live_history(
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

/// A negative guest reply proves rejection; transport failures may leave unknown side effects.
enum RequestError {
    TimedOut(String),
    Failed(String),
    Rejected(String),
}

impl RequestError {
    fn into_message(self) -> String {
        match self {
            Self::TimedOut(message) | Self::Failed(message) | Self::Rejected(message) => message,
        }
    }
}

struct Worker {
    options: BackendOptions,
    snapshot: Snapshot,
    receiver: Receiver<(u64, Command)>,
    sender: SyncSender<Notification>,
    closing: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    session: Option<Session>,
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

fn begin_base_install(progress: &Mutex<(u64, bool)>, cancel: &AtomicBool) -> Result<(), String> {
    let mut progress = progress
        .lock()
        .map_err(|_| "download progress lock poisoned")?;
    if cancel.load(Ordering::Relaxed) {
        return Err("download cancelled".into());
    }
    progress.1 = true;
    Ok(())
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
impl Worker {
    fn refresh_locations(&mut self) -> Result<(), String> {
        self.snapshot.bases = crate::locations::installed_bases(&self.options)?;
        self.snapshot.vm_locations = self
            .snapshot
            .vms
            .iter()
            .map(|vm| crate::locations::locations(&self.options, &vm.id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }
    fn emit(&mut self, notification: Notification) {
        if self.sender.try_send(notification).is_err() {
            self.snapshot.health.ui_dropped += 1;
        }
    }
    fn publish(&mut self) {
        if let Some(session) = &self.session {
            self.snapshot.events = session.history();
            session.update_runs(&mut self.snapshot);
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
    fn poll_remote(&mut self) {
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
    fn run(mut self) {
        self.publish();
        self.load_bases();
        self.publish();
        loop {
            if self.closing.load(Ordering::Relaxed) {
                if let Some(job) = self.download.as_ref() {
                    job.cancel.store(true, Ordering::Relaxed);
                }
                if let Some(job) = self.build.as_ref() {
                    job.cancel.store(true, Ordering::Relaxed);
                }
                let result = self.stop();
                if let Err(e) = result {
                    self.snapshot.last_error = Some(e);
                }
                if let Some(job) = self.download.take()
                    && job.thread.join().is_err()
                {
                    self.snapshot.last_error = Some("download worker panicked".into());
                }
                self.publish();
                storage::flush_json();
                crate::writer::barrier();
                break;
            }
            // While telemetry is flowing, take waiting commands without
            // sleeping so the next drain pass follows at once.
            let mut received = if self
                .session
                .as_ref()
                .is_some_and(|session| session.telemetry_busy)
            {
                self.receiver.try_recv().map_err(|error| match error {
                    mpsc::TryRecvError::Empty => mpsc::RecvTimeoutError::Timeout,
                    mpsc::TryRecvError::Disconnected => mpsc::RecvTimeoutError::Disconnected,
                })
            } else {
                self.receiver.recv_timeout(Duration::from_millis(10))
            };
            // Handle every queued command (up to a bound), not one per pass: a
            // busy guest makes each pass slow and the bounded queue would fill.
            // Repeated terminal reads of one run in a batch are answered once.
            let mut handled = 0;
            let mut terminal_reads = std::collections::BTreeSet::new();
            let mut disconnected = false;
            loop {
                match received {
                    Ok((id, command)) => {
                        let quiet = matches!(
                            command,
                            Command::TerminalRead { .. } | Command::TerminalResize { .. }
                        );
                        let repeated = matches!(&command, Command::TerminalRead { run_id }
                            if !terminal_reads.insert(run_id.clone()));
                        let result = if repeated {
                            Ok(String::new())
                        } else {
                            self.command(command)
                        };
                        let success = result.is_ok();
                        let message = result.unwrap_or_else(|e| e);
                        if !success {
                            self.snapshot.last_error = Some(message.clone());
                        }
                        if !quiet || !success {
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
            if disconnected {
                self.closing.store(true, Ordering::Relaxed);
                continue;
            }
            let mut exited = false;
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
                    Ok(None) => {
                        if let Err(e) = session.pump(&mut self.snapshot, &self.sender) {
                            self.snapshot.last_error = Some(e);
                            self.snapshot.state = VmState::Failed;
                        }
                        if let Err(error) =
                            session.query_run_status(&mut self.snapshot, &self.sender)
                        {
                            self.snapshot.last_error = Some(error);
                        }
                        if let Err(error) = session.probe_kernel(&mut self.snapshot, &self.sender) {
                            self.snapshot.last_error = Some(format!("guest info: {error}"));
                        }
                        session.analysis_tick(&mut self.snapshot, &self.sender);
                    }
                    Err(e) => {
                        self.snapshot.last_error = Some(e.to_string());
                        exited = true;
                    }
                }
            }
            if exited {
                if let Some(mut session) = self.session.take()
                    && let Err(e) = session.finalize("unexpected-exit", &mut self.snapshot)
                {
                    self.snapshot.last_error = Some(e);
                }
                if let Err(e) = end_network_capture(&mut self.snapshot) {
                    self.snapshot.last_error = Some(e);
                }
                self.snapshot.active_vm = None;
                self.snapshot.state = VmState::Stopped;
                self.publish();
            }
            let automatic_read = self.session.as_mut().and_then(|session| {
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
            self.poll_remote();
            self.poll_build();
            self.poll_tool();
            if self.last_publish.elapsed() >= Duration::from_millis(250) {
                self.publish();
            }
        }
    }
    fn ensure_stopped(&self, id: &str) -> Result<(), String> {
        if self.snapshot.active_vm.as_deref() == Some(id) {
            Err("stop the VM before modifying its disk or configuration".into())
        } else {
            Ok(())
        }
    }
    fn command(&mut self, command: Command) -> Result<String, String> {
        match command {
            Command::Create(vm) => self.create(vm, None),
            Command::CreateWithCredentials { vm, credentials } => {
                self.create(vm, Some(credentials))
            }
            Command::ImportBase { directory } => {
                if self.session.is_some() || self.snapshot.active_vm.is_some() {
                    return Err("stop VM before importing a base".into());
                }
                let bundle = Bundle::load(&directory)?;
                if !bundle.kernel_version.starts_with("6.12.94") {
                    return Err("boot bundle must use Linux 6.12.94".into());
                }
                require_supported(bundle.antinomie_revision, bundle.min_app_version.as_deref())?;
                storage::validate_disk_chain(&self.options, &bundle.base_disk, None)?;
                bundle.install(&self.options)?;
                self.refresh_locations()?;
                Ok("base imported".into())
            }
            Command::RefreshRemoteBases => {
                if self.refresh.is_some() {
                    return Err("base catalog refresh already in progress".into());
                }
                distribution::curl_version(&self.options.curl)?;
                let curl = self.options.curl.clone();
                let remote = self.options.remote_base.clone();
                let (sender, receiver) = mpsc::channel();
                thread::Builder::new()
                    .name("antinomie-catalog".into())
                    .spawn(move || {
                        let _ = sender.send(distribution::fetch_catalog(&curl, &remote));
                    })
                    .map_err(|e| e.to_string())?;
                self.refresh = Some(receiver);
                self.snapshot.remote_refreshing = true;
                self.snapshot.remote_error = None;
                Ok("refreshing base catalog".into())
            }
            Command::DownloadBase { identity } => {
                if self.download.is_some() {
                    return Err("a base download is already in progress".into());
                }
                distribution::curl_version(&self.options.curl)?;
                let base = self
                    .catalog
                    .bases
                    .iter()
                    .find(|base| base.identity == identity)
                    .cloned()
                    .ok_or("unknown base; refresh the catalog first")?;
                require_supported(base.antinomie_revision, base.min_app_version.as_deref())?;
                if self
                    .snapshot
                    .bases
                    .iter()
                    .any(|installed| installed.id == identity)
                {
                    return Err("base is already installed".into());
                }
                let staging = self.options.data_dir.join("downloads").join(&base.identity);
                fs::create_dir_all(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
                let options = self.options.clone();
                let curl = self.options.curl.clone();
                let remote = self.options.remote_base.clone();
                let total: u64 = base.files.iter().map(|file| file.size).sum();
                let label = match base_app_version(
                    base.antinomie_revision,
                    base.min_app_version.as_deref(),
                ) {
                    Some(version) => format!("{} · Antinomie {version}", base.label),
                    None => base.label.clone(),
                };
                let progress = Arc::new(Mutex::new((0u64, false)));
                let worker_progress = progress.clone();
                let (sender, receiver) = mpsc::channel();
                let requested = base.clone();
                let staging_thread = staging.clone();
                let cancel = Arc::new(AtomicBool::new(false));
                let worker_cancel = cancel.clone();
                let thread = thread::Builder::new()
                    .name("antinomie-download".into())
                    .spawn(move || {
                        let cancel = worker_cancel;
                        let result = distribution::download_base(
                            &curl,
                            &remote,
                            &requested,
                            &staging_thread,
                            &cancel,
                            |received, _| {
                                if let Ok(mut guard) = worker_progress.lock() {
                                    guard.0 = received;
                                }
                            },
                        )
                        .and_then(|bundle| {
                            if cancel.load(Ordering::Relaxed) {
                                return Err("download cancelled".into());
                            }
                            require_supported(
                                bundle.antinomie_revision,
                                bundle.min_app_version.as_deref(),
                            )?;
                            storage::validate_disk_chain(&options, &bundle.base_disk, None)?;
                            begin_base_install(&worker_progress, &cancel)?;
                            bundle.install(&options)?;
                            Ok(())
                        });
                        let ok = result.is_ok();
                        let _ = sender.send(result);
                        if ok {
                            let _ = fs::remove_dir_all(&staging_thread);
                        }
                    })
                    .map_err(|e| e.to_string())?;
                self.download = Some(DownloadJob {
                    identity: base.identity.clone(),
                    label: label.clone(),
                    total,
                    progress,
                    cancel,
                    done: receiver,
                    thread,
                });
                self.snapshot.download = Some(DownloadStatus {
                    identity: base.identity,
                    label,
                    received: 0,
                    total,
                    installing: false,
                    finished: false,
                    error: None,
                });
                Ok("base download started".into())
            }
            Command::CancelDownload => {
                let job = self
                    .download
                    .as_ref()
                    .ok_or("no base download is running")?;
                let progress = job
                    .progress
                    .lock()
                    .map_err(|_| "download progress lock poisoned")?;
                if progress.1 {
                    return Err("base download finished; installation is in progress".into());
                }
                job.cancel.store(true, Ordering::Relaxed);
                Ok("cancelling the base download".into())
            }
            Command::BuildBase { request } => {
                if self.build.is_some() {
                    return Err("a base build is already in progress".into());
                }
                let spec = build::profile(&request.profile).ok_or("unknown build profile")?;
                request.options.validate(spec.kind)?;
                let mode = build::resolve_mode(spec.kind, request.mode)?;
                let label = match request.options.name.trim() {
                    "" => build::automatic_base_name(spec.kind, &request.options.desktop),
                    name => name.to_string(),
                };
                let id = crate::storage::unique_id();
                let builds = self.options.data_dir.join("builds");
                storage::private_dir(&builds).map_err(|e| e.to_string())?;
                let output = builds.join(format!("{}-{id}", spec.id));
                let log_path = builds.join(format!("{}-{id}.log", spec.id));
                let stage = Arc::new(Mutex::new("prepare".to_string()));
                let log = Arc::new(Mutex::new(VecDeque::<String>::new()));
                let cancel = Arc::new(AtomicBool::new(false));
                let (sender, receiver) = mpsc::channel();
                let job = BuildRun {
                    kind: spec.kind,
                    profile: spec.id,
                    mode,
                    options: request.options,
                    data_dir: self.options.data_dir.clone(),
                    curl: self.options.curl.clone(),
                    output,
                    log_path: log_path.clone(),
                    stage: stage.clone(),
                    log: log.clone(),
                    cancel: cancel.clone(),
                };
                let options = self.options.clone();
                thread::Builder::new()
                    .name("antinomie-build".into())
                    .spawn(move || {
                        let output = job.output.clone();
                        let result = job.run().and_then(|()| {
                            let bundle = Bundle::load(&output)?;
                            require_supported(
                                bundle.antinomie_revision,
                                bundle.min_app_version.as_deref(),
                            )?;
                            storage::validate_disk_chain(&options, &bundle.base_disk, None)?;
                            bundle.install(&options)?;
                            Ok(())
                        });
                        let _ = fs::remove_dir_all(&output);
                        let _ = sender.send(result);
                    })
                    .map_err(|e| e.to_string())?;
                self.build = Some(BuildJob {
                    label: label.clone(),
                    stage,
                    log,
                    cancel,
                    done: receiver,
                });
                self.snapshot.build = Some(BuildStatus {
                    profile: spec.id.to_string(),
                    label: label.clone(),
                    mode,
                    stage: "prepare".into(),
                    log: Vec::new(),
                    log_path: Some(log_path),
                    finished: false,
                    error: None,
                });
                Ok(match mode {
                    build::BuildMode::Qemu => "base build started in the QEMU builder VM".into(),
                    _ => "base build started on this host".into(),
                })
            }
            Command::InstallTool { id } => {
                if self.tool.is_some() {
                    return Err("a tool installation is already in progress".into());
                }
                let package = crate::analysis_tools::package(&id).ok_or("unknown analysis tool")?;
                distribution::curl_version(&self.options.curl)?;
                let progress = Arc::new(Mutex::new(("download".to_string(), 0, package.size())));
                let cancel = Arc::new(AtomicBool::new(false));
                let (sender, receiver) = mpsc::channel();
                let (curl, data_dir) = (self.options.curl.clone(), self.options.data_dir.clone());
                let (worker_progress, worker_cancel) = (progress.clone(), cancel.clone());
                thread::Builder::new()
                    .name("antinomie-tool-install".into())
                    .spawn(move || {
                        let result = crate::analysis_tools::install(
                            &curl,
                            &data_dir,
                            package.id,
                            &worker_cancel,
                            |stage, received, total| {
                                if let Ok(mut guard) = worker_progress.lock() {
                                    *guard = (stage.to_string(), received, total);
                                }
                            },
                        );
                        let _ = sender.send(result);
                    })
                    .map_err(|e| e.to_string())?;
                self.tool = Some(ToolJob {
                    progress,
                    cancel,
                    done: receiver,
                });
                self.snapshot.tool_install = Some(crate::analysis_tools::ToolInstall {
                    id: package.id.into(),
                    name: package.name.into(),
                    stage: "download".into(),
                    received: 0,
                    total: package.size(),
                    finished: false,
                    error: None,
                });
                Ok(format!("installing {}", package.name))
            }
            Command::CancelToolInstall => {
                let job = self
                    .tool
                    .as_ref()
                    .ok_or("no tool installation is running")?;
                job.cancel.store(true, Ordering::Relaxed);
                Ok("cancelling tool installation".into())
            }
            Command::RemoveTool { id } => {
                if self.tool.as_ref().is_some()
                    && self
                        .snapshot
                        .tool_install
                        .as_ref()
                        .is_some_and(|t| t.id == id)
                {
                    return Err("the tool is being installed".into());
                }
                crate::analysis_tools::remove(&self.options.data_dir, &id)?;
                self.snapshot.analysis_tools =
                    crate::analysis_tools::statuses(&self.options.data_dir);
                Ok("analysis tool removed".into())
            }
            Command::CancelBuild => {
                let job = self.build.as_ref().ok_or("no base build is running")?;
                job.cancel.store(true, Ordering::Relaxed);
                Ok("cancelling the base build".into())
            }
            Command::DeleteBase {
                identity,
                confirmed,
            } => {
                if !confirmed {
                    return Err("base deletion requires confirmation".into());
                }
                if self.session.is_some() || self.snapshot.active_vm.is_some() {
                    return Err("stop the VM before deleting a base".into());
                }
                if identity.len() != 64
                    || !identity
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("invalid base identity".into());
                }
                let dependents: Vec<&str> = self
                    .snapshot
                    .vms
                    .iter()
                    .filter(|vm| vm.base_identity.as_deref() == Some(identity.as_str()))
                    .map(|vm| vm.name.as_str())
                    .collect();
                if !dependents.is_empty() {
                    return Err(format!(
                        "base is used by {} VM(s): {}",
                        dependents.len(),
                        dependents.join(", ")
                    ));
                }
                let directory = self.options.data_dir.join("bases").join(&identity);
                if !directory.is_dir() {
                    return Err("unknown base".into());
                }
                fs::remove_dir_all(&directory).map_err(|e| e.to_string())?;
                self.refresh_locations()?;
                Ok("base deleted".into())
            }
            Command::Save(mut vm) => {
                storage::validate_vm(&vm)?;
                vm.launch.validate_for(&self.options)?;
                self.ensure_stopped(&vm.id)?;
                let current = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|v| v.id == vm.id)
                    .ok_or("unknown VM")?;
                let boot_bundle =
                    crate::locations::boot_bundle(&self.options, vm.base_identity.as_deref())?;
                storage::validate_boot_display(&vm, &boot_bundle)?;
                let location =
                    crate::locations::future_recordings(&self.options, current, &mut vm)?;
                let dir = storage::vm_dir(&self.options, &vm.id)?;
                let disk_bundle: Bundle = storage::read_json(&dir.join("bundle.json"))?;
                storage::validate_guest_transition(&disk_bundle, &boot_bundle)?;
                storage::validate_vm_bundle(&self.options, &vm, &disk_bundle)?;
                storage::validate_vm_bundle(&self.options, &vm, &boot_bundle)?;
                if vm.disk_gib < current.disk_gib {
                    return Err("persistent VM disks cannot be shrunk".into());
                }
                if vm.disk_gib != current.disk_gib {
                    let output = std::process::Command::new(&self.options.qemu_img)
                        .arg("resize")
                        .arg(dir.join("disk.qcow2"))
                        .arg(format!("{}G", vm.disk_gib))
                        .output()
                        .map_err(|e| e.to_string())?;
                    if !output.status.success() {
                        return Err(format!(
                            "disk resize: {}",
                            String::from_utf8_lossy(&output.stderr)
                        ));
                    }
                }
                let previous = current.clone();
                let publication =
                    storage::save_vm_config(&self.options, &dir, &previous, &vm, &location);
                if let Err(error) = &publication
                    && !error.published
                {
                    return Err(error.to_string());
                }
                let slot = self
                    .snapshot
                    .vms
                    .iter_mut()
                    .find(|v| v.id == vm.id)
                    .ok_or("unknown VM")?;
                *slot = vm;
                self.refresh_locations()?;
                publication?;
                Ok("VM saved".into())
            }
            Command::Rename { vm_id, name } => {
                let mut vm = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|vm| vm.id == vm_id)
                    .ok_or("unknown VM")?
                    .clone();
                vm.name = name;
                storage::validate_vm(&vm)?;
                let dir = storage::vm_dir(&self.options, &vm_id)?;
                storage::atomic_json(&dir.join("config.json"), &vm)?;
                if let Some(slot) = self.snapshot.vms.iter_mut().find(|vm| vm.id == vm_id) {
                    *slot = vm;
                }
                Ok("VM renamed; identity, disk and recordings retained".into())
            }
            Command::Duplicate { vm_id, name } => {
                self.ensure_stopped(&vm_id)?;
                let source = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|vm| vm.id == vm_id)
                    .ok_or("unknown VM")?
                    .clone();
                source.launch.validate_for(&self.options)?;
                if source.launch.resolution.dimensions().is_some() {
                    let boot = crate::locations::boot_bundle(
                        &self.options,
                        source.base_identity.as_deref(),
                    )?;
                    storage::validate_boot_display(&source, &boot)?;
                }
                let result = storage::duplicate_vm(&self.options, &source, name);
                if result.is_err() {
                    self.snapshot.vms = storage::load_vms(&self.options)?;
                    self.refresh_locations()?;
                }
                let vm = result?;
                self.snapshot.vms.push(vm);
                self.refresh_locations()?;
                Ok("VM duplicated with an independent disk; no history copied".into())
            }
            Command::Delete { vm_id, confirmed } => {
                if !confirmed {
                    return Err("disk deletion requires explicit confirmation".into());
                }
                self.ensure_stopped(&vm_id)?;
                if !self.snapshot.vms.iter().any(|v| v.id == vm_id) {
                    return Err("unknown VM".into());
                }
                let result = storage::delete_vm(&self.options, &vm_id);
                if result.is_err() {
                    self.snapshot.vms = storage::load_vms(&self.options)?;
                    self.refresh_locations()?;
                    result?;
                }
                self.snapshot.vms.retain(|v| v.id != vm_id);
                self.refresh_locations()?;
                Ok("VM disk and configuration deleted; recordings retained".into())
            }
            Command::Reset { vm_id, confirmed } => {
                if !confirmed {
                    return Err("disk reset requires explicit confirmation".into());
                }
                self.ensure_stopped(&vm_id)?;
                let vm = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|v| v.id == vm_id)
                    .ok_or("unknown VM")?;
                let dir = storage::vm_dir(&self.options, &vm_id)?;
                let bundle: Bundle = storage::read_json(&dir.join("bundle.json"))?;
                storage::reset_vm_disk(&self.options, &dir, vm, &bundle)?;
                Ok("VM reset to base".into())
            }
            Command::UpdateOptions {
                bundle_dir,
                capture_quota_size,
                shutdown_timeout_secs,
            } => {
                if self.session.is_some() {
                    return Err("stop VM before changing settings".into());
                }
                if capture_quota_size < 1024 || !(1..=120).contains(&shutdown_timeout_secs) {
                    return Err(
                        "capture quota must be at least 1024 and shutdown timeout 1..120 seconds"
                            .into(),
                    );
                }
                self.options.bundle_dir = bundle_dir;
                self.options.capture_quota_size = capture_quota_size;
                self.options.shutdown_timeout = Duration::from_secs(shutdown_timeout_secs);
                Ok("settings updated".into())
            }
            Command::OpenRecording { directory } => Err(format!(
                "open {} with the independent recording reader",
                directory.display()
            )),
            Command::Start { vm_id } => self.start(&vm_id),
            Command::StartNetworkCapture => self.start_network_capture(),
            Command::StopNetworkCapture => self.stop_network_capture(),
            Command::Stop => {
                self.stop()?;
                Ok("VM stopped; capture finalized".into())
            }
            Command::Close => {
                self.closing.store(true, Ordering::Relaxed);
                self.stop()?;
                Ok("backend closed".into())
            }
            other => self.guest_command(other),
        }
    }
    fn create(
        &mut self,
        mut vm: VmConfig,
        credentials: Option<GuestCredentials>,
    ) -> Result<String, String> {
        if self.session.is_some() || self.snapshot.active_vm.is_some() {
            return Err("stop VM before creating another VM".into());
        }
        if vm.id.is_empty() {
            vm.id = storage::vm_id(&vm.name);
        }
        storage::validate_vm(&vm)?;
        vm.launch.validate_for(&self.options)?;
        if self.snapshot.vms.iter().any(|current| current.id == vm.id) {
            return Err("VM identity already exists".into());
        }
        let bundle = crate::locations::boot_bundle(&self.options, vm.base_identity.as_deref())?;
        storage::validate_boot_display(&vm, &bundle)?;
        storage::validate_vm_bundle(&self.options, &vm, &bundle)?;
        let requires_credentials = bundle
            .guest
            .as_ref()
            .is_some_and(|guest| guest.requires_credentials);
        if requires_credentials != credentials.is_some() {
            return Err(if requires_credentials {
                "guest credentials are required"
            } else {
                "this base does not accept guest credentials"
            }
            .into());
        }
        vm.base_identity = bundle.base_identity.clone();
        let location = crate::locations::prepare(&self.options, &mut vm)?;
        let dir = &location.disk_directory;
        fs::create_dir(dir).map_err(|e| e.to_string())?;
        let result = (|| -> Result<(), String> {
            storage::private_dir(dir).map_err(|e| e.to_string())?;
            storage::create_overlay(&self.options, dir, vm.disk_gib, &bundle)?;
            if let Some(credentials) = credentials {
                let account = crate::guest_account::GuestAccount::from_credentials(credentials)?;
                account.provision(&dir.join("disk.qcow2"))?;
                account.save(dir)?;
            }
            storage::atomic_json(&dir.join("config.json"), &vm)?;
            storage::sync_directory_parent(dir)
        })();
        if let Err(error) = result {
            let cleanup = fs::remove_dir_all(dir);
            return Err(format!("{error}; creation rollback {:?}", cleanup.err()));
        }
        let publication = crate::locations::publish(&self.options, &location);
        if let Err(error) = &publication
            && !error.published
        {
            let cleanup = fs::remove_dir_all(dir);
            return Err(format!("{error}; creation rollback {:?}", cleanup.err()));
        }
        self.snapshot.vms.push(vm);
        self.refresh_locations()?;
        publication?;
        Ok("VM created".into())
    }
    fn start(&mut self, id: &str) -> Result<String, String> {
        if self.session.is_some() {
            return Err("only one VM may run at a time".into());
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
        storage::validate_disk_chain(
            &self.options,
            &dir.join("disk.qcow2"),
            Some(&disk_bundle.base_disk),
        )?;
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
        self.snapshot.health = Health::default();
        self.snapshot.guest_kernel = None;
        self.snapshot.events.clear();
        self.snapshot.captures.clear();
        self.snapshot.capture_events.clear();
        self.snapshot.process_page = None;
        self.snapshot.boot_id = None;
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
            self.snapshot.boot_id = Some(boot_id.clone());
            let capture_dir = boot_dir.join("unassigned");
            let mut capture =
                RawCapture::new(capture_dir.clone(), self.options.capture_quota_size)?;
            capture.manifest(&vm, &bundle, &disk_bundle, "starting")?;
            self.snapshot.capture_dir = Some(capture_dir.clone());
            let mut assembler =
                Assembler::new(capture_dir.join("objects"), self.options.capture_quota_size)
                    .map_err(|e| e.to_string())?;
            assembler.set_event_table(vm.transport.event_table as usize);
            if let Err(e) = process.verify_ram_layout() {
                capture.manifest(&vm, &bundle, &disk_bundle, "start-failed")?;
                return Err(e);
            }
            let mut transport =
                match Transport::open(&process.ram_path, process.ram_size, process.bootstrap) {
                    Ok(t) => t,
                    Err(e) => {
                        capture.manifest(&vm, &bundle, &disk_bundle, "start-failed")?;
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
            capture.manifest(&vm, &bundle, &disk_bundle, "running")?;
            Ok(Session {
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
                captures: BTreeMap::new(),
                pending_capture_id: None,
                boot_id,
                pending: VecDeque::new(),
                pending_len: 0,
                pending_overflow: false,
                terminal_cursor: 0,
                late_reads: BTreeMap::new(),
                telemetry_busy: false,
                last_process_save: Instant::now(),
                status_cursor: 0,
                last_status_query: Instant::now(),
                persisted_packets: 0,
                kernel_probe: KernelProbe::Due(Instant::now()),
            })
        })();
        match result {
            Ok(session) => {
                self.session = Some(session);
                self.snapshot.state = VmState::Running;
                Ok("VM running; transport attached".into())
            }
            Err(e) => {
                self.snapshot.active_vm = None;
                self.snapshot.state = VmState::Failed;
                Err(e)
            }
        }
    }
    /// Attach a filter-dump to the VM's network interface: QEMU writes every
    /// frame to a new pcap in the boot recording, outside the guest.
    fn start_network_capture(&mut self) -> Result<String, String> {
        let session = self.session.as_ref().ok_or("VM is stopped")?;
        if !session.vm.nat {
            return Err(
                "this VM has no network: turn on NAT network in its settings and restart it".into(),
            );
        }
        if self.snapshot.network_capture.is_some() {
            return Err("a network capture is already running".into());
        }
        let boot_dir = crate::locations::locations(&self.options, &session.vm.id)?
            .recording_directory
            .join("boots")
            .join(&session.boot_id);
        let capture = crate::network::NetworkCapture::new(
            &boot_dir,
            &session.boot_id,
            &storage::unique_id(),
            unix_ms(),
        );
        let dir = capture.file.parent().ok_or("network capture folder")?;
        storage::private_dir(dir).map_err(|e| format!("network capture folder: {e}"))?;
        // QEMU truncates the file it is given and keeps its mode: private.
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&capture.file)
            .map_err(|e| format!("network capture file: {e}"))?;
        // The summary first, so an app that ends mid-capture still lists it.
        crate::network::save_summary(&capture)?;
        if let Err(error) = crate::network::filter_dump_add(&capture)
            .and_then(|command| session.process.qmp(&command))
        {
            let _ = fs::remove_file(capture.summary_path());
            let _ = fs::remove_file(&capture.file);
            return Err(format!("network capture: {error}"));
        }
        self.snapshot.network_capture = Some(capture);
        // Publish the changed toggle before acknowledging the command, so
        // the UI cannot briefly re-enable the old action after completion.
        self.publish();
        Ok("network capture started".into())
    }
    fn stop_network_capture(&mut self) -> Result<String, String> {
        let session = self.session.as_ref().ok_or("VM is stopped")?;
        let capture = self
            .snapshot
            .network_capture
            .as_ref()
            .ok_or("no network capture is running")?;
        session
            .process
            .qmp(&crate::network::filter_dump_del(capture))
            .map_err(|error| format!("network capture stop: {error}"))?;
        let finished = end_network_capture(&mut self.snapshot);
        self.publish();
        let packets = finished?;
        Ok(format!("network capture stopped: {packets} packets"))
    }
    fn stop(&mut self) -> Result<(), String> {
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
        let deadline = Instant::now() + self.options.shutdown_timeout;
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
        match session.request(
            control::STATS,
            &control::header(0),
            &mut self.snapshot,
            &self.sender,
            remaining_request_budget(deadline, Duration::from_secs(4)) / 4,
        ) {
            Ok(reply) => {
                if let Ok(counters) = decode_stats(&reply) {
                    self.snapshot.health.recorder_stats = Some(counters);
                }
            }
            Err(e) => issues.push(format!("final recorder stats unavailable: {e}")),
        }
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
            Err(e) => {
                issues.push(e);
                false
            }
        };
        let mut forced = false;
        let mut exit_success = false;
        loop {
            match session.process.child.try_wait() {
                Ok(Some(status)) => {
                    exit_success = status.success();
                    if !exit_success {
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
        let final_state = if forced {
            "forced"
        } else if shutdown_ack && exit_success {
            "clean"
        } else {
            "unexpected-exit"
        };
        if let Err(e) = session.finalize(final_state, &mut self.snapshot) {
            issues.push(e);
        }
        if let Err(e) = end_network_capture(&mut self.snapshot) {
            issues.push(e);
        }
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
    fn guest_command(&mut self, command: Command) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = Duration::from_secs(10);
        if matches!(
            &command,
            Command::ListProcesses { .. }
                | Command::AttachProcess { .. }
                | Command::CaptureAll
                | Command::StopCapture { .. }
        ) && !self
            .snapshot
            .guest_kernel
            .as_ref()
            .and_then(|kernel| kernel.revision)
            .is_some_and(|revision| revision >= 11)
        {
            return Err("process attachment and Capture All are unavailable; running guest requires a base for Antinomie 0.2.0 or newer".into());
        }
        match command {
            Command::ListProcesses { after_pid } => {
                let page = Some(session.list_processes(
                    after_pid,
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )?);
                let count = page.as_ref().map_or(0, |p| p.processes.len());
                self.snapshot.process_page = page;
                Ok(format!("{count} guest processes listed"))
            }
            Command::AttachProcess { identity } => {
                let message = session.start_capture(
                    &self.options,
                    CaptureScope::Process { root: identity },
                    &mut self.snapshot,
                    &self.sender,
                )?;
                // The picker's list names the attached process and its ancestors.
                if let (Some(page), Some(capture)) = (
                    &self.snapshot.process_page,
                    session
                        .captures
                        .values_mut()
                        .find(|capture| capture.summary.state == CaptureState::Active),
                ) {
                    capture.processes.seed(&page.processes);
                }
                Ok(message)
            }
            Command::CaptureAll => {
                let message = session.start_capture(
                    &self.options,
                    CaptureScope::AllUserspace,
                    &mut self.snapshot,
                    &self.sender,
                )?;
                // start_capture answers with a status message; the capture
                // just started is the active one.
                let id = session
                    .captures
                    .iter()
                    .find(|(_, capture)| capture.summary.state == CaptureState::Active)
                    .map(|(id, _)| id.clone())
                    .unwrap_or_default();
                // Name the processes already running; the capture's fork and
                // exec records name the rest. A failed list only leaves
                // early processes unnamed.
                match session.list_processes(0, &mut self.snapshot, &self.sender, timeout) {
                    Ok(page) => {
                        if let Some(capture) = session.captures.get_mut(&id) {
                            capture.processes.seed(&page.processes);
                        }
                    }
                    Err(error) => {
                        self.snapshot.last_error =
                            Some(format!("Capture All process names: {error}"));
                    }
                }
                Ok(message)
            }
            Command::StopCapture { capture_id } => {
                let capture = session
                    .captures
                    .get(&capture_id)
                    .ok_or("unknown capture in this VM boot")?;
                let mut cookie = capture.summary.capture_cookie;
                if cookie == 0 {
                    let reply = session.request(
                        control::CAPTURE_STATUS,
                        &control::with_session(0),
                        &mut self.snapshot,
                        &self.sender,
                        timeout,
                    )?;
                    let status = control::capture_status(&reply, 0)?;
                    if status.cookie == 0 {
                        return Err("capture identity is unknown; admission outcome unresolved until VM restart".into());
                    }
                    session.apply_capture_status(&capture_id, status)?;
                    session.update_captures(&mut self.snapshot);
                    cookie = session
                        .captures
                        .get(&capture_id)
                        .ok_or("unknown capture")?
                        .summary
                        .capture_cookie;
                }
                let reply = session.request(
                    control::CAPTURE_STOP,
                    &control::with_session(cookie),
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )?;
                let status = control::capture_status(&reply, cookie)?;
                if status.active {
                    return Err("capture stop reply still admits observations".into());
                }
                session.apply_capture_status(&capture_id, status)?;
                session.update_captures(&mut self.snapshot);
                Ok("capture admission stopped; programs continue running and late observation tails remain recordable".into())
            }
            Command::Execute(request) => {
                if session.runs.len() >= 64 {
                    return Err("this VM boot reached the 64-run limit; restart the VM before another launch".into());
                }
                let supported = self
                    .snapshot
                    .guest_kernel
                    .as_ref()
                    .and_then(|k| k.revision)
                    .is_some_and(|r| r >= 10);
                let desktop = request.run_in.guest_desktop();
                if desktop
                    && !session
                        .disk_bundle
                        .guest
                        .as_ref()
                        .is_some_and(|guest| guest.graphical)
                {
                    return Err(format!(
                        "{} needs a VM with a graphical base",
                        request.run_in.label()
                    ));
                }
                // A desktop run executes `/bin/sh`, so its program is acquired
                // by path after the launch instead of by the kernel's exec.
                let wire = crate::guest_desktop::wire_request(&request)?;
                let args = control::execute_analysis(&wire, supported)?;
                let selected = request.analysis.enabled;
                let inline_acquisition = selected && supported && !desktop;
                let run_id = storage::unique_id();
                let directory = crate::locations::locations(&self.options, &session.vm.id)?
                    .recording_directory
                    .join("runs")
                    .join(&run_id);
                let summary = RunSummary {
                    id: run_id,
                    vm_id: session.vm.id.clone(),
                    boot_id: session.boot_id.clone(),
                    session_id: 0,
                    root_task_cookie: 0,
                    pid: 0,
                    request: request.clone(),
                    directory,
                    terminal_eof: false,
                    state: RunState::Unknown,
                    recording_error: Some("execution has not been acknowledged".into()),
                    execution: None,
                    analysis: selected.then(|| {
                        crate::analysis::jobs::new_report(&request.path, &request.analysis)
                    }),
                };
                let mut run = ProgramRun::new(summary, session.capture.quota())?;
                run.assembler
                    .set_event_table(session.vm.transport.event_table as usize);
                run.summary.recording_error = None;
                run.boot_bundle_identity = session.bundle.base_identity.clone();
                run.disk_base_identity = session.disk_bundle.base_identity.clone();
                let reply = session.request(
                    control::EXEC,
                    &args,
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                );
                let reply = match reply {
                    Ok(reply) => reply,
                    Err(error) => {
                        run.storage_error(format!("execution acknowledgement failed: {error}; launch outcome may be unknown"));
                        let _ = run.persist_summary();
                        return Err(error);
                    }
                };
                if reply.len() != if inline_acquisition { 48 } else { 24 }
                    || u32_at(&reply, 20).map_err(|e| e.to_string())? != 0
                {
                    return Err("invalid execution reply".into());
                }
                let id = u64_at(&reply, 0).map_err(|e| e.to_string())?;
                let cookie = u64_at(&reply, 8).map_err(|e| e.to_string())?;
                let pid = u32_at(&reply, 16).map_err(|e| e.to_string())?;
                if cookie == 0 || session.runs.contains_key(&cookie) {
                    return Err(
                        "invalid or reused execution root identity; launch outcome unknown".into(),
                    );
                }
                run.summary.session_id = id;
                run.summary.root_task_cookie = cookie;
                run.summary.pid = pid;
                run.summary.state = RunState::Running;
                if let Some(report) = run.summary.analysis.take() {
                    let acquisition = if inline_acquisition {
                        control::acquisition(&reply[24..])
                    } else if supported {
                        session
                            .request(
                                control::ACQUIRE,
                                &control::acquire(&request.path, request.uid, request.gid)?,
                                &mut self.snapshot,
                                &self.sender,
                                timeout,
                            )
                            .and_then(|reply| control::acquisition(&reply))
                    } else {
                        Err(
                            "this base does not support static analysis (it needs a base for Antinomie 0.2.0 or newer); the program ran without it"
                                .into(),
                        )
                    };
                    let available = session.available().saturating_sub(run.stored_len());
                    run.summary.analysis = Some(session.analysis.submit(
                        Some(run.summary.id.clone()),
                        report,
                        run.summary.directory.join("analysis"),
                        acquisition,
                        available,
                    ));
                    if let Err(error) = run.refresh_analysis_metadata() {
                        run.storage_error(format!("analysis metadata accounting: {error}"));
                    }
                }
                if let Some(error) = session.capture.error.clone() {
                    run.capture.error = Some(error.clone());
                    run.storage_error(error);
                }
                let mut remaining = VecDeque::new();
                while let Some(packet) = session.pending.pop_front() {
                    let root = crate::parser::parse_packet(&packet)
                        .map(|(h, _)| h.root_task_cookie)
                        .unwrap_or(0);
                    if root == cookie {
                        session.pending_len -= packet.len();
                        let reserved = session.stored_len() + run.stored_len() - run.capture.bytes;
                        if !run.capture.append_with_reserved(&packet, reserved) {
                            let error = run
                                .capture
                                .error
                                .clone()
                                .unwrap_or_else(|| "pending raw saving failed".into());
                            run.storage_error(error.clone());
                            session.stop_saving(error);
                        }
                        run.assembler.set_storage_limit(
                            run.assembler.stored_len().saturating_add(
                                session.available().saturating_sub(run.stored_len()),
                            ),
                        );
                        if let Err(error) = run.assembler.ingest(&packet) {
                            self.snapshot.last_error = Some(error.to_string());
                        }
                        if let Some(error) = run.assembler.saving_error().map(str::to_owned) {
                            run.capture.error.get_or_insert(error.clone());
                            run.storage_error(error.clone());
                            session.stop_saving(error);
                        }
                    } else {
                        remaining.push_back(packet);
                    }
                }
                session.pending = remaining;
                if session.pending_overflow {
                    run.summary.recording_error.get_or_insert("pre-reply assignment buffer exceeded limit; earlier packets remain in boot unassigned raw archive".into());
                }
                if let Err(error) = run.persist_summary() {
                    run.storage_error(format!("run metadata persistence failed: {error}"));
                }
                let summary = run.summary.clone();
                session.runs.insert(cookie, run);
                session.update_runs(&mut self.snapshot);
                self.emit(Notification::RunStarted(summary));
                Ok(format!("launched pid {pid}, terminal session {id}"))
            }
            Command::AnalyzeOnly {
                path,
                uid,
                gid,
                analysis,
            } => {
                analysis.validate()?;
                control::string(&path, true)?;
                if !analysis.enabled {
                    return Err("Analyze Only requires static analysis enabled".into());
                }
                if self.snapshot.analysis_reports.len() >= 8 {
                    return Err("this VM boot reached the eight standalone analysis limit".into());
                }
                let report = crate::analysis::jobs::new_report(&path, &analysis);
                let directory = crate::locations::locations(&self.options, &session.vm.id)?
                    .recording_directory
                    .join("analyses")
                    .join(&report.id);
                let supported = self
                    .snapshot
                    .guest_kernel
                    .as_ref()
                    .and_then(|k| k.revision)
                    .is_some_and(|r| r >= 10);
                let acquisition = if supported {
                    session
                        .request(
                            control::ACQUIRE,
                            &control::acquire(&path, uid, gid)?,
                            &mut self.snapshot,
                            &self.sender,
                            timeout,
                        )
                        .and_then(|reply| control::acquisition(&reply))
                } else {
                    Err("this base does not support static analysis; use a base for Antinomie 0.2.0 or newer".into())
                };
                let available = session.available();
                session
                    .analysis
                    .submit(None, report, directory, acquisition, available);
                session.analysis_updates(&mut self.snapshot, &self.sender);
                Ok("standalone analysis request recorded".into())
            }
            Command::CancelAnalysis { analysis_id } => {
                session.analysis.cancel(&analysis_id)?;
                session.analysis_updates(&mut self.snapshot, &self.sender);
                Ok("analysis cancelled; program continues".into())
            }
            Command::Upload {
                source,
                destination,
                overwrite,
                executable,
            } => {
                let mut file =
                    File::open(&source).map_err(|e| format!("upload {}: {e}", source.display()))?;
                let metadata = file.metadata().map_err(|e| e.to_string())?;
                if !metadata.is_file() {
                    return Err("upload source must be a regular file".into());
                }
                let total = metadata.len();
                let reply = session.request(
                    control::UPLOAD_BEGIN,
                    &control::upload_begin(&destination, total, overwrite, executable)?,
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )?;
                if reply.len() != 8 {
                    return Err("invalid upload begin reply".into());
                }
                let upload = u64_at(&reply, 0).map_err(|e| e.to_string())?;
                let result = (|| -> Result<(), String> {
                    let chunk_size = session
                        .transport
                        .command_limit
                        .saturating_sub(24)
                        .min(64 * 1024);
                    if chunk_size == 0 {
                        return Err("transport has no upload payload capacity".into());
                    }
                    let mut chunk = vec![0; chunk_size];
                    let mut offset = 0u64;
                    while offset < total {
                        if self.stopping.load(Ordering::Relaxed) {
                            return Err(
                                "upload aborted for VM shutdown; partial destination remains"
                                    .into(),
                            );
                        }
                        let used = usize::try_from((total - offset).min(chunk_size as u64))
                            .map_err(|_| "upload size overflow")?;
                        file.read_exact(&mut chunk[..used])
                            .map_err(|e| e.to_string())?;
                        let mut args = control::with_session(upload);
                        args.extend(offset.to_le_bytes());
                        args.extend(&chunk[..used]);
                        let reply = session.request(
                            control::UPLOAD_CHUNK,
                            &args,
                            &mut self.snapshot,
                            &self.sender,
                            timeout,
                        )?;
                        if reply.len() != 8
                            || u64_at(&reply, 0).map_err(|e| e.to_string())? != used as u64
                        {
                            return Err("guest reported a partial upload write".into());
                        }
                        offset += used as u64;
                    }
                    session.request(
                        control::UPLOAD_COMMIT,
                        &control::with_session(upload),
                        &mut self.snapshot,
                        &self.sender,
                        timeout,
                    )?;
                    Ok(())
                })();
                if let Err(e) = result {
                    let abort = session.request(
                        control::UPLOAD_ABORT,
                        &control::with_session(upload),
                        &mut self.snapshot,
                        &self.sender,
                        Duration::from_secs(2),
                    );
                    return Err(match abort {
                        Ok(_) => e,
                        Err(a) => format!("{e}; abort failed: {a}"),
                    });
                }
                Ok(format!("uploaded {total} bytes to {destination}"))
            }
            Command::TerminalInput { run_id, data } => {
                let cookie = session.run_cookie(&run_id)?;
                let run = session.runs.get(&cookie).ok_or("unknown run")?;
                if run.summary.terminal_eof {
                    return Err("terminal is closed".into());
                }
                let terminal = run.summary.session_id;
                let chunk_size = session.transport.command_limit.saturating_sub(16);
                if chunk_size == 0 {
                    return Err("no terminal payload capacity".into());
                }
                let mut written = 0;
                for chunk in data.chunks(chunk_size) {
                    let mut args = control::with_session(terminal);
                    args.extend(chunk);
                    let reply = session.request(
                        control::INPUT,
                        &args,
                        &mut self.snapshot,
                        &self.sender,
                        timeout,
                    )?;
                    if reply.len() != 8 {
                        return Err("invalid terminal input reply".into());
                    }
                    let count = u64_at(&reply, 0).map_err(|e| e.to_string())?;
                    if count > chunk.len() as u64 {
                        return Err("invalid terminal input count".into());
                    }
                    written += count;
                    if count != chunk.len() as u64 {
                        return Err(format!("terminal accepted only {written} input bytes"));
                    }
                }
                Ok(format!("terminal input accepted {written} bytes"))
            }
            Command::TerminalRead { run_id } => {
                session.read_terminal(
                    &run_id,
                    &mut self.snapshot,
                    &self.sender,
                    Duration::from_millis(500),
                )?;
                Ok(String::new())
            }
            Command::TerminalResize { run_id, rows, cols } => {
                if rows == 0 || cols == 0 || rows > 256 || cols > 256 {
                    return Err("terminal dimensions must be 1..256".into());
                }
                let cookie = session.run_cookie(&run_id)?;
                let run = session.runs.get(&cookie).ok_or("unknown run")?;
                if run.summary.terminal_eof {
                    return Err("terminal is closed".into());
                }
                let mut args = control::with_session(run.summary.session_id);
                args.extend(rows.to_le_bytes());
                args.extend(cols.to_le_bytes());
                args.extend([0; 4]);
                session.request(
                    control::RESIZE,
                    &args,
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )?;
                let available = session.available();
                let run = session.runs.get_mut(&cookie).ok_or("unknown run")?;
                run.resize(rows, cols, available)?;
                let notification = run.screen_notification();
                self.emit(notification);
                Ok("terminal resized".into())
            }
            Command::TerminalSnapshot { run_id } => {
                let cookie = session.run_cookie(&run_id)?;
                let notification = session
                    .runs
                    .get(&cookie)
                    .ok_or("unknown run")?
                    .screen_notification();
                self.emit(notification);
                Ok(String::new())
            }
            Command::Signal { run_id, signal } => {
                if !(1..=64).contains(&signal) {
                    return Err("signal must be 1..64".into());
                }
                let cookie = session.run_cookie(&run_id)?;
                let run = session.runs.get(&cookie).ok_or("unknown run")?;
                let (id, current_pid) = (run.summary.session_id, run.summary.pid);
                let mut args = control::with_session(id);
                args.extend(signal.to_le_bytes());
                args.extend(0u32.to_le_bytes());
                session.request(
                    control::SIGNAL,
                    &args,
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )?;
                Ok(format!(
                    "signal {signal} sent to process group {current_pid}"
                ))
            }
            Command::StopRun { run_id } => {
                let cookie = session.run_cookie(&run_id)?;
                let mut args = control::header(0);
                args.extend(cookie.to_le_bytes());
                let reply =
                    session.request(0x1015, &args, &mut self.snapshot, &self.sender, timeout)?;
                if !reply.is_empty() {
                    return Err("invalid stop-run acknowledgement".into());
                }
                let run = session.runs.get_mut(&cookie).ok_or("unknown run")?;
                run.summary.state = RunState::StopRequested;
                run.persist_summary()?;
                Ok("termination signals issued; descendant completion is not yet proven".into())
            }
            Command::RecorderStats => {
                let reply = session.request(
                    control::STATS,
                    &control::header(0),
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )?;
                if reply.len() != 80 {
                    return Err("invalid recorder stats reply".into());
                }
                let counters = decode_stats(&reply)?;
                self.snapshot.health.recorder_stats = Some(counters);
                Ok(format!(
                    "recorder stream {} calls {} packets {} failed {} copy faults {} schema gaps {} context failures {}",
                    counters[0],
                    counters[3],
                    counters[5],
                    counters[6],
                    counters[7],
                    counters[8],
                    counters[9]
                ))
            }
            _ => Err("not a guest command".into()),
        }
    }
}

fn stop_capture_saving(
    capture: &mut RawCapture,
    assembler: &mut Assembler,
    runs: &mut BTreeMap<u64, ProgramRun>,
    error: String,
) {
    capture.error.get_or_insert(error.clone());
    assembler.stop_saving();
    for run in runs.values_mut() {
        run.capture.error.get_or_insert(error.clone());
        run.storage_error(error.clone());
    }
}

fn propagate_object_saving_failure(
    capture: &mut RawCapture,
    assembler: &mut Assembler,
    runs: &mut BTreeMap<u64, ProgramRun>,
) {
    let error = assembler.saving_error().map(str::to_owned).or_else(|| {
        runs.values_mut()
            .find_map(|run| run.assembler.saving_error().map(str::to_owned))
    });
    if let Some(error) = error {
        stop_capture_saving(capture, assembler, runs, error);
    }
}

fn refresh_storage_health(
    health: &mut Health,
    capture: &RawCapture,
    object_len: u64,
    runs: &BTreeMap<u64, ProgramRun>,
) {
    health.persisted_len = capture
        .bytes
        .saturating_add(object_len)
        .saturating_add(runs.values().map(ProgramRun::stored_len).sum::<u64>());
    health.persistence_error = capture.error.clone().or_else(|| {
        runs.values()
            .find_map(|run| run.summary.recording_error.clone())
    });
}

/// A kernel named by app version for messages: "for Antinomie 0.2.0 (build
/// 0164…)", "for Antinomie 0.2.0, unversioned build", "for a newer
/// Antinomie" or "from before Antinomie 0.1.0". Revisions stay internal.
fn describe_source((revision, source): (Option<u32>, Option<&str>)) -> String {
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

fn decode_stats(reply: &[u8]) -> Result<[u64; 10], String> {
    if reply.len() != 80 {
        return Err("invalid recorder stats length".into());
    }
    let mut counters = [0; 10];
    for (n, value) in counters.iter_mut().enumerate() {
        *value = u64_at(reply, n * 8).map_err(|e| e.to_string())?;
    }
    Ok(counters)
}

/// Wall clock in milliseconds since the Unix epoch.
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_millis() as u64)
}

/// Record the end of the running network capture (stopped over QMP, or its
/// VM gone) with its packet count. Returns the packets.
fn end_network_capture(snapshot: &mut Snapshot) -> Result<u64, String> {
    let Some(mut capture) = snapshot.network_capture.take() else {
        return Ok(0);
    };
    capture.stopped_ms = Some(unix_ms());
    let counted = crate::network::count_packets(&capture.file);
    if let Ok((packets, bytes)) = counted {
        capture.packets = Some(packets);
        capture.bytes = Some(bytes);
    }
    crate::network::save_summary(&capture)
        .map_err(|error| format!("network capture summary: {error}"))?;
    counted
        .map(|(packets, _)| packets)
        .map_err(|error| format!("network capture count: {error}"))
}

fn remaining_request_budget(deadline: Instant, maximum: Duration) -> Duration {
    deadline
        .saturating_duration_since(Instant::now())
        .min(maximum)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn download_worker(root: PathBuf) -> Worker {
        let (_commands, receiver) = mpsc::sync_channel(1);
        let (sender, _notifications) = mpsc::sync_channel(1);
        Worker {
            options: BackendOptions {
                bundle_dir: root.join("missing-bundle"),
                data_dir: root,
                ..BackendOptions::default()
            },
            snapshot: Snapshot::default(),
            receiver,
            sender,
            closing: Arc::new(AtomicBool::new(false)),
            stopping: Arc::new(AtomicBool::new(false)),
            session: None,
            catalog: distribution::Catalog::default(),
            refresh: None,
            download: None,
            build: None,
            tool: None,
            last_publish: Instant::now(),
            latest_snapshot: Arc::new(Mutex::new(None)),
        }
    }

    fn attach_waiting_download(worker: &mut Worker) -> Arc<AtomicBool> {
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let worker_stopped = stopped.clone();
        let (sender, done) = mpsc::channel();
        let thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !worker_cancel.load(Ordering::Relaxed) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            assert!(
                worker_cancel.load(Ordering::Relaxed),
                "download was never cancelled"
            );
            worker_stopped.store(true, Ordering::Relaxed);
            sender.send(Err("download cancelled".into())).unwrap();
        });
        worker.download = Some(DownloadJob {
            identity: "test".into(),
            label: "Test".into(),
            total: 100,
            progress: Arc::new(Mutex::new((20, false))),
            cancel,
            done,
            thread,
        });
        worker.snapshot.download = Some(DownloadStatus {
            identity: "test".into(),
            label: "Test".into(),
            received: 20,
            total: 100,
            ..DownloadStatus::default()
        });
        stopped
    }

    #[test]
    fn cancel_download_finishes_without_an_error_alert() {
        let root = std::env::temp_dir().join(format!("ant-cancel-{}", storage::unique_id()));
        let mut worker = download_worker(root);
        attach_waiting_download(&mut worker);
        worker.command(Command::CancelDownload).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while worker.download.is_some() && Instant::now() < deadline {
            worker.poll_remote();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(worker.download.is_none());
        let status = worker.snapshot.download.unwrap();
        assert!(status.finished);
        assert_eq!(status.error.as_deref(), Some("download cancelled"));
        assert!(worker.snapshot.last_error.is_none());
    }

    #[test]
    fn shutdown_cancels_and_joins_the_download_worker() {
        let root =
            std::env::temp_dir().join(format!("ant-close-download-{}", storage::unique_id()));
        let mut worker = download_worker(root);
        let stopped = attach_waiting_download(&mut worker);
        worker.closing.store(true, Ordering::Relaxed);
        worker.run();
        assert!(stopped.load(Ordering::Relaxed));
    }

    #[test]
    fn cancellation_and_installation_have_an_exclusive_transition() {
        let progress = Mutex::new((100, false));
        let cancel = AtomicBool::new(true);
        assert_eq!(
            begin_base_install(&progress, &cancel).unwrap_err(),
            "download cancelled"
        );
        assert!(!progress.lock().unwrap().1);
        cancel.store(false, Ordering::Relaxed);
        begin_base_install(&progress, &cancel).unwrap();
        assert!(progress.lock().unwrap().1);
        let root = std::env::temp_dir().join(format!("ant-install-gate-{}", storage::unique_id()));
        let mut worker = download_worker(root);
        attach_waiting_download(&mut worker);
        let job = worker.download.as_ref().unwrap();
        begin_base_install(&job.progress, &job.cancel).unwrap();
        assert!(
            worker
                .command(Command::CancelDownload)
                .unwrap_err()
                .contains("installation")
        );
        assert!(
            !worker
                .download
                .as_ref()
                .unwrap()
                .cancel
                .load(Ordering::Relaxed)
        );
        worker.closing.store(true, Ordering::Relaxed);
        worker.run();
    }

    #[test]
    fn startup_base_error_is_published_after_backend_construction() {
        let root = std::env::temp_dir().join(format!("ant-base-startup-{}", storage::unique_id()));
        fs::create_dir_all(root.join("bases/bad")).unwrap();
        fs::write(root.join("bases/bad/bundle.json"), b"invalid json").unwrap();
        let mut backend = Backend::new(BackendOptions {
            data_dir: root.clone(),
            bundle_dir: root.join("missing"),
            ..BackendOptions::default()
        })
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let snapshot = loop {
            if let Some(Notification::Snapshot(snapshot)) = backend.try_recv()
                && !snapshot.bases_checking
            {
                break snapshot;
            }
            assert!(Instant::now() < deadline, "base check never completed");
            thread::sleep(Duration::from_millis(5));
        };
        assert!(snapshot.bases.is_empty());
        assert!(snapshot.last_error.unwrap().starts_with("base images:"));
        backend.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    fn history_event(sequence: u64, path: &str) -> EventSummary {
        EventSummary {
            root_task_cookie: 99,
            stream_id: 1,
            task_cookie: 2,
            call_id: 3,
            event_seq: sequence,
            phase: 1,
            syscall_nr: 1,
            syscall_name: "write".into(),
            pid: 7,
            tid: 7,
            cpu: 0,
            timestamp_ns: sequence,
            args: None,
            result: None,
            complete: false,
            issues: Vec::new(),
            fields: vec![FieldSummary {
                object_id: 1,
                key: "buffer".into(),
                layout: "bytes".into(),
                logical_len: Some(1),
                captured_len: 1,
                status: None,
                capture_error: 0,
                complete: true,
                preview: vec![1],
                raw_path: Some(path.into()),
                ranges: vec![(0, 1)],
            }],
        }
    }
    #[test]
    fn canonical_history_deduplicates_pre_ack_packets_and_prefers_run_artifacts() {
        let boot = history_event(1, "boot/object");
        let mut run = history_event(1, "run/object");
        run.cpu = 3;
        run.complete = true;
        let mut exit = history_event(1, "run/exit-object");
        exit.phase = 2;
        let mut other_task = history_event(1, "run/other-task");
        other_task.task_cookie = 8;
        let events = canonical_live_history(vec![boot], [vec![run, exit, other_task]]);
        assert_eq!(events.len(), 3);
        let entry = events
            .iter()
            .find(|event| event.task_cookie == 2 && event.phase == 1)
            .unwrap();
        assert!(entry.complete);
        assert_eq!(entry.cpu, 3);
        assert_eq!(
            entry.fields[0].raw_path.as_deref(),
            Some(std::path::Path::new("run/object"))
        );
    }
    #[test]
    fn capture_preview_drops_oldest_evicted_rows_at_the_total_limit() {
        let mut events: Vec<_> = (0..2112)
            .map(|sequence| history_event(sequence, "capture/object"))
            .collect();
        events.reverse();
        let preview = bounded_live_history(events);
        assert_eq!(preview.len(), 2048);
        assert_eq!(preview.first().unwrap().event_seq, 64);
        assert_eq!(preview.last().unwrap().event_seq, 2111);
    }
    #[test]
    fn invalid_launch_settings_are_rejected_before_lifecycle_io() {
        let root =
            std::env::temp_dir().join(format!("ant-launch-invalid-{}", storage::unique_id()));
        let vm = VmConfig {
            id: "invalid-launch".into(),
            launch: VmLaunchOptions {
                acceleration: VmAcceleration::Kvm,
                cpu_model: VmCpuModel::Host,
                ..VmLaunchOptions::default()
            },
            ..VmConfig::default()
        };
        let (_commands, receiver) = mpsc::sync_channel(1);
        let (sender, _notifications) = mpsc::sync_channel(1);
        let mut worker = Worker {
            options: BackendOptions {
                data_dir: root.clone(),
                force_tcg: true,
                ..BackendOptions::default()
            },
            snapshot: Snapshot {
                vms: vec![vm.clone()],
                ..Snapshot::default()
            },
            receiver,
            sender,
            closing: Arc::new(AtomicBool::new(false)),
            stopping: Arc::new(AtomicBool::new(false)),
            session: None,
            catalog: distribution::Catalog::default(),
            refresh: None,
            download: None,
            build: None,
            tool: None,
            last_publish: Instant::now(),
            latest_snapshot: Arc::new(Mutex::new(None)),
        };
        for command in [
            Command::Create(VmConfig {
                id: "new-launch".into(),
                ..vm.clone()
            }),
            Command::Save(vm.clone()),
            Command::Start {
                vm_id: vm.id.clone(),
            },
            Command::Duplicate {
                vm_id: vm.id.clone(),
                name: "Copy".into(),
            },
        ] {
            assert!(
                worker
                    .command(command)
                    .unwrap_err()
                    .contains("requires KVM")
            );
            assert_eq!(worker.snapshot.vms, vec![vm.clone()]);
            assert!(worker.snapshot.active_vm.is_none());
            assert!(!root.exists());
        }
        let mut explicit_tcg = vm.clone();
        explicit_tcg.launch.acceleration = VmAcceleration::Tcg;
        worker.options.force_tcg = false;
        assert!(
            worker
                .command(Command::Save(explicit_tcg))
                .unwrap_err()
                .contains("requires KVM")
        );
    }

    #[test]
    fn fixed_display_guards_selected_boot_without_changing_pinned_disk() {
        let root =
            std::env::temp_dir().join(format!("ant-fixed-capability-{}", storage::unique_id()));
        let source = root.join("source");
        storage::private_dir(&source).unwrap();
        fs::write(source.join("kernel"), b"fixture kernel").unwrap();
        assert!(
            std::process::Command::new("qemu-img")
                .args(["create", "-f", "qcow2"])
                .arg(source.join("base.qcow2"))
                .arg("1M")
                .output()
                .unwrap()
                .status
                .success()
        );
        let options = BackendOptions {
            data_dir: root.join("data"),
            headless: true,
            ..BackendOptions::default()
        };
        let legacy: Bundle = serde_json::from_value(serde_json::json!({
            "kernel": source.join("kernel"), "base_disk": source.join("base.qcow2"),
            "kernel_version": "6.12.94", "initrd": null
        }))
        .unwrap();
        let legacy = legacy.install(&options).unwrap();
        let (_commands, receiver) = mpsc::sync_channel(1);
        let (sender, _notifications) = mpsc::sync_channel(1);
        let mut worker = Worker {
            options,
            snapshot: Snapshot::default(),
            receiver,
            sender,
            closing: Arc::new(AtomicBool::new(false)),
            stopping: Arc::new(AtomicBool::new(false)),
            session: None,
            catalog: distribution::Catalog::default(),
            refresh: None,
            download: None,
            build: None,
            tool: None,
            last_publish: Instant::now(),
            latest_snapshot: Arc::new(Mutex::new(None)),
        };
        worker
            .command(Command::Create(VmConfig {
                id: "old-disk".into(),
                ..VmConfig::default()
            }))
            .unwrap();
        let mut vm = worker.snapshot.vms[0].clone();
        vm.launch.resolution = crate::DisplayResolution::R1280x720;
        let directory = storage::vm_dir(&worker.options, &vm.id).unwrap();
        storage::atomic_json(&directory.join("config.json"), &vm).unwrap();
        worker.snapshot.vms[0] = vm.clone();
        let config = fs::read(directory.join("config.json")).unwrap();
        let disk = fs::read(directory.join("disk.qcow2")).unwrap();
        for command in [
            Command::Create(VmConfig {
                id: "rejected-fixed".into(),
                ..vm.clone()
            }),
            Command::Save(vm.clone()),
            Command::Start {
                vm_id: vm.id.clone(),
            },
            Command::Duplicate {
                vm_id: vm.id.clone(),
                name: "Rejected duplicate".into(),
            },
        ] {
            assert!(
                worker
                    .command(command)
                    .unwrap_err()
                    .contains("does not support fixed display")
            );
            assert_eq!(worker.snapshot.vms, vec![vm.clone()]);
            assert!(worker.snapshot.active_vm.is_none());
            assert!(worker.session.is_none());
            assert_eq!(fs::read(directory.join("config.json")).unwrap(), config);
            assert_eq!(fs::read(directory.join("disk.qcow2")).unwrap(), disk);
        }
        let mut capable = legacy.clone();
        capable.fixed_display = true;
        let capable = capable.install(&worker.options).unwrap();
        assert_ne!(capable.base_identity, legacy.base_identity);
        vm.base_identity = capable.base_identity;
        worker.command(Command::Save(vm.clone())).unwrap();
        let pinned: Bundle = storage::read_json(&directory.join("bundle.json")).unwrap();
        assert_eq!(pinned.base_identity, legacy.base_identity);
        assert!(!pinned.fixed_display);
        assert_eq!(fs::read(directory.join("disk.qcow2")).unwrap(), disk);
        worker
            .command(Command::Duplicate {
                vm_id: vm.id.clone(),
                name: "Compatible copy".into(),
            })
            .unwrap();
        assert!(
            worker
                .snapshot
                .vms
                .iter()
                .all(|item| item.launch == vm.launch && item.base_identity == vm.base_identity)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn base_import_and_failed_credential_creation_preserve_published_state() {
        let root =
            std::env::temp_dir().join(format!("ant-credential-create-{}", storage::unique_id()));
        let options = BackendOptions {
            data_dir: root.join("data"),
            ..BackendOptions::default()
        };
        storage::private_dir(&options.data_dir).unwrap();
        let (_commands, receiver) = mpsc::sync_channel(1);
        let (sender, _notifications) = mpsc::sync_channel(1);
        let mut worker = Worker {
            options,
            snapshot: Snapshot::default(),
            receiver,
            sender,
            closing: Arc::new(AtomicBool::new(false)),
            stopping: Arc::new(AtomicBool::new(false)),
            session: None,
            catalog: distribution::Catalog::default(),
            refresh: None,
            download: None,
            build: None,
            tool: None,
            last_publish: Instant::now(),
            latest_snapshot: Arc::new(Mutex::new(None)),
        };
        for guest in [false, true] {
            let source = root.join(if guest { "debian" } else { "busybox" });
            storage::private_dir(&source).unwrap();
            fs::write(source.join("kernel"), b"kernel fixture").unwrap();
            assert!(
                std::process::Command::new("qemu-img")
                    .args(["create", "-f", "qcow2"])
                    .arg(source.join("base.qcow2"))
                    .arg("1M")
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
            let bundle = Bundle {
                kernel: source.join("kernel"),
                base_disk: source.join("base.qcow2"),
                initrd: None,
                kernel_append: String::new(),
                kernel_version: "6.12.94".into(),
                schema_id: 1,
                base_identity: None,
                guest: guest.then(|| GuestProfile {
                    id: "debian-xfce".into(),
                    label: "Debian 13 (Xfce)".into(),
                    min_ram_mib: 2048,
                    min_disk_gib: 8,
                    requires_credentials: true,
                    graphical: true,
                }),
                fixed_display: false,
                build_provenance: None,
                antinomie_revision: None,
                antinomie_source: None,
                built_with: None,
                min_app_version: None,
                name: None,
            };
            storage::atomic_json(&source.join("bundle.json"), &bundle).unwrap();
            worker
                .command(Command::ImportBase { directory: source })
                .unwrap();
        }
        assert_eq!(worker.snapshot.bases.len(), 2);
        let newer = root.join("busybox");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(newer.join("bundle.json")).unwrap()).unwrap();
        manifest["antinomie_revision"] = (APP_REVISION + 1).into();
        manifest["antinomie_source"] = "e".repeat(64).into();
        fs::write(
            newer.join("bundle.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let error = worker
            .command(Command::ImportBase { directory: newer })
            .unwrap_err();
        assert!(error.contains("update Antinomie"), "{error}");
        assert_eq!(worker.snapshot.bases.len(), 2);
        assert!(
            crate::locations::boot_bundle(&worker.options, None)
                .unwrap()
                .guest
                .is_none()
        );
        let identity = worker
            .snapshot
            .bases
            .iter()
            .find(|base| base.guest.is_some())
            .unwrap()
            .id
            .clone();
        let vm = VmConfig {
            id: "new-debian".into(),
            base_identity: Some(identity),
            ..VmConfig::default()
        };
        assert!(
            worker
                .command(Command::Create(vm.clone()))
                .unwrap_err()
                .contains("required")
        );
        crate::guest_account::fail_next_provision();
        let secret = "private-creation-password";
        let error = worker
            .command(Command::CreateWithCredentials {
                vm: vm.clone(),
                credentials: GuestCredentials::new("analyst".into(), secret.into()).unwrap(),
            })
            .unwrap_err();
        assert!(!error.contains(secret));
        assert!(!worker.options.data_dir.join(&vm.id).exists());
        assert!(worker.snapshot.vms.is_empty());
        assert!(storage::load_vms(&worker.options).unwrap().is_empty());
        assert_eq!(
            crate::locations::installed_bases(&worker.options)
                .unwrap()
                .len(),
            2
        );
        assert!(root.join("debian/base.qcow2").is_file());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn running_vm_duplicate_and_delete_guards_preserve_data() {
        let root = std::env::temp_dir().join(format!("ant-vm-guards-{}", storage::unique_id()));
        let options = BackendOptions {
            data_dir: root.clone(),
            ..BackendOptions::default()
        };
        let vm = VmConfig {
            id: "source".into(),
            ..VmConfig::default()
        };
        storage::private_dir(&root.join(&vm.id)).unwrap();
        storage::atomic_json(&root.join(&vm.id).join("config.json"), &vm).unwrap();
        let (_commands, receiver) = mpsc::sync_channel(1);
        let (sender, _notifications) = mpsc::sync_channel(1);
        let mut worker = Worker {
            options,
            snapshot: Snapshot {
                vms: vec![vm.clone()],
                active_vm: Some(vm.id.clone()),
                state: VmState::Running,
                ..Snapshot::default()
            },
            receiver,
            sender,
            closing: Arc::new(AtomicBool::new(false)),
            stopping: Arc::new(AtomicBool::new(false)),
            session: None,
            catalog: distribution::Catalog::default(),
            refresh: None,
            download: None,
            build: None,
            tool: None,
            last_publish: Instant::now(),
            latest_snapshot: Arc::new(Mutex::new(None)),
        };
        assert!(
            worker
                .command(Command::Create(VmConfig::default()))
                .unwrap_err()
                .contains("stop")
        );
        assert!(
            worker
                .command(Command::CreateWithCredentials {
                    vm: VmConfig::default(),
                    credentials: GuestCredentials::new("analyst".into(), "fixturepassword".into())
                        .unwrap(),
                })
                .unwrap_err()
                .contains("stop")
        );
        assert!(
            worker
                .command(Command::ImportBase {
                    directory: root.join("missing-base"),
                })
                .unwrap_err()
                .contains("stop")
        );
        assert!(
            worker
                .command(Command::Duplicate {
                    vm_id: vm.id.clone(),
                    name: "Copy".into()
                })
                .unwrap_err()
                .contains("stop")
        );
        assert!(
            worker
                .command(Command::Delete {
                    vm_id: vm.id.clone(),
                    confirmed: false
                })
                .unwrap_err()
                .contains("confirmation")
        );
        assert!(
            worker
                .command(Command::Delete {
                    vm_id: vm.id.clone(),
                    confirmed: true
                })
                .unwrap_err()
                .contains("stop")
        );
        worker
            .command(Command::Rename {
                vm_id: vm.id.clone(),
                name: "Renamed".into(),
            })
            .unwrap();
        assert_eq!(worker.snapshot.vms[0].id, vm.id);
        assert_eq!(worker.snapshot.vms[0].name, "Renamed");
        assert!(root.join(&vm.id).join("config.json").exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn pending_raw_copy_quota_failure_stops_existing_and_acknowledged_runs() {
        let root =
            std::env::temp_dir().join(format!("ant-pending-copy-quota-{}", storage::unique_id()));
        let mut capture = RawCapture::new(root.join("unassigned"), 1024).unwrap();
        let mut assembler = Assembler::new(capture.directory.join("objects"), 1024).unwrap();
        let create = |cookie: u64| {
            ProgramRun::new(
                RunSummary {
                    id: cookie.to_string(),
                    vm_id: "vm".into(),
                    boot_id: "boot".into(),
                    session_id: cookie,
                    root_task_cookie: cookie,
                    pid: cookie as u32,
                    request: ExecRequest::default(),
                    directory: root.join(cookie.to_string()),
                    terminal_eof: false,
                    state: RunState::Running,
                    recording_error: None,
                    execution: None,
                    analysis: None,
                },
                1024,
            )
            .unwrap()
        };
        let mut runs = BTreeMap::from([(1, create(1))]);
        let mut pending = create(2);
        assert!(capture.append(&[0; 696]));
        let packet = [1; 236];
        assert!(capture.append(&packet));
        let retained = fs::read(capture.directory.join("telemetry.raw")).unwrap();
        assert!(!pending.capture.append_with_reserved(&packet, capture.bytes));
        let error = pending.capture.error.clone().unwrap();
        pending.storage_error(error.clone());
        stop_capture_saving(&mut capture, &mut assembler, &mut runs, error.clone());
        assert!(pending.assembler.saving_error().is_none());
        runs.insert(2, pending);
        for run in runs.values_mut() {
            assert!(run.output(b"still live", 84).is_err());
            assert_eq!(run.summary.recording_error.as_deref(), Some(error.as_str()));
            assert_eq!(run.capture.bytes, 0);
        }
        assert!(!capture.append(b"later"));
        assert_eq!(
            fs::read(capture.directory.join("telemetry.raw")).unwrap(),
            retained
        );
        let mut health = Health::default();
        refresh_storage_health(&mut health, &capture, assembler.stored_len(), &runs);
        assert_eq!(health.persisted_len, 940);
        assert_eq!(health.persistence_error.as_deref(), Some(error.as_str()));
        drop(runs);
        drop(capture);
        // Run summaries are written in the background; settle them first.
        storage::settle_json_under(&root);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn object_saving_failure_preserves_raw_and_globally_denies_terminal_saving() {
        for run_owned in [false, true] {
            for io_failure in [false, true] {
                let root = std::env::temp_dir()
                    .join(format!("ant-global-object-saving-{}", storage::unique_id()));
                let mut capture = RawCapture::new(root.join("unassigned"), 1024).unwrap();
                let mut assembler =
                    Assembler::new(capture.directory.join("objects"), 1024).unwrap();
                let mut runs = BTreeMap::new();
                for cookie in 1..=2 {
                    let run = ProgramRun::new(
                        RunSummary {
                            id: cookie.to_string(),
                            vm_id: "vm".into(),
                            boot_id: "boot".into(),
                            session_id: cookie,
                            root_task_cookie: cookie,
                            pid: cookie as u32,
                            request: ExecRequest::default(),
                            directory: root.join(cookie.to_string()),
                            terminal_eof: false,
                            state: RunState::Running,
                            recording_error: None,
                            execution: None,
                            analysis: None,
                        },
                        1024,
                    )
                    .unwrap();
                    runs.insert(cookie, run);
                }
                assert!(capture.append_with_reserved(&[0; 696], 0));
                let mut packet = vec![0; 236];
                packet[..4].copy_from_slice(b"ANTT");
                packet[4..6].copy_from_slice(&1u16.to_le_bytes());
                packet[6..8].copy_from_slice(&1u16.to_le_bytes());
                packet[8..10].copy_from_slice(&136u16.to_le_bytes());
                packet[10..12].copy_from_slice(&1u16.to_le_bytes());
                packet[12..16].copy_from_slice(&236u32.to_le_bytes());
                packet[20..24].copy_from_slice(&1u32.to_le_bytes());
                packet[96..98].copy_from_slice(&1u16.to_le_bytes());
                packet[98] = 1;
                packet[99] = 3;
                packet[100..104].copy_from_slice(&1u32.to_le_bytes());
                packet[112..120].copy_from_slice(&u64::MAX.to_le_bytes());
                packet[120..124].copy_from_slice(&100u32.to_le_bytes());
                packet[128..136].copy_from_slice(&(if run_owned { 1u64 } else { 0 }).to_le_bytes());
                let target = if run_owned {
                    let run = runs.get_mut(&1).unwrap();
                    assert!(run.capture.append_with_reserved(&packet, 700));
                    &mut run.assembler
                } else {
                    assert!(capture.append_with_reserved(&packet, 0));
                    &mut assembler
                };
                target.set_storage_limit(if io_failure { 1024 } else { 84 });
                if io_failure {
                    let directory = if run_owned {
                        root.join("1")
                    } else {
                        capture.directory.clone()
                    };
                    fs::create_dir(directory.join("objects/0-0-0-1-0-1.raw")).unwrap();
                }
                let event = target.ingest(&packet).unwrap().unwrap();
                // Write failures surface once the writer thread has tried.
                assert_eq!(event.fields[0].ranges.is_empty(), !io_failure);
                crate::writer::barrier();
                propagate_object_saving_failure(&mut capture, &mut assembler, &mut runs);
                let error = capture.error.clone().unwrap();
                assert!(error.contains(if io_failure { "persistence" } else { "quota" }));
                let mut health = Health::default();
                refresh_storage_health(&mut health, &capture, assembler.stored_len(), &runs);
                // A chunk whose write failed was counted when it was queued.
                assert_eq!(health.persisted_len, if io_failure { 1040 } else { 940 });
                assert_eq!(health.persistence_error.as_deref(), Some(error.as_str()));
                for run in runs.values_mut() {
                    assert_eq!(run.summary.recording_error.as_deref(), Some(error.as_str()));
                    assert!(run.output(b"ten bytes!", 84).is_err());
                    assert_eq!(
                        fs::metadata(run.summary.directory.join("terminal.journal"))
                            .unwrap()
                            .len(),
                        0
                    );
                    run.finalize(84, "stopped", &health).unwrap_err();
                    let manifest: serde_json::Value = serde_json::from_reader(
                        File::open(run.summary.directory.join("manifest.json")).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(manifest["persistence_error"], error);
                    assert_eq!(manifest["health"]["persistence_error"], error);
                }
                assert!(!capture.append_with_reserved(b"later", 0));
                assert!(capture.flush());
                crate::writer::barrier();
                assert_eq!(
                    capture.bytes + runs.values().map(|run| run.capture.bytes).sum::<u64>(),
                    940
                );
                assert_eq!(
                    fs::metadata(capture.directory.join("telemetry.raw"))
                        .unwrap()
                        .len(),
                    capture.bytes
                );
                drop(runs);
                drop(capture);
                fs::remove_dir_all(root).unwrap();
            }
        }
    }
    #[test]
    fn final_health_counts_screen_and_keeps_errors_scoped_to_run() {
        let root = std::env::temp_dir().join(format!("ant-final-health-{}", storage::unique_id()));
        let capture = RawCapture::new(root.join("unassigned"), 65536).unwrap();
        let create = |id: &str, cookie: u64| {
            ProgramRun::new(
                RunSummary {
                    id: id.into(),
                    vm_id: "vm".into(),
                    boot_id: "boot".into(),
                    session_id: cookie,
                    root_task_cookie: cookie,
                    pid: cookie as u32,
                    request: ExecRequest::default(),
                    directory: root.join(id),
                    terminal_eof: false,
                    state: RunState::Running,
                    recording_error: None,
                    execution: None,
                    analysis: None,
                },
                65536,
            )
            .unwrap()
        };
        let mut healthy = create("healthy", 1);
        healthy.output(b"retained", 65536).unwrap();
        let before = healthy.stored_len();
        healthy
            .finalize(65536, "clean", &Health::default())
            .unwrap();
        let screen_len = fs::metadata(healthy.summary.directory.join("terminal-screen.ansi"))
            .unwrap()
            .len();
        assert_eq!(healthy.stored_len(), before + screen_len);
        let mut failed = create("failed", 2);
        failed.storage_error("only this run failed");
        let mut runs = BTreeMap::from([(1, healthy), (2, failed)]);
        let mut health = Health {
            persisted_len: before,
            ..Health::default()
        };
        refresh_storage_health(&mut health, &capture, 0, &runs);
        assert_eq!(health.persisted_len, before + screen_len);
        assert_eq!(
            health.persistence_error.as_deref(),
            Some("only this run failed")
        );
        assert!(runs.get(&1).unwrap().summary.recording_error.is_none());
        let mut capture = capture;
        capture.final_health = Some(health.clone());
        let bundle = Bundle {
            kernel: "kernel".into(),
            base_disk: "base".into(),
            initrd: None,
            kernel_append: String::new(),
            kernel_version: String::new(),
            schema_id: 1,
            base_identity: None,
            guest: None,
            fixed_display: false,
            build_provenance: None,
            antinomie_revision: None,
            antinomie_source: None,
            built_with: None,
            min_app_version: None,
            name: None,
        };
        capture
            .manifest(&VmConfig::default(), &bundle, &bundle, "clean")
            .unwrap();
        let manifest: serde_json::Value =
            serde_json::from_reader(File::open(capture.directory.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["health"]["persisted_len"], before + screen_len);
        assert_eq!(
            manifest["health"]["persistence_error"],
            "only this run failed"
        );
        assert!(manifest["persistence_error"].is_null());
        runs.clear();
        drop(capture);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn backend_close_joins_owner_without_a_vm() {
        let data_dir = std::env::temp_dir().join(format!("ant-backend-{}", storage::unique_id()));
        let mut backend = Backend::new(BackendOptions {
            data_dir: data_dir.clone(),
            ..BackendOptions::default()
        })
        .unwrap();
        backend.shutdown().unwrap();
        assert!(backend.thread.is_none());
        assert!(backend.send(Command::Stop).is_err());
        fs::remove_dir_all(data_dir).unwrap();
    }
    #[test]
    fn shutdown_request_budget_saturates_at_shared_deadline() {
        let now = Instant::now();
        assert!(
            remaining_request_budget(now - Duration::from_millis(1), Duration::from_secs(2))
                .is_zero()
        );
        assert!(
            remaining_request_budget(now + Duration::from_millis(100), Duration::from_secs(2))
                <= Duration::from_millis(100)
        );
        assert_eq!(
            remaining_request_budget(now + Duration::from_secs(10), Duration::from_secs(1)),
            Duration::from_secs(1)
        );
    }
}
