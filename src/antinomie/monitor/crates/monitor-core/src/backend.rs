use crate::{
    api::*,
    build, control, distribution,
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
        let mut bases = crate::locations::installed_bases(&options)?;
        if bases.is_empty() && options.bundle_dir.join("bundle.json").is_file() {
            crate::locations::boot_bundle(&options, None)?;
            bases = crate::locations::installed_bases(&options)?;
        }
        let vm_locations = vms
            .iter()
            .map(|vm| crate::locations::locations(&options, &vm.id))
            .collect::<Result<Vec<_>, _>>()?;
        let (commands, receiver) = mpsc::sync_channel(32);
        let (sender, notifications) = mpsc::sync_channel(64);
        let closing = Arc::new(AtomicBool::new(false));
        let stopping = Arc::new(AtomicBool::new(false));
        let (worker_closing, worker_stopping) = (closing.clone(), stopping.clone());
        let latest_snapshot = Arc::new(Mutex::new(None));
        let worker_snapshot = latest_snapshot.clone();
        let thread = thread::Builder::new()
            .name("antinomie-transport".into())
            .spawn(move || {
                Worker {
                    options,
                    snapshot: Snapshot {
                        vms,
                        bases,
                        vm_locations,
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

struct Session {
    transport: Transport,
    process: VmProcess,
    capture: RawCapture,
    assembler: Assembler,
    vm: VmConfig,
    bundle: Bundle,
    disk_bundle: Bundle,
    runs: BTreeMap<u64, ProgramRun>,
    boot_id: String,
    pending: VecDeque<Vec<u8>>,
    pending_len: usize,
    pending_overflow: bool,
    terminal_cursor: usize,
    /// Terminal READ requests whose deadline passed before their reply arrived,
    /// keyed by request id. The guest answers commands in submission order and
    /// has already consumed the PTY bytes, so a late reply still belongs to its run.
    late_reads: BTreeMap<u64, u64>,
    status_cursor: usize,
    last_status_query: Instant,
    persisted_packets: u64,
}
impl Session {
    fn stored_len(&self) -> u64 {
        self.capture
            .bytes
            .saturating_add(self.assembler.stored_len())
            .saturating_add(self.runs.values().map(ProgramRun::stored_len).sum::<u64>())
    }
    fn available(&self) -> u64 {
        self.capture.quota().saturating_sub(self.stored_len())
    }
    fn stop_saving(&mut self, error: String) {
        stop_capture_saving(
            &mut self.capture,
            &mut self.assembler,
            &mut self.runs,
            error,
        );
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
        let mut events = self.assembler.history();
        for run in self.runs.values() {
            events.extend(run.assembler.history());
        }
        events.sort_by_key(|event| event.timestamp_ns);
        if events.len() > 2048 {
            events.drain(..events.len() - 2048);
        }
        events
    }
    fn pump(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        self.transport.poll(0)?;
        // A bounded batch returns control to command handling even under continuous telemetry.
        for _ in 0..256 {
            let Some(packet) = self.transport.read()?.map(<[u8]>::to_vec) else {
                break;
            };
            snapshot.health.received_packets = snapshot.health.received_packets.saturating_add(1);
            let root = crate::parser::parse_packet(&packet)
                .map(|(header, _)| header.root_task_cookie)
                .unwrap_or(0);
            let reserved = self.stored_len();
            let saved =
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
            propagate_object_saving_failure(&mut self.capture, &mut self.assembler, &mut self.runs);
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
        let stats = self.transport.stats()?;
        snapshot.health.attempted = stats.attempted;
        snapshot.health.dropped = stats.dropped;
        snapshot.health.bad_commands = stats.bad_commands;
        snapshot.health.reply_stalls = stats.reply_stalls;
        snapshot.health.transport_health = stats.health;
        snapshot.health.persisted_packets = self.persisted_packets;
        refresh_storage_health(
            &mut snapshot.health,
            &self.capture,
            self.assembler.stored_len(),
            &self.runs,
        );
        snapshot.health.parser_evicted_count = self.assembler.evicted_count
            + self
                .runs
                .values()
                .map(|run| run.assembler.evicted_count)
                .sum::<u64>();
        let _ = sender;
        Ok(())
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
                    return Err(RequestError::Failed(format!(
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
        refresh_storage_health(
            &mut snapshot.health,
            &self.capture,
            self.assembler.stored_len(),
            &self.runs,
        );
        self.capture.final_health = Some(snapshot.health.clone());
        let manifest = self
            .capture
            .manifest(&self.vm, &self.bundle, &self.disk_bundle, state);
        refresh_storage_health(
            &mut snapshot.health,
            &self.capture,
            self.assembler.stored_len(),
            &self.runs,
        );
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
            Err(RequestError::Failed(error)) => Err(error),
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

/// A command wait outcome: only a timeout leaves the guest-side outcome unknown.
enum RequestError {
    TimedOut(String),
    Failed(String),
}

impl RequestError {
    fn into_message(self) -> String {
        match self {
            Self::TimedOut(message) | Self::Failed(message) => message,
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
    last_publish: Instant,
    latest_snapshot: Arc<Mutex<Option<Snapshot>>>,
}

struct DownloadJob {
    identity: String,
    label: String,
    total: u64,
    progress: Arc<Mutex<(u64, bool)>>,
    done: Receiver<Result<(), String>>,
}

struct BuildJob {
    label: String,
    stage: Arc<Mutex<String>>,
    log: Arc<Mutex<std::collections::VecDeque<String>>>,
    cancel: Arc<AtomicBool>,
    done: Receiver<Result<(), String>>,
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
        }
        if let Ok(mut latest) = self.latest_snapshot.lock() {
            *latest = Some(self.snapshot.clone());
        }
        self.last_publish = Instant::now();
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
        if let Some(job) = self.download.as_ref() {
            let received = job.progress.lock().map(|guard| guard.0).unwrap_or(0);
            if let Some(status) = self.snapshot.download.as_mut() {
                status.received = received;
            }
        }
        let finished = self.download.as_ref().and_then(|job| {
            job.done.try_recv().ok().or_else(|| {
                if matches!(job.done.try_recv(), Err(mpsc::TryRecvError::Disconnected)) {
                    Some(Err("download worker disconnected".into()))
                } else {
                    None
                }
            })
        });
        if let Some(result) = finished {
            let job = self.download.take().expect("download job present");
            let error = result.err();
            if let Some(error) = &error {
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
    fn run(mut self) {
        self.publish();
        loop {
            if self.closing.load(Ordering::Relaxed) {
                if let Some(job) = self.build.as_ref() {
                    job.cancel.store(true, Ordering::Relaxed);
                }
                let result = self.stop();
                if let Err(e) = result {
                    self.snapshot.last_error = Some(e);
                }
                self.publish();
                storage::flush_json();
                break;
            }
            match self.receiver.recv_timeout(Duration::from_millis(10)) {
                Ok((id, command)) => {
                    let quiet = matches!(
                        command,
                        Command::TerminalRead { .. } | Command::TerminalResize { .. }
                    );
                    let result = self.command(command);
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
                    self.publish();
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.closing.store(true, Ordering::Relaxed);
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
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
                let progress = Arc::new(Mutex::new((0u64, false)));
                let worker_progress = progress.clone();
                let (sender, receiver) = mpsc::channel();
                let requested = base.clone();
                let staging_thread = staging.clone();
                thread::Builder::new()
                    .name("antinomie-download".into())
                    .spawn(move || {
                        let cancel = AtomicBool::new(false);
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
                            storage::validate_disk_chain(&options, &bundle.base_disk, None)?;
                            bundle.install(&options)?;
                            Ok(())
                        });
                        let ok = result.is_ok();
                        if let Ok(mut guard) = worker_progress.lock() {
                            guard.1 = true;
                        }
                        let _ = sender.send(result);
                        if ok {
                            let _ = fs::remove_dir_all(&staging_thread);
                        }
                    })
                    .map_err(|e| e.to_string())?;
                self.download = Some(DownloadJob {
                    identity: base.identity.clone(),
                    label: base.label.clone(),
                    total,
                    progress,
                    done: receiver,
                });
                self.snapshot.download = Some(DownloadStatus {
                    identity: base.identity,
                    label: base.label,
                    received: 0,
                    total,
                    finished: false,
                    error: None,
                });
                Ok("base download started".into())
            }
            Command::BuildBase { profile } => {
                if self.build.is_some() {
                    return Err("a base build is already in progress".into());
                }
                let spec = build::profile(&profile).ok_or("unknown build profile")?;
                let missing = build::missing(spec.kind);
                if !missing.is_empty() {
                    let hint = build::install_hint(spec.kind);
                    return Err(format!(
                        "missing host tools: {}{}",
                        missing
                            .iter()
                            .map(|tool| tool.tool)
                            .collect::<Vec<_>>()
                            .join(", "),
                        if hint.is_empty() {
                            String::new()
                        } else {
                            format!(" (install with: {hint})")
                        }
                    ));
                }
                let workspace = self
                    .options
                    .build_workspace
                    .clone()
                    .ok_or("no build workspace configured; set it in Settings")?;
                if !workspace.join("scripts").is_dir() {
                    return Err(format!(
                        "build workspace {} is not a repository checkout",
                        workspace.display()
                    ));
                }
                let output = self.options.data_dir.join("builds").join(format!(
                    "{}-{}",
                    spec.id,
                    crate::storage::unique_id()
                ));
                let steps = build::plan(&workspace, spec.kind, &output);
                let stage = Arc::new(Mutex::new("kernel".to_string()));
                let log = Arc::new(Mutex::new(VecDeque::<String>::new()));
                let cancel = Arc::new(AtomicBool::new(false));
                let (sender, receiver) = mpsc::channel();
                let worker_stage = stage.clone();
                let worker_log = log.clone();
                let worker_cancel = cancel.clone();
                let options = self.options.clone();
                let output_thread = output.clone();
                thread::Builder::new()
                    .name("antinomie-build".into())
                    .spawn(move || {
                        let mut step_index = 0usize;
                        let result = build::run(&steps, &workspace, &worker_cancel, |line| {
                            if line.starts_with("$ ") {
                                step_index += 1;
                                let name = match step_index {
                                    1 => "kernel",
                                    2 => "image",
                                    _ => "stage",
                                };
                                if let Ok(mut guard) = worker_stage.lock() {
                                    *guard = name.to_string();
                                }
                            }
                            if let Ok(mut guard) = worker_log.lock() {
                                if guard.len() >= 200 {
                                    guard.pop_front();
                                }
                                guard.push_back(line.to_string());
                            }
                        })
                        .and_then(|()| {
                            let bundle = Bundle::load(&output_thread)?;
                            storage::validate_disk_chain(&options, &bundle.base_disk, None)?;
                            bundle.install(&options)?;
                            Ok(())
                        });
                        let ok = result.is_ok();
                        let _ = sender.send(result);
                        if ok {
                            let _ = fs::remove_dir_all(&output_thread);
                        }
                    })
                    .map_err(|e| e.to_string())?;
                self.build = Some(BuildJob {
                    label: spec.label.to_string(),
                    stage,
                    log,
                    cancel,
                    done: receiver,
                });
                self.snapshot.build = Some(BuildStatus {
                    profile: spec.id.to_string(),
                    label: spec.label.to_string(),
                    stage: "kernel".into(),
                    log: Vec::new(),
                    finished: false,
                    error: None,
                });
                Ok("base build started".into())
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
                build_workspace,
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
                self.options.build_workspace = build_workspace;
                Ok("settings updated".into())
            }
            Command::OpenRecording { directory } => Err(format!(
                "open {} with the independent recording reader",
                directory.display()
            )),
            Command::Start { vm_id } => self.start(&vm_id),
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
        self.snapshot.state = VmState::Starting;
        self.snapshot.active_vm = Some(id.into());
        self.snapshot.health = Health::default();
        self.snapshot.events.clear();
        self.publish();
        self.stopping.store(false, Ordering::Relaxed);
        let result = (|| -> Result<Session, String> {
            let process = VmProcess::launch(&self.options, &vm, &bundle)?;
            self.snapshot.serial_log = Some(process.runtime_dir.join("serial.log"));
            let boot_id = storage::unique_id();
            let capture_dir = crate::locations::locations(&self.options, id)?
                .recording_directory
                .join("boots")
                .join(&boot_id)
                .join("unassigned");
            let mut capture =
                RawCapture::new(capture_dir.clone(), self.options.capture_quota_size)?;
            capture.manifest(&vm, &bundle, &disk_bundle, "starting")?;
            self.snapshot.capture_dir = Some(capture_dir.clone());
            let assembler =
                Assembler::new(capture_dir.join("objects"), self.options.capture_quota_size)
                    .map_err(|e| e.to_string())?;
            if let Err(e) = process.verify_ram_layout() {
                capture.manifest(&vm, &bundle, &disk_bundle, "start-failed")?;
                return Err(e);
            }
            let transport =
                match Transport::open(&process.ram_path, process.ram_size, process.bootstrap) {
                    Ok(t) => t,
                    Err(e) => {
                        capture.manifest(&vm, &bundle, &disk_bundle, "start-failed")?;
                        return Err(e);
                    }
                };
            capture.manifest(&vm, &bundle, &disk_bundle, "running")?;
            Ok(Session {
                transport,
                process,
                capture,
                assembler,
                vm,
                bundle,
                disk_bundle,
                runs: BTreeMap::new(),
                boot_id,
                pending: VecDeque::new(),
                pending_len: 0,
                pending_overflow: false,
                terminal_cursor: 0,
                late_reads: BTreeMap::new(),
                status_cursor: 0,
                last_status_query: Instant::now(),
                persisted_packets: 0,
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
    fn stop(&mut self) -> Result<(), String> {
        let Some(mut session) = self.session.take() else {
            self.snapshot.active_vm = None;
            self.snapshot.state = VmState::Stopped;
            return Ok(());
        };
        self.snapshot.state = VmState::Stopping;
        self.publish();
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
        match command {
            Command::Execute(request) => {
                if session.runs.len() >= 64 {
                    return Err("this VM boot reached the 64-run limit; restart the VM before another launch".into());
                }
                let args = control::execute(&request)?;
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
                    request,
                    directory,
                    terminal_eof: false,
                    state: RunState::Unknown,
                    recording_error: Some("execution has not been acknowledged".into()),
                    execution: None,
                };
                let mut run = ProgramRun::new(summary, session.capture.quota())?;
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
                if reply.len() != 24 || u32_at(&reply, 20).map_err(|e| e.to_string())? != 0 {
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
        runs.values()
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

fn remaining_request_budget(deadline: Instant, maximum: Duration) -> Duration {
    deadline
        .saturating_duration_since(Instant::now())
        .min(maximum)
}

#[cfg(test)]
mod tests {
    use super::*;
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
            };
            storage::atomic_json(&source.join("bundle.json"), &bundle).unwrap();
            worker
                .command(Command::ImportBase { directory: source })
                .unwrap();
        }
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
                assert!(event.fields[0].ranges.is_empty());
                propagate_object_saving_failure(&mut capture, &mut assembler, &mut runs);
                let error = capture.error.clone().unwrap();
                assert!(error.contains(if io_failure { "persistence" } else { "quota" }));
                let mut health = Health::default();
                refresh_storage_health(&mut health, &capture, assembler.stored_len(), &runs);
                assert_eq!(health.persisted_len, 940);
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
