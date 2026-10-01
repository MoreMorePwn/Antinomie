use crate::{
    api::*,
    control,
    parser::{Assembler, u32_at, u64_at},
    storage::{self, Bundle, RawCapture},
    transport::Transport,
    vm::VmProcess,
};
use std::{
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
        storage::private_dir(&options.data_dir).map_err(|e| e.to_string())?;
        options.data_dir = fs::canonicalize(&options.data_dir).map_err(|e| e.to_string())?;
        let vms = storage::load_vms(&options)?;
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
                        ..Snapshot::default()
                    },
                    receiver,
                    sender,
                    closing: worker_closing,
                    stopping: worker_stopping,
                    session: None,
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
        if let Command::TerminalInput(ref data) = command
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
    terminal: Option<(u64, u32)>,
    terminal_eof: bool,
}
impl Session {
    fn pump(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        self.transport.poll(0)?;
        // A bounded batch returns control to command handling even under continuous telemetry.
        for _ in 0..256 {
            let Some(packet) = self.transport.read()? else {
                break;
            };
            snapshot.health.received_packets = snapshot.health.received_packets.saturating_add(1);
            if !self
                .capture
                .append_with_reserved(packet, self.assembler.stored_len())
            {
                snapshot.health.storage_dropped_packets =
                    snapshot.health.storage_dropped_packets.saturating_add(1);
                self.assembler.stop_saving();
            }
            self.assembler
                .set_storage_limit(self.capture.quota().saturating_sub(self.capture.bytes));
            if let Err(err) = self.assembler.ingest(packet) {
                snapshot.health.parser_errors += 1;
                snapshot.last_error = Some(format!("telemetry parser: {err}"));
            }
        }
        let stats = self.transport.stats()?;
        snapshot.health.attempted = stats.attempted;
        snapshot.health.dropped = stats.dropped;
        snapshot.health.bad_commands = stats.bad_commands;
        snapshot.health.reply_stalls = stats.reply_stalls;
        snapshot.health.transport_health = stats.health;
        snapshot.health.persisted_packets = self.capture.packets;
        snapshot.health.persisted_len = self
            .capture
            .bytes
            .saturating_add(self.assembler.stored_len());
        snapshot.health.persistence_error = self.capture.error.clone();
        snapshot.health.parser_evicted_count = self.assembler.evicted_count;
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
        let deadline = Instant::now() + timeout;
        loop {
            self.pump(snapshot, sender)?;
            while let Some((reply_id, status, payload)) = self.transport.reply()? {
                if reply_id != id {
                    snapshot.last_error =
                        Some(format!("unmatched command reply {reply_id}; awaiting {id}"));
                    continue;
                }
                if status < 0 {
                    return Err(format!(
                        "guest command 0x{opcode:x}: {}",
                        std::io::Error::from_raw_os_error(-status)
                    ));
                }
                if status != 0 {
                    return Err(format!("guest command returned unexpected status {status}"));
                }
                return Ok(payload);
            }
            if self
                .process
                .child
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_some()
            {
                return Err("VM exited while waiting for command reply".into());
            }
            if Instant::now() >= deadline {
                return Err(format!("guest command {id} timed out; outcome unknown"));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let poll_timeout = remaining.as_millis().min(10) as i32;
            self.transport.poll(poll_timeout)?;
        }
    }
    fn terminal_session(&self) -> Result<u64, String> {
        self.terminal
            .map(|(id, _)| id)
            .ok_or_else(|| "no launched terminal session".into())
    }
    fn finalize(&mut self, state: &str, snapshot: &mut Snapshot) -> Result<(), String> {
        snapshot.events = self.assembler.history();
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
        self.capture.final_health = Some(snapshot.health.clone());
        let manifest = self.capture.manifest(&self.vm, &self.bundle, state);
        snapshot.health.persistence_error = self.capture.error.clone();
        summaries.and(manifest)
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
    last_publish: Instant,
    latest_snapshot: Arc<Mutex<Option<Snapshot>>>,
}
impl Worker {
    fn emit(&mut self, notification: Notification) {
        if self.sender.try_send(notification).is_err() {
            self.snapshot.health.ui_dropped += 1;
        }
    }
    fn publish(&mut self) {
        if let Some(session) = &self.session {
            self.snapshot.events = session.assembler.history();
        }
        if let Ok(mut latest) = self.latest_snapshot.lock() {
            *latest = Some(self.snapshot.clone());
        }
        self.last_publish = Instant::now();
    }
    fn run(mut self) {
        self.publish();
        loop {
            if self.closing.load(Ordering::Relaxed) {
                let result = self.stop();
                if let Err(e) = result {
                    self.snapshot.last_error = Some(e);
                }
                self.publish();
                break;
            }
            match self.receiver.recv_timeout(Duration::from_millis(10)) {
                Ok((id, command)) => {
                    let quiet = matches!(
                        command,
                        Command::TerminalRead | Command::TerminalResize { .. }
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
            Command::Create(mut vm) => {
                if vm.id.is_empty() {
                    vm.id = storage::unique_id();
                }
                storage::validate_vm(&vm)?;
                let dir = storage::vm_dir(&self.options, &vm.id)?;
                if dir.exists() {
                    return Err("VM already exists".into());
                }
                let bundle = Bundle::load(&self.options.bundle_dir)?.install(&self.options)?;
                storage::private_dir(&dir).map_err(|e| e.to_string())?;
                if let Err(e) = storage::create_overlay(&self.options, &dir, vm.disk_gib, &bundle)
                    .and_then(|_| storage::atomic_json(&dir.join("config.json"), &vm))
                {
                    let _ = fs::remove_dir_all(&dir);
                    return Err(e);
                }
                self.snapshot.vms.push(vm);
                Ok("VM created".into())
            }
            Command::Save(vm) => {
                storage::validate_vm(&vm)?;
                self.ensure_stopped(&vm.id)?;
                let current = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|v| v.id == vm.id)
                    .ok_or("unknown VM")?;
                if vm.disk_gib < current.disk_gib {
                    return Err("persistent VM disks cannot be shrunk".into());
                }
                let dir = storage::vm_dir(&self.options, &vm.id)?;
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
                storage::atomic_json(&dir.join("config.json"), &vm)?;
                let slot = self
                    .snapshot
                    .vms
                    .iter_mut()
                    .find(|v| v.id == vm.id)
                    .ok_or("unknown VM")?;
                *slot = vm;
                Ok("VM saved".into())
            }
            Command::Delete { vm_id, confirmed } => {
                if !confirmed {
                    return Err("disk deletion requires explicit confirmation".into());
                }
                self.ensure_stopped(&vm_id)?;
                if !self.snapshot.vms.iter().any(|v| v.id == vm_id) {
                    return Err("unknown VM".into());
                }
                fs::remove_dir_all(storage::vm_dir(&self.options, &vm_id)?)
                    .map_err(|e| e.to_string())?;
                self.snapshot.vms.retain(|v| v.id != vm_id);
                Ok("VM deleted".into())
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
                let bundle: Bundle = serde_json::from_reader(
                    File::open(dir.join("bundle.json")).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                let staging = dir.join(format!("reset-{}", storage::unique_id()));
                storage::private_dir(&staging).map_err(|e| e.to_string())?;
                let result = storage::create_overlay(&self.options, &staging, vm.disk_gib, &bundle)
                    .and_then(|_| {
                        fs::rename(staging.join("disk.qcow2"), dir.join("disk.qcow2"))
                            .map_err(|e| e.to_string())
                    });
                let cleanup = fs::remove_dir_all(&staging).map_err(|e| e.to_string());
                result?;
                cleanup?;
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
            Command::OpenRecording { directory } => {
                if self.session.is_some() {
                    return Err("stop VM before opening a saved recording".into());
                }
                let recording =
                    crate::recording::open_recording(&directory).map_err(|e| e.to_string())?;
                self.snapshot.events = recording.events;
                self.snapshot.capture_dir = Some(recording.directory);
                self.snapshot.health = recording
                    .manifest
                    .get("health")
                    .cloned()
                    .and_then(|h| serde_json::from_value(h).ok())
                    .unwrap_or_default();
                Ok("recording opened".into())
            }
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
        let dir = storage::vm_dir(&self.options, id)?;
        let bundle: Bundle = serde_json::from_reader(
            File::open(dir.join("bundle.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        bundle.verify_installed()?;
        self.snapshot.state = VmState::Starting;
        self.snapshot.active_vm = Some(id.into());
        self.snapshot.health = Health::default();
        self.snapshot.events.clear();
        self.publish();
        self.stopping.store(false, Ordering::Relaxed);
        let result = (|| -> Result<Session, String> {
            let process = VmProcess::launch(&self.options, &vm, &bundle)?;
            self.snapshot.serial_log = Some(process.runtime_dir.join("serial.log"));
            let capture_dir = self
                .options
                .data_dir
                .join("captures")
                .join(storage::unique_id());
            let mut capture =
                RawCapture::new(capture_dir.clone(), self.options.capture_quota_size)?;
            capture.manifest(&vm, &bundle, "starting")?;
            self.snapshot.capture_dir = Some(capture_dir.clone());
            let assembler =
                Assembler::new(capture_dir.join("objects"), self.options.capture_quota_size)
                    .map_err(|e| e.to_string())?;
            let transport =
                match Transport::open(&process.ram_path, process.ram_size, process.bootstrap) {
                    Ok(t) => t,
                    Err(e) => {
                        capture.manifest(&vm, &bundle, "start-failed")?;
                        return Err(e);
                    }
                };
            capture.manifest(&vm, &bundle, "running")?;
            Ok(Session {
                transport,
                process,
                capture,
                assembler,
                vm,
                bundle,
                terminal: None,
                terminal_eof: false,
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
            if self.last_publish.elapsed() >= Duration::from_millis(250) {
                self.snapshot.events = session.assembler.history();
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
                let args = control::execute(&request)?;
                let reply = session.request(
                    control::EXEC,
                    &args,
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )?;
                if reply.len() != 24 || u32_at(&reply, 20).map_err(|e| e.to_string())? != 0 {
                    return Err("invalid execution reply".into());
                }
                let id = u64_at(&reply, 0).map_err(|e| e.to_string())?;
                let pid = u32_at(&reply, 16).map_err(|e| e.to_string())?;
                session.terminal = Some((id, pid));
                session.terminal_eof = false;
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
            Command::TerminalInput(data) => {
                let terminal = session.terminal_session()?;
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
            Command::TerminalRead => {
                if session.terminal_eof || session.terminal.is_none() {
                    return Ok(String::new());
                }
                let mut args = control::with_session(session.terminal_session()?);
                args.extend(4096u32.to_le_bytes());
                args.extend(0u32.to_le_bytes());
                let reply = session.request(
                    control::READ,
                    &args,
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )?;
                let flags = u32_at(&reply, 0).map_err(|e| e.to_string())?;
                let count = u32_at(&reply, 4).map_err(|e| e.to_string())? as usize;
                if reply.len() != 8 + count || count > 4096 || flags & !1 != 0 {
                    return Err("invalid terminal read reply".into());
                }
                session.terminal_eof = flags & 1 != 0;
                if count > 0 {
                    let terminal = reply[8..].to_vec();
                    self.emit(Notification::Terminal(terminal));
                }
                Ok(String::new())
            }
            Command::TerminalResize { rows, cols } => {
                if rows == 0 || cols == 0 {
                    return Err("terminal dimensions must be positive".into());
                }
                let mut args = control::with_session(session.terminal_session()?);
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
                Ok("terminal resized".into())
            }
            Command::Signal { pid, signal } => {
                if !(1..=64).contains(&signal) {
                    return Err("signal must be 1..64".into());
                }
                let (id, current_pid) = session.terminal.ok_or("no launched process")?;
                if pid != 0 && pid != current_pid {
                    return Err(
                        "signal target differs from the current launch process group".into(),
                    );
                }
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
