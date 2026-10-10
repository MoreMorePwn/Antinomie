//! Drives the backend from a JSON plan: optionally import a base and create a
//! VM, then boot it, upload files and record runs, each waiting for a terminal
//! marker. Used for the overhead benchmark and to populate a data directory
//! with recorded runs that the app then shows.
//!
//! usage: guest-run PLAN.json
//!
//! ```json
//! {"data_dir": "/home/me/antinomie", "headless": true,
//!  "import": "work/bundle",
//!  "vm": {"name": "Debian", "cpus": 4, "ram_mib": 4096, "disk_gib": 20,
//!         "username": "analyst", "password": "analyst1"},
//!  "recreate": false, "boot_timeout": 240,
//!  "uploads": [{"source": "work/probe", "destination": "/tmp/probe"}],
//!  "runs": [{"path": "/tmp/probe", "args": [], "uid": 1000, "gid": 1000,
//!            "release_after": "READY", "release": "ping\n",
//!            "done": "NATIVE PASS", "timeout": 120}],
//!  "screenshot": "/tmp/screen.png", "screenshot_after": 20}
//! ```
//!
//! `"vm": {"nat": true}` gives the VM NAT networking (and a network.pcap).
//! `"vm": {"transport": {"ring_kib": 4096, "lossless": true, "max_wait_ms": 100,
//! "event_table": 16384}}` sets the VM's transport settings (any subset).
//!
//! `"capture_all": true` starts Capture All once the guest is up, before the
//! runs, and stops it after them; the report then includes its summary.
//!
//! A run may also set `"run_in": "guest_desktop"` (or
//! `"guest_desktop_terminal"`), `"screenshot": PATH` to save the screen
//! `"screenshot_after"` seconds (default 10) after its `done` marker, and
//! `"stop": true` to stop its process tree after that.
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, ExecRequest, GuestCredentials, Notification, RunIn, Snapshot,
    VmConfig, VmState,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

struct Session {
    backend: Backend,
    snapshot: Snapshot,
    terminals: BTreeMap<String, Vec<u8>>,
}

impl Session {
    fn pump(&mut self) -> Option<(u64, bool, String)> {
        let mut result = None;
        while let Some(notification) = self.backend.try_recv() {
            match notification {
                Notification::Snapshot(snapshot) => self.snapshot = snapshot,
                Notification::Terminal { run_id, data, .. } => {
                    self.terminals.entry(run_id).or_default().extend(data)
                }
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => result = Some((id, success, message)),
                _ => {}
            }
        }
        result
    }

    fn command(&mut self, command: Command, seconds: u64) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            if let Some((_, success, message)) = self.pump().filter(|(reply, ..)| *reply == id) {
                return if success { Ok(message) } else { Err(message) };
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "command {id} deadline; state {:?}",
                    self.snapshot.state
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Retries a guest command until the guest's kernel control accepts it.
    fn guest_command(
        &mut self,
        make: impl Fn() -> Command,
        seconds: u64,
    ) -> Result<String, String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            match self.command(make(), 60) {
                Ok(message) => return Ok(message),
                Err(error) if Instant::now() < deadline => {
                    // Let a busy command worker drain before asking again.
                    eprintln!("guest not ready yet: {error}");
                    thread::sleep(Duration::from_secs(5));
                    self.pump();
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn settle(&mut self, until: impl Fn(&Snapshot) -> bool, seconds: u64) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.pump();
            if until(&self.snapshot) {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err("snapshot condition deadline".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits for `marker` in the run's terminal. Returns false when the run's
    /// process tree exited without printing it.
    fn terminal_until(&mut self, run_id: &str, marker: &str, seconds: u64) -> Result<bool, String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            if self
                .terminals
                .get(run_id)
                .is_some_and(|data| data.windows(marker.len()).any(|w| w == marker.as_bytes()))
            {
                return Ok(true);
            }
            let exited =
                self.snapshot.runs.iter().any(|r| {
                    r.id == run_id && r.execution.as_ref().is_some_and(|e| e.flags & 2 != 0)
                });
            if exited && self.terminals.get(run_id).is_some_and(|d| !d.is_empty()) {
                // One more read collects output written just before the exit.
                self.backend.send(Command::TerminalRead {
                    run_id: run_id.into(),
                })?;
                thread::sleep(Duration::from_millis(300));
                self.pump();
                let found = self
                    .terminals
                    .get(run_id)
                    .is_some_and(|data| data.windows(marker.len()).any(|w| w == marker.as_bytes()));
                return Ok(found);
            }
            // A full command queue (the backend waiting on the disk) only
            // delays this read.
            let _ = self.backend.send(Command::TerminalRead {
                run_id: run_id.into(),
            });
            let until = Instant::now() + Duration::from_millis(100);
            while Instant::now() < until {
                self.pump();
                thread::sleep(Duration::from_millis(10));
            }
            if Instant::now() > deadline {
                let tail = self.terminals.get(run_id).map_or(String::new(), |data| {
                    String::from_utf8_lossy(&data[data.len().saturating_sub(2000)..]).into()
                });
                return Err(format!("terminal marker {marker} deadline; tail: {tail}"));
            }
        }
    }
}

fn text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn number(value: &Value, key: &str, default: u64) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(default)
}

fn run() -> Result<Value, String> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: guest-run PLAN.json")?;
    let plan: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let mut options = BackendOptions {
        headless: plan
            .get("headless")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        ..BackendOptions::default()
    };
    if let Some(data_dir) = text(&plan, "data_dir") {
        options.data_dir = PathBuf::from(data_dir);
    }
    let mut session = Session {
        backend: Backend::new(options)?,
        snapshot: Snapshot::default(),
        terminals: BTreeMap::new(),
    };
    session.settle(|_| true, 1)?;
    thread::sleep(Duration::from_millis(500));
    session.pump();

    let mut base = text(&plan, "base");
    if let Some(bundle) = text(&plan, "import") {
        let before: Vec<_> = session
            .snapshot
            .bases
            .iter()
            .map(|b| b.id.clone())
            .collect();
        session.command(
            Command::ImportBase {
                directory: bundle.into(),
            },
            600,
        )?;
        session.settle(|s| s.bases.len() > before.len(), 30)?;
        base = session
            .snapshot
            .bases
            .iter()
            .find(|b| !before.contains(&b.id))
            .map(|b| b.id.clone());
    }

    let vm_spec = plan.get("vm").cloned().unwrap_or(Value::Null);
    let name = text(&vm_spec, "name").ok_or("plan.vm.name is required")?;
    let mut existing = session
        .snapshot
        .vms
        .iter()
        .find(|vm| vm.name == name)
        .map(|vm| vm.id.clone());
    // "recreate": replace an existing VM of that name, with its run history.
    if let Some(id) = existing.take_if(|_| {
        plan.get("recreate")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }) {
        session.command(
            Command::Delete {
                vm_id: id.clone(),
                confirmed: true,
            },
            120,
        )?;
        session.settle(|s| s.vms.iter().all(|vm| vm.id != id), 30)?;
    }
    let vm_id = match existing {
        Some(id) => id,
        None => {
            let before: Vec<_> = session
                .snapshot
                .vms
                .iter()
                .map(|vm| vm.id.clone())
                .collect();
            let config = VmConfig {
                name: name.clone(),
                cpus: number(&vm_spec, "cpus", 4) as u16,
                ram_mib: number(&vm_spec, "ram_mib", 1024) as u32,
                disk_gib: number(&vm_spec, "disk_gib", 1) as u32,
                base_identity: base.clone(),
                nat: vm_spec.get("nat").and_then(Value::as_bool).unwrap_or(false),
                transport: vm_spec
                    .get("transport")
                    .map(|value| serde_json::from_value(value.clone()))
                    .transpose()
                    .map_err(|e| format!("plan.vm.transport: {e}"))?
                    .unwrap_or_default(),
                ..VmConfig::default()
            };
            match (text(&vm_spec, "username"), text(&vm_spec, "password")) {
                (Some(username), Some(password)) => session.command(
                    Command::CreateWithCredentials {
                        vm: config,
                        credentials: GuestCredentials::new(username, password)?,
                    },
                    900,
                )?,
                _ => session.command(Command::Create(config), 60)?,
            };
            session.settle(|s| s.vms.len() > before.len(), 30)?;
            session
                .snapshot
                .vms
                .iter()
                .find(|vm| !before.contains(&vm.id))
                .map(|vm| vm.id.clone())
                .ok_or("created VM missing")?
        }
    };

    session.command(
        Command::Start {
            vm_id: vm_id.clone(),
        },
        // Start verifies the installed base's hashes; a large base takes minutes.
        900,
    )?;
    let boot = number(&plan, "boot_timeout", 60);
    let started = Instant::now();
    for upload in plan
        .get("uploads")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let source = text(&upload, "source").ok_or("upload.source")?;
        let destination = text(&upload, "destination").ok_or("upload.destination")?;
        session.guest_command(
            || Command::Upload {
                source: PathBuf::from(&source),
                destination: destination.clone(),
                overwrite: true,
                executable: true,
            },
            boot,
        )?;
    }
    let capture_all = plan
        .get("capture_all")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if capture_all {
        session.guest_command(|| Command::CaptureAll, boot)?;
    }
    let boot_seconds = started.elapsed().as_secs_f64();

    let mut runs = Vec::new();
    for spec in plan
        .get("runs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let known: Vec<_> = session.snapshot.runs.iter().map(|r| r.id.clone()).collect();
        let request = ExecRequest {
            path: text(&spec, "path").ok_or("run.path")?,
            args: spec
                .get("args")
                .and_then(Value::as_array)
                .map(|args| {
                    args.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            env: vec!["PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into()],
            uid: number(&spec, "uid", 1000) as u32,
            gid: number(&spec, "gid", 1000) as u32,
            run_in: spec
                .get("run_in")
                .cloned()
                .map(serde_json::from_value::<RunIn>)
                .transpose()
                .map_err(|e| format!("run.run_in: {e}"))?
                .unwrap_or_default(),
            ..ExecRequest::default()
        };
        let launched = Instant::now();
        session.guest_command(|| Command::Execute(request.clone()), boot)?;
        session.settle(|s| s.runs.iter().any(|r| !known.contains(&r.id)), 30)?;
        let run_id = session
            .snapshot
            .runs
            .iter()
            .find(|r| !known.contains(&r.id))
            .map(|r| r.id.clone())
            .ok_or("run missing")?;
        let timeout = number(&spec, "timeout", 120);
        if let (Some(marker), Some(release)) =
            (text(&spec, "release_after"), text(&spec, "release"))
            && session.terminal_until(&run_id, &marker, timeout)?
        {
            session.command(
                Command::TerminalInput {
                    run_id: run_id.clone(),
                    data: release.into_bytes(),
                },
                20,
            )?;
        }
        let done = text(&spec, "done").ok_or("run.done")?;
        let marker_seen = session.terminal_until(&run_id, &done, timeout)?;
        let elapsed = launched.elapsed().as_secs_f64();
        let run_screenshot = match text(&spec, "screenshot") {
            Some(path) => {
                thread::sleep(Duration::from_secs(number(&spec, "screenshot_after", 10)));
                Some(screendump(&session.snapshot, &path)?)
            }
            None => None,
        };
        if spec.get("stop").and_then(Value::as_bool).unwrap_or(false) {
            session.command(
                Command::StopRun {
                    run_id: run_id.clone(),
                },
                30,
            )?;
        }
        // The status is final once the tree exited and no request is pending.
        let id = run_id.clone();
        session.settle(
            |s| {
                s.runs.iter().any(|r| {
                    r.id == id
                        && r.execution
                            .as_ref()
                            .is_some_and(|e| e.flags & 2 != 0 && e.pending_async_count == 0)
                })
            },
            30,
        )?;
        let summary = session
            .snapshot
            .runs
            .iter()
            .find(|r| r.id == run_id)
            .cloned();
        runs.push(json!({
            "run_id": run_id,
            "directory": summary.as_ref().map(|r| r.directory.clone()),
            "execution": summary.as_ref().and_then(|r| r.execution.clone()),
            "seconds": elapsed,
            "marker_seen": marker_seen,
            "screenshot": run_screenshot,
            "terminal": String::from_utf8_lossy(session.terminals.get(&run_id).map_or(&[][..], |d| d)),
        }));
    }
    let screenshot = match text(&plan, "screenshot") {
        Some(path) => {
            // Give the display manager time to show its greeter.
            thread::sleep(Duration::from_secs(number(&plan, "screenshot_after", 20)));
            Some(screendump(&session.snapshot, &path)?)
        }
        None => None,
    };
    let mut capture = None;
    if capture_all {
        let id = session
            .snapshot
            .captures
            .first()
            .map(|c| c.id.clone())
            .ok_or("Capture All capture missing")?;
        // Finalizing waits for the capture's queued writes.
        session.command(
            Command::StopCapture {
                capture_id: id.clone(),
            },
            600,
        )?;
        thread::sleep(Duration::from_secs(1));
        session.pump();
        capture = session
            .snapshot
            .captures
            .iter()
            .find(|c| c.id == id)
            .and_then(|c| serde_json::to_value(c).ok());
    }
    let recorder = session.command(Command::RecorderStats, 120)?;
    let health = session.snapshot.health.clone();
    // Stopping waits for queued recording writes, which a long never-drop
    // run can leave in the hundreds of megabytes.
    session.command(Command::Stop, 600)?;
    session.settle(|s| s.state == VmState::Stopped, 60)?;
    session.backend.shutdown()?;
    Ok(
        json!({"vm_id": vm_id, "base": base, "boot_seconds": boot_seconds,
              "runs": runs, "recorder": recorder, "health": health, "capture": capture,
              "screenshot": screenshot}),
    )
}

/// Save the VM screen as PNG through QEMU's QMP socket, which sits next to
/// the serial log in the VM's runtime directory.
fn screendump(snapshot: &Snapshot, path: &str) -> Result<String, String> {
    use std::io::{BufRead, BufReader, Write};
    let socket = snapshot
        .serial_log
        .as_ref()
        .and_then(|log| log.parent())
        .map(|dir| dir.join("qmp.sock"))
        .ok_or("no VM runtime directory for the screenshot")?;
    let stream = std::os::unix::net::UnixStream::connect(&socket)
        .map_err(|e| format!("QMP {}: {e}", socket.display()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).map_err(|e| e.to_string())?;
    let mut writer = stream;
    let mut reply = |request: &str| -> Result<Value, String> {
        writer
            .write_all(request.as_bytes())
            .map_err(|e| format!("QMP write: {e}"))?;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
                return Err("QMP closed".into());
            }
            let value: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
            if value.get("return").is_some() || value.get("error").is_some() {
                return Ok(value);
            }
        }
    };
    reply("{\"execute\":\"qmp_capabilities\"}\n")?;
    let request = json!({"execute": "screendump",
                         "arguments": {"filename": path, "format": "png"}});
    let result = reply(&format!("{request}\n"))?;
    if let Some(error) = result.get("error") {
        return Err(format!("screendump: {error}"));
    }
    Ok(path.to_string())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
