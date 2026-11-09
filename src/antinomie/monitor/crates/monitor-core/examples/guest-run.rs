// SPDX-License-Identifier: GPL-3.0-only
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
//! `"create_timeout"` (seconds, default 900) bounds the creation of a VM with
//! an account (an arm64 Debian VM's includes its provisioning boot).
//!
//! `"headless": false` starts the VM with its default in-app screen (QEMU's
//! VNC display on a private unix socket; no host display is needed), and
//! `"screen_check": true` then reads it as the app does, after the uploads:
//! RFB handshake and framebuffer updates until one shows a drawn pixel
//! (within `boot_timeout`). The report's `screen` gives its size and timing.
//!
//! `"vm": {"nat": true}` gives the VM NAT networking.
//! `"vm": {"isolated_network": true}` uses restricted networking without
//! outbound forwarding and overrides NAT, as in the application.
//! `"vm": {"routed": true}` wires the VM's card to Antinomie's own gateway
//! (Routed network: its DHCP gives the lease; runs keep the default route).
//! `"vm": {"stealth": "desktop"}` (or `"laptop"`, `"server"`, or a whole
//! stealth profile object) launches the VM with a realistic hardware identity;
//! `"laptop:dell-latitude-5420"` copies that catalog machine.
//! `"network_capture": true` (NAT VMs) starts a network capture before the
//! runs and stops it after them; `"keep"` leaves it running for the VM stop
//! to end. The report then lists the VM's network captures.
//! `"vm": {"transport": {"ring_kib": 4096, "lossless": true, "max_wait_ms": 100,
//! "event_table": 16384, "capture_all_shed": true}}` sets the VM's transport
//! settings (any subset).
//!
//! A run may set `"core_dump_on_exit"`, `"memory_dump_on_exit"`, and
//! `"capture_network"` (each boolean).
//! `"analysis": {"enabled": true, "checks": ["metadata", "strings"]}`
//! retains the exact executable specimen and runs the selected static checks.
//! `"allow_incomplete": true` keeps diagnostic results after a run completion
//! deadline. The report records the error; it never treats that run as complete.
//!
//! With `ANTINOMIE_FORCE_TCG` set in the environment the VM runs without
//! KVM (slow, but enough for a small recorded run on a host without it).
//!
//! The report carries the Summary resource feed's last guest reading
//! (`guest_resources`: memory and root filesystem) taken before the VM stops.
//!
//! `"capture_all": true` starts Capture All once the guest is up, before the
//! runs, and stops it after them; the report then includes its summary.
//!
//! A run may also set `"run_in": "guest_desktop"` (or
//! `"guest_desktop_terminal"`), `"screenshot": PATH` to save the screen
//! `"screenshot_after"` seconds (default 10) after its `done` marker, and
//! `"stop": true` to stop its process tree after that.
//!
//! `"host_copy": true` gives a run the upload whose destination is its path as
//! the host's copy of the program (as the app does for a file it uploaded),
//! which replaces the guest transfer once the guest vouches for its hash.
//! `"expect_refused": true` expects the guest to refuse the launch: the
//! report keeps the error and the saved run (`run.json`) instead of failing.
//! `"no_evidence_wait": true` takes the run as it is once its tree exited,
//! without waiting for its analysis. With `"saved_analysis_wait"` (seconds) at
//! the plan's top level, the report adds each run's analysis as saved in its
//! `run.json` after the VM stopped (`saved_analysis`), waiting that long for
//! it to settle: an analysis that needs the guest ends with the VM.
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, ExecRequest, GuestCredentials, Notification,
    RunArtifactState, RunArtifacts, RunIn, Snapshot, VmConfig, VmState,
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
    fn finish_run_evidence(&mut self, run_id: &str) -> Result<Option<RunArtifacts>, String> {
        use antinomie_monitor_core::analysis::AnalysisState;
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            self.pump();
            let run = self
                .snapshot
                .runs
                .iter()
                .find(|run| run.id == run_id)
                .ok_or("run disappeared before evidence completion")?;
            let artifacts = read_artifacts(&run.directory)?;
            let analysis_pending = run.request.analysis.enabled
                && run.analysis.as_ref().is_none_or(|report| {
                    matches!(
                        report.state,
                        AnalysisState::Acquiring | AnalysisState::Queued | AnalysisState::Running
                    )
                });
            let artifacts_pending = artifacts.as_ref().is_none_or(|artifacts| {
                [
                    artifacts.network_state,
                    artifacts.memory_state,
                    artifacts.core_state,
                ]
                .into_iter()
                .any(artifact_pending)
            });
            if !analysis_pending && !artifacts_pending {
                return Ok(artifacts);
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "run {run_id} evidence completion deadline; analysis pending={analysis_pending}, artifacts={artifacts:?}"
                ));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

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
        self.result(id, seconds).map_err(|late| {
            late.unwrap_or_else(|| {
                format!("command {id} deadline; state {:?}", self.snapshot.state)
            })
        })
    }

    /// Waits for command `id`'s result; `Err(None)` when it is not in yet.
    fn result(&mut self, id: u64, seconds: u64) -> Result<String, Option<String>> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            if let Some((_, success, message)) = self.pump().filter(|(reply, ..)| *reply == id) {
                return if success {
                    Ok(message)
                } else {
                    Err(Some(message))
                };
            }
            if Instant::now() > deadline {
                return Err(None);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Retries a guest command until the guest's kernel control accepts it.
    /// A command still unanswered is waited for, not sent again: the backend
    /// is still working on it, and a second Execute would launch the program
    /// twice.
    fn guest_command(
        &mut self,
        make: impl Fn() -> Command,
        seconds: u64,
    ) -> Result<String, String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            let id = self.backend.send(make())?;
            let mut outcome = self.result(id, 60);
            while outcome == Err(None) && Instant::now() < deadline {
                eprintln!("guest command {id} still unanswered; waiting");
                outcome = self.result(id, 60);
            }
            let outcome = outcome.map_err(|late| {
                late.unwrap_or_else(|| {
                    format!("command {id} deadline; state {:?}", self.snapshot.state)
                })
            });
            match outcome {
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
            // A program that printed nothing (one that exits at once) has
            // its tree's exit as its only end.
            if exited {
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

fn artifact_pending(state: RunArtifactState) -> bool {
    matches!(
        state,
        RunArtifactState::WaitingForTreeExit
            | RunArtifactState::WaitingForRootExit
            | RunArtifactState::Recording
            | RunArtifactState::Queued
            | RunArtifactState::InProgress
    )
}

/// A progress sidecar can be atomically replaced between stat and open. Retry
/// that exact race a bounded number of times, retaining archive validation on
/// every attempt. Other read errors fail immediately.
fn read_artifacts(directory: &std::path::Path) -> Result<Option<RunArtifacts>, String> {
    for attempt in 0..4 {
        match RunArtifacts::load(directory) {
            Err(error)
                if attempt < 3 && error == "run artifacts: archive member changed during open" =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
    Err("artifact read retry exhausted".into())
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
        force_tcg: std::env::var_os("ANTINOMIE_FORCE_TCG").is_some(),
        ..BackendOptions::default()
    };
    if let Some(data_dir) = text(&plan, "data_dir") {
        options.data_dir = PathBuf::from(data_dir);
    }
    // "quota_mib": recording quota of each boot (default 4 GiB).
    if let Some(quota) = plan.get("quota_mib").and_then(Value::as_u64) {
        options.capture_quota_size = quota * 1024 * 1024;
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
                isolated_network: vm_spec
                    .get("isolated_network")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                routed: vm_spec
                    .get("routed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                transport: vm_spec
                    .get("transport")
                    .map(|value| serde_json::from_value(value.clone()))
                    .transpose()
                    .map_err(|e| format!("plan.vm.transport: {e}"))?
                    .unwrap_or_default(),
                stealth: stealth_profile(&vm_spec)?,
                ..VmConfig::default()
            };
            match (text(&vm_spec, "username"), text(&vm_spec, "password")) {
                (Some(username), Some(password)) => session.command(
                    Command::CreateWithCredentials {
                        vm: config,
                        credentials: GuestCredentials::new(username, password)?,
                    },
                    number(&plan, "create_timeout", 900),
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
    let mut uploaded = BTreeMap::new();
    for upload in plan
        .get("uploads")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let source = text(&upload, "source").ok_or("upload.source")?;
        let destination = text(&upload, "destination").ok_or("upload.destination")?;
        uploaded.insert(destination.clone(), PathBuf::from(&source));
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
    let keep_network_capture = plan.get("network_capture") == Some(&json!("keep"));
    let network_capture = keep_network_capture
        || plan
            .get("network_capture")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    if network_capture {
        session.command(Command::StartNetworkCapture, 30)?;
    }
    let boot_seconds = started.elapsed().as_secs_f64();
    let screen = if plan
        .get("screen_check")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        Some(screen_check(&mut session, boot)?)
    } else {
        None
    };

    let mut runs = Vec::new();
    let mut saved_runs = Vec::new();
    for spec in plan
        .get("runs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let known: Vec<_> = session.snapshot.runs.iter().map(|r| r.id.clone()).collect();
        let request = ExecRequest {
            path: text(&spec, "path").ok_or("run.path")?,
            analysis: spec
                .get("analysis")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|e| format!("run.analysis: {e}"))?
                .unwrap_or_default(),
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
            capture_network: spec
                .get("capture_network")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            memory_dump_on_exit: spec
                .get("memory_dump_on_exit")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            core_dump_on_exit: spec
                .get("core_dump_on_exit")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            debug_on_start: spec
                .get("debug_on_start")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            ..ExecRequest::default()
        };
        let flag = |key: &str| spec.get(key).and_then(Value::as_bool).unwrap_or(false);
        let mut request = request;
        if flag("host_copy") {
            request.host_copy = uploaded.get(&request.path).cloned();
        }
        let launched = Instant::now();
        if flag("expect_refused") {
            // The refusal comes back as the command's error, naming the run.
            let id = session.backend.send(Command::Execute(request.clone()))?;
            let error = match session.result(id, boot) {
                Ok(message) => return Err(format!("launch was not refused: {message}")),
                Err(error) => error.unwrap_or_else(|| "refusal not answered".into()),
            };
            let directory = refused_run_directory(&session.snapshot, &vm_id, &error);
            saved_runs.extend(directory.clone());
            runs.push(json!({"refused": error, "directory": directory,
                "seconds": launched.elapsed().as_secs_f64()}));
            continue;
        }
        session.guest_command(|| Command::Execute(request.clone()), boot)?;
        session.settle(|s| s.runs.iter().any(|r| !known.contains(&r.id)), 30)?;
        if request.debug_on_start {
            thread::sleep(Duration::from_secs(3));
            session.command(Command::DebugDetach { kill: false }, 30)?;
        }
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
        let completion = session.settle(
            |s| {
                s.runs.iter().any(|r| {
                    r.id == id
                        && r.execution
                            .as_ref()
                            .is_some_and(|e| e.flags & 2 != 0 && e.pending_async_count == 0)
                })
            },
            30,
        );
        if let Err(error) = &completion
            && !plan
                .get("allow_incomplete")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            return Err(format!(
                "{error}; last error {:?}; health {:?}",
                session.snapshot.last_error, session.snapshot.health
            ));
        }
        let artifacts = if completion.is_ok() && !flag("no_evidence_wait") {
            session.finish_run_evidence(&run_id)?
        } else {
            let run = session
                .snapshot
                .runs
                .iter()
                .find(|run| run.id == run_id)
                .ok_or("diagnostic run missing")?;
            read_artifacts(&run.directory)?
        };
        let summary = session
            .snapshot
            .runs
            .iter()
            .find(|r| r.id == run_id)
            .cloned();
        saved_runs.extend(summary.as_ref().map(|r| r.directory.clone()));
        runs.push(json!({
            "run_id": run_id,
            "directory": summary.as_ref().map(|r| r.directory.clone()),
            "execution": summary.as_ref().and_then(|r| r.execution.clone()),
            "state": summary.as_ref().map(|r| r.state.clone()),
            "notes": summary.as_ref().map(|r| &r.notes),
            "recording_error": summary.as_ref().and_then(|r| r.recording_error.as_ref()),
            "completion_error": completion.err(),
            "last_error": session.snapshot.last_error,
            "artifacts": artifacts,
            "analysis": summary.as_ref().and_then(|r| r.analysis.clone()),
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
    // A capture the recording quota already ended needs no stop.
    if network_capture && !keep_network_capture && session.snapshot.network_capture.is_some() {
        session.command(Command::StopNetworkCapture, 60)?;
    }
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
    session.settle(|snapshot| snapshot.memory_dump.is_none(), 180)?;
    let recorder = session.command(Command::RecorderStats, 120)?;
    let health = session.snapshot.health.clone();
    // The Summary resource feed's last guest reading (memory, root disk).
    let guest_resources = session
        .snapshot
        .vm_resources
        .as_ref()
        .and_then(|resources| resources.guest.as_ref())
        .map(|guest| format!("{guest:?}"));
    // Stopping waits for queued recording writes, which a long never-drop
    // run can leave in the hundreds of megabytes.
    session.command(Command::Stop, 600)?;
    session.settle(|s| s.state == VmState::Stopped, 60)?;
    // A stopped capture's final summary (its end and size) is a queued
    // background write: on a busy disk the folder still holds the summary
    // from its start for a while.
    let recordings = session
        .snapshot
        .vm_locations
        .iter()
        .find(|location| location.vm_id == vm_id)
        .map(|location| location.recording_directory.clone());
    let network_captures = match recordings.filter(|_| network_capture) {
        Some(recordings) => {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let captures = antinomie_monitor_core::network::list_captures(&recordings);
                if captures.iter().all(|capture| capture.stopped_ms.is_some())
                    || Instant::now() > deadline
                {
                    break Some(captures);
                }
                thread::sleep(Duration::from_millis(200));
            }
        }
        None => None,
    };
    let saved_analysis = plan
        .get("saved_analysis_wait")
        .and_then(Value::as_u64)
        .map(|seconds| saved_analyses(&mut session, &saved_runs, seconds));
    session.backend.shutdown()?;
    Ok(
        json!({"vm_id": vm_id, "base": base, "boot_seconds": boot_seconds,
              "saved_analysis": saved_analysis,
              "runs": runs, "recorder": recorder, "health": health,
              "guest_resources": guest_resources, "capture": capture,
              "network_captures": network_captures, "screenshot": screenshot,
              "screen": screen}),
    )
}

/// The folder of the run the guest refused: the error names its id.
fn refused_run_directory(snapshot: &Snapshot, vm_id: &str, error: &str) -> Option<PathBuf> {
    let recordings = snapshot
        .vm_locations
        .iter()
        .find(|location| location.vm_id == vm_id)?
        .recording_directory
        .join("runs");
    std::fs::read_dir(&recordings)
        .ok()?
        .filter_map(Result::ok)
        .find(|entry| error.contains(entry.file_name().to_string_lossy().as_ref()))
        .map(|entry| entry.path())
}

/// Each run's analysis as its saved `run.json` has it, once it settled or
/// after `seconds`: what a run keeps when the VM is gone.
fn saved_analyses(session: &mut Session, directories: &[PathBuf], seconds: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let read = |directory: &PathBuf| -> Value {
        std::fs::read(directory.join("run.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .map_or(Value::Null, |run| run["analysis"].clone())
    };
    loop {
        session.pump();
        let reports: Vec<Value> = directories.iter().map(read).collect();
        let settled = reports.iter().all(|report| {
            !matches!(
                report["state"].as_str(),
                Some("acquiring" | "queued" | "running")
            )
        });
        if settled || Instant::now() > deadline {
            return json!(
                directories
                    .iter()
                    .zip(reports)
                    .map(|(directory, report)| json!({"directory": directory, "analysis": report}))
                    .collect::<Vec<_>>()
            );
        }
        thread::sleep(Duration::from_millis(500));
    }
}

/// The in-app screen, as the app's VM screen tab reads it: the VNC client
/// connects to the VM's private `vnc.sock`, does the RFB handshake and takes
/// framebuffer updates until one has a pixel that is not black (the firmware
/// or the kernel console drew it). Needs a VM started without `headless`.
fn screen_check(session: &mut Session, seconds: u64) -> Result<Value, String> {
    use antinomie_monitor_core::vnc::ScreenClient;
    session
        .settle(|snapshot| snapshot.vm_screen.is_some(), 30)
        .map_err(|_| "the VM has no in-app screen socket (\"headless\": false?)")?;
    let socket = session
        .snapshot
        .vm_screen
        .clone()
        .ok_or("no screen socket")?;
    let started = Instant::now();
    let client = ScreenClient::start(socket.clone(), std::sync::Arc::new(|| {}));
    let deadline = started + Duration::from_secs(seconds);
    let mut first = None;
    loop {
        session.pump();
        if let Some((width, height, rgba)) = client.frame() {
            let first_seconds = *first.get_or_insert_with(|| started.elapsed().as_secs_f64());
            let lit = rgba
                .as_chunks::<4>()
                .0
                .iter()
                .filter(|pixel| pixel[..3] != [0, 0, 0])
                .count();
            if lit > 0 {
                let report = json!({"socket": socket, "name": client.name(),
                    "width": width, "height": height, "lit_pixels": lit,
                    "first_frame_seconds": first_seconds,
                    "lit_frame_seconds": started.elapsed().as_secs_f64()});
                eprintln!("screen: {report}");
                return Ok(report);
            }
        }
        if Instant::now() > deadline {
            return Err(format!(
                "screen check: no drawn frame on {} in {seconds} s (status {:?}, first frame after {first:?} s)",
                socket.display(),
                client.status()
            ));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Find the exact QMP endpoint of the QEMU process owning this serial log.
/// Long recording paths cause the app to place its socket in a short private dir.
fn owned_qmp(serial: &std::path::Path) -> Result<PathBuf, String> {
    let mut found = None;
    for entry in std::fs::read_dir("/proc").map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if std::fs::read_link(entry.path().join("fd/1"))
            .ok()
            .as_deref()
            != Some(serial)
        {
            continue;
        }
        let command =
            std::fs::read(entry.path().join("cmdline")).map_err(|error| error.to_string())?;
        if command.len() > 64 * 1024 {
            return Err("test-owned QEMU command exceeds bound".into());
        }
        let arguments: Vec<_> = command.split(|&byte| byte == 0).collect();
        if let Some(pair) = arguments.windows(2).find(|pair| pair[0] == b"-qmp") {
            let socket = qmp_option(pair[1])?;
            if found.replace(socket).is_some() {
                return Err("multiple QEMU owners for test serial log".into());
            }
        }
    }
    found.ok_or_else(|| "test-owned QEMU QMP socket not found".into())
}

fn qmp_option(argument: &[u8]) -> Result<PathBuf, String> {
    let argument = std::str::from_utf8(argument).map_err(|error| error.to_string())?;
    let socket = argument
        .strip_prefix("unix:")
        .and_then(|argument| argument.strip_suffix(",server=on,wait=off"))
        .filter(|socket| !socket.is_empty())
        .ok_or("unexpected test-owned QMP option")?;
    Ok(PathBuf::from(socket.replace(",,", ",")))
}

/// Save the VM screen through its exact owned QMP endpoint.
fn screendump(snapshot: &Snapshot, path: &str) -> Result<String, String> {
    use std::io::{BufRead, BufReader, Write};
    let socket = owned_qmp(
        snapshot
            .serial_log
            .as_deref()
            .ok_or("no VM serial log for the screenshot")?,
    )?;
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
    // Static analysis invokes this same executable inside its isolated worker.
    if let Some(code) = antinomie_monitor_core::analysis::worker_main_if_requested() {
        std::process::exit(code);
    }
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

/// The VM's stealth profile from `plan.vm.stealth`: a preset name or a profile.
fn stealth_profile(
    vm_spec: &Value,
) -> Result<antinomie_monitor_core::stealth::StealthProfile, String> {
    use antinomie_monitor_core::stealth::{HostCpu, MACHINES, StealthPreset, StealthProfile};
    Ok(match vm_spec.get("stealth") {
        None => StealthProfile::default(),
        Some(Value::String(spec)) => {
            // "laptop:dell-latitude-5420" pins the machine the preset copies.
            let (kind, machine) = spec.split_once(':').unwrap_or((spec, ""));
            let preset = match kind {
                "desktop" => StealthPreset::RealisticDesktop,
                "laptop" => StealthPreset::RealisticLaptop,
                "server" => StealthPreset::RealisticServer,
                "transparent" => StealthPreset::Transparent,
                other => return Err(format!("plan.vm.stealth: unknown preset {other}")),
            };
            let mut profile = StealthProfile::default().for_preset_on(preset, &HostCpu::detect());
            if !machine.is_empty() {
                let machine = MACHINES
                    .iter()
                    .find(|known| known.id == machine)
                    .ok_or_else(|| format!("plan.vm.stealth: unknown machine {machine}"))?;
                profile.use_machine(machine);
            }
            profile
        }
        Some(value) => {
            serde_json::from_value(value.clone()).map_err(|e| format!("plan.vm.stealth: {e}"))?
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_wait_includes_queued_transfers_and_accepts_explicit_partial_results() {
        for state in [
            RunArtifactState::WaitingForRootExit,
            RunArtifactState::WaitingForTreeExit,
            RunArtifactState::Recording,
            RunArtifactState::Queued,
            RunArtifactState::InProgress,
        ] {
            assert!(artifact_pending(state));
        }
        for state in [
            RunArtifactState::Disabled,
            RunArtifactState::Complete,
            RunArtifactState::Partial,
            RunArtifactState::Failed,
            RunArtifactState::Interrupted,
        ] {
            assert!(!artifact_pending(state));
        }
    }
    #[test]
    fn screenshot_uses_exact_owned_qmp_options_including_escaped_commas() {
        assert_eq!(
            qmp_option(b"unix:/tmp/ant-owned/qmp.sock,server=on,wait=off").unwrap(),
            PathBuf::from("/tmp/ant-owned/qmp.sock")
        );
        assert_eq!(
            qmp_option(b"unix:/tmp/ant,,owned/qmp.sock,server=on,wait=off").unwrap(),
            PathBuf::from("/tmp/ant,owned/qmp.sock")
        );
        for invalid in [
            b"tcp:localhost:1".as_slice(),
            b"unix:,server=on,wait=off",
            b"unix:/tmp/q,server=on",
            &[0xff],
        ] {
            assert!(qmp_option(invalid).is_err());
        }
    }
}
