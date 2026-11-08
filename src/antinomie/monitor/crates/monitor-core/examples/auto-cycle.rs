// SPDX-License-Identifier: GPL-3.0-only
//! Throw-away spike for the headless/Auto design (card P0-1): one full
//! unattended cycle over the existing `Backend`, timed stage by stage, with
//! the `Command` / `Notification` trace saved as JSON lines for a later
//! `FakeEngine`.
//!
//! usage:
//!   auto-cycle run --bundle DIR --data DIR --out DIR --case NAME
//!       [--strategy reset|snapshot_disk|snapshot_full] [--workload few|many|hang|none]
//!       [--cycles N] [--ram MIB] [--disk GIB] [--user-run] [--no-route] [--keep]
//!       [--run-limit SECONDS] [--desktop] [--probe-analysis]
//!   auto-cycle compat --data DIR
//!       tries to resume the VM's Full snapshot with a non-headless host
//!       (the E16 question); the refusal comes before any window opens.
//!
//! Each cycle: provision (revert and start), upload a benign script from the
//! sample library, launch it on the Drop route, run under a time limit,
//! collect (stop, flush, wait for the run layer) and report. `--keep` keeps
//! the data directory. Benign programs only.
//!
//! `<out>/<case>.trace.jsonl` is the fixture a fake engine replays: one JSON
//! object per line with `t` (seconds since the engine started) and `dir`:
//! `command` (`id`, `name`, `detail`), `note` (a `Notification`: `kind` is
//! `snapshot` with a `digest` that is written only when it changes,
//! `command_result`, `run_started`, `analysis_updated`, `terminal`,
//! `terminal_screen`, or `run_layer_file` with `present`, which is the layer
//! marker `run-layer.json` seen on disk) or `meta` (stage marks of this
//! driver). `<case>.summary.json` has the per-stage seconds of every cycle.
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, ExecRequest, GuestCredentials, Notification,
    RunArtifactState, RunArtifacts, RunIn, Snapshot, SnapshotRequest, VmConfig, VmSnapshotMode,
    VmState,
    route::RouteKind,
    samples::{Library, NewSample, SampleRef},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

struct Lab {
    backend: Backend,
    snapshot: Snapshot,
    terminals: BTreeMap<String, Vec<u8>>,
    results: BTreeMap<u64, (bool, String, f64)>,
    started: Instant,
    trace: File,
    digest: String,
    layer_file: Option<PathBuf>,
    layer_seen: Option<bool>,
}

fn clip(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

impl Lab {
    fn now(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    fn log(&mut self, value: Value) {
        let mut value = value;
        value["t"] = json!((self.now() * 1000.0).round() / 1000.0);
        let _ = writeln!(self.trace, "{value}");
    }

    fn snapshot_digest(&self) -> Value {
        let s = &self.snapshot;
        json!({
            "state": format!("{:?}", s.state),
            "active_vm": s.active_vm,
            "boot_id": s.boot_id,
            "guest_kernel": s.guest_kernel.is_some(),
            "vms": s.vms.len(),
            "bases": s.bases.len(),
            "last_error": s.last_error,
            "snapshot_progress": s.vm_snapshot_progress.as_ref().map(|p| p.stage.clone()),
            "recording_flush": s.recording_flush.as_ref().map(|f| json!({
                "done": f.done_count, "total": f.total_count,
                "current": clip(&f.current, 80), "errors": f.errors.len()})),
            "runs": s.runs.iter().map(|r| json!({
                "id": r.id, "state": format!("{:?}", r.state),
                "live_tasks": r.execution.as_ref().map(|e| e.live_task_count),
                "pending_async": r.execution.as_ref().map(|e| e.pending_async_count),
                "flags": r.execution.as_ref().map(|e| e.flags),
                "terminal_eof": r.terminal_eof,
                "recording_error": r.recording_error,
            })).collect::<Vec<_>>(),
            "analysis_reports": s.analysis_reports.len(),
            "snapshot_nodes": s.vm_snapshot_trees.iter()
                .map(|(vm, tree)| (vm.clone(), tree.nodes.len())).collect::<BTreeMap<_, _>>(),
        })
    }

    fn pump(&mut self) {
        while let Some(notification) = self.backend.try_recv() {
            match notification {
                Notification::Snapshot(snapshot) => {
                    self.snapshot = snapshot;
                    let digest = self.snapshot_digest();
                    let text = digest.to_string();
                    if text != self.digest {
                        self.digest = text;
                        self.log(json!({"dir": "note", "kind": "snapshot", "digest": digest}));
                    }
                }
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    self.log(json!({"dir": "note", "kind": "command_result", "id": id,
                        "success": success, "message": clip(&message, 400)}));
                    let t = self.now();
                    self.results.insert(id, (success, message, t));
                }
                Notification::RunStarted(run) => {
                    self.log(json!({"dir": "note", "kind": "run_started", "run": run.id,
                        "state": format!("{:?}", run.state), "path": run.request.path}));
                }
                Notification::AnalysisUpdated { run_id, report } => {
                    self.log(
                        json!({"dir": "note", "kind": "analysis_updated", "run": run_id,
                        "state": format!("{:?}", report.state)}),
                    );
                }
                Notification::Terminal {
                    run_id,
                    sequence,
                    data,
                    eof,
                } => {
                    self.log(json!({"dir": "note", "kind": "terminal", "run": run_id,
                        "sequence": sequence, "len": data.len(), "eof": eof,
                        "text": clip(&String::from_utf8_lossy(&data), 160)}));
                    self.terminals.entry(run_id).or_default().extend(data);
                }
                Notification::TerminalScreen {
                    run_id,
                    sequence,
                    data,
                    ..
                } => self.log(json!({"dir": "note", "kind": "terminal_screen",
                    "run": run_id, "sequence": sequence, "len": data.len()})),
            }
        }
        // The run layer is a file in the VM folder, not part of any Notification.
        if let Some(path) = self.layer_file.clone() {
            let present = path.exists();
            if self.layer_seen != Some(present) {
                self.layer_seen = Some(present);
                self.log(json!({"dir": "note", "kind": "run_layer_file", "present": present}));
            }
        }
    }

    fn send(&mut self, command: Command) -> Result<u64, String> {
        let name = format!("{command:?}");
        let name = name.split(['(', ' ', '{']).next().unwrap_or("").to_owned();
        let detail = match &command {
            Command::Create(_) | Command::CreateWithCredentials { .. } => String::new(),
            other => clip(&format!("{other:?}"), 300),
        };
        let id = self.backend.send(command)?;
        self.log(json!({"dir": "command", "id": id, "name": name, "detail": detail}));
        Ok(id)
    }

    /// Sends a command and waits for its result; the second value is the
    /// seconds from the send to the result.
    fn command(&mut self, command: Command, seconds: u64) -> Result<(String, f64), String> {
        let begun = Instant::now();
        let id = self.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.pump();
            if let Some((success, message, _)) = self.results.remove(&id) {
                let took = begun.elapsed().as_secs_f64();
                return if success {
                    Ok((message, took))
                } else {
                    Err(message)
                };
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

    /// Retries a guest command until the guest accepts it; returns seconds.
    fn guest_command(
        &mut self,
        make: impl Fn() -> Command,
        seconds: u64,
    ) -> Result<(String, f64, u32), String> {
        let begun = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut tries = 0;
        loop {
            tries += 1;
            match self.command(make(), 60) {
                Ok((message, _)) => return Ok((message, begun.elapsed().as_secs_f64(), tries)),
                Err(error) if Instant::now() < deadline => {
                    eprintln!("guest not ready yet: {}", clip(&error, 120));
                    thread::sleep(Duration::from_secs(1));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn settle(&mut self, until: impl Fn(&Snapshot) -> bool, seconds: u64) -> Result<f64, String> {
        let begun = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.pump();
            if until(&self.snapshot) {
                return Ok(begun.elapsed().as_secs_f64());
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "snapshot condition deadline; state {:?}, error {:?}",
                    self.snapshot.state, self.snapshot.last_error
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn artifact_pending(state: RunArtifactState) -> bool {
    state.in_progress()
}

fn artifacts_pending(directory: &Path) -> bool {
    match RunArtifacts::load(directory) {
        Ok(Some(a)) => [a.network_state, a.memory_state, a.core_state]
            .into_iter()
            .any(artifact_pending),
        _ => false,
    }
}

fn workload(name: &str) -> String {
    let body = match name {
        // Writes three new files: the run changes few blocks.
        "few" => "for i in 1 2 3; do echo run$i > /tmp/cycle-$i.txt; done\necho work-done",
        // Overwrites 4 KiB of up to 3000 existing data files under /usr/share
        // (root only), so the earlier-bytes copy has real work to do.
        "many" => {
            "n=0\nfor f in $(find /usr/share -type f -size +4k 2>/dev/null | head -3000); do\n  dd if=/dev/zero of=\"$f\" bs=4096 count=1 conv=notrunc 2>/dev/null && n=$((n+1))\ndone\nsync\necho overwrote=$n\necho work-done"
        }
        // Never ends by itself: the run limit has to stop it.
        "hang" => "echo work-started\nsleep 600",
        _ => "echo work-done",
    };
    format!("#!/bin/sh\necho CYCLE-START\n{body}\necho CYCLE-END\n")
}

struct Config {
    bundle: PathBuf,
    data: PathBuf,
    out: PathBuf,
    case: String,
    strategy: String,
    workload: String,
    cycles: u32,
    ram: u32,
    disk: u32,
    root: bool,
    route: bool,
    keep: bool,
    limit: u64,
    desktop: bool,
    probe_analysis: bool,
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn parse(args: &[String]) -> Result<Config, String> {
    let need = |name: &str| arg_value(args, name).ok_or(format!("{name} is required"));
    let workload = arg_value(args, "--workload").unwrap_or_else(|| "few".into());
    Ok(Config {
        bundle: need("--bundle")?.into(),
        data: need("--data")?.into(),
        out: need("--out")?.into(),
        case: need("--case")?,
        strategy: arg_value(args, "--strategy").unwrap_or_else(|| "snapshot_disk".into()),
        cycles: arg_value(args, "--cycles")
            .map_or(Ok(1), |v| v.parse().map_err(|e| format!("{e}")))?,
        ram: arg_value(args, "--ram")
            .map_or(Ok(1024), |v| v.parse().map_err(|e| format!("{e}")))?,
        disk: arg_value(args, "--disk").map_or(Ok(4), |v| v.parse().map_err(|e| format!("{e}")))?,
        // "many" needs root to overwrite system data files.
        root: workload == "many" && !args.iter().any(|a| a == "--user-run"),
        route: !args.iter().any(|a| a == "--no-route"),
        keep: args.iter().any(|a| a == "--keep"),
        limit: arg_value(args, "--run-limit")
            .map_or(Ok(120), |v| v.parse().map_err(|e| format!("{e}")))?,
        desktop: args.iter().any(|a| a == "--desktop"),
        probe_analysis: args.iter().any(|a| a == "--probe-analysis"),
        workload,
    })
}

fn dir_stats(path: &Path) -> (u64, u64) {
    let (mut bytes, mut files) = (0, 0);
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                let (b, f) = dir_stats(&entry.path());
                bytes += b;
                files += f;
            } else {
                // Allocated, not apparent, size.
                use std::os::unix::fs::MetadataExt;
                bytes += meta.blocks() * 512;
                files += 1;
            }
        }
    }
    (bytes, files)
}

fn qcow_files(path: &Path) -> usize {
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "qcow2"))
                .count()
        })
        .unwrap_or(0)
}

/// Layers behind the newest qcow2 file under `snapshots/`, by
/// `qemu-img info --backing-chain`; None when there is none or it cannot be read.
fn chain_depth(snapshots: &Path) -> Option<usize> {
    let newest = std::fs::read_dir(snapshots)
        .ok()?
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "qcow2"))
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())?
        .path();
    let output = std::process::Command::new("qemu-img")
        .args(["info", "--backing-chain", "--force-share", "--output=json"])
        .arg(&newest)
        .output()
        .ok()?;
    let chain: Value = serde_json::from_slice(&output.stdout).ok()?;
    chain.as_array().map(Vec::len)
}

#[allow(clippy::too_many_lines)]
fn run_case(config: &Config) -> Result<Value, String> {
    std::fs::create_dir_all(&config.out).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&config.data).map_err(|e| e.to_string())?;
    let trace = File::create(config.out.join(format!("{}.trace.jsonl", config.case)))
        .map_err(|e| e.to_string())?;
    let options = BackendOptions {
        data_dir: config.data.clone(),
        headless: true,
        force_tcg: std::env::var_os("ANTINOMIE_FORCE_TCG").is_some(),
        ..BackendOptions::default()
    };
    let mut lab = Lab {
        backend: Backend::new(options)?,
        snapshot: Snapshot::default(),
        terminals: BTreeMap::new(),
        results: BTreeMap::new(),
        started: Instant::now(),
        trace,
        digest: String::new(),
        layer_file: None,
        layer_seen: None,
    };
    lab.log(
        json!({"dir": "meta", "case": config.case, "strategy": config.strategy,
        "workload": config.workload, "cycles": config.cycles}),
    );
    lab.settle(|_| true, 1)?;
    thread::sleep(Duration::from_millis(500));
    lab.pump();

    // One-time setup: import, create, library.
    let mut setup = BTreeMap::new();
    let before = lab.snapshot.bases.len();
    let (_, took) = lab.command(
        Command::ImportBase {
            directory: config.bundle.clone(),
        },
        600,
    )?;
    setup.insert("import_base_s", took);
    lab.settle(|s| s.bases.len() > before, 30)?;
    let base = lab.snapshot.bases.last().map(|b| b.id.clone());
    let vm_config = VmConfig {
        name: "auto-cycle".into(),
        cpus: 2,
        ram_mib: config.ram,
        disk_gib: config.disk,
        base_identity: base,
        routed: config.route,
        ..VmConfig::default()
    };
    let vms_before = lab.snapshot.vms.len();
    let needs_credentials = std::fs::read(config.bundle.join("bundle.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|v| v["guest"]["requires_credentials"].as_bool())
        .unwrap_or(false);
    let create = if needs_credentials {
        Command::CreateWithCredentials {
            vm: vm_config,
            credentials: GuestCredentials::new("analyst".into(), "analyst1".into())?,
        }
    } else {
        Command::Create(vm_config)
    };
    let (_, took) = lab.command(create, 900)?;
    setup.insert("create_vm_s", took);
    lab.settle(|s| s.vms.len() > vms_before, 30)?;
    let vm_id = lab
        .snapshot
        .vms
        .last()
        .map(|v| v.id.clone())
        .ok_or("VM missing")?;
    let location = lab
        .snapshot
        .vm_locations
        .iter()
        .find(|l| l.vm_id == vm_id)
        .cloned()
        .ok_or("VM location missing")?;
    lab.layer_file = Some(location.disk_directory.join("run-layer.json"));

    let script = workload(&config.workload);
    let mut library = Library::open(&config.data)?;
    let added = library.add_bytes(
        script.as_bytes(),
        NewSample {
            name: format!("{}.sh", config.workload),
            ..NewSample::default()
        },
    )?;
    let sha256 = added.sha256;
    let guest_path = format!("/tmp/{}-{}.sh", &sha256[..8], config.workload);

    // Lane preparation: make the clean state the strategy reverts to.
    let mut prep = BTreeMap::new();
    let snapshot_id = if config.strategy == "reset" {
        None
    } else {
        // Boot once to the point a clean lane would be at, then freeze.
        let begun = Instant::now();
        lab.command(
            Command::Start {
                vm_id: vm_id.clone(),
            },
            900,
        )?;
        lab.settle(
            |s| s.state == VmState::Running && s.guest_kernel.is_some(),
            300,
        )?;
        prep.insert("first_boot_s", begun.elapsed().as_secs_f64());
        let full = config.strategy == "snapshot_full";
        if !full {
            lab.command(Command::Stop, 600)?;
            lab.settle(|s| s.state == VmState::Stopped, 120)?;
            lab.settle(|s| s.recording_flush.is_none(), 600)?;
            let begun = Instant::now();
            while lab.layer_file.as_ref().is_some_and(|p| p.exists()) {
                if begun.elapsed() > Duration::from_secs(900) {
                    return Err("first boot's layer never settled".into());
                }
                lab.pump();
                thread::sleep(Duration::from_millis(100));
            }
        }
        let begun = Instant::now();
        lab.command(
            Command::CreateVmSnapshot {
                vm_id: vm_id.clone(),
                request: SnapshotRequest {
                    name: "clean".into(),
                    description: "auto-cycle lane".into(),
                    mode: if full {
                        VmSnapshotMode::Full
                    } else {
                        VmSnapshotMode::Disk
                    },
                },
            },
            600,
        )?;
        prep.insert("create_snapshot_s", begun.elapsed().as_secs_f64());
        lab.settle(
            |s| {
                s.vm_snapshot_trees
                    .get(&vm_id)
                    .is_some_and(|t| !t.nodes.is_empty())
            },
            30,
        )?;
        let id = lab.snapshot.vm_snapshot_trees[&vm_id]
            .nodes
            .iter()
            .find(|n| n.name == "clean")
            .map(|n| n.id.clone())
            .ok_or("clean snapshot missing")?;
        if full {
            lab.command(Command::Stop, 600)?;
            lab.settle(|s| s.state == VmState::Stopped, 120)?;
        }
        Some(id)
    };
    lab.log(json!({"dir": "meta", "kind": "lane_ready", "strategy": config.strategy}));

    let mut cycles = Vec::new();
    for cycle in 1..=config.cycles {
        let mut stage = BTreeMap::<&str, f64>::new();
        let cycle_begun = Instant::now();
        lab.log(json!({"dir": "meta", "kind": "cycle_begin", "cycle": cycle}));
        // provision: revert, start, ready.
        let begun = Instant::now();
        match (&snapshot_id, config.strategy.as_str()) {
            (None, _) => {
                lab.command(
                    Command::Reset {
                        vm_id: vm_id.clone(),
                        confirmed: true,
                    },
                    300,
                )?;
            }
            (Some(id), strategy) => {
                lab.command(
                    Command::RestoreVmSnapshot {
                        vm_id: vm_id.clone(),
                        snapshot_id: id.clone(),
                        boot_from_disk: strategy != "snapshot_full",
                        save_current: None,
                        confirmed: true,
                        switch_profile: false,
                    },
                    600,
                )?;
            }
        }
        stage.insert("revert_s", begun.elapsed().as_secs_f64());
        // A restore starts the VM itself (a disk restore boots it, a Full one
        // resumes it); only a reset leaves it stopped for a Start.
        let resumed = config.strategy != "reset";
        if !resumed {
            let begun = Instant::now();
            lab.command(
                Command::Start {
                    vm_id: vm_id.clone(),
                },
                900,
            )?;
            stage.insert("start_command_s", begun.elapsed().as_secs_f64());
        }
        let begun = Instant::now();
        lab.settle(|s| s.state == VmState::Running, 300)?;
        lab.settle(|s| s.guest_kernel.is_some(), 300)?;
        stage.insert("kernel_answered_s", begun.elapsed().as_secs_f64());

        // upload: the library copy, decrypted in memory only.
        let (_, took, tries) = lab.guest_command(
            || Command::UploadSample {
                sha256: sha256.clone(),
                destination: guest_path.clone(),
                executable: true,
            },
            180,
        )?;
        stage.insert("upload_s", took);
        stage.insert("upload_tries", f64::from(tries));
        // Everything up to here is the design's `provision` plus `upload`.
        stage.insert(
            "provision_upload_total_s",
            cycle_begun.elapsed().as_secs_f64(),
        );

        // launch
        let known: Vec<_> = lab.snapshot.runs.iter().map(|r| r.id.clone()).collect();
        let request = ExecRequest {
            path: guest_path.clone(),
            cwd: "/tmp".into(),
            env: vec!["PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into()],
            uid: if config.root { 0 } else { 1000 },
            gid: if config.root { 0 } else { 1000 },
            run_in: if config.desktop {
                RunIn::GuestDesktop
            } else {
                RunIn::AppTerminal
            },
            route: config.route.then_some(RouteKind::Drop),
            sample: Some(SampleRef {
                sha256: sha256.clone(),
                name: format!("{}.sh", config.workload),
            }),
            ..ExecRequest::default()
        };
        let begun = Instant::now();
        lab.guest_command(|| Command::Execute(request.clone()), 60)?;
        lab.settle(|s| s.runs.iter().any(|r| !known.contains(&r.id)), 30)?;
        stage.insert("launch_s", begun.elapsed().as_secs_f64());
        let run = lab
            .snapshot
            .runs
            .iter()
            .find(|r| !known.contains(&r.id))
            .cloned()
            .ok_or("run missing")?;

        // run: wait for the design's exit condition, draining the terminal (E17).
        let begun = Instant::now();
        let mut ended_flags = None;
        let mut ended_design = None;
        let mut limit_hit = false;
        let mut stop_sent = None;
        loop {
            let _ = lab.send(Command::TerminalRead {
                run_id: run.id.clone(),
            });
            for _ in 0..10 {
                lab.pump();
                thread::sleep(Duration::from_millis(20));
            }
            lab.results.clear();
            let Some(current) = lab.snapshot.runs.iter().find(|r| r.id == run.id) else {
                return Err("run vanished".into());
            };
            let elapsed = begun.elapsed().as_secs_f64();
            let execution = current.execution.clone();
            let state_text = format!("{:?}", current.state);
            if ended_flags.is_none() && execution.as_ref().is_some_and(|e| e.flags & 2 != 0) {
                ended_flags = Some(elapsed);
            }
            let design = matches!(
                state_text.as_str(),
                "Finished" | "Stopped" | "TerminalClosed" | "Finalized"
            ) && execution.as_ref().is_some_and(|e| e.live_task_count == 0);
            if ended_design.is_none() && design {
                ended_design = Some(elapsed);
            }
            if ended_design.is_some() {
                break;
            }
            if !limit_hit && elapsed > config.limit as f64 {
                limit_hit = true;
                stop_sent = Some(elapsed);
                let _ = lab.send(Command::StopRun {
                    run_id: run.id.clone(),
                });
            }
            if elapsed > config.limit as f64 + 120.0 {
                return Err(format!("run never ended; state {state_text}"));
            }
        }
        stage.insert("run_s", begun.elapsed().as_secs_f64());
        if let Some(t) = ended_flags {
            stage.insert("run_flags_exit_at_s", t);
        }
        if let Some(t) = ended_design {
            stage.insert("run_design_exit_at_s", t);
        }
        if let Some(t) = stop_sent {
            stage.insert("stop_run_sent_at_s", t);
        }

        // collect: artifacts, Stop, flush, layer.
        let collect_begun = Instant::now();
        let begun = Instant::now();
        let directory = run.directory.clone();
        let deadline = Instant::now() + Duration::from_secs(300);
        while artifacts_pending(&directory) {
            if Instant::now() > deadline {
                return Err("artifacts still pending".into());
            }
            lab.pump();
            thread::sleep(Duration::from_millis(100));
        }
        stage.insert("artifacts_s", begun.elapsed().as_secs_f64());
        let layer_before_stop = lab.layer_file.as_ref().is_some_and(|p| p.exists());
        let begun = Instant::now();
        lab.command(Command::Stop, 600)?;
        stage.insert("stop_command_s", begun.elapsed().as_secs_f64());
        lab.settle(|s| s.state == VmState::Stopped, 120)?;
        stage.insert("stopped_s", begun.elapsed().as_secs_f64());
        // Host-side analysis of the library copy needs no guest, but the only
        // command that analyses a file asks the running guest for it.
        let analyze_after_stop = if config.probe_analysis && cycle == 1 {
            let selection = antinomie_monitor_core::analysis::AnalysisSelection {
                enabled: true,
                ..Default::default()
            };
            Some(
                match lab.command(
                    Command::AnalyzeOnly {
                        path: guest_path.clone(),
                        uid: 1000,
                        gid: 1000,
                        analysis: selection,
                    },
                    30,
                ) {
                    Ok((message, _)) => format!("ok: {message}"),
                    Err(error) => format!("refused: {error}"),
                },
            )
        } else {
            None
        };
        lab.settle(|s| s.recording_flush.is_none(), 1800)?;
        stage.insert("flush_done_s", begun.elapsed().as_secs_f64());
        let layer_file = lab.layer_file.clone();
        let layer_at_flush = layer_file.as_ref().is_some_and(|p| p.exists());
        let layer_begun = Instant::now();
        let mut layer_settled = true;
        while layer_file.as_ref().is_some_and(|p| p.exists()) {
            if layer_begun.elapsed() > Duration::from_secs(1800) {
                layer_settled = false;
                break;
            }
            lab.pump();
            thread::sleep(Duration::from_millis(50));
        }
        stage.insert(
            "layer_wait_after_flush_s",
            layer_begun.elapsed().as_secs_f64(),
        );
        stage.insert("stop_to_layer_settled_s", begun.elapsed().as_secs_f64());
        stage.insert("collect_s", collect_begun.elapsed().as_secs_f64());
        stage.insert("cycle_s", cycle_begun.elapsed().as_secs_f64());
        lab.log(json!({"dir": "meta", "kind": "cycle_end", "cycle": cycle}));

        let final_run = lab.snapshot.runs.iter().find(|r| r.id == run.id).cloned();
        let text =
            String::from_utf8_lossy(lab.terminals.get(&run.id).map_or(&[][..], |d| d)).into_owned();
        let tree = lab.snapshot.vm_snapshot_trees.get(&vm_id);
        let (disk_bytes, disk_files) = dir_stats(&location.disk_directory);
        let snapshots_dir = location.disk_directory.join("snapshots");
        let (rec_bytes, _) = dir_stats(&location.recording_directory);
        cycles.push(json!({
            "cycle": cycle,
            // What the analyse and report stages need to find the evidence.
            "handoff": {
                "vm_id": vm_id, "boot_id": run.boot_id, "run_id": run.id,
                "run_directory": run.directory,
                "recording_directory": location.recording_directory,
                "sample_sha256": sha256,
                "digest_file_present": run.directory.join("triage-digest.json").exists(),
                "artifacts_json_present": run.directory.join("artifacts.json").exists(),
            },
            "stages": stage,
            "layer_pending_before_stop": layer_before_stop,
            "layer_pending_at_flush_done": layer_at_flush,
            "layer_settled": layer_settled,
            "run_state": final_run.as_ref().map(|r| format!("{:?}", r.state)),
            "recording_error": final_run.as_ref().and_then(|r| r.recording_error.clone()),
            "route": final_run.as_ref().and_then(|r| r.route.as_ref().map(|r| format!("{r:?}"))),
            "terminal_has_end_marker": text.contains("CYCLE-END"),
            "terminal_tail": clip(&text.chars().rev().take(200).collect::<String>().chars().rev().collect::<String>(), 200),
            "snapshot_nodes": tree.map(|t| t.nodes.len()),
            "qcow2_files_in_snapshots_dir": qcow_files(&snapshots_dir),
            "backing_chain_depth": chain_depth(&snapshots_dir),
            "analyze_only_after_stop": analyze_after_stop,
            "vm_disk_dir_bytes": disk_bytes,
            "vm_disk_dir_files": disk_files,
            "recording_dir_bytes": rec_bytes,
            "last_error": lab.snapshot.last_error,
        }));
        eprintln!(
            "cycle {cycle}: {}",
            cycles.last().map_or(String::new(), Value::to_string)
        );
        if let Some(error) = lab.snapshot.last_error.clone() {
            lab.log(json!({"dir": "meta", "kind": "last_error", "error": error}));
        }
    }
    let result = json!({
        "case": config.case, "strategy": config.strategy, "workload": config.workload,
        "route_kind": config.route.then_some("drop"), "headless": true,
        "setup": setup, "lane_prep": prep, "snapshot_id": snapshot_id, "cycles": cycles,
        "data_dir": config.data,
    });
    lab.backend.shutdown()?;
    std::fs::write(
        config.out.join(format!("{}.summary.json", config.case)),
        serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if !config.keep {
        std::fs::remove_dir_all(&config.data).map_err(|e| e.to_string())?;
    }
    Ok(result)
}

/// E16: a Full snapshot taken by a headless host, resumed by a host that is
/// not headless. The compatibility check refuses before any window opens.
fn compat(data: PathBuf) -> Result<Value, String> {
    let dir = std::env::temp_dir().join("auto-cycle-compat.jsonl");
    let options = BackendOptions {
        data_dir: data,
        headless: false,
        ..BackendOptions::default()
    };
    let mut lab = Lab {
        backend: Backend::new(options)?,
        snapshot: Snapshot::default(),
        terminals: BTreeMap::new(),
        results: BTreeMap::new(),
        started: Instant::now(),
        trace: File::create(dir).map_err(|e| e.to_string())?,
        digest: String::new(),
        layer_file: None,
        layer_seen: None,
    };
    lab.settle(|s| !s.vms.is_empty(), 20)?;
    let vm = lab.snapshot.vms[0].id.clone();
    lab.command(Command::RefreshVmSnapshots { vm_id: vm.clone() }, 30)?;
    lab.settle(|s| s.vm_snapshot_trees.contains_key(&vm), 30)?;
    let tree = &lab.snapshot.vm_snapshot_trees[&vm];
    let node = tree
        .nodes
        .iter()
        .find(|n| n.mode == VmSnapshotMode::Full)
        .ok_or("no Full snapshot in this data directory")?
        .id
        .clone();
    let resume = lab.command(
        Command::RestoreVmSnapshot {
            vm_id: vm,
            snapshot_id: node,
            boot_from_disk: false,
            save_current: None,
            confirmed: true,
            switch_profile: false,
        },
        120,
    );
    let out = json!({"resume_by_non_headless_host": match resume {
        Ok((m, _)) => json!({"ok": m}),
        Err(e) => json!({"refused": e}),
    }});
    lab.backend.shutdown()?;
    Ok(out)
}

fn main() {
    // Static analysis invokes this same executable inside its isolated worker.
    if let Some(code) = antinomie_monitor_core::analysis::worker_main_if_requested() {
        std::process::exit(code);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => parse(&args).and_then(|c| run_case(&c)),
        Some("compat") => arg_value(&args, "--data")
            .ok_or("--data is required".to_owned())
            .and_then(|d| compat(d.into())),
        _ => Err("usage: auto-cycle run|compat ...".into()),
    };
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
