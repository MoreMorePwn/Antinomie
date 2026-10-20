// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM qualification of configurable process-core sizes: one case per run,
//! one JSON `ROW` line for the result. The data folder must be new.
//!
//!   core-size-check CASE BUNDLE NEW_DATA_DIR PROGRAM [options] [-- PROGRAM_ARGS...]
//!
//! CASE: `limits` (print what the guest reports and what it refuses),
//!       `exit` (core on exit), `manual` (Dump core while the program waits for
//!       READY text), `manual-cancel` (as manual, canceled at --cancel-at).
//! options: --ram MIB (2048) --cpus N (4) --budget MIB (256) --timeout MS (auto)
//!          --ready TEXT (manual: terminal text that says the program is ready)
//!          --cancel-at capture|PERCENT   --tcg (force software emulation)
//!          --uid N (0)   --quota MIB (4096, the recording quota)
use antinomie_monitor_core::*;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

struct Driver {
    backend: Backend,
    snapshot: Snapshot,
    replies: BTreeMap<u64, Result<String, String>>,
    output: BTreeMap<String, String>,
}
impl Driver {
    fn receive(&mut self) {
        while let Some(message) = self.backend.try_recv() {
            match message {
                Notification::Snapshot(snapshot) => self.snapshot = snapshot,
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    self.replies
                        .insert(id, if success { Ok(message) } else { Err(message) });
                }
                Notification::Terminal { run_id, data, .. } => {
                    let text = self.output.entry(run_id).or_default();
                    text.push_str(&String::from_utf8_lossy(&data));
                    if text.len() > 65536 {
                        let cut = text.ceil_char_boundary(text.len() - 32768);
                        text.drain(..cut);
                    }
                }
                _ => {}
            }
        }
    }
    fn command(&mut self, command: Command) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            self.receive();
            if let Some(reply) = self.replies.remove(&id) {
                return reply;
            }
            if Instant::now() >= deadline {
                return Err(format!("command {id} timed out"));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn wait(
        &mut self,
        label: &str,
        seconds: u64,
        ready: impl Fn(&Snapshot) -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.receive();
            if ready(&self.snapshot) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{label} timed out: {:?}", self.snapshot.last_error));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn wait_text(&mut self, run: &str, needle: &str, seconds: u64) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.receive();
            if self
                .output
                .get(run)
                .is_some_and(|text| text.contains(needle))
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("output never contained {needle:?}"));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn available(&self) -> Option<u64> {
        self.snapshot
            .vm_resources
            .as_ref()
            .and_then(|resources| resources.guest.as_ref())
            .and_then(|guest| guest.memory_available_size)
    }
}

struct Options {
    ram: u32,
    cpus: u16,
    budget: u32,
    timeout: Option<u32>,
    ready: Option<String>,
    cancel_at: Option<String>,
    tcg: bool,
    uid: u32,
    quota: u64,
    args: Vec<String>,
}

fn options(rest: &[String]) -> Result<Options, String> {
    let mut options = Options {
        ram: 2048,
        cpus: 4,
        budget: 256,
        timeout: None,
        ready: None,
        cancel_at: None,
        tcg: false,
        uid: 0,
        quota: 4096,
        args: Vec::new(),
    };
    let mut at = 0;
    while at < rest.len() {
        let value = |at: usize| rest.get(at + 1).cloned().ok_or("option needs a value");
        match rest[at].as_str() {
            "--ram" => options.ram = value(at)?.parse().map_err(|_| "bad --ram")?,
            "--cpus" => options.cpus = value(at)?.parse().map_err(|_| "bad --cpus")?,
            "--budget" => options.budget = value(at)?.parse().map_err(|_| "bad --budget")?,
            "--timeout" => options.timeout = Some(value(at)?.parse().map_err(|_| "bad --timeout")?),
            "--ready" => options.ready = Some(value(at)?),
            "--cancel-at" => options.cancel_at = Some(value(at)?),
            "--quota" => options.quota = value(at)?.parse().map_err(|_| "bad --quota")?,
            "--uid" => options.uid = value(at)?.parse().map_err(|_| "bad --uid")?,
            "--tcg" => {
                options.tcg = true;
                at += 1;
                continue;
            }
            "--" => {
                options.args = rest[at + 1..].to_vec();
                return Ok(options);
            }
            other => return Err(format!("unknown option {other}")),
        }
        at += 2;
    }
    Ok(options)
}

fn mib(size: u64) -> u64 {
    size >> 20
}

fn boot(
    bundle: &str,
    data: &str,
    program: &str,
    options: &Options,
) -> Result<(Driver, String), String> {
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("the data folder must be new".into());
    }
    let mut driver = Driver {
        backend: Backend::new(BackendOptions {
            bundle_dir: PathBuf::from(bundle),
            data_dir: data,
            headless: true,
            capture_quota_size: options.quota << 20,
            force_tcg: options.tcg,
            ..Default::default()
        })?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        output: BTreeMap::new(),
    };
    driver.command(Command::Create(VmConfig {
        name: "Core size qualification".into(),
        cpus: options.cpus,
        ram_mib: options.ram,
        disk_gib: 2,
        launch: VmLaunchOptions {
            acceleration: if options.tcg {
                VmAcceleration::Tcg
            } else {
                VmAcceleration::Default
            },
            ..Default::default()
        },
        ..Default::default()
    }))?;
    driver.wait("VM publication", 10, |snapshot| !snapshot.vms.is_empty())?;
    let vm_id = driver.snapshot.vms[0].id.clone();
    driver.command(Command::Start {
        vm_id: vm_id.clone(),
    })?;
    driver.wait("ready guest", 120, |snapshot| {
        snapshot
            .guest_kernel
            .as_ref()
            .and_then(|kernel| kernel.revision)
            .is_some_and(|revision| revision >= 16)
            && snapshot.guest_core_limits.is_some()
            && snapshot
                .serial_log
                .as_ref()
                .and_then(|path| fs::read(path).ok())
                .is_some_and(|log| log.windows(19).any(|part| part == b"BusyBox guest ready"))
    })?;
    driver.command(Command::Upload {
        source: PathBuf::from(program),
        destination: "/tmp/core-size-program".into(),
        overwrite: false,
        executable: true,
    })?;
    // The upload's last write may still be settling in the guest (ETXTBSY).
    thread::sleep(Duration::from_secs(2));
    Ok((driver, vm_id))
}

fn launch(
    driver: &mut Driver,
    options: &Options,
    core: bool,
    timeout: u32,
) -> Result<RunSummary, String> {
    let known: Vec<_> = driver
        .snapshot
        .runs
        .iter()
        .map(|run| run.id.clone())
        .collect();
    driver.command(Command::Execute(ExecRequest {
        path: "/tmp/core-size-program".into(),
        args: options.args.clone(),
        uid: options.uid,
        gid: options.uid,
        core_dump_on_exit: core,
        core_max_size: core.then_some(options.budget << 20),
        core_timeout_ms: core.then_some(timeout),
        ..Default::default()
    }))?;
    driver.wait("run publication", 20, |snapshot| {
        snapshot.runs.iter().any(|run| !known.contains(&run.id))
    })?;
    driver
        .snapshot
        .runs
        .iter()
        .find(|run| !known.contains(&run.id))
        .cloned()
        .ok_or_else(|| "new run missing".into())
}

fn file_row(path: Option<&PathBuf>) -> serde_json::Value {
    use std::os::unix::fs::MetadataExt;
    let Some(metadata) = path.and_then(|path| fs::metadata(path).ok()) else {
        return serde_json::json!({});
    };
    serde_json::json!({"logical": metadata.len(), "on_disk": metadata.blocks() * 512})
}

fn inspect(path: Option<&PathBuf>) -> serde_json::Value {
    let Some(path) = path else {
        return serde_json::json!({});
    };
    match core_dump::CoreDump::open(path) {
        Ok(core) => {
            // A mapping is complete when every byte of it is in the file.
            let short: Vec<_> = core
                .mappings
                .iter()
                .filter(|mapping| mapping.captured_size < mapping.memory_size)
                .map(|mapping| {
                    serde_json::json!({"start": format!("{:#x}", mapping.start),
                        "memory": mapping.memory_size, "captured": mapping.captured_size})
                })
                .collect();
            serde_json::json!({"threads": core.threads.len(), "mappings": core.mappings.len(),
                "short_mappings": short, "warnings": core.warnings})
        }
        Err(error) => serde_json::json!({"open_error": error.to_string()}),
    }
}

fn limits(driver: &Driver, vm_id: &str, options: &Options) -> Result<(), String> {
    println!(
        "ROW {}",
        serde_json::json!({"case": "limits", "ram_mib": options.ram,
            "limits": driver.snapshot.guest_core_limits, "vm": vm_id})
    );
    Ok(())
}

fn refusals(driver: &mut Driver, vm_id: &str, options: &Options) -> Result<(), String> {
    let mut refusals = Vec::new();
    for (budget, timeout) in [(options.budget, 5000), (options.budget, 20_000)] {
        let result = driver.command(Command::Execute(ExecRequest {
            path: "/tmp/core-size-program".into(),
            args: options.args.clone(),
            core_dump_on_exit: true,
            core_max_size: Some(budget << 20),
            core_timeout_ms: Some(timeout),
            ..Default::default()
        }));
        refusals.push(
            serde_json::json!({"budget_mib": budget, "timeout_ms": timeout,
            "refused": result.as_ref().err()}),
        );
    }
    println!(
        "ROW {}",
        serde_json::json!({"case": "refusals", "ram_mib": options.ram, "vm": vm_id,
            "limits": driver.snapshot.guest_core_limits, "requests": refusals})
    );
    Ok(())
}

fn exit_case(driver: &mut Driver, options: &Options) -> Result<(), String> {
    let timeout = options.timeout.unwrap_or_else(|| {
        driver.snapshot.guest_core_limits.map_or(5000, |limits| {
            limits.default_timeout_ms(u64::from(options.budget) << 20)
        })
    });
    let before = driver.available();
    let started = Instant::now();
    let run = launch(driver, options, true, timeout)?;
    driver.wait("core outcome", 900, |_| {
        RunArtifacts::load(&run.directory).is_ok_and(|artifacts| {
            artifacts.is_some_and(|artifacts| {
                matches!(
                    artifacts.core_state,
                    RunArtifactState::Complete
                        | RunArtifactState::Partial
                        | RunArtifactState::Failed
                        | RunArtifactState::Interrupted
                )
            })
        })
    })?;
    let elapsed = started.elapsed();
    let artifacts = RunArtifacts::load(&run.directory)?.ok_or("artifacts missing")?;
    let sidecar: serde_json::Value = fs::read(run.directory.join("core/core.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    println!(
        "ROW {}",
        serde_json::json!({"case": "exit", "ram_mib": options.ram, "budget_mib": options.budget,
            "timeout_ms": timeout, "state": artifacts.core_state, "reason": artifacts.core_reason,
            "issues": artifacts.issues, "file": file_row(artifacts.core_dump.as_ref()),
            "expected": artifacts.core_expected_size, "saved": artifacts.core_saved_size,
            "logical": artifacts.core_logical_size, "copy_ms": sidecar["copy_ms"],
            "stored_bytes": sidecar["stored_bytes"], "sha256": sidecar["sha256"],
            "wall_s": elapsed.as_secs_f64(), "available_before": before.map(mib),
            "available_after": driver.available().map(mib),
            "inspect": inspect(artifacts.core_dump.as_ref()),
            "path": artifacts.core_dump})
    );
    Ok(())
}

fn manual_case(
    driver: &mut Driver,
    vm_id: &str,
    options: &Options,
    cancel: bool,
) -> Result<(), String> {
    let timeout = options.timeout.unwrap_or_else(|| {
        driver.snapshot.guest_core_limits.map_or(5000, |limits| {
            limits.default_timeout_ms(u64::from(options.budget) << 20)
        })
    });
    let run = launch(driver, options, false, timeout)?;
    let ready = options.ready.as_deref().unwrap_or("READY");
    driver.wait_text(&run.id, ready, 300)?;
    driver.command(Command::ListProcesses { after_pid: 0 })?;
    driver.wait("process identity", 20, |snapshot| {
        snapshot.process_page.as_ref().is_some_and(|page| {
            page.processes.iter().any(|process| {
                process.identity.tgid == run.pid
                    && process.identity.task_cookie == run.root_task_cookie
            })
        })
    })?;
    let target = driver
        .snapshot
        .process_page
        .as_ref()
        .and_then(|page| {
            page.processes
                .iter()
                .find(|process| process.identity.tgid == run.pid)
        })
        .ok_or("target missing")?
        .identity
        .clone();
    let before = driver.available();
    let started = Instant::now();
    let known: Vec<_> = driver
        .snapshot
        .process_cores
        .iter()
        .map(|core| core.id.clone())
        .collect();
    driver.command(Command::DumpProcessCore {
        request: ProcessCoreRequest {
            vm_id: vm_id.into(),
            target,
            source_run_id: Some(run.id.clone()),
            max_size: options.budget << 20,
            timeout_ms: timeout,
        },
    })?;
    let mut canceled_at = None;
    let mut capture_seen = false;
    let deadline = Instant::now() + Duration::from_secs(1800);
    let capture = loop {
        driver.receive();
        let current = driver
            .snapshot
            .process_cores
            .iter()
            .find(|core| !known.contains(&core.id))
            .cloned();
        if let Some(core) = current {
            capture_seen = true;
            if cancel && canceled_at.is_none() {
                let hit = match options.cancel_at.as_deref().unwrap_or("capture") {
                    "capture" => true,
                    percent => {
                        let percent: u64 = percent.parse().map_err(|_| "bad --cancel-at")?;
                        core.guest_size.is_some_and(|size| {
                            size > 0 && core.stored_size * 100 >= size * percent
                        })
                    }
                };
                if hit {
                    canceled_at = Some((core.stored_size, core.guest_size, core.phase));
                    driver.command(Command::CancelCoreCapture {
                        capture_id: core.id.clone(),
                    })?;
                }
            }
            if core.phase == ProcessCorePhase::Finished {
                break core;
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("manual core never finished (seen {capture_seen})"));
        }
        thread::sleep(Duration::from_millis(2));
    };
    let elapsed = started.elapsed();
    let sidecar: serde_json::Value = fs::read(capture.directory.join("core.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    println!(
        "ROW {}",
        serde_json::json!({"case": if cancel {"manual-cancel"} else {"manual"}, "ram_mib": options.ram,
            "budget_mib": options.budget, "timeout_ms": timeout, "state": capture.state,
            "reason": capture.reason, "issue": capture.issue, "file": file_row(capture.file.as_ref()),
            "expected": capture.expected_size, "stored_bytes": capture.stored_bytes,
            "allocated": capture.allocated_size, "logical": capture.stored_size,
            "guest_size": capture.guest_size, "pause_released": capture.pause_released,
            "copy_ms": sidecar["copy_ms"], "sha256": capture.sha256,
            "canceled_at": canceled_at, "wall_s": elapsed.as_secs_f64(),
            "available_before": before.map(mib), "available_after": driver.available().map(mib),
            "inspect": inspect(capture.file.as_ref()), "path": capture.file})
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [case, bundle, data, program, rest @ ..] = args.as_slice() else {
        eprintln!("usage: core-size-check CASE BUNDLE NEW_DATA_DIR PROGRAM [options] [-- ARGS]");
        std::process::exit(2);
    };
    let outcome = (|| {
        let options = options(rest)?;
        let (mut driver, vm_id) = boot(bundle, data, program, &options)?;
        let result = match case.as_str() {
            "limits" => limits(&driver, &vm_id, &options)
                .and_then(|()| refusals(&mut driver, &vm_id, &options)),
            "exit" => exit_case(&mut driver, &options),
            "manual" => manual_case(&mut driver, &vm_id, &options, false),
            "manual-cancel" => manual_case(&mut driver, &vm_id, &options, true),
            other => Err(format!("unknown case {other}")),
        };
        let stopped = driver.command(Command::Stop);
        let closed = driver.backend.shutdown();
        result.and(stopped.map(|_| ())).and(closed)
    })();
    if let Err(error) = outcome {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}
