// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real four-vCPU process-core acquisition qualification in a fresh data folder.
//! Usage: process-core-check BUNDLE NEW_DATA_DIR STATIC_FIXTURE
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
}
impl Driver {
    fn receive(&mut self) {
        while let Some(notification) = self.backend.try_recv() {
            match notification {
                Notification::Snapshot(snapshot) => self.snapshot = snapshot,
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    self.replies
                        .insert(id, if success { Ok(message) } else { Err(message) });
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
            if let Some(result) = self.replies.remove(&id) {
                return result;
            }
            if Instant::now() > deadline {
                return Err(format!("command {id} timed out"));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn wait(
        &mut self,
        label: &str,
        seconds: u64,
        done: impl Fn(&Snapshot) -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.receive();
            if done(&self.snapshot) {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(format!("{label} timed out: {:?}", self.snapshot.last_error));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn launch(&mut self, mode: &str, capture: bool) -> Result<RunSummary, String> {
        let known: Vec<_> = self
            .snapshot
            .runs
            .iter()
            .map(|run| run.id.clone())
            .collect();
        self.command(Command::Execute(ExecRequest {
            path: "/tmp/core-fixture".into(),
            args: vec![mode.into()],
            uid: if mode == "nonroot" { 1000 } else { 0 },
            gid: if mode == "nonroot" { 1000 } else { 0 },
            core_dump_on_exit: capture,
            ..Default::default()
        }))?;
        self.wait("run publication", 10, |snapshot| {
            snapshot.runs.iter().any(|run| !known.contains(&run.id))
        })?;
        self.snapshot
            .runs
            .iter()
            .find(|run| !known.contains(&run.id))
            .cloned()
            .ok_or_else(|| "new run missing".into())
    }
    fn core(&mut self, run: &RunSummary, expected: RunArtifactState) -> Result<PathBuf, String> {
        self.wait("retained core", 120, |_| {
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
        let artifacts = RunArtifacts::load(&run.directory)?.ok_or("missing artifact metadata")?;
        if artifacts.core_state != expected {
            return Err(format!(
                "core result {:?}, expected {expected:?}: {:?}",
                artifacts.core_state, artifacts.issues
            ));
        }
        artifacts
            .core_dump
            .ok_or_else(|| "core file missing".into())
    }
}

fn save_evidence(data: &std::path::Path, evidence: &[serde_json::Value]) -> Result<(), String> {
    fs::write(
        data.join("process-core-result.json"),
        serde_json::to_vec_pretty(evidence).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn check() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [bundle, data, fixture] = args.as_slice() else {
        return Err("usage: process-core-check BUNDLE NEW_DATA_DIR STATIC_FIXTURE".into());
    };
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("qualification requires a new disposable data folder".into());
    }
    let mut driver = Driver {
        backend: Backend::new(BackendOptions {
            bundle_dir: PathBuf::from(bundle),
            data_dir: data.clone(),
            headless: true,
            capture_quota_size: 256 * 1024 * 1024,
            ..Default::default()
        })?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
    };
    // Cleanup remains unconditional even when an assertion or guest operation fails.
    let result = (|| {
        driver.command(Command::Create(VmConfig {
            name: "Process core qualification".into(),
            cpus: 4,
            ram_mib: 512,
            disk_gib: 1,
            ..Default::default()
        }))?;
        driver.wait("VM publication", 10, |snapshot| !snapshot.vms.is_empty())?;
        let vm_id = driver.snapshot.vms[0].id.clone();
        driver.command(Command::Start {
            vm_id: vm_id.clone(),
        })?;
        driver.wait("revision-15 guest", 60, |snapshot| {
            snapshot
                .guest_kernel
                .as_ref()
                .and_then(|kernel| kernel.revision)
                .is_some_and(|revision| revision >= 15)
                && snapshot
                    .serial_log
                    .as_ref()
                    .and_then(|path| fs::read(path).ok())
                    .is_some_and(|log| log.windows(19).any(|part| part == b"BusyBox guest ready"))
        })?;
        driver.wait("host resources", 5, |snapshot| {
            snapshot.vm_resources.as_ref().is_some_and(|resources| {
                resources.vm_id == vm_id
                    && resources.qemu_cpu_percent.is_some()
                    && resources.qemu_resident_size.is_some()
                    && resources.data_disk_available_size.is_some()
            })
        })?;
        driver.command(Command::Upload {
            source: PathBuf::from(fixture),
            destination: "/tmp/core-fixture".into(),
            overwrite: false,
            executable: true,
        })?;
        let mut evidence = Vec::new();
        for (mode, count) in [
            ("normal", 3),
            ("crash", 3),
            ("terminate", 3),
            ("thread-exit", 1),
            ("nonroot", 3),
            ("descendant", 3),
            ("leader-exit", 0),
        ] {
            let run = driver.launch(mode, true)?;
            let expected_state = if mode == "leader-exit" {
                RunArtifactState::Partial
            } else {
                RunArtifactState::Complete
            };
            let path = driver.core(&run, expected_state)?;
            let core = core_dump::CoreDump::open(&path).map_err(|error| error.to_string())?;
            if (count != 0 && core.threads.len() != count)
                || core.threads.is_empty()
                || core.threads.iter().any(|thread| {
                    thread.register("rip").is_none() || thread.register("rsp").is_none()
                })
            {
                return Err(format!(
                    "{mode}: missing expected {count} thread register contexts"
                ));
            }
            driver.wait("original process termination", 20, |snapshot| {
                snapshot
                    .runs
                    .iter()
                    .find(|item| item.id == run.id)
                    .and_then(|run| run.execution.as_ref())
                    .is_some_and(|execution| execution.root_exit.is_some())
            })?;
            let ending = driver
                .snapshot
                .runs
                .iter()
                .find(|item| item.id == run.id)
                .and_then(|run| run.execution.as_ref())
                .and_then(|execution| execution.root_exit.clone());
            let expected = match mode {
                "crash" => WaitStatus::Signaled {
                    signal: 11,
                    core_dumped: false,
                },
                "terminate" => WaitStatus::Signaled {
                    signal: 15,
                    core_dumped: false,
                },
                "leader-exit" => WaitStatus::Exited { code: 0 },
                _ => WaitStatus::Exited { code: 7 },
            };
            if ending.as_ref() != Some(&expected) {
                return Err(format!(
                    "{mode}: exit semantics changed: {ending:?}, expected {expected:?}"
                ));
            }
            evidence.push(serde_json::json!({"mode":mode,"run_id":run.id,"core":path,"threads":core.threads,"exit":ending}));
            if mode == "leader-exit" {
                driver.wait("leader peer survival evidence", 10, |_| {
                    let marker = b"worker survived leader exit";
                    fs::read(run.directory.join("terminal-screen.ansi")).is_ok_and(|terminal| {
                        terminal
                            .windows(marker.len())
                            .filter(|part| *part == marker)
                            .count()
                            == 2
                    })
                })?;
            }
            println!(
                "PASS {mode}: {} real thread contexts retained",
                core.threads.len()
            );
            save_evidence(&data, &evidence)?;
        }
        let killed = driver.launch("kill", true)?;
        driver.wait("SIGKILL unavailable core", 20, |_| {
            RunArtifacts::load(&killed.directory).is_ok_and(|artifacts| {
                artifacts.is_some_and(|artifacts| artifacts.core_state == RunArtifactState::Failed)
            })
        })?;
        println!("PASS SIGKILL reports unavailable context without delaying immediate teardown");
        let partial = driver.launch("large", true)?;
        let path = driver.core(&partial, RunArtifactState::Partial)?;
        let size = fs::metadata(&path)
            .map_err(|error| error.to_string())?
            .len();
        if size > 64 * 1024 * 1024 {
            return Err("partial core exceeded its configured limit".into());
        }
        println!("PASS bounded partial core: {size} bytes");
        let core = core_dump::CoreDump::open(&path).map_err(|error| error.to_string())?;
        evidence.push(serde_json::json!({"mode":"large","run_id":partial.id,"core":path,"threads":core.threads,"partial":true}));
        save_evidence(&data, &evidence)?;
        let canceled = driver.launch("wait", true)?;
        let second = driver.launch("wait", true)?;
        let rejected = driver.launch("normal", true)?;
        driver.wait(
            "reservation pressure leaves execution intact",
            20,
            |snapshot| {
                RunArtifacts::load(&rejected.directory).is_ok_and(|artifacts| {
                    artifacts
                        .is_some_and(|artifacts| artifacts.core_state == RunArtifactState::Failed)
                }) && snapshot.runs.iter().any(|run| {
                    run.id == rejected.id
                        && run.execution.as_ref().is_some_and(|execution| {
                            execution.root_exit == Some(WaitStatus::Exited { code: 7 })
                        })
                })
            },
        )?;
        for run in [&canceled, &second] {
            driver.command(Command::CancelProcessCore {
                run_id: run.id.clone(),
            })?;
            driver.wait("durable cancellation metadata", 20, |_| {
                RunArtifacts::load(&run.directory).is_ok_and(|artifacts| {
                    artifacts.is_some_and(|artifacts| {
                        artifacts.core_state == RunArtifactState::Interrupted
                    })
                })
            })?;
        }
        println!(
            "PASS guest reservation pressure does not prevent execution; cancellation releases capture ownership"
        );
        driver.command(Command::ReconnectTransport)?;
        let ordinary = driver.launch("normal", false)?;
        driver.wait("ordinary launch after reconnect", 20, |snapshot| {
            snapshot
                .runs
                .iter()
                .find(|run| run.id == ordinary.id)
                .is_some_and(|run| {
                    run.execution
                        .as_ref()
                        .is_some_and(|execution| execution.root_exit.is_some())
                })
        })?;
        println!("PASS cancellation, reconnect and host resource measurements");
        let before = driver.launch("snapshot", true)?;
        let old_boot = driver.snapshot.boot_id.clone();
        driver.command(Command::CreateVmSnapshot {
            vm_id: vm_id.clone(),
            request: SnapshotRequest {
                name: "Armed process core".into(),
                description: String::new(),
                mode: VmSnapshotMode::Full,
            },
        })?;
        driver.wait("snapshot publication", 10, |snapshot| {
            snapshot.vm_snapshot_trees.get(&vm_id).is_some_and(|tree| {
                tree.nodes
                    .iter()
                    .any(|node| node.name == "Armed process core")
            })
        })?;
        let checkpoint = driver
            .snapshot
            .vm_snapshot_trees
            .get(&vm_id)
            .and_then(|tree| {
                tree.nodes
                    .iter()
                    .find(|node| node.name == "Armed process core")
            })
            .ok_or("checkpoint missing")?
            .id
            .clone();
        driver.command(Command::RestoreVmSnapshot {
            vm_id: vm_id.clone(),
            snapshot_id: checkpoint,
            boot_from_disk: false,
            save_current: None,
            confirmed: true,
        })?;
        driver.wait("fresh restored core owner", 10, |snapshot| {
            snapshot.boot_id != old_boot
                && snapshot.runs.iter().any(|run| {
                    run.root_task_cookie == before.root_task_cookie
                        && run.boot_id == snapshot.boot_id.clone().unwrap_or_default()
                })
        })?;
        let restored = driver
            .snapshot
            .runs
            .iter()
            .find(|run| {
                run.root_task_cookie == before.root_task_cookie
                    && run.boot_id == driver.snapshot.boot_id.clone().unwrap_or_default()
            })
            .cloned()
            .ok_or("restored run missing")?;
        if restored.directory == before.directory {
            return Err("restore reused the original core directory".into());
        }
        let path = driver.core(&restored, RunArtifactState::Complete)?;
        let core = core_dump::CoreDump::open(&path).map_err(|error| error.to_string())?;
        if core.threads.len() != 3 {
            return Err("restored core lost thread contexts".into());
        }
        let previous =
            RunArtifacts::load(&before.directory)?.ok_or("original timeline artifacts missing")?;
        if previous.core_state != RunArtifactState::Interrupted {
            return Err("original core ownership was not sealed at restore".into());
        }
        println!("PASS full snapshot restores armed core into a fresh evidence timeline");
        evidence.push(serde_json::json!({"mode":"snapshot","run_id":restored.id,"core":path,"threads":core.threads,"source_run_id":before.id}));
        save_evidence(&data, &evidence)?;
        Ok(())
    })();
    let stopped = driver.command(Command::Stop);
    let closed = driver.backend.shutdown();
    result.and(stopped.map(|_| ())).and(closed)
}

fn main() {
    if let Err(error) = check() {
        eprintln!("FAILED: {error}");
        std::process::exit(1);
    }
}
