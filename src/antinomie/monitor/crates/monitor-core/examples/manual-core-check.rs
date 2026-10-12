// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real four-vCPU live-core qualification; requires a fresh disposable data folder.
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
    output: BTreeMap<String, (u64, Vec<u8>)>,
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
                Notification::Terminal {
                    run_id,
                    sequence,
                    data,
                    ..
                } => {
                    let output = self.output.entry(run_id).or_default();
                    output.0 = sequence;
                    output.1.extend(data);
                    if output.1.len() > 16384 {
                        output.1.drain(..output.1.len() - 16384);
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
            thread::sleep(Duration::from_millis(20));
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
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn wait_output(&mut self, run_id: &str, previous: u64) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            self.receive();
            if self.output.get(run_id).is_some_and(|(sequence, data)| {
                *sequence > previous && data.windows(9).any(|part| part == b"live tick")
            }) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("live heartbeat for {run_id} timed out"));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn check() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [bundle, data, fixture] = args.as_slice() else {
        return Err("usage: manual-core-check BUNDLE NEW_DATA_DIR STATIC_FIXTURE".into());
    };
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("qualification needs a new disposable data folder".into());
    }
    let mut driver = Driver {
        backend: Backend::new(BackendOptions {
            bundle_dir: PathBuf::from(bundle),
            data_dir: data.clone(),
            headless: true,
            capture_quota_size: 512 * 1024 * 1024,
            ..Default::default()
        })?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        output: BTreeMap::new(),
    };
    let result = (|| {
        driver.command(Command::Create(VmConfig {
            name: "Live core qualification".into(),
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
        driver.wait("revision-16 ready guest", 60, |snapshot| {
            snapshot
                .guest_kernel
                .as_ref()
                .and_then(|kernel| kernel.revision)
                .is_some_and(|revision| revision >= 16)
                && snapshot
                    .serial_log
                    .as_ref()
                    .and_then(|path| fs::read(path).ok())
                    .is_some_and(|log| log.windows(19).any(|part| part == b"BusyBox guest ready"))
        })?;
        driver.command(Command::Upload {
            source: PathBuf::from(fixture),
            destination: "/tmp/core-fixture".into(),
            overwrite: false,
            executable: true,
        })?;
        let mut evidence = Vec::new();
        let mut saved_live: Option<(String, ProcessCoreCapture, u64)> = None;
        for uid in [0, 1000] {
            let known: Vec<_> = driver
                .snapshot
                .runs
                .iter()
                .map(|run| run.id.clone())
                .collect();
            driver.command(Command::Execute(ExecRequest {
                path: "/tmp/core-fixture".into(),
                args: vec!["live".into()],
                uid,
                gid: uid,
                core_dump_on_exit: true,
                ..Default::default()
            }))?;
            driver.wait("new live run", 10, |snapshot| {
                snapshot.runs.iter().any(|run| !known.contains(&run.id))
            })?;
            let run = driver
                .snapshot
                .runs
                .iter()
                .find(|run| !known.contains(&run.id))
                .cloned()
                .ok_or("live run missing")?;
            driver.wait_output(&run.id, 0)?;
            driver.command(Command::ListProcesses { after_pid: 0 })?;
            driver.wait("process identity", 10, |snapshot| {
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
                    page.processes.iter().find(|process| {
                        process.identity.tgid == run.pid
                            && process.identity.task_cookie == run.root_task_cookie
                    })
                })
                .ok_or("exact target missing")?
                .identity
                .clone();
            for iteration in 0..2 {
                let old_ids: Vec<_> = driver
                    .snapshot
                    .process_cores
                    .iter()
                    .map(|core| core.id.clone())
                    .collect();
                driver.command(Command::DumpProcessCore {
                    request: ProcessCoreRequest {
                        vm_id: vm_id.clone(),
                        target: target.clone(),
                        source_run_id: Some(run.id.clone()),
                        ..Default::default()
                    },
                })?;
                if iteration == 0 {
                    match driver.command(Command::CreateVmSnapshot {
                        vm_id: vm_id.clone(),
                        request: SnapshotRequest {
                            name: format!("Live acquisition boundary uid {uid}"),
                            description: String::new(),
                            mode: VmSnapshotMode::Disk,
                        },
                    }) {
                        Err(error) if error.contains("manual core") => {
                            println!("PASS snapshot refuses in-flight live acquisition")
                        }
                        Err(error) => {
                            return Err(format!("unexpected snapshot boundary failure: {error}"));
                        }
                        Ok(_) => {
                            if !driver.snapshot.process_cores.iter().any(|core| {
                                !old_ids.contains(&core.id) && core.pause_released == Some(true)
                            }) {
                                return Err(
                                    "snapshot accepted before process pause release was proven"
                                        .into(),
                                );
                            }
                            println!("PASS snapshot accepted only after live acquisition resumed");
                        }
                    }
                }
                if uid == 0 && iteration == 0 {
                    driver.wait("resumed immutable manual buffer", 20, |snapshot| {
                        snapshot.process_cores.iter().any(|core| {
                            !old_ids.contains(&core.id)
                                && core.pause_released == Some(true)
                                && core.phase == ProcessCorePhase::Transfer
                        })
                    })?;
                    let saved = driver
                        .snapshot
                        .process_cores
                        .iter()
                        .find(|core| !old_ids.contains(&core.id))
                        .cloned()
                        .ok_or("resumed capture missing")?;
                    driver.command(Command::CreateVmSnapshot {
                        vm_id: vm_id.clone(),
                        request: SnapshotRequest {
                            name: "Resumed live core buffer".into(),
                            description: String::new(),
                            mode: VmSnapshotMode::Full,
                        },
                    })?;
                    driver.wait("manual checkpoint publication", 10, |snapshot| {
                        snapshot.vm_snapshot_trees.get(&vm_id).is_some_and(|tree| {
                            tree.nodes
                                .iter()
                                .any(|node| node.name == "Resumed live core buffer")
                        })
                    })?;
                    let checkpoint = driver
                        .snapshot
                        .vm_snapshot_trees
                        .get(&vm_id)
                        .and_then(|tree| {
                            tree.nodes
                                .iter()
                                .find(|node| node.name == "Resumed live core buffer")
                        })
                        .ok_or("manual checkpoint missing")?
                        .id
                        .clone();
                    saved_live = Some((checkpoint, saved, run.root_task_cookie));
                }
                driver.wait("manual core retained", 120, |snapshot| {
                    snapshot.process_cores.iter().any(|core| {
                        !old_ids.contains(&core.id) && core.phase == ProcessCorePhase::Finished
                    })
                })?;
                let capture = driver
                    .snapshot
                    .process_cores
                    .iter()
                    .find(|core| !old_ids.contains(&core.id))
                    .cloned()
                    .ok_or("capture missing")?;
                if let Some((_, saved, _)) = &mut saved_live
                    && saved.id == capture.id
                {
                    *saved = capture.clone();
                }
                if capture.pause_released != Some(true)
                    || !matches!(
                        capture.state,
                        RunArtifactState::Complete | RunArtifactState::Partial
                    )
                {
                    return Err(format!(
                        "manual capture failed or resume not proven: {capture:?}"
                    ));
                }
                let path = capture.file.clone().ok_or("manual core missing")?;
                let core = core_dump::CoreDump::open(&path).map_err(|error| error.to_string())?;
                if core.threads.len() != 3
                    || core.threads.iter().any(|thread| {
                        thread.register("rip").is_none() || thread.register("rsp").is_none()
                    })
                {
                    return Err(format!(
                        "manual capture missing thread contexts: {:?}",
                        core.threads
                    ));
                }
                if !core
                    .mappings
                    .iter()
                    .any(|mapping| mapping.memory_size > 0 && mapping.captured_size == 0)
                {
                    return Err("manual core has no explicit unavailable memory extents".into());
                }
                let previous = driver
                    .output
                    .get(&run.id)
                    .map_or(0, |(sequence, _)| *sequence);
                driver.wait_output(&run.id, previous)?;
                if driver
                    .snapshot
                    .runs
                    .iter()
                    .find(|saved| saved.id == run.id)
                    .and_then(|saved| saved.execution.as_ref())
                    .is_none_or(|execution| execution.root_exit.is_some())
                {
                    return Err("fixture exited during live capture qualification".into());
                }
                evidence.push(serde_json::json!({"mode":format!("manual-uid{uid}-{iteration}"),"run_id":run.id,"core":path,"threads":core.threads,"capture":capture,"continued_execution":true}));
                fs::write(
                    data.join("manual-core-result.json"),
                    serde_json::to_vec_pretty(&evidence).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
                println!(
                    "PASS uid {uid}: live capture {iteration}, three contexts, explicit gaps and continued execution"
                );
            }
            let old_ids: Vec<_> = driver
                .snapshot
                .process_cores
                .iter()
                .map(|core| core.id.clone())
                .collect();
            driver.command(Command::DumpProcessCore {
                request: ProcessCoreRequest {
                    vm_id: vm_id.clone(),
                    target: target.clone(),
                    ..Default::default()
                },
            })?;
            driver.wait("cancel capture publication", 10, |snapshot| {
                snapshot
                    .process_cores
                    .iter()
                    .any(|core| !old_ids.contains(&core.id))
            })?;
            let cancel_id = driver
                .snapshot
                .process_cores
                .iter()
                .find(|core| !old_ids.contains(&core.id))
                .ok_or("cancel capture missing")?
                .id
                .clone();
            driver.command(Command::CancelCoreCapture {
                capture_id: cancel_id.clone(),
            })?;
            driver.wait("manual cancellation releases pause", 20, |snapshot| {
                snapshot.process_cores.iter().any(|core| {
                    core.id == cancel_id
                        && core.phase == ProcessCorePhase::Finished
                        && (core.guest_handle.is_none() || core.pause_released == Some(true))
                })
            })?;
            let previous = driver
                .output
                .get(&run.id)
                .map_or(0, |(sequence, _)| *sequence);
            driver.wait_output(&run.id, previous)?;
            println!("PASS uid {uid}: canceled capture released its pause and target continued");
            let old_ids: Vec<_> = driver
                .snapshot
                .process_cores
                .iter()
                .map(|core| core.id.clone())
                .collect();
            driver.command(Command::DumpProcessCore {
                request: ProcessCoreRequest {
                    vm_id: vm_id.clone(),
                    target: target.clone(),
                    timeout_ms: 1,
                    ..Default::default()
                },
            })?;
            driver.wait("manual timeout cleanup", 20, |snapshot| {
                snapshot.process_cores.iter().any(|core| {
                    !old_ids.contains(&core.id) && core.phase == ProcessCorePhase::Finished
                })
            })?;
            let timed = driver
                .snapshot
                .process_cores
                .iter()
                .find(|core| !old_ids.contains(&core.id))
                .ok_or("timeout capture missing")?;
            if timed.pause_released != Some(true)
                || timed
                    .guest_status
                    .as_ref()
                    .and_then(|status| status.get("status"))
                    .and_then(|status| status.as_i64())
                    != Some(-110)
            {
                return Err(format!(
                    "one-millisecond deadline did not report released timeout: {timed:?}"
                ));
            }
            let previous = driver
                .output
                .get(&run.id)
                .map_or(0, |(sequence, _)| *sequence);
            driver.wait_output(&run.id, previous)?;
            println!(
                "PASS uid {uid}: short deadline reports timeout, releases capture pause and target continues"
            );
            driver.command(Command::TerminalInput {
                run_id: run.id.clone(),
                data: b"finish\n".to_vec(),
            })?;
            driver.wait("original exit and independent exit core", 120, |snapshot| {
                snapshot
                    .runs
                    .iter()
                    .find(|saved| saved.id == run.id)
                    .and_then(|saved| saved.execution.as_ref())
                    .is_some_and(|execution| {
                        execution.root_exit == Some(WaitStatus::Exited { code: 7 })
                    })
                    && RunArtifacts::load(&run.directory).is_ok_and(|artifacts| {
                        artifacts.is_some_and(|artifacts| {
                            matches!(
                                artifacts.core_state,
                                RunArtifactState::Complete | RunArtifactState::Partial
                            ) && artifacts.core_dump.is_some()
                        })
                    })
            })?;
            let mut stale = target;
            stale.start_boot_ns = stale.start_boot_ns.saturating_add(1);
            let old_ids: Vec<_> = driver
                .snapshot
                .process_cores
                .iter()
                .map(|core| core.id.clone())
                .collect();
            let stale_result = driver.command(Command::DumpProcessCore {
                request: ProcessCoreRequest {
                    vm_id: vm_id.clone(),
                    target: stale,
                    ..Default::default()
                },
            });
            if stale_result.is_ok() {
                // Admission is asynchronous. A queued request must become a
                // failed capture after exact identity validation in the guest.
                driver.wait("stale identity failure", 20, |snapshot| {
                    snapshot.process_cores.iter().any(|core| {
                        !old_ids.contains(&core.id)
                            && core.phase == ProcessCorePhase::Finished
                            && core.state == RunArtifactState::Failed
                            && core.file.is_none()
                    })
                })?;
            }
            println!(
                "PASS uid {uid}: original exit 7, independent on-exit core and stale identity rejection"
            );
        }
        if let Some((checkpoint, original, cookie)) = saved_live {
            let old_boot = driver.snapshot.boot_id.clone();
            driver.command(Command::RestoreVmSnapshot {
                vm_id: vm_id.clone(),
                snapshot_id: checkpoint,
                boot_from_disk: false,
                save_current: None,
                confirmed: true,
            })?;
            driver.wait("manual immutable buffer adoption", 120, |snapshot| {
                snapshot.boot_id != old_boot
                    && snapshot.process_cores.iter().any(|core| {
                        core.restored_from_capture_id.as_deref() == Some(original.id.as_str())
                            && core.phase == ProcessCorePhase::Finished
                    })
            })?;
            let adopted = driver
                .snapshot
                .process_cores
                .iter()
                .find(|core| core.restored_from_capture_id.as_deref() == Some(original.id.as_str()))
                .cloned()
                .ok_or("adopted manual capture missing")?;
            if adopted.pause_released != Some(true)
                || adopted.sha256 != original.sha256
                || adopted.nonce != original.nonce
                || adopted.guest_handle != original.guest_handle
                || adopted.directory == original.directory
                || adopted.file.is_none()
            {
                return Err(format!(
                    "manual checkpoint ownership/hash/timeline changed: {adopted:?}"
                ));
            }
            let file = adopted.file.clone().ok_or("adopted core file missing")?;
            let core = core_dump::CoreDump::open(&file).map_err(|error| error.to_string())?;
            evidence.push(serde_json::json!({"mode":"manual-restored","core":file,"threads":core.threads,"capture":adopted,"same_immutable_hash":true}));
            fs::write(
                data.join("manual-core-result.json"),
                serde_json::to_vec_pretty(&evidence).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let restored_run = driver
                .snapshot
                .runs
                .iter()
                .find(|run| {
                    run.root_task_cookie == cookie
                        && Some(&run.boot_id) == driver.snapshot.boot_id.as_ref()
                })
                .cloned()
                .ok_or("restored live run missing")?;
            driver.wait_output(&restored_run.id, 0)?;
            driver.command(Command::TerminalInput {
                run_id: restored_run.id.clone(),
                data: b"finish\n".to_vec(),
            })?;
            driver.wait("restored process original exit", 30, |snapshot| {
                snapshot
                    .runs
                    .iter()
                    .find(|run| run.id == restored_run.id)
                    .and_then(|run| run.execution.as_ref())
                    .is_some_and(|execution| {
                        execution.root_exit == Some(WaitStatus::Exited { code: 7 })
                    })
            })?;
            println!(
                "PASS full restore adopts identical immutable core in a fresh timeline; restored program continues and exits 7"
            );
        }
        driver.command(Command::ReconnectTransport)?;
        driver.command(Command::CreateVmSnapshot {
            vm_id,
            request: SnapshotRequest {
                name: "After live captures resumed".into(),
                description: String::new(),
                mode: VmSnapshotMode::Full,
            },
        })?;
        println!("PASS reconnect and full snapshot after capture pause released");
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
