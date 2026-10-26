// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real host-only lifecycle qualification with an existing revision-14 BusyBox base.
//! Usage: host-lifecycle-check BUNDLE NEW_DATA_DIR
use antinomie_monitor_core::*;
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
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
                Notification::CommandResult { id: 0, message, .. } => {
                    eprintln!("notice: {message}")
                }
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
            thread::sleep(Duration::from_millis(25));
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
            thread::sleep(Duration::from_millis(25));
        }
    }
    fn launch(&mut self, request: ExecRequest) -> Result<RunSummary, String> {
        let known: Vec<_> = self
            .snapshot
            .runs
            .iter()
            .map(|run| run.id.clone())
            .collect();
        self.command(Command::Execute(request))?;
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
}
fn artifacts(run: &RunSummary) -> Result<RunArtifacts, String> {
    RunArtifacts::load(&run.directory)?.ok_or_else(|| "artifacts sidecar missing".into())
}
fn ensure(condition: bool, error: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(error.into()) }
}

fn qmp_filter_count() -> Result<usize, String> {
    let socket = fs::read_dir("/proc")
        .map_err(|error| error.to_string())?
        .flatten()
        .find_map(|entry| {
            let data = fs::read(entry.path().join("cmdline")).ok()?;
            let arguments: Vec<_> = data.split(|byte| *byte == 0).collect();
            if !arguments.windows(2).any(|pair| {
                pair == [
                    b"-name".as_slice(),
                    b"Host lifecycle qualification".as_slice(),
                ]
            }) {
                return None;
            }
            let address = arguments.windows(2).find(|pair| pair[0] == b"-qmp")?[1];
            std::str::from_utf8(address)
                .ok()?
                .strip_prefix("unix:")?
                .split(',')
                .next()
                .map(PathBuf::from)
        })
        .ok_or("qualification QEMU QMP socket missing")?;
    let mut stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|error| error.to_string())?);
    let receive = |reader: &mut BufReader<UnixStream>| -> Result<serde_json::Value, String> {
        let mut line = String::new();
        reader
            .take(64 * 1024)
            .read_line(&mut line)
            .map_err(|error| error.to_string())?;
        serde_json::from_str(&line).map_err(|error| error.to_string())
    };
    let greeting = receive(&mut reader)?;
    ensure(greeting.get("QMP").is_some(), "missing QMP greeting")?;
    stream
        .write_all(b"{\"execute\":\"qmp_capabilities\"}\n")
        .map_err(|error| error.to_string())?;
    ensure(
        receive(&mut reader)?.get("return").is_some(),
        "QMP capabilities failed",
    )?;
    stream
        .write_all(b"{\"execute\":\"qom-list\",\"arguments\":{\"path\":\"/objects\"}}\n")
        .map_err(|error| error.to_string())?;
    for _ in 0..16 {
        let reply = receive(&mut reader)?;
        if let Some(objects) = reply["return"].as_array() {
            return Ok(objects
                .iter()
                .filter(|object| {
                    object["name"]
                        .as_str()
                        .is_some_and(|name| name.starts_with("netdump-"))
                })
                .count());
        }
        if reply.get("error").is_some() {
            return Err(format!("QMP object query failed: {reply}"));
        }
    }
    Err("too many QMP events before object reply".into())
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (bundle, data) = match args.as_slice() {
        [bundle, data] => (PathBuf::from(bundle), PathBuf::from(data)),
        _ => return Err("usage: host-lifecycle-check BUNDLE NEW_DATA_DIR".into()),
    };
    ensure(
        !data.exists(),
        "the data directory must be new and disposable",
    )?;
    let mut driver = Driver {
        backend: Backend::new(BackendOptions {
            bundle_dir: bundle,
            data_dir: data.clone(),
            headless: true,
            capture_quota_size: 256 * 1024 * 1024,
            ..Default::default()
        })?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
    };
    driver.command(Command::Create(VmConfig {
        name: "Host lifecycle qualification".into(),
        cpus: 4,
        ram_mib: 512,
        disk_gib: 1,
        // Verify isolation also wins over a legacy NAT flag.
        nat: true,
        isolated_network: true,
        ..Default::default()
    }))?;
    driver.wait("VM publication", 10, |snapshot| !snapshot.vms.is_empty())?;
    let vm_id = driver.snapshot.vms[0].id.clone();
    driver.command(Command::Start {
        vm_id: vm_id.clone(),
    })?;
    driver.wait("revision-14 guest", 60, |snapshot| {
        snapshot
            .guest_kernel
            .as_ref()
            .and_then(|kernel| kernel.revision)
            .is_some_and(|revision| revision >= 14)
            && snapshot
                .serial_log
                .as_ref()
                .and_then(|path| fs::read(path).ok())
                .is_some_and(|log| log.windows(19).any(|part| part == b"BusyBox guest ready"))
    })?;
    driver.command(Command::StartNetworkCapture)?;
    let manual = driver
        .snapshot
        .network_capture
        .clone()
        .ok_or("manual capture missing")?;
    let first = driver.launch(ExecRequest {
        path: "/bin/sh".into(),
        args: vec![
            "-c".into(),
            "sleep 10 </dev/null >/dev/null 2>&1 & echo ROOT_DONE; exit 0".into(),
        ],
        capture_network: true,
        memory_dump_on_exit: true,
        ..Default::default()
    })?;
    let second = driver.launch(ExecRequest {
        path: "/bin/sh".into(),
        args: vec!["-c".into(), "sleep 3600".into()],
        capture_network: true,
        ..Default::default()
    })?;
    driver.wait("root exit with living descendant", 6, |snapshot| {
        snapshot
            .runs
            .iter()
            .find(|run| run.id == first.id)
            .and_then(|run| run.execution.as_ref())
            .is_some_and(|status| status.root_exit.is_some() && status.live_task_count > 0)
    })?;
    let before = artifacts(&first)?;
    ensure(
        before.network_state == RunArtifactState::Recording,
        "capture stopped at root exit",
    )?;
    ensure(
        before.memory_state == RunArtifactState::WaitingForTreeExit,
        "RAM dump started before child exited",
    )?;
    ensure(
        driver
            .snapshot
            .network_capture
            .as_ref()
            .map(|capture| &capture.id)
            == Some(&manual.id),
        "manual capture ownership changed",
    )?;
    println!("PASS root exit retains detached child capture and defers RAM dump");
    driver.wait("tree completion and post-exit RAM", 90, |_| {
        artifacts(&first).is_ok_and(|summary| {
            summary.memory_state == RunArtifactState::Complete
                && summary.network_state == RunArtifactState::Complete
        })
    })?;
    let after = artifacts(&first)?;
    let parallel = artifacts(&second)?;
    ensure(
        parallel.network_state == RunArtifactState::Recording,
        "finishing one run stopped the other run capture",
    )?;
    ensure(
        driver
            .snapshot
            .network_capture
            .as_ref()
            .map(|capture| &capture.id)
            == Some(&manual.id),
        "finishing one run stopped the manual capture",
    )?;
    ensure(
        after.network_captures.len() == 1
            && parallel.network_captures.len() == 1
            && after.network_captures[0] != parallel.network_captures[0],
        "run capture files alias",
    )?;
    for path in &after.network_captures {
        ensure(
            fs::metadata(path).map_err(|error| error.to_string())?.len() >= 24,
            "completed pcap has no header",
        )?;
        ensure(
            network::count_packets(path).is_ok(),
            "completed pcap is invalid",
        )?;
    }
    let dump_dir = after
        .memory_dump
        .clone()
        .ok_or("RAM dump relation missing")?;
    let dump_file = dump_dir.join(memory::DUMP_FILE);
    ensure(
        fs::metadata(&dump_file)
            .map_err(|error| error.to_string())?
            .len()
            > 1024,
        "RAM dump is empty",
    )?;
    let mut magic = [0; 4];
    fs::File::open(&dump_file)
        .and_then(|mut file| file.read_exact(&mut magic))
        .map_err(|error| error.to_string())?;
    ensure(&magic == b"\x7fELF", "RAM dump is not ELF")?;
    println!(
        "PASS authoritative tree exit completes only its capture and a linked post-exit VM RAM dump"
    );
    // A rejected launch must close its own newly started capture while keeping
    // the manually-owned capture and the other run's capture intact.
    ensure(
        driver
            .command(Command::Execute(ExecRequest {
                path: "/does/not/exist".into(),
                capture_network: true,
                ..Default::default()
            }))
            .is_err(),
        "invalid launch unexpectedly succeeded",
    )?;
    driver.receive();
    ensure(
        driver
            .snapshot
            .network_capture
            .as_ref()
            .map(|capture| &capture.id)
            == Some(&manual.id),
        "launch failure stopped manual capture",
    )?;
    ensure(
        artifacts(&second)?.network_state == RunArtifactState::Recording,
        "launch failure stopped another run capture",
    )?;
    println!("PASS rejected launch cleanup preserves other capture owners");
    driver.command(Command::StopNetworkCapture)?;
    ensure(
        qmp_filter_count()? == 1,
        "failed launch leaked a QMP filter owner",
    )?;
    driver.command(Command::CreateVmSnapshot {
        vm_id: vm_id.clone(),
        request: SnapshotRequest {
            name: "Lifecycle boundary".into(),
            description: String::new(),
            mode: VmSnapshotMode::Disk,
        },
    })?;
    driver.wait("disk checkpoint publication", 10, |snapshot| {
        snapshot.vm_snapshot_trees.get(&vm_id).is_some_and(|tree| {
            tree.nodes
                .iter()
                .any(|node| node.name == "Lifecycle boundary")
        })
    })?;
    let checkpoint = driver
        .snapshot
        .vm_snapshot_trees
        .get(&vm_id)
        .and_then(|tree| {
            tree.nodes
                .iter()
                .find(|node| node.name == "Lifecycle boundary")
        })
        .ok_or("disk checkpoint missing")?
        .id
        .clone();
    ensure(
        artifacts(&second)?.network_state == RunArtifactState::Recording,
        "snapshot did not resume the live capture",
    )?;
    ensure(
        qmp_filter_count()? == 1,
        "snapshot leaked the previous filter segment",
    )?;
    ensure(
        driver
            .command(Command::RestoreVmSnapshot {
                vm_id: vm_id.clone(),
                snapshot_id: checkpoint,
                boot_from_disk: true,
                save_current: Some(SnapshotRequest {
                    name: String::new(),
                    description: String::new(),
                    mode: VmSnapshotMode::Disk,
                }),
                confirmed: true,
                switch_profile: false,
            })
            .is_err(),
        "invalid save-current snapshot unexpectedly succeeded",
    )?;
    ensure(
        artifacts(&second)?.network_state == RunArtifactState::Recording,
        "failed restore left a living run capture suspended",
    )?;
    ensure(
        qmp_filter_count()? == 1,
        "failed restore lost or duplicated its filter owner",
    )?;
    println!("PASS snapshot segmentation and failed restore recover the living capture");
    let old_boot = driver.snapshot.boot_id.clone();
    driver.command(Command::ReconnectTransport)?;
    driver.wait("reconnected timeline", 20, |snapshot| {
        snapshot.boot_id != old_boot
    })?;
    let resumed = driver
        .snapshot
        .runs
        .iter()
        .find(|run| run.root_task_cookie == second.root_task_cookie)
        .cloned()
        .ok_or("reconnected run missing")?;
    let fresh = artifacts(&resumed)?;
    ensure(
        fresh.network_state == RunArtifactState::Recording,
        "reconnect did not resume capture",
    )?;
    ensure(
        fresh.network_captures.first() != artifacts(&second)?.network_captures.last(),
        "reconnect reused an old pcap",
    )?;
    ensure(
        qmp_filter_count()? == 1,
        "reconnect leaked an old QMP filter",
    )?;
    ensure(
        artifacts(&first)?.memory_state == RunArtifactState::Complete,
        "reconnect rewrote old completed RAM evidence",
    )?;
    println!("PASS reconnect seals old filters and resumes a fresh capture in the new timeline");
    driver.command(Command::StopRun {
        run_id: resumed.id.clone(),
    })?;
    driver.wait("second capture finalized", 30, |_| {
        artifacts(&resumed).is_ok_and(|summary| summary.network_state == RunArtifactState::Complete)
    })?;
    ensure(
        qmp_filter_count()? == 0,
        "completed reconnected run left a filter active",
    )?;
    driver.command(Command::Stop)?;
    fs::write(data.join("host-lifecycle-result.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "checks":"root/descendant lifetime, per-run/manual ownership, rejected launch cleanup, post-exit RAM",
        "first":after, "second_sealed":artifacts(&second)?, "second_resumed":artifacts(&resumed)?, "manual_pcap":manual.file,
        "qualification":"host lifecycle only; no process-core or Volatility correctness claim"
    })).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
    println!(
        "PASS host lifecycle qualification; retained evidence in {}",
        data.display()
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("FAIL: {error}");
        std::process::exit(1);
    }
}
