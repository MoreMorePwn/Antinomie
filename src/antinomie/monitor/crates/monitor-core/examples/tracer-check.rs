// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM qualification of the hashes of written files and of the launched
//! program's own image, and of a run recorded across a transport reconnect.
//!
//!   tracer-check record BUNDLE NEW_DATA_DIR FIXTURE
//!   tracer-check legacy BUNDLE NEW_DATA_DIR FIXTURE
//!   tracer-check reconnects BUNDLE NEW_DATA_DIR FIXTURE [COUNT]
//!
//! FIXTURE is the static `tests/monitor/tracer-fixture`. `record` boots one
//! VM and makes four runs: `writes` as root (every written-file case), `slow`
//! with a transport reconnect in its middle, and `exit0` as uid 1000 (named in
//! the base) and as uid 65534 (not named). It
//! stops the VM, checks the guest's records against the digests the fixture's
//! patterns must have (computed here, not read from the guest) and prints a
//! `RUN label=directory` line for each run; the ignored test
//! `recorded_tracer_triage` of the app's triage module reads them. `legacy`
//! is for a base from before the written-file hashes: the host must ask for
//! nothing and the run must work as before, with no such record.
//! `reconnects` reconnects the transport COUNT times (default 10) during one
//! run that writes a file every second, and prints what each reconnect took,
//! step by step (`RECONNECT` lines). It fails if a reconnect takes longer
//! than [`RECONNECT_BUDGET`], if the run does not keep its identity across
//! them, or if a segment of it has no write: what a slow reconnect costs is
//! measured, not inferred from a missing segment. The data folder must be new
//! and disposable. Every result is a `RESULT` line.
use antinomie_monitor_core::kernel_notes::{self, FileHash, HashKind, HashStatus};
use antinomie_monitor_core::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    thread,
    time::{Duration, Instant},
};

struct Driver {
    backend: Backend,
    snapshot: Snapshot,
    replies: BTreeMap<u64, Result<String, String>>,
    vm_id: String,
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
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn run(&self, id: &str) -> Option<&RunSummary> {
        self.snapshot.runs.iter().find(|run| run.id == id)
    }
    fn launch(&mut self, program: &str, args: &[&str], uid: u32) -> Result<String, String> {
        self.launch_with(program, args, uid, false)
    }
    fn launch_with(
        &mut self,
        program: &str,
        args: &[&str],
        uid: u32,
        capture_network: bool,
    ) -> Result<String, String> {
        let known: Vec<String> = self.snapshot.runs.iter().map(|r| r.id.clone()).collect();
        self.command(Command::Execute(ExecRequest {
            path: program.into(),
            args: args.iter().map(|a| (*a).to_string()).collect(),
            uid,
            gid: uid,
            cwd: "/tmp".into(),
            capture_network,
            ..Default::default()
        }))?;
        self.wait("run publication", 15, |s| {
            s.runs.iter().any(|r| !known.contains(&r.id))
        })?;
        let id = self
            .snapshot
            .runs
            .iter()
            .find(|r| !known.contains(&r.id))
            .ok_or("new run missing")?
            .id
            .clone();
        self.wait("run identity", 15, |s| {
            s.runs
                .iter()
                .any(|r| r.id == id && r.pid != 0 && r.root_task_cookie != 0)
        })?;
        Ok(id)
    }
    fn finished(&mut self, id: &str, seconds: u64) -> Result<(), String> {
        let id = id.to_owned();
        self.wait("run end", seconds, move |s| {
            s.runs
                .iter()
                .any(|r| r.id == id && matches!(r.state, RunState::Finished | RunState::Stopped))
        })
    }
}

fn setup(bundle: &str, data: &str, name: &str) -> Result<Driver, String> {
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("qualification needs a new disposable data folder".into());
    }
    let options = BackendOptions {
        bundle_dir: PathBuf::from(bundle),
        data_dir: data,
        headless: true,
        capture_quota_size: 1024 * 1024 * 1024,
        ..Default::default()
    };
    let mut driver = Driver {
        backend: Backend::new(options)?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        vm_id: String::new(),
    };
    driver.command(Command::Create(VmConfig {
        name: name.into(),
        cpus: 1,
        ram_mib: 1024,
        disk_gib: 1,
        // A NIC with no way out: the reconnected run's DNS queries are
        // captured, and go nowhere.
        nat: true,
        isolated_network: true,
        ..Default::default()
    }))?;
    driver.wait("VM publication", 10, |s| !s.vms.is_empty())?;
    driver.vm_id = driver.snapshot.vms[0].id.clone();
    let vm_id = driver.vm_id.clone();
    driver.command(Command::Start { vm_id })?;
    driver.wait("revision-17 guest", 120, |s| {
        s.guest_kernel
            .as_ref()
            .and_then(|k| k.revision)
            .is_some_and(|r| r >= 17)
            && s.serial_log
                .as_ref()
                .and_then(|p| fs::read(p).ok())
                .is_some_and(|log| log.windows(19).any(|part| part == b"BusyBox guest ready"))
    })?;
    // The tracer probe follows INFO and CORE_CAPS.
    driver.wait("tracer capabilities", 30, |s| s.guest_tracer.is_some())?;
    Ok(driver)
}

fn result(line: String) {
    println!("RESULT {line}");
}

const FIXTURE: &str = "/tmp/tracer-fixture";

/// The bytes the fixture writes: byte i = (i * 31 + seed) & 0xff.
fn pattern_sha(seed: u64, size: u64) -> String {
    let mut digest = Sha256::new();
    let mut chunk = Vec::with_capacity(65536);
    let mut at = 0u64;
    while at < size {
        chunk.clear();
        let count = (size - at).min(65536);
        chunk.extend((0..count).map(|i| ((at + i) * 31 + seed) as u8));
        digest.update(&chunk);
        at += count;
    }
    format!("{:x}", digest.finalize())
}

/// Every hash record of a saved run, with the pid of the call it came with.
fn hashes(directory: &Path) -> Result<Vec<(u32, String, FileHash)>, String> {
    let recording = recording::Recording {
        directory: directory.to_path_buf(),
        manifest: serde_json::Value::Null,
        events: Vec::new(),
    };
    let cancel = AtomicBool::new(false);
    let mut found = Vec::new();
    let mut offset = 0;
    loop {
        let page = recording
            .invocation_page_cancellable(offset, 256, &cancel)
            .map_err(|e| e.to_string())?;
        for call in &page.invocations {
            let Some(event) = call.entry.as_ref().or(call.exit.as_ref()) else {
                continue;
            };
            for hash in call.kernel_notes.iter().filter_map(kernel_notes::file_hash) {
                found.push((event.pid, event.syscall_name.clone(), hash));
            }
        }
        match page.next_offset {
            Some(next) => offset = next,
            None => return Ok(found),
        }
    }
}

/// The run's launch record, read from its first segment.
fn launch_of(directory: &Path, root: u64) -> Result<Option<recording::LaunchRecord>, String> {
    let recording = recording::Recording {
        directory: directory.to_path_buf(),
        manifest: serde_json::Value::Null,
        events: Vec::new(),
    };
    let cancel = AtomicBool::new(false);
    let page = recording
        .invocation_page_cancellable(0, 1, &cancel)
        .map_err(|e| e.to_string())?;
    let Some(stream) = page.invocations.first().map(|call| call.stream_id) else {
        return Ok(None);
    };
    recording
        .launch_record_cancellable(stream, root, &cancel)
        .map_err(|e| e.to_string())
}

fn hex(hash: &FileHash) -> String {
    hash.sha256_hex().unwrap_or_else(|| "-".into())
}

/// The checks of the `writes` run; each failure is a message.
fn check_writes(directory: &Path, root: u64, fixture_sha: &str) -> Result<Vec<String>, String> {
    let mut bad = Vec::new();
    let all = hashes(directory)?;
    let writes: Vec<_> = all
        .iter()
        .filter(|(_, _, hash)| hash.kind == HashKind::Write)
        .collect();
    for (_, call, hash) in &writes {
        let file = hash.file.expect("write records carry their file");
        println!(
            "WRITE {call} {:?} size {} sha256 {} nlink {} mode {:o} changed {} cached {} queue_us {} hash_us {} lost {}",
            hash.status,
            hash.size,
            hex(hash),
            file.nlink,
            file.mode,
            hash.changed,
            hash.cached,
            hash.queue_us,
            hash.hash_us,
            hash.lost
        );
    }
    let with_digest = |sha: &str| {
        writes
            .iter()
            .filter(|(_, _, hash)| hash.sha256_hex().as_deref() == Some(sha))
            .collect::<Vec<_>>()
    };
    let expect = |bad: &mut Vec<String>,
                  label: &str,
                  seed: u64,
                  size: u64,
                  count: std::ops::RangeInclusive<usize>| {
        let found = with_digest(&pattern_sha(seed, size));
        let ok = count.contains(&found.len());
        result(format!(
            "write {label}: {} record(s) with the pattern digest{}",
            found.len(),
            if ok { "" } else { " FAILED" }
        ));
        if !ok {
            bad.push(format!("{label}: {} records", found.len()));
        }
        found
    };
    // New file, then again when it is opened read-write and closed.
    expect(&mut bad, "new + rdwr", 1, 100_000, 2..=2);
    // Two writers: one hash, after the second close.
    expect(&mut bad, "two writers", 2, 8192, 1..=1);
    let child = expect(&mut bad, "inherited by a child", 3, 8192, 1..=1);
    if child.iter().any(|(_, call, _)| call != "exit_group") {
        bad.push("the child's write hash is not carried by its exit".into());
    }
    expect(&mut bad, "left open at exit", 4, 5000, 1..=1);
    expect(&mut bad, "renamed while open", 6, 3000, 1..=1);
    let gone = expect(&mut bad, "unlinked while open", 7, 2000, 1..=1);
    if gone
        .iter()
        .any(|(_, _, hash)| hash.file.is_none_or(|file| file.nlink != 0))
    {
        bad.push("the unlinked file does not report nlink 0".into());
    }
    expect(&mut bad, "memfd", 8, 6000, 1..=1);
    // The dropped copy is this program; its exec hash is the same digest.
    let dropped = with_digest(fixture_sha);
    let exec_dropped = all
        .iter()
        .filter(|(_, _, hash)| {
            hash.kind == HashKind::Exec && hash.sha256_hex().as_deref() == Some(fixture_sha)
        })
        .count();
    result(format!(
        "dropper: {} write record(s), {exec_dropped} exec record(s) of the dropped copy",
        dropped.len()
    ));
    if dropped.len() != 1 || exec_dropped != 1 {
        bad.push("dropper not hashed at write and exec".into());
    }
    let big: Vec<_> = writes
        .iter()
        .filter(|(_, _, hash)| hash.status == HashStatus::TooLarge && hash.size == 17 << 20)
        .collect();
    result(format!("over the limit: {} refusal(s) TooLarge", big.len()));
    if big.len() != 1 {
        bad.push("the 17 MiB file is not refused as too large".into());
    }
    if writes
        .iter()
        .any(|(_, _, hash)| hash.status == HashStatus::UnsupportedFilesystem)
    {
        bad.push("a pseudo filesystem write produced a record".into());
    }
    // Six 15 MiB files hashed one at a time, then rewritten and closed at
    // once: more bytes than the guest queues.
    let first = with_digest(&pattern_sha(9, 15 << 20)).len();
    let again: Vec<_> = writes
        .iter()
        .filter(|(_, _, hash)| {
            hash.size == 15 << 20 && hash.sha256_hex() != Some(pattern_sha(9, 15 << 20))
        })
        .collect();
    let refused = again
        .iter()
        .filter(|(_, _, hash)| matches!(hash.status, HashStatus::QueueFull | HashStatus::Budget))
        .count();
    result(format!(
        "burst: {first} of 6 hashed one at a time; at once: {} hashed, {refused} refused {:?}",
        again.len() - refused,
        again
            .iter()
            .map(|(_, _, hash)| hash.status)
            .collect::<Vec<_>>()
    ));
    if first != 6 || again.len() != 6 || refused == 0 {
        bad.push("the burst was not accounted for, or nothing was refused".into());
    }
    let changed: Vec<_> = writes
        .iter()
        .filter(|(_, _, hash)| hash.size == 12 << 20 || hash.hashed == 12 << 20)
        .collect();
    result(format!(
        "rewritten during the hash: {} record(s), changed flags {:?}",
        changed.len(),
        changed
            .iter()
            .map(|(_, _, hash)| hash.changed)
            .collect::<Vec<_>>()
    ));
    if changed.len() != 2 {
        bad.push("the 12 MiB file is not hashed at both closes".into());
    }
    let launch = launch_of(directory, root)?.ok_or("no launch record")?;
    let own = launch
        .notes
        .iter()
        .filter_map(kernel_notes::file_hash)
        .find(|hash| hash.kind == HashKind::Exec);
    result(format!(
        "launched image: path {:?} argv {:?} hash {}",
        launch.path,
        launch.argv,
        own.as_ref().map_or_else(|| "none".into(), hex)
    ));
    if own.as_ref().and_then(FileHash::sha256_hex).as_deref() != Some(fixture_sha) {
        bad.push("the launched program's own image is not hashed".into());
    }
    let stats: Vec<_> = writes
        .iter()
        .filter(|(_, _, hash)| hash.status == HashStatus::Ok && !hash.cached)
        .map(|(_, _, hash)| (hash.queue_us, hash.hash_us))
        .collect();
    if let (Some(queue), Some(work)) = (
        stats.iter().map(|s| s.0).max(),
        stats.iter().map(|s| s.1).max(),
    ) {
        result(format!(
            "worker: {} digests, longest wait {queue} us, longest hash {work} us",
            stats.len()
        ));
    }
    Ok(bad)
}

fn record(bundle: &str, data: &str, fixture: &str) -> Result<(), String> {
    let mut d = setup(bundle, data, "tracer record")?;
    let caps = d.snapshot.guest_tracer.ok_or("no tracer capabilities")?;
    result(format!(
        "tracer capabilities: exec flags {:#x}, file limit {}, queue {}, pending {}",
        caps.exec_flags, caps.hash_file_max_size, caps.hash_queue_count, caps.hash_pending_max_size
    ));
    if !caps.hashes_root() || !caps.hashes_writes() {
        return Err("the guest does not offer the hashes".into());
    }
    d.command(Command::Upload {
        source: PathBuf::from(fixture),
        destination: FIXTURE.into(),
        overwrite: true,
        executable: true,
    })?;
    let fixture_sha = format!(
        "{:x}",
        Sha256::digest(fs::read(fixture).map_err(|e| e.to_string())?)
    );
    let mut runs = Vec::new();

    let writes = d.launch(FIXTURE, &["writes"], 0)?;
    d.finished(&writes, 180)?;
    let writes_run = d.run(&writes).ok_or("run missing")?.clone();
    runs.push(("writes", writes_run.clone()));

    // A reconnect in the middle of a run: one run, two recording segments.
    let slow = d.launch_with(FIXTURE, &["slow", "30"], 0, true)?;
    thread::sleep(Duration::from_secs(4));
    let started = Instant::now();
    let reconnected = d.command(Command::ReconnectTransport)?;
    // The command's own account of its steps, beside the time it took from
    // here (which includes waiting for the backend to take the command).
    result(format!(
        "reconnect took {} ms ({reconnected})",
        started.elapsed().as_millis()
    ));
    d.finished(&slow, 120)?;
    runs.push(("reconnect", d.run(&slow).ok_or("run missing")?.clone()));

    // A user the base names, and one it does not.
    for (label, uid) in [("user", 1000), ("nobody", 65534)] {
        let user = d.launch(FIXTURE, &["exit0"], uid)?;
        d.finished(&user, 60)?;
        runs.push((label, d.run(&user).ok_or("run missing")?.clone()));
    }

    // The recordings are complete when the VM has stopped.
    d.command(Command::Stop)?;
    d.wait("VM stop", 90, |s| s.state == VmState::Stopped)?;
    thread::sleep(Duration::from_secs(2));

    let mut bad = check_writes(
        &writes_run.directory,
        writes_run.root_task_cookie,
        &fixture_sha,
    )?;
    let (_, reconnected) = &runs[1];
    let segments =
        recording::run_segments(&reconnected.directory, &reconnected.id, &reconnected.vm_id)
            .map_err(|e| e.to_string())?;
    result(format!(
        "reconnect: {} segments: {:?}",
        segments.len(),
        segments
            .iter()
            .map(|s| s.directory.display().to_string())
            .collect::<Vec<_>>()
    ));
    if segments.len() != 2 {
        bad.push("the reconnected run does not have two segments".into());
    }
    for segment in &segments {
        let captures = RunArtifacts::load(&segment.directory)
            .map_err(|e| e.to_string())?
            .map(|artifacts| artifacts.network_captures)
            .unwrap_or_default();
        let sizes: Vec<_> = captures
            .iter()
            .map(|path| fs::metadata(path).map_or(0, |meta| meta.len()))
            .collect();
        result(format!(
            "reconnect segment {}: network captures {sizes:?} bytes",
            segment.boot_id
        ));
        if sizes.iter().all(|size| *size <= 24) {
            bad.push("a segment of the reconnected run captured no packets".into());
        }
    }
    for (label, run) in &runs {
        println!("RUN {label}={}", run.directory.display());
    }
    println!("FIXTURE_SHA256 {fixture_sha}");
    if bad.is_empty() {
        println!("PASS record");
        Ok(())
    } else {
        Err(format!("{bad:?}"))
    }
}

fn legacy(bundle: &str, data: &str, fixture: &str) -> Result<(), String> {
    let mut d = setup(bundle, data, "tracer legacy")?;
    let caps = d.snapshot.guest_tracer.ok_or("no tracer capabilities")?;
    result(format!(
        "legacy guest offers exec flags {:#x}",
        caps.exec_flags
    ));
    d.command(Command::Upload {
        source: PathBuf::from(fixture),
        destination: FIXTURE.into(),
        overwrite: true,
        executable: true,
    })?;
    let id = d.launch(FIXTURE, &["writes"], 0)?;
    d.finished(&id, 180)?;
    let run = d.run(&id).ok_or("run missing")?.clone();
    let state = run.state.clone();
    let exit = run.execution.as_ref().and_then(|e| e.root_exit.clone());
    d.command(Command::Stop)?;
    d.wait("VM stop", 90, |s| s.state == VmState::Stopped)?;
    thread::sleep(Duration::from_secs(2));
    let all = hashes(&run.directory)?;
    let writes = all
        .iter()
        .filter(|(_, _, h)| h.kind == HashKind::Write)
        .count();
    let execs = all
        .iter()
        .filter(|(_, _, h)| h.kind == HashKind::Exec)
        .count();
    let deletes = all
        .iter()
        .filter(|(_, _, h)| h.kind == HashKind::Delete)
        .count();
    let launch = launch_of(&run.directory, run.root_task_cookie)?;
    let own = launch.as_ref().map_or(0, |launch| launch.notes.len());
    result(format!(
        "legacy run: state {state:?} exit {exit:?}; records: {writes} write, {execs} exec, {deletes} delete, {own} for the launch"
    ));
    println!("RUN legacy={}", run.directory.display());
    if caps.exec_flags != 0 || writes != 0 || own != 0 || state != RunState::Finished {
        return Err("a legacy guest was asked for, or wrote, the new hashes".into());
    }
    println!("PASS legacy");
    Ok(())
}

/// The longest a reconnect may take in `reconnects`: about ten times the
/// usual (0.2 to 1 s), far below the 41 and 49 s ones it is to catch.
const RECONNECT_BUDGET: Duration = Duration::from_secs(10);

fn reconnects(bundle: &str, data: &str, fixture: &str, count: usize) -> Result<(), String> {
    let mut d = setup(bundle, data, "tracer reconnects")?;
    d.command(Command::Upload {
        source: PathBuf::from(fixture),
        destination: FIXTURE.into(),
        overwrite: true,
        executable: true,
    })?;
    let seconds = (count * 8 + 20).to_string();
    let run = d.launch(FIXTURE, &["slow", &seconds], 0)?;
    let mut bad = Vec::new();
    let mut took = Vec::new();
    for index in 0..count {
        thread::sleep(Duration::from_secs(5));
        let started = Instant::now();
        let message = d.command(Command::ReconnectTransport)?;
        let elapsed = started.elapsed();
        println!("RECONNECT {index} {} ms: {message}", elapsed.as_millis());
        took.push(elapsed);
        if elapsed > RECONNECT_BUDGET {
            bad.push(format!(
                "reconnect {index} took {} ms, over {} ms",
                elapsed.as_millis(),
                RECONNECT_BUDGET.as_millis()
            ));
        }
        // The continued run's status is unknown until the guest answers a poll.
        let id = run.clone();
        if d.wait("the run's status after the reconnect", 30, move |s| {
            s.runs
                .iter()
                .any(|r| r.id == id && r.state != RunState::Unknown)
        })
        .is_err()
            || d.run(&run)
                .is_none_or(|summary| summary.state != RunState::Running)
        {
            bad.push(format!(
                "the run is {:?} after reconnect {index}",
                d.run(&run).map(|summary| summary.state.clone())
            ));
            break;
        }
    }
    d.finished(&run, (count * 8 + 120) as u64)?;
    let summary = d.run(&run).ok_or("run missing")?.clone();
    d.command(Command::Stop)?;
    d.wait("VM stop", 90, |s| s.state == VmState::Stopped)?;
    thread::sleep(Duration::from_secs(2));
    let segments = recording::run_segments(&summary.directory, &summary.id, &summary.vm_id)
        .map_err(|e| e.to_string())?;
    result(format!(
        "reconnects: {} segments of run {}",
        segments.len(),
        summary.id
    ));
    if segments.len() != took.len() + 1 {
        bad.push(format!(
            "{} reconnects but {} segments",
            took.len(),
            segments.len()
        ));
    }
    took.sort();
    if let (Some(fastest), Some(slowest)) = (took.first(), took.last()) {
        result(format!(
            "reconnect times: fastest {} ms, median {} ms, slowest {} ms",
            fastest.as_millis(),
            took[took.len() / 2].as_millis(),
            slowest.as_millis()
        ));
    }
    if bad.is_empty() {
        println!("PASS reconnects");
        Ok(())
    } else {
        Err(bad.join("; "))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["record", bundle, data, fixture] => record(bundle, data, fixture),
        ["legacy", bundle, data, fixture] => legacy(bundle, data, fixture),
        ["reconnects", bundle, data, fixture] => reconnects(bundle, data, fixture, 10),
        ["reconnects", bundle, data, fixture, count] => count
            .parse()
            .map_err(|_| format!("bad reconnect count {count}"))
            .and_then(|count| reconnects(bundle, data, fixture, count)),
        _ => {
            eprintln!(
                "usage: tracer-check record|legacy|reconnects BUNDLE NEW_DATA_DIR FIXTURE [COUNT]"
            );
            std::process::exit(2);
        }
    };
    if let Err(error) = outcome {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}
