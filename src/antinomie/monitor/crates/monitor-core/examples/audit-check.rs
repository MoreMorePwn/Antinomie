// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM qualification of Stop escalation, run identity across a transport
//! reconnect, and process-core completeness.
//!
//!   audit-check stop      BUNDLE NEW_DATA_DIR FIXTURE
//!   audit-check reconnect BUNDLE NEW_DATA_DIR FIXTURE
//!   audit-check core      BUNDLE NEW_DATA_DIR FIXTURE
//!   audit-check hash      BUNDLE NEW_DATA_DIR PROBE
//!
//! FIXTURE is the static `tests/monitor/audit-fixture` program (PROBE is
//! `tests/monitor/creds-hash-probe`). The data folder must be new and
//! disposable. One BusyBox VM, one vCPU. Every result is a `RESULT` line.
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
    options: BackendOptions,
    snapshot: Snapshot,
    replies: BTreeMap<u64, Result<String, String>>,
    output: BTreeMap<String, String>,
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
                Notification::Terminal { run_id, data, .. } => {
                    self.output
                        .entry(run_id)
                        .or_default()
                        .push_str(&String::from_utf8_lossy(&data));
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
    fn output(&self, run: &str) -> &str {
        self.output.get(run).map_or("", String::as_str)
    }
    fn wait_text(&mut self, run: &str, needle: &str, seconds: u64) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.receive();
            if self.output(run).contains(needle) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let text = self.output(run);
                let start = text.len().saturating_sub(300);
                return Err(format!(
                    "output never contained {needle:?}; tail: {}",
                    &text[text.ceil_char_boundary(start)..]
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn run(&self, id: &str) -> Option<&RunSummary> {
        self.snapshot.runs.iter().find(|run| run.id == id)
    }
    /// Start `program` with `args`; returns the new run id once it has an identity.
    fn launch(&mut self, program: &str, args: &[&str], core: bool) -> Result<String, String> {
        let known: Vec<String> = self.snapshot.runs.iter().map(|r| r.id.clone()).collect();
        self.command(Command::Execute(ExecRequest {
            path: program.into(),
            args: args.iter().map(|a| (*a).to_string()).collect(),
            uid: 0,
            gid: 0,
            core_dump_on_exit: core,
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
    fn execution(&self, id: &str) -> Option<RunExecution> {
        self.run(id).and_then(|run| run.execution.clone())
    }
    fn describe(&self, id: &str) -> String {
        match (self.run(id), self.execution(id)) {
            (Some(run), Some(e)) => format!(
                "state {:?} root_exit {:?} flags {:#x} live {} total {}",
                run.state, e.root_exit, e.flags, e.live_task_count, e.total_task_count
            ),
            (Some(run), None) => format!("state {:?} (no execution status)", run.state),
            _ => "run missing".into(),
        }
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
        backend: Backend::new(options.clone())?,
        options,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        output: BTreeMap::new(),
        vm_id: String::new(),
    };
    driver.command(Command::Create(VmConfig {
        name: name.into(),
        cpus: 1,
        ram_mib: 1024,
        disk_gib: 1,
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
    Ok(driver)
}

fn upload(driver: &mut Driver, source: &str, destination: &str) -> Result<(), String> {
    driver
        .command(Command::Upload {
            source: PathBuf::from(source),
            destination: destination.into(),
            overwrite: false,
            executable: true,
        })
        .map(|_| ())
}

fn result(line: String) {
    println!("RESULT {line}");
}

fn stop_and_time(
    driver: &mut Driver,
    id: &str,
    label: &str,
    seconds: u64,
) -> Result<Duration, String> {
    let started = Instant::now();
    driver.command(Command::StopRun {
        run_id: id.to_string(),
    })?;
    let ack = started.elapsed();
    let outcome = driver.wait(&format!("{label} tree end"), seconds, |s| {
        s.runs.iter().any(|r| {
            r.id == id
                && r.execution
                    .as_ref()
                    .is_some_and(|e| e.flags & 2 != 0 && e.root_exit.is_some())
        })
    });
    let elapsed = started.elapsed();
    result(format!(
        "{label}: ack {} ms, ended={} after {} ms; {}",
        ack.as_millis(),
        outcome.is_ok(),
        elapsed.as_millis(),
        driver.describe(id)
    ));
    outcome.map(|()| elapsed)
}

fn stop(bundle: &str, data: &str, fixture: &str) -> Result<(), String> {
    let mut d = setup(bundle, data, "Stop qualification")?;
    upload(&mut d, fixture, "/tmp/audit-fixture")?;
    let mut failures = Vec::new();
    for (label, mode, ready) in [
        ("ignores-sigterm", "ignore-term", "IGNORE READY"),
        ("handles-sigterm", "handle-term", "HANDLE READY"),
        ("process-tree", "tree", "TREE READY"),
    ] {
        let id = d.launch("/tmp/audit-fixture", &[mode], false)?;
        d.wait_text(&id, ready, 20)?;
        d.wait("run status", 10, |s| {
            s.runs.iter().any(|r| r.id == id && r.execution.is_some())
        })?;
        result(format!("{label}: before stop {}", d.describe(&id)));
        if stop_and_time(&mut d, &id, label, 40).is_err() {
            failures.push(label);
        }
        // A second Stop on an ended run must be refused cleanly, not hang.
        let again = d.command(Command::StopRun { run_id: id.clone() });
        result(format!("{label}: second stop -> {again:?}"));
        thread::sleep(Duration::from_millis(500));
        result(format!("{label}: final {}", d.describe(&id)));
    }
    if failures.is_empty() {
        println!("PASS stop");
        Ok(())
    } else {
        Err(format!("runs that did not end: {failures:?}"))
    }
}

/// Run History as the app lists it, polled until `ready` holds: a new segment's
/// `run.json` is written by a background writer.
fn history_until(
    d: &mut Driver,
    seconds: u64,
    ready: impl Fn(&[RunSummary]) -> bool,
) -> Result<Vec<RunSummary>, String> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        d.receive();
        let history = recording::list_vm_runs(&d.options, &d.vm_id).map_err(|e| e.to_string())?;
        if ready(&history) || Instant::now() >= deadline {
            return Ok(history);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn brief(history: &[RunSummary]) -> String {
    format!(
        "{} record(s): {:?}",
        history.len(),
        history
            .iter()
            .map(|r| (
                r.id.chars().take(8).collect::<String>(),
                r.segments(),
                r.state.clone()
            ))
            .collect::<Vec<_>>()
    )
}

fn reconnect(bundle: &str, data: &str, fixture: &str) -> Result<(), String> {
    let mut d = setup(bundle, data, "Reconnect qualification")?;
    upload(&mut d, fixture, "/tmp/audit-fixture")?;
    let first = d.launch("/tmp/audit-fixture", &["ticks", "250"], false)?;
    d.wait_text(&first, "tick 8", 20)?;
    let second = d.launch("/tmp/audit-fixture", &["ignore-term"], false)?;
    d.wait_text(&second, "IGNORE READY", 20)?;
    let cookie = d.run(&first).map_or(0, |r| r.root_task_cookie);
    result(format!(
        "before reconnect: first {first} (cookie {cookie}), second {second}"
    ));
    let mut failures = Vec::new();
    for round in 1..=2usize {
        d.command(Command::ReconnectTransport)?;
        d.wait("run status after reconnect", 30, |s| {
            [&first, &second].iter().all(|id| {
                s.runs
                    .iter()
                    .any(|r| &r.id == *id && r.state == RunState::Running)
            })
        })?;
        let same = d.run(&first).is_some_and(|r| r.root_task_cookie == cookie);
        let history = history_until(&mut d, 15, |h| {
            h.len() == 2 && h.iter().all(|r| r.segments() == round + 1)
        })?;
        result(format!(
            "after reconnect {round}: ids kept {same}, history {}",
            brief(&history)
        ));
        if !same || history.len() != 2 || history.iter().any(|r| r.segments() != round + 1) {
            failures.push(format!("round {round}: {}", brief(&history)));
        }
    }
    // The program kept running through both reconnects and ends with its own code.
    d.wait("first run end", 90, |s| {
        s.runs.iter().any(|r| {
            r.id == first
                && r.execution
                    .as_ref()
                    .is_some_and(|e| e.flags & 2 != 0 && e.root_exit.is_some())
        })
    })?;
    result(format!("first run ended: {}", d.describe(&first)));
    if d.execution(&first).and_then(|e| e.root_exit) != Some(WaitStatus::Exited { code: 7 }) {
        failures.push("first run did not end with its own exit code".into());
    }
    // Stop by the id the UI knew before the reconnects.
    if let Err(error) = stop_and_time(&mut d, &second, "stop by pre-reconnect id", 40) {
        failures.push(format!("stop after reconnect: {error}"));
    }
    let history = history_until(&mut d, 15, |h| h.len() == 2)?;
    result(format!("final history: {}", brief(&history)));
    for record in &history {
        result(format!("notes of {}: {:?}", &record.id[..8], record.notes));
    }
    if history.len() != 2 {
        failures.push(format!("final history: {}", brief(&history)));
    }
    if failures.is_empty() {
        println!("PASS reconnect");
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn core(bundle: &str, data: &str, fixture: &str) -> Result<(), String> {
    let mut d = setup(bundle, data, "Core qualification")?;
    upload(&mut d, fixture, "/tmp/audit-fixture")?;
    // (label, mode, MiB, touch, how it ends)
    let cases = [
        ("small-all-exit", "heap-exit", "8", "all", "exit"),
        ("mid-all-exit", "heap-exit", "40", "all", "exit"),
        ("mid-all-stop", "heap", "40", "all", "stop"),
        ("big-sparse-exit", "heap-exit", "300", "sparse", "exit"),
        ("big-none-exit", "heap-exit", "300", "none", "exit"),
        ("big-none-stop", "heap", "300", "none", "stop"),
        ("mid-sparse-crash", "heap-crash", "100", "sparse", "exit"),
        ("over-limit-all", "heap-exit", "80", "all", "exit"),
    ];
    let mut bad = Vec::new();
    for (label, mode, mib, touch, end) in cases {
        let id = d.launch("/tmp/audit-fixture", &[mode, mib, touch], true)?;
        d.wait_text(&id, "HEAP READY", 90)?;
        if end == "stop" {
            d.command(Command::StopRun { run_id: id.clone() })?;
        }
        let directory = d.run(&id).ok_or("run missing")?.directory.clone();
        d.wait("core outcome", 120, |_| {
            RunArtifacts::load(&directory).is_ok_and(|a| {
                a.is_some_and(|a| {
                    matches!(
                        a.core_state,
                        RunArtifactState::Complete
                            | RunArtifactState::Partial
                            | RunArtifactState::Interrupted
                            | RunArtifactState::Failed
                    )
                })
            })
        })?;
        let artifacts = RunArtifacts::load(&directory)?.ok_or("artifacts missing")?;
        let size = artifacts
            .core_dump
            .as_ref()
            .and_then(|p| fs::metadata(p).ok())
            .map(|m| m.len());
        let expected = mib.parse::<u64>().unwrap_or(0) << 20;
        result(format!(
            "{label}: core {:?} size {size:?} (heap {expected} bytes) issues {:?}",
            artifacts.core_state, artifacts.issues
        ));
        let want_complete = label != "over-limit-all";
        let complete = artifacts.core_state == RunArtifactState::Complete;
        if complete != want_complete {
            bad.push(label);
        }
        if let Some(path) = &artifacts.core_dump {
            match core_dump::CoreDump::open(path) {
                Ok(opened) => result(format!(
                    "{label}: ELF threads {} mappings {}",
                    opened.threads.len(),
                    opened.mappings.len()
                )),
                Err(error) => result(format!("{label}: ELF open failed: {error}")),
            }
        }
        d.wait("run end", 60, |s| {
            s.runs.iter().any(|r| {
                r.id == id
                    && r.execution
                        .as_ref()
                        .is_some_and(|e| e.flags & 2 != 0 && e.root_exit.is_some())
            })
        })?;
        result(format!("{label}: {}", d.describe(&id)));
    }
    if bad.is_empty() {
        println!("PASS core");
        Ok(())
    } else {
        Err(format!("unexpected core outcomes: {bad:?}"))
    }
}

fn hash(bundle: &str, data: &str, probe: &str) -> Result<(), String> {
    let mut d = setup(bundle, data, "Hash qualification")?;
    upload(&mut d, probe, "/tmp/creds-hash-probe")?;
    let id = d.launch("/tmp/creds-hash-probe", &[], false)?;
    d.wait("probe end", 180, |s| {
        s.runs.iter().any(|r| {
            r.id == id
                && r.execution
                    .as_ref()
                    .is_some_and(|e| e.flags & 2 != 0 && e.root_exit.is_some())
        })
    })?;
    thread::sleep(Duration::from_secs(2));
    let directory = d.run(&id).ok_or("run missing")?.directory.clone();
    result(format!("probe: {}", d.describe(&id)));
    let text = d.output(&id).to_string();
    fs::write(PathBuf::from(data).join("probe-output.txt"), &text).map_err(|e| e.to_string())?;
    result(format!("run directory {}", directory.display()));
    println!("PASS hash (decode the records with kernel-notes-check)");
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [mode, bundle, data, fixture] = args.as_slice() else {
        eprintln!("usage: audit-check stop|reconnect|core|hash BUNDLE NEW_DATA_DIR FIXTURE");
        std::process::exit(2);
    };
    let outcome = match mode.as_str() {
        "stop" => stop(bundle, data, fixture),
        "reconnect" => reconnect(bundle, data, fixture),
        "core" => core(bundle, data, fixture),
        "hash" => hash(bundle, data, fixture),
        other => Err(format!("unknown mode {other}")),
    };
    if let Err(error) = outcome {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}
