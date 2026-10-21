// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM qualification of how a run that uses io_uring (or AIO) reports its
//! status: the root's wait status, the tree's end and the async count come from
//! the guest's RUN_STATUS, never from terminal EOF or a workload marker, and a
//! worker thread of the kernel never leaves the status inconsistent.
//!
//!   uring-check status BUNDLE NEW_DATA_DIR TORTURE FIXTURE
//!   uring-check boots  BUNDLE NEW_DATA_DIR TORTURE FIXTURE [COUNT]
//!   uring-check legacy BUNDLE NEW_DATA_DIR TORTURE FIXTURE
//!   uring-check record BUNDLE NEW_DATA_DIR TORTURE FIXTURE
//!
//! TORTURE is the static `ant-torture` sample and FIXTURE the static
//! `tests/monitor/uring-fixture` program. `status` runs every case with and
//! without a core on exit: the torture async-io module, linked pairs on
//! workers, cancellation, requests pending at exit, a kernel submission thread,
//! a root that exits from a non-leader thread, a crash, and Stop of a run
//! with workers (with and without a handled SIGTERM). `boots` repeats the
//! hardest cases on COUNT fresh boots (default 3). `legacy` is for a base
//! from before the io_uring worker accounting: the host must still reach
//! Finished, with the root's exit code unknown or right, never invented.
//! `record` runs the file stories Triage reads (io_uring, AIO and plain system
//! calls on one file, an SQPOLL ring, sync, splice, attribute and directory
//! requests, a script exec, the torture async-io module) on four vCPUs, stops the
//! VM so the recordings are complete, and prints a `RUN label=directory` line
//! for each; the ignored test `recorded_uring_triage` of the app's triage
//! module reads them (see its documentation). The data folder must be new and
//! disposable. Every result is a `RESULT` line.
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

fn setup(bundle: &str, data: &str, name: &str, cpus: u16) -> Result<Driver, String> {
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
        cpus,
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

/// The guest disk keeps `/tmp` across a VM restart, so a later boot of `boots`
/// replaces the copy the first boot made.
fn upload(driver: &mut Driver, source: &str, destination: &str) -> Result<(), String> {
    driver
        .command(Command::Upload {
            source: PathBuf::from(source),
            destination: destination.into(),
            overwrite: true,
            executable: true,
        })
        .map(|_| ())
}

fn result(line: String) {
    println!("RESULT {line}");
}

/// How a program must end.
#[derive(Clone, Copy, Debug)]
enum End {
    Exit(u8),
    Signal(u8),
}

impl End {
    fn matches(self, status: &WaitStatus) -> bool {
        match (self, status) {
            (End::Exit(want), WaitStatus::Exited { code }) => want == *code,
            (End::Signal(want), WaitStatus::Signaled { signal, .. }) => want == *signal,
            _ => false,
        }
    }
}

struct Case {
    label: &'static str,
    program: &'static str,
    args: &'static [&'static str],
    end: End,
    /// Whether the guest is expected to have worker threads of its own at exit
    /// (io-wq, SQPOLL), which the run counts as tasks.
    workers: bool,
    /// The leader left before the rest of the process: its register state is
    /// gone, so a core of the others is Partial for exactly that reason.
    leaderless: bool,
}

const TORTURE: &str = "/tmp/ant-torture";
const FIXTURE: &str = "/tmp/uring-fixture";

const CASES: &[Case] = &[
    Case {
        label: "torture-async-io",
        program: TORTURE,
        args: &["--only", "async-io", "--level", "light"],
        end: End::Exit(0),
        workers: true,
        leaderless: false,
    },
    Case {
        label: "linked-pairs",
        program: FIXTURE,
        args: &["pairs", "8"],
        end: End::Exit(3),
        workers: true,
        leaderless: false,
    },
    Case {
        label: "cancellation",
        program: FIXTURE,
        args: &["cancel"],
        end: End::Exit(4),
        workers: true,
        leaderless: false,
    },
    Case {
        label: "async-drain-at-exit",
        program: FIXTURE,
        args: &["drain"],
        end: End::Exit(5),
        workers: true,
        leaderless: false,
    },
    Case {
        label: "sqpoll",
        program: FIXTURE,
        args: &["sqpoll"],
        end: End::Exit(6),
        workers: true,
        leaderless: false,
    },
    Case {
        label: "threaded-root-exit",
        program: FIXTURE,
        args: &["threads"],
        end: End::Exit(9),
        workers: true,
        leaderless: true,
    },
    Case {
        label: "crash",
        program: FIXTURE,
        args: &["crash"],
        end: End::Signal(11),
        workers: true,
        leaderless: false,
    },
    Case {
        label: "aio",
        program: FIXTURE,
        args: &["aio"],
        end: End::Exit(0),
        workers: false,
        leaderless: false,
    },
];

/// What `watch` saw while a run ended.
struct Watched {
    generations: Vec<u64>,
    errors: Vec<String>,
    ended: bool,
    elapsed: Duration,
}

impl Driver {
    /// Poll until the run is `Finished` or `Stopped`, or `seconds` pass, keeping
    /// every generation and every inconsistent-status error that was reported.
    fn watch(&mut self, id: &str, seconds: u64) -> Watched {
        let started = Instant::now();
        let deadline = started + Duration::from_secs(seconds);
        let mut watched = Watched {
            generations: Vec::new(),
            errors: Vec::new(),
            ended: false,
            elapsed: Duration::ZERO,
        };
        loop {
            self.receive();
            if let Some(error) = self
                .snapshot
                .last_error
                .as_ref()
                .filter(|error| !watched.errors.contains(error))
            {
                watched.errors.push(error.clone());
            }
            if let Some(execution) = self
                .execution(id)
                .filter(|e| watched.generations.last() != Some(&e.generation))
            {
                watched.generations.push(execution.generation);
            }
            if self
                .run(id)
                .is_some_and(|r| matches!(r.state, RunState::Finished | RunState::Stopped))
            {
                watched.ended = true;
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        watched.elapsed = started.elapsed();
        // The status stays readable after the end.
        thread::sleep(Duration::from_millis(500));
        self.receive();
        watched
    }
}

/// The checks every ended run must pass; each failure is a message.
fn check_end(
    d: &Driver,
    id: &str,
    case: &Case,
    watched: &Watched,
    first: (&str, u64),
    strict_root: bool,
) -> Vec<String> {
    let mut bad = Vec::new();
    let Some(run) = d.run(id) else {
        return vec!["run disappeared".into()];
    };
    if run.id != first.0 || run.root_task_cookie != first.1 {
        bad.push("run id or root cookie changed".into());
    }
    if !watched.ended {
        bad.push(format!(
            "no authoritative end within the deadline: state {:?}",
            run.state
        ));
    }
    // A late or unmatched reply on a loaded VM is a transport timeout the
    // host recovers from; an inconsistent reply is the defect.
    if let Some(error) = watched
        .errors
        .iter()
        .find(|e| e.contains("inconsistent run status"))
    {
        bad.push(format!("status error reported: {error}"));
    }
    if watched.generations.windows(2).any(|pair| pair[1] < pair[0]) {
        bad.push(format!("generation went back: {:?}", watched.generations));
    }
    let Some(execution) = &run.execution else {
        bad.push("execution status is null".into());
        return bad;
    };
    if execution.live_task_count != 0 || execution.pending_async_count != 0 {
        bad.push(format!(
            "tasks or requests left: live {} pending {}",
            execution.live_task_count, execution.pending_async_count
        ));
    }
    if execution.flags & 2 == 0 {
        bad.push("tree not reported ended".into());
    }
    match &execution.root_exit {
        Some(status) if case.end.matches(status) => {}
        Some(status) => bad.push(format!("root ended {status:?}, wanted {:?}", case.end)),
        None if strict_root => bad.push("root wait status not recorded".into()),
        None if !execution.root_status_missing() => {
            bad.push("no root status and not reported as missing".into())
        }
        None => {}
    }
    if strict_root && case.workers && execution.total_task_count < 2 {
        bad.push(format!(
            "worker threads not counted: total {}",
            execution.total_task_count
        ));
    }
    bad
}

fn core_checks(
    d: &mut Driver,
    id: &str,
    case: &Case,
    total: u64,
    strict: bool,
) -> Result<Vec<String>, String> {
    let directory = d.run(id).ok_or("run missing")?.directory.clone();
    d.wait("core outcome", 90, |_| {
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
    let mut bad = Vec::new();
    let threads = artifacts
        .core_dump
        .as_ref()
        .and_then(|path| core_dump::CoreDump::open(path).ok())
        .map(|opened| opened.threads.len());
    result(format!(
        "{}: core {:?} size {:?} ELF threads {threads:?} run total {total}",
        case.label, artifacts.core_state, artifacts.core_saved_size
    ));
    let thread_context_only = artifacts
        .issues
        .iter()
        .all(|issue| issue.contains("thread context"));
    if case.leaderless && artifacts.core_state == RunArtifactState::Partial && thread_context_only {
        // The exited leader has no registers to dump; everything else is there.
    } else if artifacts.core_state != RunArtifactState::Complete {
        bad.push(format!(
            "core {:?}: {:?}",
            artifacts.core_state, artifacts.issues
        ));
    }
    if let Some(threads) = threads.filter(|threads| strict && *threads as u64 > total) {
        bad.push(format!("core has {threads} threads, run counted {total}"));
    }
    Ok(bad)
}

fn run_case(d: &mut Driver, case: &Case, core: bool, strict_root: bool) -> Result<bool, String> {
    let label = format!("{}{}", case.label, if core { "+core" } else { "" });
    let id = d.launch(case.program, case.args, core)?;
    let first = d
        .run(&id)
        .map(|r| (r.id.clone(), r.root_task_cookie))
        .ok_or("run missing")?;
    let watched = d.watch(&id, 60);
    let mut bad = check_end(d, &id, case, &watched, (&first.0, first.1), strict_root);
    result(format!(
        "{label}: {} after {} ms; generations {}; status errors {:?}",
        d.describe(&id),
        watched.elapsed.as_millis(),
        watched.generations.len(),
        watched.errors
    ));
    if let Some(execution) = d.execution(&id) {
        result(format!(
            "{label}: total tasks {} loss {} observation_incomplete {} root_status_missing {}",
            execution.total_task_count,
            execution.async_loss_count,
            execution.observation_incomplete(),
            execution.root_status_missing()
        ));
    }
    if core && !matches!(case.end, End::Signal(9)) {
        let total = d.execution(&id).map_or(0, |e| e.total_task_count);
        bad.extend(core_checks(d, &id, case, total, strict_root)?);
    }
    // The saved record says the same as the live status. It is written by the
    // persistence thread, which a loaded host can hold back for a while.
    let history = history_until(d, 60, |h| {
        h.iter()
            .any(|r| r.id == id && r.state == RunState::Finished)
    })?;
    if !history.iter().any(|r| {
        r.id == id
            && r.state == RunState::Finished
            && r.execution
                .as_ref()
                .is_some_and(|e| e.flags & 2 != 0 && (e.root_exit.is_some() || !strict_root))
    }) {
        bad.push("Run History does not hold the finished execution".into());
    }
    result(format!(
        "{label}: {}",
        if bad.is_empty() {
            "ok".to_string()
        } else {
            format!("FAILED {bad:?}")
        }
    ));
    Ok(bad.is_empty())
}

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

/// Status runs use two vCPUs, so a worker thread and the leader can leave at
/// the same time. Recordings use four: a task moves between vCPUs and a
/// worker publishes for a call (an unlink's hash) on another vCPU than the
/// call's, and the stories must still read in the order they happened.
const STATUS_CPUS: u16 = 2;
const RECORD_CPUS: u16 = 4;

fn prepare(
    bundle: &str,
    data: &str,
    name: &str,
    torture: &str,
    fixture: &str,
    cpus: u16,
) -> Result<Driver, String> {
    let mut d = setup(bundle, data, name, cpus)?;
    upload(&mut d, torture, TORTURE)?;
    upload(&mut d, fixture, FIXTURE)?;
    Ok(d)
}

fn status(bundle: &str, data: &str, torture: &str, fixture: &str) -> Result<(), String> {
    let mut d = prepare(
        bundle,
        data,
        "io_uring status",
        torture,
        fixture,
        STATUS_CPUS,
    )?;
    let mut failed = Vec::new();
    for core in [false, true] {
        for case in CASES {
            if !run_case(&mut d, case, core, true)? {
                failed.push(format!("{}{}", case.label, if core { "+core" } else { "" }));
            }
        }
    }
    stop_cases(&mut d, &mut failed)?;
    finish("status", failed)
}

/// Stop of a run that has worker threads and requests pending on them.
fn stop_cases(d: &mut Driver, failed: &mut Vec<String>) -> Result<(), String> {
    for (label, mode, signal, escalated) in [
        ("stop-hold", "hold", 15u8, false),
        ("stop-hold-ignore-term", "hold-ignore", 9u8, true),
    ] {
        for core in [false, true] {
            let name = format!("{label}{}", if core { "+core" } else { "" });
            let id = d.launch(FIXTURE, &[mode], core)?;
            d.wait_text(&id, "URING READY", 30)?;
            d.command(Command::StopRun { run_id: id.clone() })?;
            let watched = d.watch(&id, 60);
            let execution = d.execution(&id);
            let ok = watched.ended
                && execution.as_ref().is_some_and(|e| {
                    e.live_task_count == 0
                        && e.pending_async_count == 0
                        && e.kill_escalated() == escalated
                        && matches!(e.root_exit, Some(WaitStatus::Signaled { signal: s, .. }) if s == signal)
                })
                && d.run(&id).is_some_and(|r| r.state == RunState::Stopped)
                && !watched
                    .errors
                    .iter()
                    .any(|e| e.contains("inconsistent run status"));
            result(format!(
                "{name}: {} after {} ms -> {}",
                d.describe(&id),
                watched.elapsed.as_millis(),
                if ok { "ok" } else { "FAILED" }
            ));
            if !ok {
                failed.push(name);
            }
        }
    }
    Ok(())
}

/// One recorded run for the triage test: wait for the end and note where it is.
fn record_run(
    d: &mut Driver,
    labels: &mut Vec<(String, PathBuf)>,
    label: &str,
    program: &str,
    args: &[&str],
) -> Result<(), String> {
    let id = d.launch(program, args, false)?;
    let watched = d.watch(&id, 90);
    result(format!(
        "{label}: {} after {} ms",
        d.describe(&id),
        watched.elapsed.as_millis()
    ));
    if !watched.ended {
        return Err(format!("{label} did not end"));
    }
    let directory = d.run(&id).ok_or("run missing")?.directory.clone();
    labels.push((label.to_string(), directory));
    Ok(())
}

fn record(bundle: &str, data: &str, torture: &str, fixture: &str) -> Result<(), String> {
    let mut d = prepare(
        bundle,
        data,
        "io_uring record",
        torture,
        fixture,
        RECORD_CPUS,
    )?;
    let mut runs = Vec::new();
    record_run(&mut d, &mut runs, "files", FIXTURE, &["files"])?;
    record_run(&mut d, &mut runs, "regfiles", FIXTURE, &["regfiles"])?;
    record_run(&mut d, &mut runs, "syncfiles", FIXTURE, &["syncfiles"])?;
    record_run(&mut d, &mut runs, "aio", FIXTURE, &["aio"])?;
    record_run(&mut d, &mut runs, "sqfiles", FIXTURE, &["sqfiles"])?;
    record_run(&mut d, &mut runs, "morefiles", FIXTURE, &["morefiles"])?;
    record_run(
        &mut d,
        &mut runs,
        "script",
        FIXTURE,
        &["script", "/tmp/uring-script.sh"],
    )?;
    record_run(
        &mut d,
        &mut runs,
        "async-io",
        TORTURE,
        &["--only", "async-io", "--level", "light"],
    )?;
    // The recordings are complete when the VM has stopped.
    d.command(Command::Stop)?;
    d.wait("VM stop", 90, |s| s.state == VmState::Stopped)?;
    thread::sleep(Duration::from_secs(2));
    for (label, directory) in &runs {
        println!("RUN {label}={}", directory.display());
    }
    println!("PASS record");
    Ok(())
}

fn finish(mode: &str, failed: Vec<String>) -> Result<(), String> {
    if failed.is_empty() {
        println!("PASS {mode}");
        Ok(())
    } else {
        Err(format!("cases that failed: {failed:?}"))
    }
}

/// Fresh boots in a row: the hardest cases each time, so a rare ordering of
/// the workers' exit cannot hide behind one lucky boot.
fn boots(
    bundle: &str,
    data: &str,
    torture: &str,
    fixture: &str,
    count: usize,
) -> Result<(), String> {
    let mut d = prepare(
        bundle,
        data,
        "io_uring boots",
        torture,
        fixture,
        STATUS_CPUS,
    )?;
    let mut failed = Vec::new();
    for boot in 1..=count {
        if boot > 1 {
            let previous = d.snapshot.boot_id.clone();
            d.command(Command::Stop)?;
            d.wait("VM stop", 60, |s| s.state == VmState::Stopped)?;
            let vm_id = d.vm_id.clone();
            d.command(Command::Start { vm_id })?;
            d.wait("new boot", 180, |s| {
                s.state == VmState::Running && s.boot_id.is_some() && s.boot_id != previous
            })?;
            d.wait("guest ready", 120, |s| {
                s.guest_kernel
                    .as_ref()
                    .and_then(|k| k.revision)
                    .is_some_and(|r| r >= 17)
                    && s.serial_log
                        .as_ref()
                        .and_then(|p| fs::read(p).ok())
                        .is_some_and(|log| {
                            log.windows(19).any(|part| part == b"BusyBox guest ready")
                        })
            })?;
            upload(&mut d, torture, TORTURE)?;
            upload(&mut d, fixture, FIXTURE)?;
        }
        result(format!("boot {boot} of {count}: {:?}", d.snapshot.boot_id));
        for case in CASES
            .iter()
            .filter(|c| matches!(c.label, "torture-async-io" | "threaded-root-exit" | "crash"))
        {
            for core in [true, false] {
                if !run_case(&mut d, case, core, true)? {
                    failed.push(format!(
                        "boot {boot} {}{}",
                        case.label,
                        if core { "+core" } else { "" }
                    ));
                }
            }
        }
    }
    finish("boots", failed)
}

fn legacy(bundle: &str, data: &str, torture: &str, fixture: &str) -> Result<(), String> {
    let mut d = prepare(
        bundle,
        data,
        "io_uring legacy",
        torture,
        fixture,
        STATUS_CPUS,
    )?;
    let mut failed = Vec::new();
    for core in [false, true] {
        for case in CASES.iter().filter(|c| c.label != "crash") {
            if !run_case(&mut d, case, core, false)? {
                failed.push(format!("{}{}", case.label, if core { "+core" } else { "" }));
            }
        }
    }
    finish("legacy", failed)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["status", bundle, data, torture, fixture] => status(bundle, data, torture, fixture),
        ["legacy", bundle, data, torture, fixture] => legacy(bundle, data, torture, fixture),
        ["record", bundle, data, torture, fixture] => record(bundle, data, torture, fixture),
        ["boots", bundle, data, torture, fixture] => boots(bundle, data, torture, fixture, 3),
        ["boots", bundle, data, torture, fixture, count] => count
            .parse()
            .map_err(|_| "COUNT must be a number".to_string())
            .and_then(|count| boots(bundle, data, torture, fixture, count)),
        _ => {
            eprintln!(
                "usage: uring-check status|legacy|record|boots BUNDLE NEW_DATA_DIR TORTURE FIXTURE [COUNT]"
            );
            std::process::exit(2);
        }
    };
    if let Err(error) = outcome {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}
