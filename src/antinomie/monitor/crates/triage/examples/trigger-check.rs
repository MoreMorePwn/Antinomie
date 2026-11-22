// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM check of Dump on suspicious activity with the app's own Triage rules
//! and its own list of watched calls, on any architecture (ANT-T0426: on arm64
//! the live judge never saw a call, so the trigger never fired).
//!
//!   trigger-check BUNDLE NEW_DATA_DIR FIXTURE [FIXTURE32]
//!
//! One BusyBox VM, no network. Every run asks for a core at High:
//! * `shell`: `sh -c` writes a systemd unit and sleeps: persistence.systemd;
//! * `native`: FIXTURE (tests/monitor/trigger-fixture.c built for the VM's
//!   architecture) writes a cron entry and sleeps: persistence.cron;
//! * `compat`: the same program built for the 32-bit ABI (i386 on x86-64,
//!   AArch32 on arm64), when FIXTURE32 is given and exists (a host without
//!   the 32-bit compiler builds none: "SKIP compat"). It is judged on both;
//!   an AArch32 program gets its ELF32 core, an ia32 one on x86-64 never
//!   gets a core (the guest has no ia32 core writer), so there its core
//!   must be Failed with that reason;
//! * `quiet`: `sh -c 'sleep 2'`, which matches nothing at High;
//! * `fast` (a base of guest contract revision 22 or later, else SKIP):
//!   FIXTURE writes its cron entry and exits at once (SECONDS 0, about a
//!   millisecond later): the guest holds it at its exit (EXEC_EXIT_HOLD), so
//!   its core is still taken, and the run's note says it was held.
//! * `selfscan` (revision 22, ANT-T0596): FIXTURE starts as a daemon does
//!   (fork, fork, both parents exit at once) and the grandchild looks for a
//!   running copy of itself (/proc/*/exe, kill(pid, 0)) while the guest holds
//!   its exiting parents. It must find none, see that its parent was hidden
//!   (getppid() still names it while /proc no longer does), write its cron
//!   entry and stay: one trigger record with its core. The fixture's outcome
//!   line from the run's terminal is printed.
//!
//! * `dropexec-plain`, `-fork`, `-vfork` (ANT-T0591): FIXTURE copies itself to
//!   /tmp/.ntmrun.PID, makes it executable and executes it, itself, from a
//!   forked child or from a vfork child: execution.dropped_exec, fired at the
//!   execve. The core must be taken after the exec has finished, so it is of
//!   the new image (its process name is the dropped file's), and a core the
//!   guest cannot take must not use up the trigger's one core.
//!
//! * `dropexec-threads` (three more threads end inside the exec) and
//!   `dropexec-spawn` (the new image starts a helper with vfork and waits
//!   for it; the guest refuses the core until the helper starts a program,
//!   and the host asks again: the core is of the new image) and
//!   `dropexec-spawnlong` (the helper outlasts the retries: the refusal names
//!   it and is not counted, and the next match takes the core).
//!
//! The first three, `fast` and `selfscan` must have one trigger record whose core was written
//! (complete, or partial: pages not resident have no bytes; ia32 `compat`:
//! failed, as above); the
//! last none, and a note saying the trigger was armed but never matched. Every
//! program is benign. The data folder must be new and disposable.
#[path = "../../monitor-core/examples/support/serial_ready.rs"]
mod serial_ready;

use antinomie_monitor_core::dump_trigger::{DumpTrigger, TriggerTier};
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
    scale: u64,
    /// Every run's terminal output, in arrival order.
    terminal: Vec<u8>,
}

impl Driver {
    fn receive(&mut self) {
        while let Some(message) = self.backend.try_recv() {
            match message {
                Notification::Snapshot(snapshot) => self.snapshot = snapshot,
                Notification::Terminal { data, .. } => self.terminal.extend(data),
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
    fn command(&mut self, command: Command, seconds: u64) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(seconds * self.scale);
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
        let deadline = Instant::now() + Duration::from_secs(seconds * self.scale);
        loop {
            self.receive();
            if ready(&self.snapshot) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{label} timed out: {:?}", self.snapshot.last_error));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    fn boot(&mut self) -> Result<String, String> {
        self.command(
            Command::Create(VmConfig {
                name: "trigger check".into(),
                cpus: 2,
                ram_mib: 1024,
                disk_gib: 1,
                ..Default::default()
            }),
            120,
        )?;
        self.wait("VM publication", 10, |s| !s.vms.is_empty())?;
        let vm_id = self.snapshot.vms[0].id.clone();
        self.command(
            Command::Start {
                vm_id: vm_id.clone(),
            },
            300,
        )?;
        self.wait("guest", 180, |s| {
            s.guest_kernel.as_ref().and_then(|k| k.revision).is_some()
                && s.guest_tracer.is_some()
                && s.serial_log
                    .as_ref()
                    .and_then(|p| fs::read(p).ok())
                    .is_some_and(|log| serial_ready::ready(&log, b"BusyBox guest ready"))
        })?;
        thread::sleep(Duration::from_secs(3));
        Ok(vm_id)
    }
    fn start(&mut self, path: &str, args: &[&str]) -> Result<String, String> {
        let known: Vec<String> = self.snapshot.runs.iter().map(|r| r.id.clone()).collect();
        self.command(
            Command::Execute(ExecRequest {
                path: path.into(),
                args: args.iter().map(|a| (*a).to_owned()).collect(),
                uid: 0,
                gid: 0,
                cwd: "/tmp".into(),
                core_max_size: Some(64 << 20),
                core_timeout_ms: Some(30_000),
                dump_trigger: Some(DumpTrigger {
                    min_tier: TriggerTier::High,
                    memory: false,
                    core: true,
                    max_cores: 1,
                    max_memory_dumps: 1,
                    cooldown_secs: 30,
                    memory_max_mib: 0,
                }),
                ..Default::default()
            }),
            60,
        )?;
        self.wait("run publication", 15, |s| {
            s.runs.iter().any(|r| !known.contains(&r.id))
        })?;
        Ok(self
            .snapshot
            .runs
            .iter()
            .find(|r| !known.contains(&r.id))
            .ok_or("new run missing")?
            .id
            .clone())
    }
    /// The run once it ended and its trigger settled: its core is no longer
    /// being taken and its notes say what the trigger did.
    fn settled(&mut self, vm_id: &str, id: &str) -> Result<RunSummary, String> {
        self.wait("run end", 120, |s| {
            s.runs
                .iter()
                .any(|r| r.id == id && matches!(r.state, RunState::Finished | RunState::Stopped))
        })?;
        let deadline = Instant::now() + Duration::from_secs(60 * self.scale);
        loop {
            self.receive();
            let saved = recording::list_vm_runs(&self.options, vm_id)
                .ok()
                .and_then(|runs| runs.into_iter().find(|r| r.id == id));
            if let Some(run) = saved {
                let pending = run
                    .triggers
                    .as_ref()
                    .is_some_and(|log| log.records.iter().any(|r| r.pending()));
                let said = run.triggers.is_some() || run.notes.iter().any(|n| n.contains("armed"));
                if !pending && said {
                    return Ok(run);
                }
                if Instant::now() >= deadline {
                    return Ok(run);
                }
            } else if Instant::now() >= deadline {
                return Err("run.json missing".into());
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
}

fn describe(run: &RunSummary) -> String {
    format!(
        "state {:?}; notes {:?}; triggers {}",
        run.state,
        run.notes,
        serde_json::to_string(&run.triggers).unwrap_or_default()
    )
}

/// The core of a dropped program is of the new image: its process name, in
/// the notes at the start of the file, is the dropped file's.
fn new_image(core: &antinomie_monitor_core::dump_trigger::TriggerDump) -> Result<(), String> {
    let path = core.path.as_ref().ok_or("no core file")?;
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let head = &bytes[..bytes.len().min(16 << 10)];
    if head.windows(8).any(|w| w == b".ntmrun.") {
        Ok(())
    } else {
        Err("the core is of the dropper, not of the dropped program".into())
    }
}

/// `dropexec-spawnlong`: the dropped program starts a helper with vfork at
/// once that outlasts the host's retries, and while it waits for it the guest
/// cannot pause it (`dropexec-spawn`, whose helper starts a program after
/// 1.5 s, gets its core on a retry). Either the first core is refused, the
/// reason names the started program, the refusal does not use up the
/// trigger's one core, and the later match (the program writes a cron entry
/// once the helper is done) takes it; or the core of the new image lands
/// before the helper's vfork (a race of the fixture, correct behaviour): the
/// first core is Complete, not refused, and the only one that counts. The
/// branch taken is printed. Either way at most `max_cores` (1) cores count.
fn spawned(run: &RunSummary) -> Result<(), String> {
    let log = run.triggers.as_ref().ok_or("no trigger log")?;
    let first = log.records.first().ok_or("no trigger record")?;
    let core = first.core.as_ref().ok_or("no core asked")?;
    if first.finding.rule != "execution.dropped_exec" {
        return Err(format!("first trigger by {}", first.finding.rule));
    }
    let counted = log.records.iter().filter(|record| record.counts()).count();
    if counted > 1 {
        return Err(format!(
            "{counted} records count, the trigger allows one core"
        ));
    }
    if !core.refused && matches!(core.state, RunArtifactState::Complete) {
        if !first.counts() {
            return Err("the first core is Complete but does not count".into());
        }
        new_image(core)?;
        println!("SPAWNLONG branch: core before the helper's vfork (first core Complete, the only one counted)");
        return Ok(());
    }
    if !(core.refused && matches!(core.state, RunArtifactState::Failed)) {
        return Err(format!(
            "the first core {:?} (refused {}): {:?}, expected a refused one or a Complete one",
            core.state, core.refused, core.error
        ));
    }
    let error = core.error.as_deref().unwrap_or_default();
    if !error.contains("another program") || !error.contains("did not use up") {
        return Err(format!("the refusal does not say what it was: {error}"));
    }
    let taken = log
        .records
        .iter()
        .skip(1)
        .filter_map(|record| record.core.as_ref())
        .any(|core| {
            matches!(
                core.state,
                RunArtifactState::Complete | RunArtifactState::Partial
            ) && core.path.as_ref().is_some_and(|path| path.is_file())
        });
    if !taken {
        return Err("no later match took the core the refusal left".into());
    }
    println!("SPAWNLONG branch: first core refused (not counted), a later match took the core");
    Ok(())
}

/// One trigger record of `rule`, whose core was written.
fn fired(run: &RunSummary, rule: &str, ia32: bool) -> Result<(), String> {
    let log = run.triggers.as_ref().ok_or("no trigger log")?;
    let record = log
        .records
        .first()
        .ok_or_else(|| format!("no trigger record (missed {:?})", log.missed))?;
    if record.finding.rule != rule || record.finding.tier != TriggerTier::High {
        return Err(format!(
            "trigger by {}, expected {rule}",
            record.finding.rule_with_tier()
        ));
    }
    let core = record.core.as_ref().ok_or("no core asked")?;
    // An ia32 program on x86-64: the trigger fires, the core is refused
    // with the documented reason (core_limits.rs, guest status -95).
    if ia32 {
        let refused = matches!(core.state, RunArtifactState::Failed)
            && core.error.as_deref().is_some_and(|e| e.contains("ia32"));
        if !refused {
            return Err(format!(
                "ia32 core {:?}: {:?}, expected Failed (no ia32 core writer)",
                core.state, core.error
            ));
        }
        return Ok(());
    }
    // Partial is a core whose non-resident pages have no bytes (the guest
    // reads resident pages only): taken, as a sleeping static program's is.
    let written = core.path.as_ref().is_some_and(|path| path.is_file());
    if !matches!(
        core.state,
        RunArtifactState::Complete | RunArtifactState::Partial
    ) || !written
    {
        return Err(format!("core {:?}: {:?}", core.state, core.error));
    }
    Ok(())
}

fn quiet(run: &RunSummary) -> Result<(), String> {
    if run
        .triggers
        .as_ref()
        .is_some_and(|log| !log.records.is_empty())
    {
        return Err("a trigger fired on a program that matches nothing".into());
    }
    if !run
        .notes
        .iter()
        .any(|n| n.starts_with("Dump trigger armed") && n.contains("no rule of that tier matched"))
    {
        return Err("no note says the trigger was armed but never matched".into());
    }
    Ok(())
}

fn check(bundle: &str, data: &str, native: &str, compat: Option<&str>) -> Result<(), String> {
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("the check needs a new disposable data folder".into());
    }
    fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    // What the app does at start: its rules judge, its list filters.
    antinomie_triage::live_judge::register();
    let arm64 = fs::read_to_string(PathBuf::from(bundle).join("bundle.json"))
        .is_ok_and(|text| text.contains("\"arm64\""));
    let options = BackendOptions {
        bundle_dir: PathBuf::from(bundle),
        data_dir: data,
        headless: true,
        serial_console: true,
        capture_quota_size: 1024 * 1024 * 1024,
        reduced_keep_calls: antinomie_triage::rules::watched_calls(),
        ..Default::default()
    };
    let mut d = Driver {
        backend: Backend::new(options.clone())?,
        options,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        scale: if arm64 { 8 } else { 1 },
        terminal: Vec::new(),
    };
    let vm_id = d.boot()?;
    let mut programs = vec![("native", native)];
    match compat {
        Some(path) if PathBuf::from(path).is_file() => programs.push(("compat", path)),
        Some(path) => println!("SKIP compat: no {path}"),
        None => {}
    }
    for (name, path) in &programs {
        d.command(
            Command::Upload {
                source: PathBuf::from(path),
                destination: format!("/tmp/trigger-{name}"),
                overwrite: true,
                executable: true,
            },
            120,
        )?;
    }
    let mut errors = Vec::new();
    let unit = "mkdir -p /etc/systemd/system && printf '[Service]\\nExecStart=/bin/true\\n' > /etc/systemd/system/antinomie-trigger.service && sleep 20";
    let mut cases: Vec<(&str, String, Vec<String>, Option<&str>)> = vec![(
        "shell",
        "/bin/sh".into(),
        vec!["-c".into(), unit.into()],
        Some("persistence.systemd"),
    )];
    for (name, _) in &programs {
        cases.push((
            name,
            format!("/tmp/trigger-{name}"),
            vec![format!("antinomie-{name}"), "20".into()],
            Some("persistence.cron"),
        ));
    }
    for mode in ["plain", "fork", "vfork", "threads", "spawn", "spawnlong"] {
        cases.push((
            match mode {
                "plain" => "dropexec-plain",
                "fork" => "dropexec-fork",
                "threads" => "dropexec-threads",
                "spawn" => "dropexec-spawn",
                "spawnlong" => "dropexec-spawnlong",
                _ => "dropexec-vfork",
            },
            "/tmp/trigger-native".into(),
            vec!["--dropexec".into(), mode.into(), "20".into()],
            Some("execution.dropped_exec"),
        ));
    }
    cases.push((
        "quiet",
        "/bin/sh".into(),
        vec!["-c".into(), "sleep 2".into()],
        None,
    ));
    let holds = d
        .snapshot
        .guest_kernel
        .as_ref()
        .and_then(|kernel| kernel.revision)
        .is_some_and(|revision| revision >= 22);
    if holds {
        cases.push((
            "fast",
            "/tmp/trigger-native".into(),
            vec!["antinomie-fast".into(), "0".into()],
            Some("persistence.cron"),
        ));
        // Waits 3 ms (KVM) after its parent's exit started, inside the hold
        // (at least HOLD_GRACE, scaled like the hold under TCG).
        cases.push((
            "selfscan",
            "/tmp/trigger-native".into(),
            vec!["--selfscan".into(), "20".into(), (3 * d.scale).to_string()],
            Some("persistence.cron"),
        ));
    } else {
        println!("SKIP fast, selfscan: the base has no exit hold (revision 22)");
    }
    // TRIGGER_CHECK_ONLY=prefix keeps the cases whose name starts with it.
    let only = std::env::var("TRIGGER_CHECK_ONLY").unwrap_or_default();
    for (name, path, args, rule) in cases {
        if !name.starts_with(only.as_str()) {
            continue;
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let outcome = d.start(&path, &args).and_then(|id| {
            let run = d.settled(&vm_id, &id)?;
            println!("RUN {name} {id}: {}", describe(&run));
            match rule {
                Some(_) if name == "dropexec-spawnlong" => spawned(&run),
                Some(rule) => fired(&run, rule, name == "compat" && !arm64).and_then(|()| {
                    if name.starts_with("dropexec") {
                        let core = run.triggers.as_ref().and_then(|log| log.records.first());
                        new_image(core.and_then(|r| r.core.as_ref()).ok_or("no core")?)?;
                        // The trigger's one core: a refused try that was asked
                        // again must not leave a second core beside it.
                        let taken = run.triggers.as_ref().map_or(0, |log| {
                            log.records
                                .iter()
                                .filter(|r| {
                                    r.core.as_ref().is_some_and(|c| {
                                        matches!(c.state, RunArtifactState::Complete)
                                    })
                                })
                                .count()
                        });
                        if taken > 1 {
                            return Err(format!("{taken} cores taken, the trigger allows one"));
                        }
                    }
                    // The exit hold is what made the core possible.
                    if name == "fast"
                        && !run
                            .triggers
                            .as_ref()
                            .is_some_and(|log| log.records.iter().any(|record| record.held))
                    {
                        return Err(
                            "the fast program's trigger record does not say it was held".into()
                        );
                    }
                    Ok(())
                }),
                None => quiet(&run),
            }
        });
        if name == "selfscan" {
            let text = String::from_utf8_lossy(&d.terminal).into_owned();
            let said = text
                .lines()
                .rev()
                .find(|line| line.contains("TRIGGER-FIXTURE selfscan"))
                .map(|line| line.trim().to_owned());
            println!(
                "SELFSCAN {}",
                said.as_deref()
                    .unwrap_or("(no outcome line in the terminal)")
            );
        }
        match outcome {
            Ok(()) => println!("PASS {name}"),
            Err(error) => {
                println!("FAIL {name}: {error}");
                errors.push(format!("{name}: {error}"));
            }
        }
    }
    let _ = d.command(Command::Stop, 120);
    let _ = d.wait("VM stop", 120, |s| s.state == VmState::Stopped);
    let _ = d.command(Command::Close, 30);
    if errors.is_empty() {
        println!("TRIGGER-CHECK DONE");
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (bundle, data, native, compat) = match args.as_slice() {
        [bundle, data, native] => (*bundle, *data, *native, None),
        [bundle, data, native, compat] => (*bundle, *data, *native, Some(*compat)),
        _ => {
            eprintln!("usage: trigger-check BUNDLE NEW_DATA_DIR FIXTURE [FIXTURE32]");
            std::process::exit(2);
        }
    };
    if let Err(error) = check(bundle, data, native, compat) {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}
