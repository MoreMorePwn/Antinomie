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
//!   the 32-bit compiler builds none: "SKIP compat");
//! * `quiet`: `sh -c 'sleep 2'`, which matches nothing at High;
//! * `fast` (a base of guest contract revision 22 or later, else SKIP):
//!   FIXTURE writes its cron entry and exits at once (SECONDS 0, about a
//!   millisecond later): the guest holds it at its exit (EXEC_EXIT_HOLD), so
//!   its core is still taken, and the run's note says it was held.
//!
//! The first three and `fast` must have one trigger record whose core was written
//! (complete, or partial: pages not resident have no bytes); the
//! last none, and a note saying the trigger was armed but never matched. Every
//! program is benign. The data folder must be new and disposable.
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
                    .is_some_and(|log| log.windows(19).any(|w| w == b"BusyBox guest ready"))
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
                    max_dumps: 1,
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

/// One trigger record of `rule`, whose core was written.
fn fired(run: &RunSummary, rule: &str) -> Result<(), String> {
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
    } else {
        println!("SKIP fast: the base has no exit hold (revision 22)");
    }
    for (name, path, args, rule) in cases {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let outcome = d.start(&path, &args).and_then(|id| {
            let run = d.settled(&vm_id, &id)?;
            println!("RUN {name} {id}: {}", describe(&run));
            match rule {
                Some(rule) => fired(&run, rule).and_then(|()| {
                    // The exit hold is what made the core possible.
                    if name == "fast" && !run.notes.iter().any(|n| n.contains("held at its exit")) {
                        return Err("the fast program's note does not say it was held".into());
                    }
                    Ok(())
                }),
                None => quiet(&run),
            }
        });
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
