// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM measurement of what a sample sees of the VM, the sandbox and
//! Antinomie: the stealth giveaway table.
//!
//!   stealth-check measure BUNDLE NEW_DATA_DIR PROBE [PRESET]
//!
//! PROBE is the static `tests/monitor/stealth-probe` program; PRESET is
//! `desktop` (default), `laptop`, `server` or `transparent`. One BusyBox VM
//! with two vCPUs and 2 GiB boots with that stealth profile; the probe is
//! uploaded and launched as a run, as root and as uid 1000, the way a sample
//! is. Every check becomes a table row (giveaway, what root and the user see,
//! pass or fail), printed as `ROW` lines and written to `stealth.md` and
//! `stealth.tsv` in the data folder. The root run's recording must hold the
//! probe's calls, so observation is checked alongside. The data folder must
//! be new and disposable.
use antinomie_monitor_core::stealth::{StealthPreset, StealthProfile, host_cpu_vendor};
use antinomie_monitor_core::*;
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
    /// Run `program` as `uid` until it ends; returns its run id.
    fn run_to_end(&mut self, program: &str, uid: u32) -> Result<String, String> {
        let known: Vec<String> = self.snapshot.runs.iter().map(|r| r.id.clone()).collect();
        self.command(Command::Execute(ExecRequest {
            path: program.into(),
            uid,
            gid: uid,
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
        let wanted = id.clone();
        self.wait("run end", 120, move |s| {
            s.runs.iter().any(|r| {
                r.id == wanted && matches!(r.state, RunState::Finished | RunState::Stopped)
            })
        })?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.output(&id).contains("STEALTH-END") && Instant::now() < deadline {
            self.receive();
            thread::sleep(Duration::from_millis(20));
        }
        Ok(id)
    }
}

fn preset(name: &str) -> Result<StealthProfile, String> {
    let kind = match name {
        "desktop" => StealthPreset::RealisticDesktop,
        "laptop" => StealthPreset::RealisticLaptop,
        "server" => StealthPreset::RealisticServer,
        "transparent" => StealthPreset::Transparent,
        other => return Err(format!("unknown preset {other}")),
    };
    Ok(StealthProfile::default().for_preset(kind, &host_cpu_vendor()))
}

/// The probe's `STEALTH verdict key value` lines, by key, in output order.
fn checks(text: &str) -> Vec<(String, String, String)> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim_end_matches('\r').strip_prefix("STEALTH ")?;
            let mut parts = rest.splitn(3, ' ');
            let verdict = parts.next()?.to_owned();
            let key = parts.next()?.to_owned();
            let value = parts.next().unwrap_or("").to_owned();
            Some((key, verdict, value))
        })
        .collect()
}

/// Calls the run's recording holds.
fn recorded_calls(directory: &Path) -> Result<u64, String> {
    let recording = recording::Recording {
        directory: directory.to_path_buf(),
        manifest: serde_json::Value::Null,
        events: Vec::new(),
    };
    let cancel = AtomicBool::new(false);
    let mut count = 0;
    let mut offset = 0;
    loop {
        let page = recording
            .invocation_page_cancellable(offset, 256, &cancel)
            .map_err(|e| e.to_string())?;
        count += page.invocations.len() as u64;
        match page.next_offset {
            Some(next) => offset = next,
            None => return Ok(count),
        }
    }
}

fn cell(text: &str) -> String {
    text.replace('|', "\\|")
}

fn measure(bundle: &str, data: &str, probe: &str, preset_name: &str) -> Result<(), String> {
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("the measurement needs a new disposable data folder".into());
    }
    let stealth = preset(preset_name)?;
    let options = BackendOptions {
        bundle_dir: PathBuf::from(bundle),
        data_dir: data.clone(),
        headless: true,
        capture_quota_size: 1024 * 1024 * 1024,
        ..Default::default()
    };
    let mut d = Driver {
        backend: Backend::new(options)?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        output: BTreeMap::new(),
    };
    d.command(Command::Create(VmConfig {
        name: "stealth check".into(),
        cpus: 2,
        ram_mib: 2048,
        disk_gib: 8,
        nat: true,
        isolated_network: true,
        stealth,
        ..Default::default()
    }))?;
    d.wait("VM publication", 10, |s| !s.vms.is_empty())?;
    let vm_id = d.snapshot.vms[0].id.clone();
    d.command(Command::Start { vm_id })?;
    d.wait("guest", 120, |s| {
        s.guest_kernel.as_ref().and_then(|k| k.revision).is_some()
            && s.serial_log
                .as_ref()
                .and_then(|p| fs::read(p).ok())
                .is_some_and(|log| log.windows(19).any(|part| part == b"BusyBox guest ready"))
    })?;
    // Like a sample a while after boot: the host's first polls have run.
    thread::sleep(Duration::from_secs(5));
    let program = "/tmp/probe";
    d.command(Command::Upload {
        source: PathBuf::from(probe),
        destination: program.into(),
        overwrite: true,
        executable: true,
    })?;
    let root_run = d.run_to_end(program, 0)?;
    let user_run = d.run_to_end(program, 1000)?;
    let root_text = d.output(&root_run).to_owned();
    let user_text = d.output(&user_run).to_owned();
    let root_dir = d
        .snapshot
        .runs
        .iter()
        .find(|r| r.id == root_run)
        .map(|r| r.directory.clone())
        .ok_or("root run missing")?;
    d.command(Command::Stop)?;
    d.wait("VM stop", 90, |s| s.state == VmState::Stopped)?;
    thread::sleep(Duration::from_secs(2));
    fs::write(data.join("probe-root.txt"), &root_text).map_err(|e| e.to_string())?;
    fs::write(data.join("probe-user.txt"), &user_text).map_err(|e| e.to_string())?;
    if !root_text.contains("STEALTH-END") || !user_text.contains("STEALTH-END") {
        return Err("the probe did not finish in both runs".into());
    }
    let root = checks(&root_text);
    let user: BTreeMap<_, _> = checks(&user_text)
        .into_iter()
        .map(|(key, verdict, value)| (key, (verdict, value)))
        .collect();
    let mut table =
        String::from("| Giveaway | Root sees | Root | User sees | User |\n|---|---|---|---|---|\n");
    let mut tsv = String::new();
    let (mut failed, mut passed) = (0, 0);
    for (key, verdict, value) in &root {
        let (user_verdict, user_value) = user
            .get(key)
            .cloned()
            .unwrap_or_else(|| ("-".into(), "-".into()));
        let shown_user = if user_value == *value {
            "same".to_owned()
        } else {
            user_value.clone()
        };
        println!("ROW {key} | {verdict}/{user_verdict} | {value} | {shown_user}");
        table.push_str(&format!(
            "| {key} | {} | {verdict} | {} | {user_verdict} |\n",
            cell(value),
            cell(&shown_user)
        ));
        tsv.push_str(&format!(
            "{key}\t{verdict}\t{value}\t{user_verdict}\t{user_value}\n"
        ));
        if verdict == "fail" || user_verdict == "fail" {
            failed += 1;
        } else if verdict == "pass" {
            passed += 1;
        }
    }
    fs::write(data.join("stealth.md"), &table).map_err(|e| e.to_string())?;
    fs::write(data.join("stealth.tsv"), &tsv).map_err(|e| e.to_string())?;
    let calls = recorded_calls(&root_dir)?;
    println!("RESULT observation: the root run recorded {calls} calls");
    println!(
        "RESULT preset {preset_name}: {} checks, {passed} pass, {failed} give the VM or Antinomie away",
        root.len()
    );
    println!("TABLE {}", data.join("stealth.md").display());
    if calls < 100 {
        return Err("the probe's run was not observed".into());
    }
    println!("PASS measure");
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["measure", bundle, data, probe] => measure(bundle, data, probe, "desktop"),
        ["measure", bundle, data, probe, preset] => measure(bundle, data, probe, preset),
        _ => {
            eprintln!("usage: stealth-check measure BUNDLE NEW_DATA_DIR PROBE [PRESET]");
            std::process::exit(2);
        }
    };
    if let Err(error) = outcome {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}
