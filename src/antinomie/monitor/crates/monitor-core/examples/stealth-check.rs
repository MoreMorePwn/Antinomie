// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM measurement of what a sample sees of the VM, the sandbox and
//! Antinomie: the stealth giveaway table.
//!
//!   stealth-check measure BUNDLE NEW_DATA_DIR PROBE [PRESET [ENTRY=VALUE...]]
//!   stealth-check boots BUNDLE NEW_DATA_DIR COUNT [PRESET [ENTRY=VALUE...]]
//!
//! PROBE is the static `tests/monitor/stealth-probe` program; PRESET is
//! `desktop` (default), `laptop`, `server` or `transparent`; entries change
//! the preset: `firmware=bios|uefi|uefi-sb`, `disk=virtio|sata|nvme`,
//! `nat=qemu|home`, `cdrom=on|off`, `smt=on|off` and `gpa=ADDRESS` (the
//! bootstrap page). One BusyBox VM with two vCPUs and 2 GiB boots with that
//! stealth profile, as the base and host can boot it (`NOTE` lines say what
//! fell back).
//!
//! measure: the probe is uploaded and launched as a run, as root and as uid
//! 1000, the way a sample is. Every check becomes a table row (giveaway, what
//! root and the user see, pass or fail), printed as `ROW` lines and written to
//! `stealth.md` and `stealth.tsv` in the data folder. The root run's recording
//! must hold the probe's calls, so observation is checked alongside.
//!
//! boots: the VM starts and stops COUNT times; each boot must bring the guest
//! transport up and run a shell that reports the firmware type and where the
//! kernel was placed (KASLR), and the firmware type must be the profile's.
//! A boot whose transport does not come up within two minutes fails.
//!
//! The data folder must be new and disposable.
use antinomie_monitor_core::stealth::{
    BaseSupport, DiskBus, Firmware, HostCpu, HostSupport, NatNetwork, StealthPreset, StealthProfile,
};
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

/// The VM's profile and the bootstrap page, from the preset and entries.
fn profile(args: &[&str]) -> Result<(StealthProfile, Option<u64>), String> {
    let kind = match args.first().copied().unwrap_or("desktop") {
        "desktop" => StealthPreset::RealisticDesktop,
        "laptop" => StealthPreset::RealisticLaptop,
        "server" => StealthPreset::RealisticServer,
        "transparent" => StealthPreset::Transparent,
        other => return Err(format!("unknown preset {other}")),
    };
    let mut profile = StealthProfile::default().for_preset_on(kind, &HostCpu::detect());
    let mut gpa = None;
    for entry in args.iter().skip(1) {
        let on = |value: &str| match value {
            "on" => Ok(true),
            "off" => Ok(false),
            _ => Err(format!("{entry}: on or off")),
        };
        match entry
            .split_once('=')
            .ok_or(format!("{entry} is not ENTRY=VALUE"))?
        {
            ("firmware", "bios") => profile.firmware = Firmware::Bios,
            ("firmware", "uefi") => profile.firmware = Firmware::Uefi,
            ("firmware", "uefi-sb") => profile.firmware = Firmware::UefiSecureBoot,
            ("disk", "virtio") => profile.disk_bus = DiskBus::Virtio,
            ("disk", "sata") => profile.disk_bus = DiskBus::Sata,
            ("disk", "nvme") => profile.disk_bus = DiskBus::Nvme,
            ("nat", "qemu") => profile.nat = NatNetwork::default(),
            ("nat", "home") => profile.nat = NatNetwork::home(),
            ("cdrom", value) => profile.cdrom = on(value)?,
            ("smt", value) => profile.smt = on(value)?,
            ("gpa", value) => {
                gpa = Some(
                    u64::from_str_radix(value.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("{entry}: a hex address"))?,
                )
            }
            _ => return Err(format!("unknown entry {entry}")),
        }
    }
    Ok((profile, gpa))
}

/// A backend on a new data folder with one VM of `profile`, after printing
/// what the base and host cannot boot of it.
fn driver(
    bundle: &str,
    data: &Path,
    profile: StealthProfile,
    gpa: Option<u64>,
) -> Result<(Driver, String), String> {
    if data.exists() {
        return Err("the measurement needs a new disposable data folder".into());
    }
    let base = antinomie_monitor_core::storage::Bundle::load(Path::new(bundle))?;
    let (_, notes) = profile.fitted(
        &BaseSupport::from_list(&base.stealth_support),
        &HostSupport::detect(Path::new("qemu-system-x86_64")),
    );
    for note in notes {
        println!("NOTE {note}");
    }
    let options = BackendOptions {
        bundle_dir: PathBuf::from(bundle),
        data_dir: data.to_path_buf(),
        headless: true,
        capture_quota_size: 1024 * 1024 * 1024,
        bootstrap_gpa: gpa,
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
        stealth: profile,
        ..Default::default()
    }))?;
    d.wait("VM publication", 10, |s| !s.vms.is_empty())?;
    let vm_id = d.snapshot.vms[0].id.clone();
    Ok((d, vm_id))
}

impl Driver {
    /// Start the VM and wait for the guest transport and the base's init.
    fn boot(&mut self, vm_id: &str) -> Result<(), String> {
        self.command(Command::Start {
            vm_id: vm_id.to_owned(),
        })?;
        self.wait("guest", 120, |s| {
            s.guest_kernel.as_ref().and_then(|k| k.revision).is_some()
                && s.serial_log
                    .as_ref()
                    .and_then(|p| fs::read(p).ok())
                    .is_some_and(|log| log.windows(19).any(|part| part == b"BusyBox guest ready"))
        })
    }

    fn stop(&mut self) -> Result<(), String> {
        self.command(Command::Stop)?;
        self.wait("VM stop", 90, |s| s.state == VmState::Stopped)?;
        thread::sleep(Duration::from_secs(2));
        Ok(())
    }
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

fn measure(bundle: &str, data: &str, probe: &str, args: &[&str]) -> Result<(), String> {
    let data = PathBuf::from(data);
    let preset_name = args.first().copied().unwrap_or("desktop");
    let (stealth, gpa) = profile(args)?;
    let (mut d, vm_id) = driver(bundle, &data, stealth, gpa)?;
    d.boot(&vm_id)?;
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
    d.stop()?;
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

/// Boot `count` times; every boot must bring the transport up on the
/// profile's firmware.
fn boots(bundle: &str, data: &str, count: &str, args: &[&str]) -> Result<(), String> {
    let count: u32 = count.parse().map_err(|_| "COUNT is a number")?;
    let (stealth, gpa) = profile(args)?;
    let (mut d, vm_id) = driver(bundle, Path::new(data), stealth, gpa)?;
    let firmware = d.snapshot.vms[0].stealth.firmware;
    let base = antinomie_monitor_core::storage::Bundle::load(Path::new(bundle))?;
    let (fitted, _) = d.snapshot.vms[0].stealth.fitted(
        &BaseSupport::from_list(&base.stealth_support),
        &HostSupport::detect(Path::new("qemu-system-x86_64")),
    );
    let expected = if fitted.firmware.is_uefi() {
        "uefi"
    } else {
        "bios"
    };
    let script = "if [ -d /sys/firmware/efi ]; then echo BOOT-FIRMWARE uefi; \
                  else echo BOOT-FIRMWARE bios; fi; \
                  echo BOOT-KERNEL $(grep -m1 'Kernel code' /proc/iomem)";
    let (mut failed, mut placements) = (0, std::collections::BTreeSet::new());
    for boot in 1..=count {
        let started = Instant::now();
        if let Err(error) = d.boot(&vm_id) {
            failed += 1;
            println!("BOOT {boot} FAIL transport: {error}");
            let _ = d.stop();
            continue;
        }
        let known: Vec<String> = d.snapshot.runs.iter().map(|r| r.id.clone()).collect();
        d.command(Command::Execute(ExecRequest {
            path: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            // Root reads the kernel's physical placement in /proc/iomem.
            uid: 0,
            gid: 0,
            ..Default::default()
        }))?;
        d.wait("run", 60, |s| {
            s.runs.iter().any(|r| {
                !known.contains(&r.id) && matches!(r.state, RunState::Finished | RunState::Stopped)
            })
        })?;
        let run = d
            .snapshot
            .runs
            .iter()
            .find(|r| !known.contains(&r.id))
            .ok_or("run missing")?
            .id
            .clone();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !d.output(&run).contains("BOOT-KERNEL") && Instant::now() < deadline {
            d.receive();
            thread::sleep(Duration::from_millis(20));
        }
        let output = d.output(&run).to_owned();
        let found = output
            .lines()
            .find_map(|line| line.trim().strip_prefix("BOOT-FIRMWARE "))
            .unwrap_or("none")
            .to_owned();
        let kernel = output
            .lines()
            .find_map(|line| line.trim().strip_prefix("BOOT-KERNEL "))
            .unwrap_or("")
            .trim()
            .to_owned();
        placements.insert(kernel.split('-').next().unwrap_or("").to_owned());
        let verdict = if found == expected { "PASS" } else { "FAIL" };
        if verdict == "FAIL" {
            failed += 1;
        }
        println!(
            "BOOT {boot} {verdict} firmware {found} kernel {kernel} in {:.1} s",
            started.elapsed().as_secs_f64()
        );
        d.stop()?;
    }
    println!(
        "RESULT {count} boots ({firmware:?} as {expected}), {failed} failed, {} kernel placements",
        placements.len()
    );
    if failed > 0 {
        return Err(format!("{failed} of {count} boots failed"));
    }
    println!("PASS boots");
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
        ["measure", bundle, data, probe, rest @ ..] => measure(bundle, data, probe, rest),
        ["boots", bundle, data, count, rest @ ..] => boots(bundle, data, count, rest),
        _ => {
            eprintln!(
                "usage: stealth-check measure BUNDLE NEW_DATA_DIR PROBE [PRESET [ENTRY=VALUE...]]\n       \
                 stealth-check boots BUNDLE NEW_DATA_DIR COUNT [PRESET [ENTRY=VALUE...]]"
            );
            std::process::exit(2);
        }
    };
    if let Err(error) = outcome {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}
