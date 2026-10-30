// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM measurement of what a sample sees of the VM, the sandbox and
//! Antinomie: the stealth giveaway table.
//!
//!   stealth-check measure BUNDLE NEW_DATA_DIR PROBE [PRESET [ENTRY=VALUE...]]
//!   stealth-check boots BUNDLE NEW_DATA_DIR COUNT [PRESET [ENTRY=VALUE...]]
//!   stealth-check cloud BUNDLE NEW_DATA_DIR CLOUD_PROBE [PROVIDER...]
//!   stealth-check abi BUNDLE NEW_DATA_DIR FIXTURES HEADER_DEBS
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
//! abi: Debian Minimal with four vCPUs and 2 GiB verifies the distribution's
//! signed modules, a real filesystem restriction, an out-of-tree module built
//! against Debian headers, fentry, and the retained module/BPF syscalls. NAT
//! is used only by this disposable benign-test VM to install build tools.
//!
//! The data folder must be new and disposable.
use antinomie_monitor_core::route::RouteKind;
use antinomie_monitor_core::stealth::{
    BaseSupport, CLOUDS, DiskBus, Firmware, HostCpu, HostSupport, NatNetwork, StealthPreset,
    StealthProfile,
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
    ready: &'static [u8],
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
        self.command_for(command, 120)
    }

    fn command_for(&mut self, command: Command, seconds: u64) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
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
        self.run_routed(program, uid, None)
    }

    /// [`run_to_end`](Self::run_to_end) on `route` (a Routed VM).
    fn run_routed(
        &mut self,
        program: &str,
        uid: u32,
        route: Option<RouteKind>,
    ) -> Result<String, String> {
        self.run_for(program, uid, route, 120)
    }

    fn run_for(
        &mut self,
        program: &str,
        uid: u32,
        route: Option<RouteKind>,
        seconds: u64,
    ) -> Result<String, String> {
        let known: Vec<String> = self.snapshot.runs.iter().map(|r| r.id.clone()).collect();
        self.command(Command::Execute(ExecRequest {
            path: program.into(),
            uid,
            gid: uid,
            route,
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
        self.wait("run end", seconds, move |s| {
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
    driver_on(bundle, data, profile, gpa, false)
}

/// [`driver`] with the VM's network Routed when `routed`: the gateway of the
/// per-run route, which a cloud profile's metadata service lives in.
fn driver_on(
    bundle: &str,
    data: &Path,
    profile: StealthProfile,
    gpa: Option<u64>,
    routed: bool,
) -> Result<(Driver, String), String> {
    driver_network(
        bundle,
        data,
        profile,
        gpa,
        if routed {
            VmNetwork::Routed
        } else {
            VmNetwork::Isolated
        },
        2,
    )
}

fn driver_network(
    bundle: &str,
    data: &Path,
    profile: StealthProfile,
    gpa: Option<u64>,
    network: VmNetwork,
    cpus: u16,
) -> Result<(Driver, String), String> {
    if data.exists() {
        return Err("the measurement needs a new disposable data folder".into());
    }
    let base = antinomie_monitor_core::storage::Bundle::load(Path::new(bundle))?;
    let guest = base.guest.as_ref();
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
        serial_console: true,
        capture_quota_size: 1024 * 1024 * 1024,
        bootstrap_gpa: gpa,
        ..Default::default()
    };
    let mut d = Driver {
        backend: Backend::new(options)?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        output: BTreeMap::new(),
        ready: if guest.is_some() {
            b" login: "
        } else {
            b"BusyBox guest ready"
        },
    };
    let vm = VmConfig {
        name: "stealth check".into(),
        cpus,
        ram_mib: 2048.max(guest.map_or(0, |guest| guest.min_ram_mib)),
        disk_gib: 8.max(guest.map_or(0, |guest| guest.min_disk_gib)),
        nat: network == VmNetwork::Nat,
        isolated_network: network == VmNetwork::Isolated,
        routed: network == VmNetwork::Routed,
        stealth: profile,
        ..Default::default()
    };
    // The same offline provisioning and private credentials as conformance.
    let create = if guest.is_some_and(|guest| guest.requires_credentials) {
        let mut random = [0u8; 16];
        use std::io::Read;
        fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut random))
            .map_err(|error| error.to_string())?;
        let password = random.iter().map(|byte| format!("{byte:02x}")).collect();
        Command::CreateWithCredentials {
            vm,
            credentials: GuestCredentials::new("cloudqa".into(), password)?,
        }
    } else {
        Command::Create(vm)
    };
    d.command_for(create, 600)?;
    d.wait("VM publication", 10, |s| !s.vms.is_empty())?;
    let vm_id = d.snapshot.vms[0].id.clone();
    Ok((d, vm_id))
}

impl Driver {
    /// Start the VM and wait for the guest transport and the base's init.
    fn boot(&mut self, vm_id: &str) -> Result<(), String> {
        self.command_for(
            Command::Start {
                vm_id: vm_id.to_owned(),
            },
            900,
        )?;
        let ready = self.ready;
        self.wait("guest", 240, |s| {
            s.guest_kernel.as_ref().and_then(|k| k.revision).is_some()
                && s.serial_log
                    .as_ref()
                    .and_then(|p| fs::read(p).ok())
                    .is_some_and(|log| log.windows(ready.len()).any(|part| part == ready))
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

/// The value of `CLOUD key ...` lines, by key, in output order.
fn cloud_lines(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim_end_matches('\r').strip_prefix("CLOUD ")?;
            let (key, value) = rest.split_once(' ')?;
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Boots each cloud profile (a Routed VM), runs the cloud probe on the
/// InetSim route and checks what the guest read of its machine and of the
/// provider's metadata service against the provider's profile, then that the
/// gateway wrote the run's metadata report with the requests, the
/// credentials handed out and the canary's use.
fn cloud(bundle: &str, data: &str, probe: &str, only: &[&str]) -> Result<(), String> {
    let data = PathBuf::from(data);
    fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    let mut failures = Vec::new();
    for provider in CLOUDS
        .iter()
        .filter(|p| only.is_empty() || only.contains(&p.id))
    {
        let folder = data.join(provider.id);
        let profile = StealthProfile::cloud_vps(provider);
        let mac_prefix = profile.mac[..8].to_owned();
        let (mut d, vm_id) = driver_on(bundle, &folder, profile, None, true)?;
        d.boot(&vm_id)?;
        thread::sleep(Duration::from_secs(3));
        let program = "/tmp/cloud-probe";
        d.command(Command::Upload {
            source: PathBuf::from(probe),
            destination: program.into(),
            overwrite: true,
            executable: true,
        })?;
        let run = d.run_routed(program, 0, Some(RouteKind::InetSim))?;
        let text = d.output(&run).to_owned();
        let directory = d
            .snapshot
            .runs
            .iter()
            .find(|r| r.id == run)
            .map(|r| r.directory.clone())
            .ok_or("run missing")?;
        // The report is written when the run's process tree has ended.
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut report = None;
        while report.is_none() && Instant::now() < deadline {
            d.receive();
            report = antinomie_monitor_core::route::read_metadata_report(&directory);
            thread::sleep(Duration::from_millis(200));
        }
        d.stop()?;
        fs::write(folder.join("cloud-probe.txt"), &text).map_err(|e| e.to_string())?;
        let lines = cloud_lines(&text);
        let get = |key: &str| lines.iter().find(|l| l.0 == key).map(|l| l.1.clone());
        let mut check = |name: &str, ok: bool, got: String| {
            println!(
                "{} {} {name}: {got}",
                if ok { "PASS" } else { "FAIL" },
                provider.id
            );
            if !ok {
                failures.push(format!("{} {name}", provider.id));
            }
        };
        let value = |key: &str| get(key).unwrap_or_else(|| "(missing)".into());
        check(
            "dmi.sys_vendor",
            value("dmi.sys_vendor") == provider.system.0,
            value("dmi.sys_vendor"),
        );
        check(
            "dmi.product_name",
            value("dmi.product_name") == provider.system.1,
            value("dmi.product_name"),
        );
        check(
            "dmi.bios_vendor",
            value("dmi.bios_vendor") == provider.bios.0 || provider.bios.0.is_empty(),
            value("dmi.bios_vendor"),
        );
        check(
            "dmi.chassis_type",
            value("dmi.chassis_type") == provider.chassis_type.to_string(),
            value("dmi.chassis_type"),
        );
        check(
            "net.mac",
            value("net.mac").starts_with(&mac_prefix),
            value("net.mac"),
        );
        check(
            "net.gateway",
            value("net.gateway") == provider.nat.1,
            value("net.gateway"),
        );
        check(
            "net.resolv",
            lines
                .iter()
                .any(|l| l.0 == "net.resolv" && l.1.contains(provider.nat.2)),
            provider.nat.2.to_owned(),
        );
        let chipset = match provider.machine.qemu() {
            "pc" => "8086:1237",
            _ => "8086:29c0",
        };
        check(
            "pci chipset",
            lines.iter().any(|l| l.0 == "pci" && l.1.contains(chipset)),
            chipset.to_owned(),
        );
        let prefix = format!("meta.{}", provider.metadata_ip);
        let answered: Vec<_> = lines
            .iter()
            .filter(|l| l.0.starts_with(&prefix) && l.1.starts_with("[200"))
            .collect();
        check(
            "metadata answers",
            !answered.is_empty(),
            format!("{} paths answered", answered.len()),
        );
        let others = lines
            .iter()
            .filter(|l| l.0.starts_with("meta.") && !l.0.starts_with(&prefix))
            .count();
        check(
            "other providers' addresses stay silent",
            others == 0,
            format!("{others} answers"),
        );
        if !provider.metadata_name.is_empty() {
            check(
                "metadata name resolves",
                value(&format!("dns.{}", provider.metadata_name)) == provider.metadata_ip,
                value(&format!("dns.{}", provider.metadata_name)),
            );
        }
        let kinds: Vec<_> = report
            .iter()
            .flat_map(|r| r.events.iter().map(|e| e.kind.as_str()))
            .collect();
        check(
            "report: requests",
            kinds.contains(&"request"),
            format!("{} events", kinds.len()),
        );
        check(
            "report: credentials",
            kinds.contains(&"credentials"),
            format!("{kinds:?}").chars().take(60).collect(),
        );
        check(
            "report: canary use",
            report.iter().any(|r| {
                r.events
                    .iter()
                    .any(|e| e.kind == "canary-use" && e.endpoint == "203.0.113.9:80")
            }),
            "203.0.113.9:80".into(),
        );
        println!(
            "INFO {} cpu.hypervisor={} clocksource={}",
            provider.id,
            value("cpu.hypervisor"),
            value("clocksource")
        );
        fs::remove_file(folder.join("vms").join(&vm_id).join("disk.qcow2")).ok();
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("failed: {}", failures.join(", ")))
    }
}

/// A Debian VM verifies signed modules, an actual LSM restriction, a module
/// built against Debian's headers in the guest, fentry and retained calls.
fn abi(bundle: &str, data: &str, fixtures: &str, headers: &str) -> Result<(), String> {
    let folder = Path::new(data);
    let (mut driver, vm) = driver_network(
        bundle,
        folder,
        StealthProfile::transparent(),
        None,
        VmNetwork::Nat,
        4,
    )?;
    let mut module_directory = None;
    let result = (|| {
        driver.boot(&vm)?;
        for (source, destination) in [
            ("debian-abi-check.sh", "/tmp/debian-abi-check"),
            ("debian-oot-build.sh", "/tmp/debian-oot-build"),
            ("debian-oot-run.sh", "/tmp/debian-oot-run"),
            ("debian-module/Makefile", "/tmp/Makefile"),
            ("debian-module/module_fixture.c", "/tmp/module_fixture.c"),
        ] {
            driver.command(Command::Upload {
                source: Path::new(fixtures).join(source),
                destination: destination.into(),
                overwrite: true,
                executable: source.ends_with(".sh"),
            })?;
        }
        for (name, seconds, marker) in [
            ("debian-abi-check", 180, "ABI-CHECK-PASS"),
            ("debian-oot-build", 1200, "OOT-BUILD-PASS"),
            ("debian-oot-run", 180, "OOT-RUN-PASS"),
        ] {
            if name == "debian-oot-build" {
                // Stage the small pinned header packages in guest RAM. This
                // keeps disk flush latency out of the fixture transfer; the
                // actual package install and module build still use its disk.
                for package in [
                    "linux-headers-6.12.94+deb13-amd64_6.12.94-1_amd64.deb",
                    "linux-headers-6.12.94+deb13-common_6.12.94-1_all.deb",
                    "linux-kbuild-6.12.94+deb13_6.12.94-1_amd64.deb",
                ] {
                    println!("Staging {package} in guest RAM");
                    driver.command(Command::Upload {
                        source: Path::new(headers).join(package),
                        destination: format!("/dev/shm/{package}"),
                        overwrite: true,
                        executable: false,
                    })?;
                }
            }
            println!("Running {name}");
            let run = driver.run_for(&format!("/tmp/{name}"), 0, None, seconds)?;
            let output = driver.output(&run).to_owned();
            fs::write(folder.join(format!("{name}.txt")), &output).map_err(|e| e.to_string())?;
            print!("{output}");
            if !output.lines().any(|line| line.trim() == marker) {
                return Err(format!("{name} did not finish its checks"));
            }
            if name == "debian-oot-run" {
                let recorded = driver
                    .snapshot
                    .runs
                    .iter()
                    .find(|r| r.id == run)
                    .ok_or("module run missing")?;
                if let Some(error) = &recorded.recording_error {
                    return Err(format!("module recording: {error}"));
                }
                module_directory = Some(recorded.directory.clone());
            }
        }
        Ok(())
    })();
    let stopped = driver.stop();
    result.and(stopped)?;
    driver.wait("recordings saved", 120, |s| s.recording_flush.is_none())?;
    let directory = module_directory.ok_or("module run missing")?;
    let recording = recording::Recording {
        directory,
        manifest: serde_json::Value::Null,
        events: Vec::new(),
    };
    let mut load = false;
    let mut unload = false;
    let mut bpf = false;
    let mut calls = 0;
    let mut offset = 0;
    let cancel = AtomicBool::new(false);
    loop {
        let page = recording
            .invocation_page_cancellable(offset, 256, &cancel)
            .map_err(|e| e.to_string())?;
        if !page.issues.is_empty() {
            return Err(format!("module recording issues: {:?}", page.issues));
        }
        calls += page.invocations.len();
        for call in page.invocations {
            if let Some(event) = call
                .exit
                .filter(|event| event.result.is_some_and(|value| value >= 0))
            {
                match event.syscall_name.as_str() {
                    "init_module" | "finit_module" => load = true,
                    "delete_module" => unload = true,
                    "bpf" => bpf = true,
                    _ => (),
                }
            }
        }
        match page.next_offset {
            Some(next) => offset = next,
            None => break,
        }
    }
    if !(load && unload && bpf) {
        return Err(format!(
            "missing successful retained calls: load={load} unload={unload} bpf={bpf}"
        ));
    }
    println!("PASS retained module load/unload and BPF calls among {calls} calls");
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
        ["cloud", bundle, data, probe, rest @ ..] => cloud(bundle, data, probe, rest),
        ["abi", bundle, data, fixtures, headers] => abi(bundle, data, fixtures, headers),
        _ => {
            eprintln!(
                "usage: stealth-check measure BUNDLE NEW_DATA_DIR PROBE [PRESET [ENTRY=VALUE...]]\n       \
                 stealth-check boots BUNDLE NEW_DATA_DIR COUNT [PRESET [ENTRY=VALUE...]]\n       \
                 stealth-check cloud BUNDLE NEW_DATA_DIR CLOUD_PROBE [PROVIDER...]\n       \
                 stealth-check abi BUNDLE NEW_DATA_DIR FIXTURES HEADER_DEBS"
            );
            std::process::exit(2);
        }
    };
    if let Err(error) = outcome {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}
