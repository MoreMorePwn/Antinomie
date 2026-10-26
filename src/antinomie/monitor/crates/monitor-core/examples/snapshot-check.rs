//! Real four-vCPU snapshot/reconnect qualification in a disposable data folder.
//! Usage: snapshot-check BUNDLE WORK_DIR [debian]
//! With `debian` the VM is sized for a Debian desktop base and boots longer.
use antinomie_monitor_core::*;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};
struct Driver {
    backend: Backend,
    snapshot: Snapshot,
    terminal: BTreeMap<String, Vec<u8>>,
    /// Serial log text that says guest userspace is up.
    ready: &'static str,
    boot_secs: u64,
}
impl Driver {
    fn pump(&mut self) -> Vec<(u64, bool, String)> {
        let mut replies = Vec::new();
        while let Some(notification) = self.backend.try_recv() {
            match notification {
                Notification::Snapshot(snapshot) => self.snapshot = snapshot,
                Notification::Terminal { run_id, data, .. } => {
                    self.terminal.entry(run_id).or_default().extend(data)
                }
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => replies.push((id, success, message)),
                _ => {}
            }
        }
        replies
    }
    fn command(&mut self, command: Command) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(360);
        loop {
            for (reply, success, message) in self.pump() {
                if reply == id {
                    eprintln!("{id}: {message}");
                    thread::sleep(Duration::from_millis(50));
                    self.pump();
                    return if success { Ok(message) } else { Err(message) };
                }
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "command {id} timed out: {:?}",
                    self.snapshot.last_error
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn marker(&mut self, id: &str, marker: &str) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(40);
        loop {
            self.pump();
            if self.terminal.get(id).is_some_and(|data| {
                data.windows(marker.len())
                    .any(|value| value == marker.as_bytes())
            }) {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "marker {marker} missing: {:?}; output {}",
                    self.snapshot.last_error,
                    String::from_utf8_lossy(self.terminal.get(id).map_or(&[][..], Vec::as_slice))
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn input(&mut self, id: &str, line: &str, marker: &str) -> Result<(), String> {
        self.terminal.insert(id.into(), Vec::new());
        self.command(Command::TerminalInput {
            run_id: id.into(),
            data: format!("{line}\n").into_bytes(),
        })?;
        self.marker(id, marker)
    }
    fn guest_ready(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(self.boot_secs);
        loop {
            self.pump();
            if self.snapshot.serial_log.as_ref().is_some_and(|path| {
                std::fs::read(path).is_ok_and(|text| {
                    text.windows(self.ready.len())
                        .any(|part| part == self.ready.as_bytes())
                })
            }) {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err("guest userspace did not finish booting".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    /// Launches `request` and returns its run. A guest that has just booted
    /// may not have its terminal devices yet, so a failed launch is retried
    /// until the boot deadline.
    fn launch(&mut self, request: ExecRequest) -> Result<String, String> {
        let deadline = Instant::now() + Duration::from_secs(self.boot_secs);
        loop {
            let before: Vec<String> = self
                .snapshot
                .runs
                .iter()
                .map(|run| run.id.clone())
                .collect();
            match self.command(Command::Execute(request.clone())) {
                Ok(_) => {
                    return self
                        .snapshot
                        .runs
                        .iter()
                        .find(|run| {
                            !before.contains(&run.id)
                                && Some(run.boot_id.as_str()) == self.snapshot.boot_id.as_deref()
                        })
                        .map(|run| run.id.clone())
                        .ok_or_else(|| "launched run missing".into());
                }
                Err(error) if Instant::now() < deadline => {
                    eprintln!("launch retried: {error}");
                    thread::sleep(Duration::from_secs(2));
                }
                Err(error) => return Err(error),
            }
        }
    }
    fn current_run(&self) -> Result<String, String> {
        self.snapshot
            .runs
            .iter()
            .find(|run| Some(run.boot_id.as_str()) == self.snapshot.boot_id.as_deref())
            .map(|run| run.id.clone())
            .ok_or_else(|| "no restored terminal owner".into())
    }
    fn snapshot(&mut self, vm: &str, name: &str, mode: VmSnapshotMode) -> Result<String, String> {
        self.command(Command::CreateVmSnapshot {
            vm_id: vm.into(),
            request: SnapshotRequest {
                name: name.into(),
                description: "qualification fixture".into(),
                mode,
            },
        })?;
        self.command(Command::RefreshVmSnapshots { vm_id: vm.into() })?;
        self.snapshot
            .vm_snapshot_trees
            .get(vm)
            .and_then(|tree| tree.nodes.iter().find(|node| node.name == name))
            .map(|node| node.id.clone())
            .ok_or_else(|| "checkpoint missing".into())
    }
}
/// A snapshot is restored under the stealth profile it was taken with: take
/// one, give the VM another profile, see the restore refused, switch back and
/// restore. The VM is stopped.
fn profile_phase(driver: &mut Driver, vm: &str) -> Result<(), String> {
    use antinomie_monitor_core::stealth::{StealthPreset, StealthProfile, host_cpu_vendor};
    let mut config = driver
        .snapshot
        .vms
        .iter()
        .find(|known| known.id == vm)
        .cloned()
        .ok_or("VM missing")?;
    let original = config.stealth.clone();
    let taken = driver.snapshot(vm, "Profile A", VmSnapshotMode::Disk)?;
    config.stealth = StealthProfile::realistic(StealthPreset::RealisticDesktop, &host_cpu_vendor());
    driver.command(Command::Save(config))?;
    driver.command(Command::RefreshVmSnapshots { vm_id: vm.into() })?;
    let node = |driver: &Driver| {
        driver
            .snapshot
            .vm_snapshot_trees
            .get(vm)
            .and_then(|tree| tree.nodes.iter().find(|node| node.id == taken))
            .map(|node| node.profile.clone())
    };
    if !matches!(node(driver), Some(SnapshotProfile::Other { .. })) {
        return Err(format!("profile change not listed: {:?}", node(driver)));
    }
    let restore = |switch_profile| Command::RestoreVmSnapshot {
        vm_id: vm.into(),
        snapshot_id: taken.clone(),
        boot_from_disk: true,
        save_current: None,
        confirmed: true,
        switch_profile,
    };
    match driver.command(restore(false)) {
        Err(error) if error.contains("switch the VM back to that profile") => {}
        other => {
            return Err(format!(
                "restore under another profile not refused: {other:?}"
            ));
        }
    }
    driver.command(restore(true))?;
    driver.guest_ready()?;
    let now = driver
        .snapshot
        .vms
        .iter()
        .find(|known| known.id == vm)
        .map(|known| known.stealth.clone());
    if now.as_ref() != Some(&original) {
        return Err("the VM did not get its profile back".into());
    }
    driver.command(Command::Stop)?;
    eprintln!("profile phase passed");
    Ok(())
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let debian = match args.get(2).and_then(|arg| arg.to_str()) {
        None if args.len() == 2 => false,
        Some("debian") if args.len() == 3 => true,
        _ => return Err("usage: snapshot-check BUNDLE WORK_DIR [debian]".into()),
    };
    let work = PathBuf::from(&args[1]);
    if work.exists() {
        return Err("qualification requires a fresh disposable work directory".into());
    }
    let options = BackendOptions {
        data_dir: work.clone(),
        bundle_dir: PathBuf::from(&args[0]),
        headless: true,
        capture_quota_size: 256 * 1024 * 1024,
        ..BackendOptions::default()
    };
    let mut driver = Driver {
        backend: Backend::new(options)?,
        snapshot: Snapshot::default(),
        terminal: BTreeMap::new(),
        ready: if debian {
            "systemd["
        } else {
            "BusyBox guest ready"
        },
        boot_secs: if debian { 180 } else { 40 },
    };
    let vm = VmConfig {
        name: "Snapshot qualification".into(),
        cpus: 4,
        ram_mib: if debian { 4096 } else { 1024 },
        disk_gib: if debian { 16 } else { 2 },
        ..VmConfig::default()
    };
    driver.command(if debian {
        // A Debian base asks for the guest user's account.
        let mut random = [0; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut source| std::io::Read::read_exact(&mut source, &mut random))
            .map_err(|error| error.to_string())?;
        let password = random.iter().map(|byte| format!("{byte:02x}")).collect();
        Command::CreateWithCredentials {
            vm,
            credentials: GuestCredentials::new("qauser".into(), password)?,
        }
    } else {
        Command::Create(vm)
    })?;
    let vm = driver.snapshot.vms.first().ok_or("VM missing")?.id.clone();
    driver.command(Command::Start { vm_id: vm.clone() })?;
    let deadline = Instant::now() + Duration::from_secs(driver.boot_secs);
    loop {
        driver.pump();
        if driver
            .snapshot
            .guest_kernel
            .as_ref()
            .is_some_and(|kernel| kernel.revision.is_some_and(|revision| revision >= 14))
        {
            break;
        }
        if Instant::now() > deadline {
            return Err("ABI9 guest probe did not complete".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    driver.guest_ready()?;
    driver.command(Command::CaptureAll)?;
    // On disk for the disk restore: Debian keeps /tmp in memory.
    let value = if debian {
        "/var/tmp/snapshot-value"
    } else {
        "/tmp/snapshot-value"
    };
    let run = driver.launch(ExecRequest {path:"/bin/sh".into(),args:vec!["-c".into(),format!("n=7; echo SNAP_READY; while IFS= read -r line; do case \"$line\" in A) echo A >{value}; sync; echo SET_A;; B) echo B >{value}; sync; echo SET_B;; get) cat {value}; echo DISK_DONE;; inc) n=$((n+1)); echo COUNT_$n;; *) echo TICK_$line;; esac; done")],cwd:"/".into(),env:vec!["PATH=/bin:/sbin:/usr/bin:/usr/sbin".into()],uid:1000,gid:1000,analysis:Default::default(),run_in:RunIn::AppTerminal,..Default::default()})?;
    driver.marker(&run, "SNAP_READY")?;
    driver.input(&run, "A", "SET_A")?;
    let original_boot = driver.snapshot.boot_id.clone();
    let full = driver.snapshot(&vm, "Full A", VmSnapshotMode::Full)?;
    let disk = driver.snapshot(&vm, "Disk A", VmSnapshotMode::Disk)?;
    driver.input(&run, "B", "SET_B")?;
    driver.input(&run, "inc", "COUNT_8")?;
    let future = driver.snapshot(&vm, "Future B", VmSnapshotMode::Disk)?;
    for iteration in 0..2 {
        driver.command(Command::RestoreVmSnapshot {
            vm_id: vm.clone(),
            snapshot_id: full.clone(),
            boot_from_disk: false,
            save_current: None,
            confirmed: true,
            switch_profile: false,
        })?;
        if driver.snapshot.boot_id == original_boot {
            return Err("full restore appended to old timeline".into());
        }
        let restored = driver.current_run()?;
        if restored == run {
            return Err("restored host run identity was reused".into());
        }
        driver.input(&restored, "get", "A\r\nDISK_DONE")?;
        driver.input(&restored, "inc", "COUNT_8")?;
        driver.input(&restored, "hello", "TICK_hello")?;
        if driver.snapshot.health.parser_errors != 0 {
            return Err("restored parser errors".into());
        }
        if !driver
            .snapshot
            .captures
            .iter()
            .any(|capture| capture.boot_id == driver.snapshot.boot_id.clone().unwrap_or_default())
        {
            return Err("restored capture ownership missing".into());
        }
        driver.snapshot(&vm, &format!("Branch {iteration}"), VmSnapshotMode::Disk)?;
    }
    driver.command(Command::ReconnectTransport)?;
    let attached = driver.current_run()?;
    driver.input(&attached, "again", "TICK_again")?;
    if driver
        .command(Command::RestoreVmSnapshot {
            vm_id: vm.clone(),
            snapshot_id: disk.clone(),
            boot_from_disk: true,
            save_current: None,
            confirmed: false,
            switch_profile: false,
        })
        .is_ok()
    {
        return Err("unconfirmed restore accepted".into());
    }
    driver.command(Command::RestoreVmSnapshot {
        vm_id: vm.clone(),
        snapshot_id: disk.clone(),
        boot_from_disk: true,
        save_current: Some(SnapshotRequest {
            name: "Saved before restore".into(),
            description: String::new(),
            mode: VmSnapshotMode::Disk,
        }),
        confirmed: true,
        switch_profile: false,
    })?;
    driver.guest_ready()?;
    let rebooted = driver.launch(ExecRequest {
        path: "/bin/sh".into(),
        args: vec!["-c".into(), format!("cat {value}; echo DISK_REBOOT_DONE")],
        cwd: "/".into(),
        env: vec!["PATH=/bin".into()],
        uid: 1000,
        gid: 1000,
        analysis: Default::default(),
        run_in: RunIn::AppTerminal,
        ..Default::default()
    })?;
    driver.marker(&rebooted, "A\r\nDISK_REBOOT_DONE")?;
    driver.command(Command::Stop)?;
    profile_phase(&mut driver, &vm)?;
    driver.command(Command::DeleteVmSnapshot {
        vm_id: vm.clone(),
        snapshot_id: full.clone(),
        confirmed: true,
    })?;
    driver.command(Command::RefreshVmSnapshots { vm_id: vm.clone() })?;
    let tree = driver
        .snapshot
        .vm_snapshot_trees
        .get(&vm)
        .ok_or("graph missing")?;
    if !tree.nodes.iter().any(|node| node.id == future)
        || !tree
            .nodes
            .iter()
            .any(|node| node.id == full && node.deleted)
        || tree.nodes.len() < 6
    {
        return Err("snapshot branches/dependencies lost".into());
    }
    std::fs::write(work.join("qualification.json"),serde_json::to_vec_pretty(&serde_json::json!({"passed":true,"base":if debian {"debian"} else {"busybox"},"cpus":4,"full_restores":2,"disk_reboot":true,"reconnect":true,"graph":tree,"health":driver.snapshot.health})).map_err(|error|error.to_string())?).map_err(|error|error.to_string())?;
    driver.backend.shutdown()?;
    println!("four-vCPU snapshot, branch and reconnect qualification passed");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
