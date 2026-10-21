// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! One disposable VM per fixture group: boot a new VM from the base, upload
//! the group's programs, run one program as the group's user until its whole
//! process tree ended, read the recorder's counters, stop the VM and keep only
//! the run's recording.
use antinomie_monitor_core::*;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

/// What a group runs and how its VM is shaped.
#[derive(Clone, Debug)]
pub struct VmPlan {
    pub cpus: u16,
    pub ram_mib: u32,
    pub transport: TransportSettings,
    /// (host file, guest path) pairs, uploaded executable.
    pub uploads: Vec<(PathBuf, String)>,
    pub program: String,
    pub args: Vec<String>,
    pub uid: u32,
    pub gid: u32,
    /// Longest the program may run, in seconds.
    pub timeout: u64,
}

/// Everything the checks read about one finished group run.
#[derive(Debug)]
pub struct GroupRun {
    pub run: RunSummary,
    /// The recorder's boot counters, read after the run ended (STATS reply).
    pub recorder_stats: Option<[u64; 10]>,
    pub health: Health,
    /// Command failures and backend errors seen while the group ran.
    pub errors: Vec<String>,
    pub boot_seconds: f64,
    pub run_seconds: f64,
}

/// Host memory the other users of this machine need: a VM boots only when
/// at least this much is available.
const MEMORY_FLOOR_KIB: u64 = 3_670_016; // 3.5 GiB

fn available_kib() -> Option<u64> {
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
}

/// Wait (at most `seconds`) until the host has room for another VM.
pub fn wait_for_memory(seconds: u64) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        match available_kib() {
            Some(kib) if kib >= MEMORY_FLOOR_KIB => return Ok(()),
            Some(kib) if Instant::now() >= deadline => {
                return Err(format!(
                    "only {} MiB of host memory available after {seconds} s; a VM needs 3.5 GiB free",
                    kib / 1024
                ));
            }
            None => return Err("MemAvailable missing from /proc/meminfo".into()),
            Some(kib) => {
                eprintln!(
                    "conformance: waiting for host memory ({} MiB available)",
                    kib / 1024
                );
                thread::sleep(Duration::from_secs(15));
            }
        }
    }
}

struct Driver {
    backend: Backend,
    snapshot: Snapshot,
    replies: BTreeMap<u64, Result<String, String>>,
    errors: Vec<String>,
}

impl Driver {
    fn receive(&mut self) {
        while let Some(message) = self.backend.try_recv() {
            match message {
                Notification::Snapshot(snapshot) => {
                    if let Some(error) = snapshot
                        .last_error
                        .as_ref()
                        .filter(|error| self.snapshot.last_error.as_ref() != Some(*error))
                    {
                        self.errors.push(format!("backend error: {error}"));
                    }
                    self.snapshot = snapshot;
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

    fn command(&mut self, command: Command, seconds: u64) -> Result<String, String> {
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
                return Err(format!(
                    "{label} timed out; last error {:?}",
                    self.snapshot.last_error
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

/// The console without kernel messages, which can land in the middle of a
/// line userspace is writing ("BusyBox guest re[    2.27] rcS (103) …\nady").
fn userspace_console(log: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(log.len());
    let mut index = 0;
    while index < log.len() {
        if log[index] == b'[' {
            let rest = &log[index + 1..];
            let digits = rest
                .iter()
                .take_while(|b| b.is_ascii_digit() || **b == b' ' || **b == b'.')
                .count();
            if digits > 0 && rest.get(digits) == Some(&b']') {
                let end = rest
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(log.len(), |n| index + 2 + n);
                index = end;
                continue;
            }
        }
        out.push(log[index]);
        index += 1;
    }
    out
}

fn guest_ready(snapshot: &Snapshot) -> bool {
    snapshot.state == VmState::Running
        && snapshot
            .guest_kernel
            .as_ref()
            .and_then(|kernel| kernel.revision)
            .is_some_and(|revision| revision >= 17)
        && snapshot
            .serial_log
            .as_ref()
            .and_then(|path| fs::read(path).ok())
            .is_some_and(|log| {
                userspace_console(&log)
                    .windows(19)
                    .any(|part| part == b"BusyBox guest ready")
            })
}

/// Boot a new VM in the new folder `data_dir`, run the plan and stop the VM.
pub fn run_group(base: &Path, data_dir: &Path, plan: &VmPlan) -> Result<GroupRun, String> {
    if data_dir.exists() {
        return Err(format!("{} already exists", data_dir.display()));
    }
    wait_for_memory(1800)?;
    let options = BackendOptions {
        bundle_dir: base.to_path_buf(),
        data_dir: data_dir.to_path_buf(),
        headless: true,
        capture_quota_size: 8 * 1024 * 1024 * 1024,
        // After a load group the guest flushes gigabytes of file churn to
        // its disk before it powers off; the app's 10 s default would force
        // it off and mark the capture forced.
        shutdown_timeout: Duration::from_secs(120),
        ..Default::default()
    };
    let mut driver = Driver {
        backend: Backend::new(options)?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        errors: Vec::new(),
    };
    let result = drive(&mut driver, plan);
    // Whatever happened, the VM goes away with the backend.
    if driver.snapshot.state != VmState::Stopped {
        if let Err(error) = driver.command(Command::Stop, 600) {
            eprintln!("conformance: stopping the VM: {error}");
        }
        let _ = driver.wait("VM stop", 120, |s| s.state == VmState::Stopped);
    }
    // The guest's console, for diagnosing a boot or shutdown.
    if let (Some(serial), Some(group)) = (&driver.snapshot.serial_log, data_dir.parent())
        && let Err(error) = fs::copy(serial, group.join("serial.log"))
    {
        eprintln!("conformance: keeping the serial log: {error}");
    }
    driver.backend.shutdown()?;
    result
}

fn drive(driver: &mut Driver, plan: &VmPlan) -> Result<GroupRun, String> {
    driver.command(
        Command::Create(VmConfig {
            name: "conformance".into(),
            cpus: plan.cpus,
            ram_mib: plan.ram_mib,
            disk_gib: 2,
            transport: plan.transport,
            ..Default::default()
        }),
        60,
    )?;
    driver.wait("VM publication", 30, |s| !s.vms.is_empty())?;
    let vm_id = driver.snapshot.vms[0].id.clone();
    let booted = Instant::now();
    driver.command(Command::Start { vm_id }, 900)?;
    driver.wait("guest boot", 240, guest_ready)?;
    let boot_seconds = booted.elapsed().as_secs_f64();
    for (source, destination) in &plan.uploads {
        driver.command(
            Command::Upload {
                source: source.clone(),
                destination: destination.clone(),
                overwrite: true,
                executable: true,
            },
            300,
        )?;
    }
    let known: Vec<String> = driver.snapshot.runs.iter().map(|r| r.id.clone()).collect();
    let started = Instant::now();
    driver.command(
        Command::Execute(ExecRequest {
            path: plan.program.clone(),
            args: plan.args.clone(),
            env: vec!["PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into()],
            uid: plan.uid,
            gid: plan.gid,
            ..Default::default()
        }),
        120,
    )?;
    driver.wait("run publication", 60, |s| {
        s.runs.iter().any(|r| !known.contains(&r.id))
    })?;
    let id = driver
        .snapshot
        .runs
        .iter()
        .find(|r| !known.contains(&r.id))
        .map(|r| r.id.clone())
        .ok_or("new run missing")?;
    // The run ends when the guest says its whole tree ended with no request
    // outstanding, never on a terminal marker.
    let ended = driver.wait("run end", plan.timeout, |s| {
        s.runs.iter().any(|r| {
            r.id == id
                && r.execution
                    .as_ref()
                    .is_some_and(|e| e.flags & 2 != 0 && e.pending_async_count == 0)
        })
    });
    let run_seconds = started.elapsed().as_secs_f64();
    if let Err(error) = ended {
        let _ = driver.command(Command::StopRun { run_id: id.clone() }, 30);
        let _ = driver.wait("stopped run end", 60, |s| {
            s.runs
                .iter()
                .any(|r| r.id == id && r.execution.as_ref().is_some_and(|e| e.flags & 2 != 0))
        });
        return Err(format!("{} did not end: {error}", plan.program));
    }
    // Let the last terminal output and packets drain before reading counters.
    thread::sleep(Duration::from_secs(2));
    driver.command(Command::RecorderStats, 120)?;
    driver.receive();
    let recorder_stats = driver.snapshot.health.recorder_stats;
    // Stopping waits for queued recording writes.
    driver.command(Command::Stop, 900)?;
    driver.wait("VM stop", 120, |s| s.state == VmState::Stopped)?;
    thread::sleep(Duration::from_secs(1));
    driver.receive();
    let health = driver.snapshot.health.clone();
    let run = driver
        .snapshot
        .runs
        .iter()
        .find(|r| r.id == id)
        .cloned()
        .ok_or("run missing after the VM stopped")?;
    Ok(GroupRun {
        run,
        recorder_stats,
        health,
        errors: std::mem::take(&mut driver.errors),
        boot_seconds,
        run_seconds,
    })
}

/// Remove what the VM left besides the recording: disk overlay and runtime.
pub fn discard_vm_files(data_dir: &Path) {
    let Ok(entries) = fs::read_dir(data_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        for name in ["disk.qcow2", "runtime"] {
            let target = path.join(name);
            let removed = if target.is_dir() {
                fs::remove_dir_all(&target)
            } else {
                fs::remove_file(&target)
            };
            match removed {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    eprintln!("conformance: removing {}: {error}", target.display())
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn kernel_messages_inside_a_userspace_line_are_removed() {
        let log = b"x\nBusyBox guest re[    2.270733] rcS (103) used greatest stack depth\nady\n";
        let console = super::userspace_console(log);
        assert!(
            console
                .windows(19)
                .any(|part| part == b"BusyBox guest ready")
        );
        assert_eq!(super::userspace_console(b"[1] a\n[x] b"), b"[x] b");
    }
}
