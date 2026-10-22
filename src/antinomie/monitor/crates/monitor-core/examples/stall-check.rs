// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! A guest that stops answering for longer than the transport's health
//! timeout (its QEMU frozen with SIGSTOP, as a host under heavy load starves
//! it) must be reconnected by the app on its own once it runs again, and must
//! then run programs as before.
//!
//! usage: stall-check BUNDLE NEW_DATA_DIR [STALL_SECONDS]
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, ExecRequest, Notification, Snapshot, VmConfig, VmState,
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::Command as Process,
    thread,
    time::{Duration, Instant},
};

struct Harness {
    backend: Backend,
    snapshot: Snapshot,
    replies: BTreeMap<u64, Result<String, String>>,
    notices: Vec<String>,
    output: Vec<u8>,
}

impl Harness {
    fn receive(&mut self) {
        while let Some(message) = self.backend.try_recv() {
            match message {
                Notification::Snapshot(snapshot) => self.snapshot = snapshot,
                Notification::CommandResult { id: 0, message, .. } => {
                    println!("notice: {message}");
                    self.notices.push(message);
                }
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    self.replies
                        .insert(id, if success { Ok(message) } else { Err(message) });
                }
                Notification::Terminal { data, .. } => self.output.extend(data),
                _ => {}
            }
        }
    }

    fn command(&mut self, command: Command) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            self.receive();
            if let Some(result) = self.replies.remove(&id) {
                return result;
            }
            if Instant::now() >= deadline {
                return Err(format!("command {id} exceeded its deadline"));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait(&mut self, what: &str, secs: u64, done: impl Fn(&Self) -> bool) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            self.receive();
            if done(self) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "{what}: deadline; state {:?}, last error {:?}",
                    self.snapshot.state, self.snapshot.last_error
                ));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

fn signal(pid: u32, name: &str) -> Result<(), String> {
    let status = Process::new("kill")
        .args([format!("-{name}"), pid.to_string()])
        .status()
        .map_err(|e| e.to_string())?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("kill -{name} {pid} failed"))
}

/// The QEMU process of the VM named `name` (its command line holds `-name NAME`).
fn qemu_pid(name: &str) -> Option<u32> {
    fs::read_dir("/proc").ok()?.flatten().find_map(|entry| {
        let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
        let cmdline = fs::read(entry.path().join("cmdline")).ok()?;
        let args: Vec<&[u8]> = cmdline.split(|&b| b == 0).collect();
        let qemu = args.first()?.ends_with(b"qemu-system-x86_64");
        let named = args
            .windows(2)
            .any(|w| w[0] == b"-name" && w[1] == name.as_bytes());
        (qemu && named).then_some(pid)
    })
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (bundle, data) = match args.as_slice() {
        [bundle, data, ..] => (PathBuf::from(bundle), PathBuf::from(data)),
        _ => return Err("usage: stall-check BUNDLE NEW_DATA_DIR [STALL_SECONDS]".into()),
    };
    let stall: u64 = args
        .get(2)
        .and_then(|value| value.to_str()?.parse().ok())
        .unwrap_or(40);
    if data.exists() {
        return Err("the data folder must not exist yet".into());
    }
    let mut test = Harness {
        backend: Backend::new(BackendOptions {
            data_dir: data,
            bundle_dir: bundle,
            headless: true,
            ..BackendOptions::default()
        })?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        notices: Vec::new(),
        output: Vec::new(),
    };
    let name = "Stall check";
    test.command(Command::Create(VmConfig {
        name: name.into(),
        cpus: 2,
        ram_mib: 512,
        disk_gib: 1,
        ..VmConfig::default()
    }))?;
    test.receive();
    let vm_id = test.snapshot.vms.first().ok_or("VM missing")?.id.clone();
    test.command(Command::Start { vm_id })?;
    test.wait("guest ready", 60, |t| {
        t.snapshot
            .serial_log
            .as_ref()
            .and_then(|path| fs::read(path).ok())
            .is_some_and(|log| log.windows(19).any(|w| w == b"BusyBox guest ready"))
    })?;
    let echo = |marker: &str| ExecRequest {
        path: "/bin/sh".into(),
        args: vec!["-c".into(), format!("echo {marker}")],
        ..ExecRequest::default()
    };
    test.command(Command::Execute(echo("BEFORE-STALL")))?;
    test.wait("output before the stall", 30, |t| {
        String::from_utf8_lossy(&t.output).contains("BEFORE-STALL")
    })?;
    let pid = qemu_pid(name).ok_or("QEMU process not found")?;
    println!("freezing QEMU {pid} for {stall} s");
    signal(pid, "STOP")?;
    let frozen = Instant::now();
    while frozen.elapsed() < Duration::from_secs(stall) {
        test.receive();
        thread::sleep(Duration::from_millis(200));
    }
    signal(pid, "CONT")?;
    println!("QEMU running again");
    test.wait("automatic reconnection", 90, |t| {
        t.notices
            .iter()
            .any(|n| n.starts_with("The guest answers again"))
    })?;
    if !matches!(test.snapshot.state, VmState::Running) {
        return Err(format!(
            "VM state after reconnecting: {:?}",
            test.snapshot.state
        ));
    }
    test.command(Command::Execute(echo("AFTER-STALL")))?;
    test.wait("output after reconnecting", 30, |t| {
        String::from_utf8_lossy(&t.output).contains("AFTER-STALL")
    })?;
    println!("the guest runs programs again");
    test.command(Command::Stop)?;
    println!("STALL-CHECK-PASS");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("stall-check: {error}");
        std::process::exit(1);
    }
}
