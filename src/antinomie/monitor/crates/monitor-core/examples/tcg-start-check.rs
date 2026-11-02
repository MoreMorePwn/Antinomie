// SPDX-License-Identifier: GPL-3.0-only
//! Starts one VM from a saved VM configuration in a throwaway data folder and
//! reports how long the boot took to attach: `tcg-start-check DATA_DIR
//! CONFIG_JSON [default|kvm|tcg] [stay_seconds]`. The base the configuration
//! names must already be under DATA_DIR/bases. Meant for hosts without KVM.
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, Notification, Snapshot, VmAcceleration, VmConfig, VmState,
};
use std::{
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

fn load() -> String {
    std::fs::read_to_string("/proc/loadavg").unwrap_or_default()
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        return Err(
            "usage: tcg-start-check DATA_DIR CONFIG_JSON [default|kvm|tcg] [stay_seconds]".into(),
        );
    }
    let mut config: VmConfig = serde_json::from_str(
        &std::fs::read_to_string(&args[1]).map_err(|e| format!("config: {e}"))?,
    )
    .map_err(|e| format!("config: {e}"))?;
    config.launch.acceleration = match args.get(2).map(String::as_str) {
        Some("kvm") => VmAcceleration::Kvm,
        Some("tcg") | None => VmAcceleration::Tcg,
        Some("default") => VmAcceleration::Default,
        Some(other) => return Err(format!("unknown accelerator {other}")),
    };
    let stay: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
    let base = config
        .base_identity
        .clone()
        .ok_or("the configuration names no base")?;
    config.id = String::new();
    config.name = "tcg start check".into();
    let backend = Backend::new(BackendOptions {
        data_dir: PathBuf::from(&args[0]),
        bundle_dir: PathBuf::from(&args[0]).join("bases").join(base),
        headless: true,
        ..BackendOptions::default()
    })?;
    let mut snapshot = Snapshot::default();
    let create = backend.send(Command::Create(config))?;
    let begin = Instant::now();
    let mut vm_id = None;
    let mut started = None;
    let mut last_state = None;
    let pending = Some(create);
    let mut stopped = None;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        while let Some(n) = backend.try_recv() {
            match n {
                Notification::Snapshot(s) => snapshot = s,
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    println!(
                        "[{:6.1}s] command {id} success={success}: {message}",
                        begin.elapsed().as_secs_f32()
                    );
                    if Some(id) == pending && vm_id.is_none() {
                        if !success {
                            return Err(message);
                        }
                    } else if Some(id) == started && !success {
                        return Err(message);
                    }
                }
                _ => {}
            }
        }
        if vm_id.is_none()
            && let Some(vm) = snapshot.vms.last()
        {
            vm_id = Some(vm.id.clone());
            started = Some(backend.send(Command::Start {
                vm_id: vm.id.clone(),
            })?);
            println!(
                "[{:6.1}s] started; load {}",
                begin.elapsed().as_secs_f32(),
                load().trim()
            );
        }
        if last_state.as_ref() != Some(&snapshot.state) {
            println!(
                "[{:6.1}s] state {:?}; load {}",
                begin.elapsed().as_secs_f32(),
                snapshot.state,
                load().trim()
            );
            last_state = Some(snapshot.state.clone());
        }
        if let Some(note) = &snapshot.start_note
            && seen.insert(note.split(" after ").next().unwrap_or(note).to_owned())
        {
            println!("[{:6.1}s] note: {note}", begin.elapsed().as_secs_f32());
        }
        if let Some(error) = &snapshot.last_error
            && seen.insert(error.clone())
        {
            println!("[{:6.1}s] error: {error}", begin.elapsed().as_secs_f32());
        }
        match snapshot.state {
            VmState::Running if stopped.is_none() => {
                println!(
                    "[{:6.1}s] attached; accelerator {:?}; staying {stay}s",
                    begin.elapsed().as_secs_f32(),
                    snapshot.accelerator
                );
                thread::sleep(Duration::from_secs(stay));
                stopped = Some(Instant::now());
                backend.send(Command::Stop)?;
            }
            VmState::Failed => return Err("VM failed to start".into()),
            VmState::Stopped if stopped.is_some() => {
                println!("[{:6.1}s] stopped", begin.elapsed().as_secs_f32());
                return Ok(());
            }
            _ => {}
        }
        if begin.elapsed() > Duration::from_secs(900) {
            return Err("gave up after 900 s".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("FAIL: {error}");
        std::process::exit(1);
    }
}
