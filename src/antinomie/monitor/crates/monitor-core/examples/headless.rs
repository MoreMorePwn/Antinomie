// SPDX-License-Identifier: GPL-3.0-only
use antinomie_monitor_core::{
    APP_REVISION, Backend, BackendOptions, Command, ExecRequest, Notification, Snapshot, VmConfig,
    VmLaunchOptions, VmState, recording::open_recording,
};
use std::{
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

fn verify_preserved_raw(
    directory: &std::path::Path,
    quota: u64,
    expected_packets: u64,
) -> Result<(), String> {
    let file = File::open(directory.join("telemetry.raw")).map_err(|e| e.to_string())?;
    let raw_len = file.metadata().map_err(|e| e.to_string())?.len();
    if raw_len == 0 || raw_len > quota {
        return Err("quota test did not preserve a nonempty raw archive within quota".into());
    }
    let mut reader = BufReader::new(file);
    let mut packets = 0;
    loop {
        let mut prefix = [0; 4];
        let len = reader.read(&mut prefix).map_err(|e| e.to_string())?;
        if len == 0 {
            break;
        }
        if len != 4 {
            reader
                .read_exact(&mut prefix[len..])
                .map_err(|e| format!("truncated raw length prefix: {e}"))?;
        }
        let data_len = u32::from_le_bytes(prefix) as usize;
        if !(128..=262112).contains(&data_len) {
            return Err("invalid preserved packet length".into());
        }
        let mut packet = vec![0; data_len];
        reader
            .read_exact(&mut packet)
            .map_err(|e| format!("truncated preserved packet: {e}"))?;
        antinomie_monitor_core::parser::parse_packet(&packet)
            .map_err(|e| format!("preserved packet invalid: {e}"))?;
        packets += 1;
    }
    if packets != expected_packets {
        return Err("preserved raw packet count differs from final health".into());
    }
    Ok(())
}

fn wait_command(
    backend: &Backend,
    id: u64,
    snapshot: &mut Snapshot,
    terminal: &mut Vec<u8>,
    seconds: u64,
) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        while let Some(notification) = backend.try_recv() {
            match notification {
                Notification::Snapshot(s) => *snapshot = s,
                Notification::Terminal { data, .. } => terminal.extend(data),
                Notification::CommandResult {
                    id: reply,
                    success,
                    message,
                } if reply == id => return if success { Ok(message) } else { Err(message) },
                _ => {}
            }
        }
        if Instant::now() > deadline {
            return Err(format!(
                "backend command {id} deadline; state {:?}; error {:?}",
                snapshot.state, snapshot.last_error
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}
fn terminal_until(
    backend: &Backend,
    marker: &[u8],
    snapshot: &mut Snapshot,
    terminal: &mut Vec<u8>,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if terminal.windows(marker.len()).any(|w| w == marker) {
            return Ok(());
        }
        if let Some(run) = snapshot.runs.last() {
            backend.send(Command::TerminalRead {
                run_id: run.id.clone(),
            })?;
        }
        let until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < until {
            while let Some(n) = backend.try_recv() {
                match n {
                    Notification::Snapshot(s) => *snapshot = s,
                    Notification::Terminal { data, .. } => terminal.extend(data),
                    Notification::CommandResult {
                        success: false,
                        message,
                        ..
                    } => return Err(message),
                    _ => {}
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        if Instant::now() > deadline {
            return Err(format!(
                "terminal marker {} deadline; received {}",
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(terminal)
            ));
        }
        if terminal.len() > 1024 * 1024 {
            return Err("terminal output exceeded smoke-test limit".into());
        }
    }
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 2 && args[0] == "--recording" {
        let recording = open_recording(&PathBuf::from(&args[1])).map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::json!({"manifest":recording.manifest,"event_count":recording.events.len()})
        );
        return Ok(());
    }
    if args.len() != 3 {
        return Err(
            "usage: headless BUNDLE DATA_DIR HOST_PROBE | headless --recording CAPTURE_DIR".into(),
        );
    }
    let test_quota = std::env::var("ANTINOMIE_TEST_QUOTA_SIZE")
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|e| format!("invalid ANTINOMIE_TEST_QUOTA_SIZE: {e}"))
        })
        .transpose()?;
    let mut backend = Backend::new(BackendOptions {
        bundle_dir: PathBuf::from(&args[0]),
        data_dir: PathBuf::from(&args[1]),
        headless: true,
        force_tcg: std::env::var_os("ANTINOMIE_FORCE_TCG").is_some(),
        capture_quota_size: test_quota
            .unwrap_or_else(|| BackendOptions::default().capture_quota_size),
        ..BackendOptions::default()
    })?;
    let mut snapshot = Snapshot::default();
    let mut terminal = Vec::new();
    let launch: VmLaunchOptions = std::env::var("ANTINOMIE_QA_LAUNCH")
        .ok()
        .map(|value| serde_json::from_str(&value).map_err(|error| error.to_string()))
        .transpose()?
        .unwrap_or_default();
    let id = backend.send(Command::Create(VmConfig {
        name: "Backend smoke".into(),
        cpus: 4,
        ram_mib: 1024,
        disk_gib: 1,
        launch,
        ..VmConfig::default()
    }))?;
    wait_command(&backend, id, &mut snapshot, &mut terminal, 30)?;
    let until = Instant::now() + Duration::from_secs(3);
    while snapshot.vms.is_empty() && Instant::now() < until {
        if let Some(Notification::Snapshot(s)) = backend.try_recv() {
            snapshot = s;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let vm_id = snapshot
        .vms
        .last()
        .ok_or("created VM missing from snapshot")?
        .id
        .clone();
    let id = backend.send(Command::Start {
        vm_id: vm_id.clone(),
    })?;
    wait_command(&backend, id, &mut snapshot, &mut terminal, 40)?;
    let readiness = Instant::now() + Duration::from_secs(20);
    loop {
        while let Some(n) = backend.try_recv() {
            if let Notification::Snapshot(s) = n {
                snapshot = s;
            }
        }
        if snapshot
            .serial_log
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .is_some_and(|data| {
                data.windows(b"BusyBox guest ready".len())
                    .any(|w| w == b"BusyBox guest ready")
            })
        {
            break;
        }
        if Instant::now() > readiness {
            return Err(format!(
                "guest rootfs readiness deadline; serial log {:?}",
                snapshot.serial_log
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
    // Revision 9: the guest identifies its kernel; the harness requires this
    // app's revision so a gate never passes against a stale kernel.
    let identified = Instant::now() + Duration::from_secs(10);
    let kernel = loop {
        while let Some(n) = backend.try_recv() {
            if let Notification::Snapshot(s) = n {
                snapshot = s;
            }
        }
        if let Some(kernel) = &snapshot.guest_kernel {
            break kernel.clone();
        }
        if Instant::now() > identified {
            return Err("guest kernel did not answer the INFO probe".into());
        }
        thread::sleep(Duration::from_millis(50));
    };
    println!(
        "GUEST KERNEL revision {:?} source {} release {}",
        kernel.revision,
        kernel.source.as_deref().unwrap_or("none"),
        kernel.release.as_deref().unwrap_or("unknown")
    );
    if kernel.revision != Some(APP_REVISION) {
        return Err(format!(
            "guest kernel revision {:?} differs from this app's {APP_REVISION}; last error: {}",
            kernel.revision,
            snapshot.last_error.as_deref().unwrap_or("none")
        ));
    }
    let id = backend.send(Command::Upload {
        source: PathBuf::from(&args[2]),
        destination: "/tmp/antinomie-probe".into(),
        overwrite: true,
        executable: true,
    })?;
    wait_command(&backend, id, &mut snapshot, &mut terminal, 30)?;
    let id = backend.send(Command::Execute(ExecRequest {
        path: "/tmp/antinomie-probe".into(),
        env: vec!["PATH=/bin:/sbin".into(), "ANT_PROBE=verified".into()],
        ..ExecRequest::default()
    }))?;
    wait_command(&backend, id, &mut snapshot, &mut terminal, 20)?;
    terminal_until(&backend, b"READY", &mut snapshot, &mut terminal)?;
    let id = backend.send(Command::TerminalInput {
        run_id: snapshot.runs.last().ok_or("run missing")?.id.clone(),
        data: b"ping\n".to_vec(),
    })?;
    wait_command(&backend, id, &mut snapshot, &mut terminal, 20)?;
    terminal_until(&backend, b"PASS", &mut snapshot, &mut terminal)?;
    let main_run = snapshot.runs.last().ok_or("run missing")?.id.clone();
    // The same probe then runs as root for the privileged bpf and uretprobe
    // cases (contract revision 5); quota tests stop after the main run.
    let mut root_run = None;
    let mut stress_run = None;
    if test_quota.is_none() {
        let main_terminal = std::mem::take(&mut terminal);
        let id = backend.send(Command::Execute(ExecRequest {
            path: "/tmp/antinomie-probe".into(),
            args: vec!["--root-bpf".into()],
            env: vec!["PATH=/bin:/sbin".into(), "ANT_PROBE=verified".into()],
            uid: 0,
            gid: 0,
            ..ExecRequest::default()
        }))?;
        wait_command(&backend, id, &mut snapshot, &mut terminal, 20)?;
        terminal_until(&backend, b"NATIVE PASS", &mut snapshot, &mut terminal)?;
        // The snapshot's run order is not launch order, and it may lag the terminal;
        // find the root run by its request once the snapshot includes it.
        let until = Instant::now() + Duration::from_secs(10);
        while root_run.is_none() {
            while let Some(n) = backend.try_recv() {
                if let Notification::Snapshot(s) = n {
                    snapshot = s;
                }
            }
            root_run = snapshot
                .runs
                .iter()
                .find(|run| run.request.args.iter().any(|arg| arg == "--root-bpf"))
                .map(|run| run.id.clone());
            if root_run.is_none() && Instant::now() > until {
                return Err("root run missing from snapshot".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
        // Contract revision 7, 14.8: a third run (UID 1000) exhausts async
        // staging, so its deliberate losses stay out of the main run.
        let id = backend.send(Command::Execute(ExecRequest {
            path: "/tmp/antinomie-probe".into(),
            args: vec!["--async-stress".into()],
            env: vec!["PATH=/bin:/sbin".into(), "ANT_PROBE=verified".into()],
            ..ExecRequest::default()
        }))?;
        wait_command(&backend, id, &mut snapshot, &mut terminal, 20)?;
        terminal_until(&backend, b"ASYNC STRESS PASS", &mut snapshot, &mut terminal)?;
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            while let Some(n) = backend.try_recv() {
                if let Notification::Snapshot(s) = n {
                    snapshot = s;
                }
            }
            // Its status is final once the tree exited and no request is pending.
            let finished = snapshot.runs.iter().find(|run| {
                run.request.args.iter().any(|arg| arg == "--async-stress")
                    && run
                        .execution
                        .as_ref()
                        .is_some_and(|e| e.flags & 2 != 0 && e.pending_async_count == 0)
            });
            if let Some(run) = finished {
                stress_run = Some((run.id.clone(), run.execution.clone()));
                break;
            }
            if Instant::now() > until {
                return Err("async stress run did not finish".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
        terminal = main_terminal;
    }
    let id = backend.send(Command::RecorderStats)?;
    let recorder = wait_command(&backend, id, &mut snapshot, &mut terminal, 10)?;
    let id = backend.send(Command::Stop)?;
    wait_command(&backend, id, &mut snapshot, &mut terminal, 20)?;
    backend.shutdown()?;
    while let Some(n) = backend.try_recv() {
        if let Notification::Snapshot(s) = n {
            snapshot = s;
        }
    }
    if snapshot.state != VmState::Stopped {
        return Err("VM did not stop".into());
    }
    let run_directory = |id: &str| {
        snapshot
            .runs
            .iter()
            .find(|run| run.id == id)
            .map(|run| run.directory.clone())
            .ok_or("run capture missing")
    };
    let directory = &run_directory(&main_run)?;
    let root_directory = root_run.as_deref().map(run_directory).transpose()?;
    let stress_directory = stress_run
        .as_ref()
        .map(|(id, _)| run_directory(id))
        .transpose()?;
    let stress_execution = stress_run.and_then(|(_, execution)| execution);
    let recording = open_recording(directory).map_err(|e| e.to_string())?;
    if recording.events.is_empty() {
        return Err("probe produced no syscall events".into());
    }
    if test_quota.is_none()
        && !recording
            .events
            .iter()
            .any(|e| e.fields.iter().any(|f| !f.preview.is_empty()))
    {
        return Err("probe produced no captured field data".into());
    }
    if let Some(quota) = test_quota {
        if snapshot.health.storage_dropped_packets == 0 {
            return Err("quota test did not count packets lost by the recording writer".into());
        }
        if !snapshot
            .health
            .persistence_error
            .as_ref()
            .is_some_and(|error| error.contains("quota exhausted"))
        {
            return Err(
                "quota test did not expose capture quota exhaustion in final health".into(),
            );
        }
        if !recording
            .manifest
            .get("persistence_error")
            .and_then(|v| v.as_str())
            .is_some_and(|error| error.contains("quota exhausted"))
        {
            return Err("quota exhaustion missing from final capture manifest".into());
        }
        if recording
            .manifest
            .get("final_state")
            .and_then(|v| v.as_str())
            != Some("clean")
        {
            return Err("guest failed to stop cleanly after capture quota exhaustion".into());
        }
        verify_preserved_raw(directory, quota, snapshot.health.persisted_packets)?;
    }
    println!(
        "{}",
        serde_json::json!({"vm_id":vm_id,"capture_dir":directory,"root_capture_dir":root_directory,"stress_capture_dir":stress_directory,"stress_execution":stress_execution,"event_count":recording.events.len(),"complete_count":recording.events.iter().filter(|e|e.complete).count(),"terminal":String::from_utf8_lossy(&terminal),"recorder":recorder,"health":snapshot.health,"manifest":recording.manifest,"test_quota_size":test_quota})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
