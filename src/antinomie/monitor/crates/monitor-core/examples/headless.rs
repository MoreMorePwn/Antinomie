use antinomie_monitor_core::{
    Backend, BackendOptions, Command, ExecRequest, Notification, Snapshot, VmConfig, VmState,
    recording::open_recording,
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
                Notification::Terminal(data) => terminal.extend(data),
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
        backend.send(Command::TerminalRead)?;
        let until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < until {
            while let Some(n) = backend.try_recv() {
                match n {
                    Notification::Snapshot(s) => *snapshot = s,
                    Notification::Terminal(data) => terminal.extend(data),
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
    let id = backend.send(Command::Create(VmConfig {
        name: "Backend smoke".into(),
        cpus: 4,
        ram_mib: 1024,
        disk_gib: 1,
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
    let id = backend.send(Command::TerminalInput(b"ping\n".to_vec()))?;
    wait_command(&backend, id, &mut snapshot, &mut terminal, 20)?;
    terminal_until(&backend, b"PASS", &mut snapshot, &mut terminal)?;
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
    let directory = snapshot
        .capture_dir
        .as_ref()
        .ok_or("capture directory missing")?;
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
        serde_json::json!({"vm_id":vm_id,"capture_dir":directory,"event_count":recording.events.len(),"complete_count":recording.events.iter().filter(|e|e.complete).count(),"terminal":String::from_utf8_lossy(&terminal),"recorder":recorder,"health":snapshot.health,"manifest":recording.manifest,"test_quota_size":test_quota})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
