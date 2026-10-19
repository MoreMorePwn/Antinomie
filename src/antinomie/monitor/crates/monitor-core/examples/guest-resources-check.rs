//! Boots one disposable BusyBox guest and watches the Summary resource feed.
//! Usage: guest-resources-check BUNDLE DATA_DIR
//! Prints the host's guest readings next to the guest's own `/proc/meminfo`,
//! `df` and process list, then freezes QEMU (SIGSTOP) to show the stale state
//! and resumes it (SIGCONT) to show recovery. Use a fresh DATA_DIR.
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, ExecRequest, GuestResources, Notification, Snapshot,
    VmConfig, VmState,
};
use std::{
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

fn pump(backend: &Backend, snapshot: &mut Snapshot, terminal: &mut Vec<u8>) {
    while let Some(notification) = backend.try_recv() {
        match notification {
            Notification::Snapshot(s) => *snapshot = s,
            Notification::Terminal { data, .. } => terminal.extend(data),
            _ => {}
        }
    }
}
fn wait(
    backend: &Backend,
    id: u64,
    snapshot: &mut Snapshot,
    terminal: &mut Vec<u8>,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        while let Some(notification) = backend.try_recv() {
            match notification {
                Notification::Snapshot(s) => *snapshot = s,
                Notification::Terminal { data, .. } => terminal.extend(data),
                Notification::CommandResult {
                    id: reply,
                    success,
                    message,
                } if reply == id => return if success { Ok(()) } else { Err(message) },
                _ => {}
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(format!("command {id} deadline"))
}
fn show(label: &str, guest: &GuestResources) {
    let mib =
        |value: Option<u64>| value.map_or("-".into(), |v| format!("{:.1}", v as f64 / 1048576.0));
    println!(
        "{label}: seq {} age {:?} ms stale {} mem used/total {}/{} MiB avail {} | root used/total {}/{} MiB free {} avail {} | error {:?}",
        guest.sample_sequence,
        guest.age_ms,
        guest.stale,
        mib(guest.memory_used_size),
        mib(guest.memory_total_size),
        mib(guest.memory_available_size),
        mib(guest.root_used_size),
        mib(guest.root_total_size),
        mib(guest.root_free_size),
        mib(guest.root_available_size),
        guest.error
    );
}
fn watch(
    backend: &Backend,
    snapshot: &mut Snapshot,
    terminal: &mut Vec<u8>,
    label: &str,
    seconds: u64,
) {
    let end = Instant::now() + Duration::from_secs(seconds);
    let mut next = Instant::now();
    while Instant::now() < end {
        pump(backend, snapshot, terminal);
        if Instant::now() >= next {
            match snapshot
                .vm_resources
                .as_ref()
                .and_then(|r| r.guest.as_ref())
            {
                Some(guest) => show(label, guest),
                None => println!("{label}: no guest resources in snapshot"),
            }
            next = Instant::now() + Duration::from_secs(1);
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn qemu_pid(vm_id: &str) -> Option<String> {
    let out = std::process::Command::new("pgrep")
        .args(["-f", &format!("qemu.*{vm_id}")])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(str::to_string)
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: guest-resources-check BUNDLE DATA_DIR".into());
    }
    let backend = Backend::new(BackendOptions {
        bundle_dir: PathBuf::from(&args[0]),
        data_dir: PathBuf::from(&args[1]),
        headless: true,
        ..BackendOptions::default()
    })?;
    let (mut snapshot, mut terminal) = (Snapshot::default(), Vec::new());
    let id = backend.send(Command::Create(VmConfig {
        name: "Resource check".into(),
        cpus: 1,
        ram_mib: 1024,
        disk_gib: 1,
        ..VmConfig::default()
    }))?;
    wait(&backend, id, &mut snapshot, &mut terminal)?;
    let until = Instant::now() + Duration::from_secs(3);
    while snapshot.vms.is_empty() && Instant::now() < until {
        pump(&backend, &mut snapshot, &mut terminal);
        thread::sleep(Duration::from_millis(10));
    }
    let vm_id = snapshot.vms.last().ok_or("VM missing")?.id.clone();
    let id = backend.send(Command::Start {
        vm_id: vm_id.clone(),
    })?;
    wait(&backend, id, &mut snapshot, &mut terminal)?;
    let until = Instant::now() + Duration::from_secs(60);
    while snapshot.guest_kernel.is_none() || snapshot.state != VmState::Running {
        pump(&backend, &mut snapshot, &mut terminal);
        if Instant::now() > until {
            return Err("guest kernel did not identify itself".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    println!("GUEST KERNEL {:?}", snapshot.guest_kernel);
    watch(&backend, &mut snapshot, &mut terminal, "boot", 6);

    // The guest's own view, from a shell launched through the normal control path.
    let id = backend.send(Command::Execute(ExecRequest {
        path: "/bin/sh".into(),
        args: vec![
            "-c".into(),
            "grep -E '^(MemTotal|MemAvailable)' /proc/meminfo; df -k /; ps; echo CHECK-DONE".into(),
        ],
        env: vec!["PATH=/bin:/sbin".into()],
        ..ExecRequest::default()
    }))?;
    wait(&backend, id, &mut snapshot, &mut terminal)?;
    let until = Instant::now() + Duration::from_secs(20);
    while !String::from_utf8_lossy(&terminal).contains("CHECK-DONE") && Instant::now() < until {
        pump(&backend, &mut snapshot, &mut terminal);
        if let Some(run) = snapshot.runs.last() {
            backend.send(Command::TerminalRead {
                run_id: run.id.clone(),
            })?;
        }
        thread::sleep(Duration::from_millis(100));
    }
    println!(
        "--- guest output ---\n{}",
        String::from_utf8_lossy(&terminal)
    );
    watch(&backend, &mut snapshot, &mut terminal, "after", 3);

    if let Some(pid) = qemu_pid(&vm_id) {
        println!("--- SIGSTOP qemu {pid} (guest frozen, replies delayed) ---");
        let _ = std::process::Command::new("kill")
            .args(["-STOP", &pid])
            .status();
        watch(&backend, &mut snapshot, &mut terminal, "frozen", 9);
        println!("--- SIGCONT ---");
        let _ = std::process::Command::new("kill")
            .args(["-CONT", &pid])
            .status();
        watch(&backend, &mut snapshot, &mut terminal, "resumed", 6);
    } else {
        println!("qemu pid not found; stale test skipped");
    }
    let id = backend.send(Command::Stop)?;
    let _ = wait(&backend, id, &mut snapshot, &mut terminal);
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("FAIL: {error}");
        std::process::exit(1);
    }
}
