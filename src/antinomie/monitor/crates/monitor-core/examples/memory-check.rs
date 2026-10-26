// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Memory analysis end to end on a Debian base: boot a VM, start a marked
//! process, dump the VM's RAM as the Memory tab's Dump memory button does,
//! and run Volatility plugins on the dump as its Run button does.
//!
//! usage: memory-check DATA_DIR BASE_IDENTITY
//!
//! DATA_DIR holds the installed base and Volatility 3 (`install-tool DATA_DIR
//! volatility3`); the VM is left in it, with the dump and the plugin runs.
//!
//! With `ANTINOMIE_QA_COMMUNITY=1` the guest also caches a GnuPG passphrase
//! and opens an SSH session before the dump, and the catalog's GnuPG and
//! OpenSSH plugins (installed in DATA_DIR) must find them. The SSH session
//! (`ANTINOMIE_QA_SSH=USER:AUTHORIZED_KEYS`) needs a throwaway sshd on the
//! host's 127.0.0.1:22222 reading that keys file.
//!
//! With `ANTINOMIE_QA_SNAPSHOT=1` the VM is saved and restored from a full
//! snapshot before the dump, so the dump is of a restored VM; a snapshot asked
//! for while the dump runs must be refused, and one after it must work.
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, ExecRequest, GuestCredentials, Notification, Snapshot,
    SnapshotRequest, VmConfig, VmSnapshotMode,
    memory::{self, MemoryDump, RunState, Volatility},
};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const MARKER: &str = "memtest-marker";
/// Cached by gpg-agent in the community check; the partial plugin shows 8.
const GPG_PASSPHRASE: &str = "qa-pass-7319";

struct Harness {
    backend: Backend,
    snapshot: Snapshot,
    replies: BTreeMap<u64, Result<String, String>>,
    /// Terminal output of every guest program, together.
    output: Vec<u8>,
}

impl Harness {
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
                Notification::Terminal { data, .. } => self.output.extend(data),
                _ => {}
            }
        }
    }

    fn command(&mut self, command: Command) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(300);
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

    fn wait(
        &mut self,
        what: &str,
        secs: u64,
        done: impl Fn(&Snapshot) -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            self.receive();
            if done(&self.snapshot) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{what}: deadline"));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Harness {
    fn wait_output(&mut self, marker: &str, secs: u64) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            self.receive();
            if self
                .output
                .windows(marker.len())
                .any(|part| part == marker.as_bytes())
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "{marker} missing; guest output: {}",
                    String::from_utf8_lossy(&self.output)
                ));
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
}

/// The host's sshd for the SSH check: its user and authorized keys file.
fn ssh_target() -> Result<Option<(String, PathBuf)>, String> {
    let Some(value) = std::env::var_os("ANTINOMIE_QA_SSH") else {
        return Ok(None);
    };
    let value = value.to_string_lossy().into_owned();
    let (user, keys) = value
        .split_once(':')
        .ok_or("ANTINOMIE_QA_SSH is USER:AUTHORIZED_KEYS")?;
    if user.is_empty()
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err("bad ANTINOMIE_QA_SSH user".into());
    }
    Ok(Some((user.to_owned(), PathBuf::from(keys))))
}

/// Recording directories holding memory dumps under `dir`.
fn dump_roots(dir: &Path, depth: usize, roots: &mut Vec<PathBuf>) {
    if depth == 0 {
        return;
    }
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        if entry.file_name() == memory::MEMORY_DIR {
            roots.push(dir.to_path_buf());
        } else {
            dump_roots(&path, depth - 1, roots);
        }
    }
}

fn run_plugin(
    volatility: &Volatility,
    dump: &MemoryDump,
    plugin: &str,
    args: &[&str],
) -> Result<memory::ResultTable, String> {
    let started = Instant::now();
    let handle = volatility.start(
        dump,
        plugin,
        args.iter().map(|s| s.to_string()).collect(),
        false,
    )?;
    let deadline = started + Duration::from_secs(900);
    let run = loop {
        if let Some(run) = handle.progress().finished {
            break run;
        }
        if Instant::now() >= deadline {
            handle.cancel();
            return Err(format!("{plugin}: deadline"));
        }
        thread::sleep(Duration::from_millis(200));
    };
    if run.state != RunState::Finished {
        let log = fs::read_to_string(run.dir.join("log.txt")).unwrap_or_default();
        return Err(format!(
            "{plugin}: {:?} {:?}\n{}",
            run.state,
            run.error,
            log.lines().rev().take(15).collect::<Vec<_>>().join("\n")
        ));
    }
    let table = memory::read_result(&run.output(), 100_000)?;
    println!(
        "{plugin}: {} rows, {} columns, {:.1} s",
        table.rows.len(),
        table.columns.len(),
        started.elapsed().as_secs_f32()
    );
    Ok(table)
}

/// Rows of `table` with `needle` in any value.
fn rows_with(table: &memory::ResultTable, needle: &str) -> Vec<String> {
    table
        .rows
        .iter()
        .map(|row| {
            row.values
                .iter()
                .zip(&table.columns)
                .map(|(value, column)| memory::value_text(column.kind, value))
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .filter(|line| line.contains(needle))
        .collect()
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [data, base] = args.as_slice() else {
        return Err("usage: memory-check DATA_DIR BASE_IDENTITY".into());
    };
    let data = PathBuf::from(data);
    let volatility = Volatility::locate(&data)?;
    let community = std::env::var_os("ANTINOMIE_QA_COMMUNITY").is_some();
    let snapshots = std::env::var_os("ANTINOMIE_QA_SNAPSHOT").is_some();
    let mut random = [0; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|e| e.to_string())?;
    let password: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut test = Harness {
        backend: Backend::new(BackendOptions {
            data_dir: data.clone(),
            bundle_dir: data.join("bases").join(base),
            headless: true,
            shutdown_timeout: Duration::from_secs(60),
            ..BackendOptions::default()
        })?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        output: Vec::new(),
    };
    test.command(Command::CreateWithCredentials {
        vm: VmConfig {
            name: "Memory check".into(),
            cpus: 4,
            ram_mib: 4096,
            disk_gib: 16,
            // The SSH check reaches the host through NAT.
            nat: community,
            base_identity: Some(base.to_string_lossy().into_owned()),
            ..VmConfig::default()
        },
        credentials: GuestCredentials::new("qauser".into(), password)?,
    })?;
    test.receive();
    let vm_id = test
        .snapshot
        .vms
        .iter()
        .rev()
        .find(|vm| vm.name == "Memory check")
        .ok_or("created VM missing")?
        .id
        .clone();
    let booted = Instant::now();
    test.command(Command::Start {
        vm_id: vm_id.clone(),
    })?;
    test.wait("Debian PID1 start", 180, |s| {
        s.serial_log
            .as_ref()
            .and_then(|path| fs::read(path).ok())
            .is_some_and(|data| data.windows(8).any(|part| part == b"systemd["))
    })?;
    // A process to find in the dump: its own name, a listening socket.
    test.command(Command::Execute(ExecRequest {
        path: "/bin/bash".into(),
        args: vec![
            "-c".into(),
            format!(
                "cp /usr/bin/python3 /tmp/{MARKER}; exec /tmp/{MARKER} -c \
                 'import socket,time; s=socket.socket(); s.bind((\"0.0.0.0\",48151)); \
                 s.listen(); time.sleep(3600)'"
            ),
        ],
        uid: 1000,
        gid: 1000,
        ..ExecRequest::default()
    }))?;
    if community {
        // A signing key whose passphrase gpg-agent then caches.
        test.command(Command::Execute(ExecRequest {
            path: "/bin/bash".into(),
            args: vec![
                "-c".into(),
                format!(
                    "export HOME=/home/qauser GNUPGHOME=/home/qauser/.gnupg; \
                     mkdir -p -m 700 $GNUPGHOME; \
                     gpg --batch --pinentry-mode loopback --passphrase '{GPG_PASSPHRASE}' \
                     --quick-gen-key 'QA <qa@example.org>' ed25519 sign never && \
                     echo signed | gpg --batch --pinentry-mode loopback \
                     --passphrase '{GPG_PASSPHRASE}' --sign > /tmp/signed.gpg && \
                     echo GPG-READY; sleep 3600"
                ),
            ],
            uid: 1000,
            gid: 1000,
            ..ExecRequest::default()
        }))?;
        // An open SSH session (its session keys in the client's memory) to a
        // throwaway sshd on the host: ANTINOMIE_QA_SSH=USER:AUTHORIZED_KEYS
        // names its user and the file it reads keys from, at 127.0.0.1:22222.
        // The guest's key is allowed to run only `echo; sleep`.
        if let Some(user) = ssh_target()?.map(|(user, _)| user) {
            test.command(Command::Execute(ExecRequest {
                path: "/bin/bash".into(),
                args: vec![
                    "-c".into(),
                    format!(
                        "export HOME=/root DEBIAN_FRONTEND=noninteractive; \
                         for n in $(seq 90); do ip route | grep -q default && break; \
                         sleep 2; done; \
                         command -v ssh >/dev/null || {{ \
                         echo 'nameserver 10.0.2.3' > /etc/resolv.conf; \
                         apt-get update -qq && apt-get install -y -qq openssh-client \
                         >/dev/null; }}; \
                         su - qauser -c 'mkdir -p ~/.ssh; \
                         ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_qa; \
                         echo PUBKEY: $(cat ~/.ssh/id_qa.pub); \
                         until ssh -T -i ~/.ssh/id_qa -o StrictHostKeyChecking=no \
                         -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
                         -p 22222 {user}@10.0.2.2; do sleep 2; done'"
                    ),
                ],
                uid: 0,
                gid: 0,
                ..ExecRequest::default()
            }))?;
        }
    }
    if community {
        test.wait_output("GPG-READY", 600)?;
        println!("guest: GPG-READY");
        if let Some((_, keys)) = ssh_target()? {
            test.wait_output("PUBKEY: ", 600)?;
            let text = String::from_utf8_lossy(&test.output).into_owned();
            let key = text
                .split("PUBKEY: ")
                .nth(1)
                .and_then(|rest| rest.lines().next())
                .map(str::trim)
                .filter(|key| key.starts_with("ssh-ed25519 "))
                .ok_or("guest SSH key missing")?;
            fs::write(
                &keys,
                format!("restrict,command=\"echo SSH-SESSION-OPEN; sleep 3600\" {key}\n"),
            )
            .map_err(|e| format!("{}: {e}", keys.display()))?;
            test.wait_output("SSH-SESSION-OPEN", 120)?;
            println!("guest: SSH session open");
        }
    }
    thread::sleep(Duration::from_secs(20));
    println!("guest up in {:.0} s", booted.elapsed().as_secs_f32());

    let full = |name: &str| Command::CreateVmSnapshot {
        vm_id: vm_id.clone(),
        request: SnapshotRequest {
            name: name.into(),
            description: String::new(),
            mode: VmSnapshotMode::Full,
        },
    };
    if snapshots {
        let saved = Instant::now();
        test.command(full("Before dump"))?;
        test.command(Command::RefreshVmSnapshots {
            vm_id: vm_id.clone(),
        })?;
        let snapshot_id = test
            .snapshot
            .vm_snapshot_trees
            .get(&vm_id)
            .and_then(|tree| tree.nodes.iter().find(|node| node.name == "Before dump"))
            .ok_or("snapshot missing")?
            .id
            .clone();
        test.command(Command::RestoreVmSnapshot {
            vm_id: vm_id.clone(),
            snapshot_id,
            boot_from_disk: false,
            save_current: None,
            confirmed: true,
            switch_profile: false,
        })?;
        println!(
            "full snapshot saved and restored in {:.1} s",
            saved.elapsed().as_secs_f32()
        );
    }

    let dumped = Instant::now();
    test.command(Command::DumpMemory)?;
    if snapshots {
        match test.command(full("During dump")) {
            Ok(_) => return Err("snapshot accepted while the dump ran".into()),
            Err(error) => println!("snapshot during the dump refused: {error}"),
        }
    }
    test.wait("memory dump", 300, |s| s.memory_dump.is_none())?;
    println!("dump written in {:.1} s", dumped.elapsed().as_secs_f32());
    let mut roots = Vec::new();
    dump_roots(&data.join("vms"), 6, &mut roots);
    dump_roots(&data, 4, &mut roots);
    let dump = memory::list(&roots)
        .into_iter()
        .find(|dump| dump.vm_name == "Memory check")
        .ok_or("dump missing")?;
    println!(
        "dump {} {} bytes, symbols {}, system {}",
        dump.id,
        dump.bytes.unwrap_or(0),
        dump.symbols,
        dump.system
    );
    if !dump.complete() || !dump.symbols {
        return Err(format!("dump incomplete or without symbols: {dump:?}"));
    }
    // The VM keeps running after the dump.
    let status = test.command(Command::Execute(ExecRequest {
        path: "/bin/true".into(),
        uid: 1000,
        gid: 1000,
        ..ExecRequest::default()
    }));
    println!("guest still answers after the dump: {}", status.is_ok());
    status?;
    if snapshots {
        test.command(full("After dump"))?;
        println!("full snapshot after the dump saved");
    }

    let catalog = volatility.plugins()?;
    println!(
        "{} plugins, {} community failures",
        catalog.plugins.len(),
        catalog.failures.len()
    );
    let pslist = run_plugin(&volatility, &dump, "linux.pslist.PsList", &[])?;
    let found = rows_with(&pslist, "memtest-marke");
    println!("pslist marker rows: {found:#?}");
    if found.is_empty() {
        return Err("marked process not in pslist".into());
    }
    let pid = found[0].split(" | ").nth(1).unwrap_or_default().to_string();
    let psaux = run_plugin(&volatility, &dump, "linux.psaux.PsAux", &["--pid", &pid])?;
    println!("psaux: {:#?}", rows_with(&psaux, MARKER));
    let sockets = run_plugin(
        &volatility,
        &dump,
        "linux.sockstat.Sockstat",
        &["--pids", &pid],
    )?;
    let listening = rows_with(&sockets, "48151");
    println!("sockstat: {listening:#?}");
    if listening.is_empty() {
        return Err("marked socket not in sockstat".into());
    }
    let tree = run_plugin(&volatility, &dump, "linux.pstree.PsTree", &[])?;
    println!(
        "pstree rows nested: {}",
        tree.rows.iter().filter(|r| r.depth > 0).count()
    );
    for plugin in [
        "linux.lsmod.Lsmod",
        "linux.mountinfo.MountInfo",
        "linux.malware.check_syscall.Check_syscall",
    ] {
        if let Err(error) = run_plugin(&volatility, &dump, plugin, &[]) {
            println!("{error}");
        }
    }
    if community {
        // GPGItem decrypts gpg-agent's cache (needs python3-cryptography).
        let full = run_plugin(&volatility, &dump, "kudelski_gpg.gpg_full.GPGItem", &[])?;
        let found = rows_with(&full, GPG_PASSPHRASE);
        println!("gpg_full: {found:#?}");
        if found.is_empty() {
            return Err("cached GnuPG passphrase not found".into());
        }
        // Reported only: libgcrypt 1.8.9 and later defeat GPGPassphrase, and
        // the OpenSSH plugin knows older OpenSSH structures.
        for plugin in [
            "kudelski_gpg.gpg_partial.GPGPassphrase",
            "fox_openssh.openssh_sessionkeys.SSHKeys",
        ] {
            match run_plugin(&volatility, &dump, plugin, &[]) {
                Ok(table) => println!("{plugin}: {} rows", table.rows.len()),
                Err(error) => println!("{error}"),
            }
        }
    }
    test.command(Command::Stop)?;
    println!("MEMORY-CHECK-PASS");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("memory-check: {error}");
        std::process::exit(1);
    }
}
