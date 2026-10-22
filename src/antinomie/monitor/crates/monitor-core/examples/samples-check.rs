// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Sending a downloaded sample into a VM, end to end, without MalwareBazaar:
//! PROGRAM (a harmless static x86-64 test program that prints SAMPLE-RAN) is
//! packed as MalwareBazaar packs samples (AES zip, password `infected`) into
//! NEW_DATA_DIR's samples, a BusyBox VM is booted from BUNDLE, the sample is
//! sent in with UploadSample and run, and the push must be recorded with no
//! plaintext copy anywhere in the data folder.
//!
//! usage: samples-check BUNDLE NEW_DATA_DIR PROGRAM
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, ExecRequest, Notification, Snapshot, VmConfig, samples,
};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

struct Harness {
    backend: Backend,
    snapshot: Snapshot,
    replies: BTreeMap<u64, Result<String, String>>,
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
            thread::sleep(Duration::from_millis(100));
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Files under `dir` whose content is exactly `bytes`.
fn copies(dir: &Path, bytes: &[u8], found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => copies(&path, bytes, found),
            Ok(kind)
                if kind.is_file()
                    && entry
                        .metadata()
                        .is_ok_and(|m| m.len() == bytes.len() as u64)
                    && fs::read(&path).is_ok_and(|content| content == bytes) =>
            {
                found.push(path);
            }
            _ => {}
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [bundle, data, program] = args.as_slice() else {
        return Err("usage: samples-check BUNDLE NEW_DATA_DIR PROGRAM".into());
    };
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("the data folder must not exist yet".into());
    }
    let bytes = fs::read(program).map_err(|e| e.to_string())?;
    let hash = sha256(&bytes);
    // As MalwareBazaar serves it.
    fs::create_dir_all(samples::samples_dir(&data)).map_err(|e| e.to_string())?;
    let archive = samples::archive_path(&data, &hash)?;
    let mut writer = zip::ZipWriter::new(fs::File::create(&archive).map_err(|e| e.to_string())?);
    writer
        .start_file(
            format!("{hash}.elf"),
            zip::write::SimpleFileOptions::default()
                .with_aes_encryption(zip::AesMode::Aes128, samples::ARCHIVE_PASSWORD),
        )
        .map_err(|e| e.to_string())?;
    writer.write_all(&bytes).map_err(|e| e.to_string())?;
    writer.finish().map_err(|e| e.to_string())?;
    let record = samples::StoredSample {
        info: samples::SampleInfo {
            sha256_hash: hash.clone(),
            file_name: "sample-check.elf".into(),
            file_size: bytes.len() as u64,
            file_type: "elf".into(),
            file_arch: samples::elf_arch(&bytes).map(str::to_owned),
            ..samples::SampleInfo::default()
        },
        source: "samples-check".into(),
        downloaded_ms: 1,
        pushes: Vec::new(),
    };
    fs::write(
        archive.with_extension("json"),
        serde_json::to_vec(&record).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "archive {} ({} bytes)",
        archive.display(),
        fs::metadata(&archive).map_or(0, |m| m.len())
    );

    let mut test = Harness {
        backend: Backend::new(BackendOptions {
            data_dir: data.clone(),
            bundle_dir: PathBuf::from(bundle),
            headless: true,
            ..BackendOptions::default()
        })?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        output: Vec::new(),
    };
    test.command(Command::Create(VmConfig {
        name: "Samples check".into(),
        cpus: 2,
        ram_mib: 512,
        disk_gib: 1,
        ..VmConfig::default()
    }))?;
    test.receive();
    let vm_id = test.snapshot.vms.first().ok_or("VM missing")?.id.clone();
    test.command(Command::Start { vm_id })?;
    // The guest's root filesystem is ready when BusyBox says so.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        test.receive();
        if test
            .snapshot
            .serial_log
            .as_ref()
            .and_then(|path| fs::read(path).ok())
            .is_some_and(|log| log.windows(19).any(|w| w == b"BusyBox guest ready"))
        {
            break;
        }
        if Instant::now() >= deadline {
            return Err("guest readiness deadline".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
    let destination = format!("/tmp/{}-sample-check.elf", &hash[..12]);
    let sent = test.command(Command::UploadSample {
        sha256: hash.clone(),
        destination: destination.clone(),
        executable: true,
    })?;
    println!("{sent}");
    test.command(Command::Execute(ExecRequest {
        path: destination.clone(),
        uid: 1000,
        gid: 1000,
        cwd: "/tmp".into(),
        ..ExecRequest::default()
    }))?;
    test.wait_output("SAMPLE-RAN", 60)?;
    println!("the sample ran in the guest");
    let pushes = &samples::stored(&data)[0].pushes;
    if pushes.len() != 1 || pushes[0].path != destination {
        return Err(format!("push not recorded: {pushes:?}"));
    }
    println!("push recorded: {} at {}", pushes[0].vm_name, pushes[0].path);
    test.command(Command::Stop)?;
    let mut found = Vec::new();
    copies(&data, &bytes, &mut found);
    if !found.is_empty() {
        return Err(format!("plaintext copies on the host: {found:?}"));
    }
    println!("no plaintext copy in the data folder");
    println!("SAMPLES-CHECK-PASS");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("samples-check: {error}");
        std::process::exit(1);
    }
}
