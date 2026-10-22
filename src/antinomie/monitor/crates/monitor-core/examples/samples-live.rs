// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! MalwareBazaar end to end with a real API key: the searches the Malware
//! samples window makes, one small ELF sample downloaded into
//! NEW_DATA_DIR, its archive opened in memory and its hash checked, and, with
//! BUNDLE (a BusyBox base), the sample sent into a VM and hashed there. The
//! sample is never run, on the host or in the guest.
//!
//! With `ANTINOMIE_QA_SOURCE=malshare` the same is done with MalShare (its
//! newest ELF samples instead of Mirai).
//!
//! usage: samples-live NEW_DATA_DIR [BUNDLE] < key
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, ExecRequest, Notification, Snapshot, VmConfig,
    samples::{self, Query, Source},
};
use std::{
    collections::BTreeMap,
    fs,
    io::BufRead,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const CURL: &str = "/usr/bin/curl";

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

    fn wait_output(&mut self, marker: &str, secs: u64) -> Result<String, String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            self.receive();
            let text = String::from_utf8_lossy(&self.output).into_owned();
            if text.contains(marker) {
                return Ok(text);
            }
            if Instant::now() >= deadline {
                return Err(format!("{marker} missing; guest output: {text}"));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
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
    let (data, bundle) = match args.as_slice() {
        [data] => (PathBuf::from(data), None),
        [data, bundle] => (PathBuf::from(data), Some(PathBuf::from(bundle))),
        _ => return Err("usage: samples-live NEW_DATA_DIR [BUNDLE] < key".into()),
    };
    if data.exists() {
        return Err("the data folder must not exist yet".into());
    }
    let mut key = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut key)
        .map_err(|e| e.to_string())?;
    fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    let source = match std::env::var("ANTINOMIE_QA_SOURCE").as_deref() {
        Ok("malshare") => Source::MalShare,
        _ => Source::MalwareBazaar,
    };
    // Host-only checks need the key only in memory, not in a test data folder.
    let key = key.trim().to_owned();
    let curl = Path::new(CURL);
    println!("source {}", source.label());

    // The searches the window makes, then candidates to download.
    let texts: &[&str] = match source {
        Source::MalwareBazaar => &["", "Mirai", "elf"],
        Source::MalShare => &["", "elf", "x86_64"],
    };
    for text in texts {
        // A large tag can be more than MalwareBazaar answers in time.
        match source.find(curl, &key, text, 50) {
            Ok((listing, found)) => println!(
                "{listing}: {} samples, {} ELF",
                found.len(),
                found.iter().filter(|s| s.is_elf()).count()
            ),
            Err(error) => println!("{text:?}: {error}"),
        }
    }
    let mut candidates = match source {
        Source::MalwareBazaar => {
            samples::search(curl, &key, &Query::Signature("Mirai".into()), 100)?
        }
        Source::MalShare => source.find(curl, &key, "", 100)?.1,
    };
    candidates.retain(|s| s.is_elf() && s.file_size < 2 * 1024 * 1024);
    // MalShare lists no sizes (0): those keep its order.
    candidates.sort_by_key(|s| s.file_size);
    // A host-only encrypted round-trip can use any ELF architecture. Guest
    // upload checks need an x86-64 candidate for the supported guest platform.
    let mut chosen = None;
    for info in candidates.iter().take(15) {
        let stored = source.download(curl, &key, &data, info)?;
        let archive = samples::archive_path(&data, &info.sha256_hash)?;
        let bytes = samples::open_sample(&archive, &info.sha256_hash)?;
        let arch = samples::elf_arch(&bytes);
        println!(
            "downloaded {} ({} bytes, archive {} bytes): {arch:?}",
            &info.sha256_hash[..16],
            bytes.len(),
            fs::metadata(&archive).map_or(0, |m| m.len())
        );
        if fs::read(&archive).is_ok_and(|zip| !zip.starts_with(b"PK")) {
            return Err("the stored archive is not a zip".into());
        }
        if bytes.len() < 2 * 1024 * 1024 && (bundle.is_none() || arch == Some("x86_64")) {
            chosen = Some((stored, bytes));
            break;
        }
        samples::delete(&data, &info.sha256_hash)?;
    }
    let (stored, bytes) = chosen.ok_or("no small x86-64 ELF sample among the first 15")?;
    let hash = stored.info.sha256_hash.clone();
    println!(
        "kept {hash}: {} ({}), first seen {}, from {}",
        stored.info.file_name,
        stored.info.signature.as_deref().unwrap_or("no family"),
        stored.info.first_seen,
        stored.source
    );
    let (_, by_hash) = source.find(curl, &key, &hash, 1)?;
    if by_hash.first().map(|s| s.sha256_hash.as_str()) != Some(hash.as_str()) {
        return Err("hash lookup did not return the sample".into());
    }
    println!("hash lookup returns the sample");

    if let Some(bundle) = bundle {
        samples::save_source_key(&data, source, &key)?;
        let mut test = Harness {
            backend: Backend::new(BackendOptions {
                data_dir: data.clone(),
                bundle_dir: bundle,
                headless: true,
                ..BackendOptions::default()
            })?,
            snapshot: Snapshot::default(),
            replies: BTreeMap::new(),
            output: Vec::new(),
        };
        // No network: the VM has no NAT.
        test.command(Command::Create(VmConfig {
            name: "Samples live".into(),
            cpus: 2,
            ram_mib: 512,
            disk_gib: 1,
            ..VmConfig::default()
        }))?;
        test.receive();
        let vm_id = test.snapshot.vms.first().ok_or("VM missing")?.id.clone();
        test.command(Command::Start { vm_id })?;
        let deadline = Instant::now() + Duration::from_secs(60);
        while !test
            .snapshot
            .serial_log
            .as_ref()
            .and_then(|path| fs::read(path).ok())
            .is_some_and(|log| log.windows(19).any(|w| w == b"BusyBox guest ready"))
        {
            if Instant::now() >= deadline {
                return Err("guest readiness deadline".into());
            }
            thread::sleep(Duration::from_millis(100));
            test.receive();
        }
        let destination = format!("/tmp/{}-sample.elf", &hash[..12]);
        println!(
            "{}",
            test.command(Command::UploadSample {
                sha256: hash.clone(),
                destination: destination.clone(),
                executable: false,
            })?
        );
        test.command(Command::Execute(ExecRequest {
            path: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!("sha256sum {destination}; ls -l {destination}; echo HASHED"),
            ],
            uid: 1000,
            gid: 1000,
            cwd: "/tmp".into(),
            ..ExecRequest::default()
        }))?;
        let text = test.wait_output("HASHED", 60)?;
        if !text.contains(&hash) {
            return Err(format!("guest hash differs: {text}"));
        }
        println!("the guest's copy has the sample's SHA-256 and is not executable:");
        for line in text.lines().filter(|l| l.contains(&hash[..12])) {
            println!("  {}", line.trim());
        }
        let pushes = &samples::stored(&data)[0].pushes;
        if pushes.len() != 1 || pushes[0].path != destination {
            return Err(format!("push not recorded: {pushes:?}"));
        }
        println!("push recorded: {} at {}", pushes[0].vm_name, pushes[0].path);
        test.command(Command::Stop)?;
    }
    let mut found = Vec::new();
    copies(&data, &bytes, &mut found);
    if !found.is_empty() {
        return Err(format!("plaintext copies on the host: {found:?}"));
    }
    println!("no plaintext copy in the data folder");
    println!("SAMPLES-LIVE-PASS");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("samples-live: {error}");
        std::process::exit(1);
    }
}
