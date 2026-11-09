// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM check of the non-resident core policy and the coverage counts of a
//! live core (guest contract revision 22, ANT-T0343).
//!
//!   core-coverage-check BUNDLE NEW_DATA_DIR FIXTURE
//!
//! One BusyBox VM. FIXTURE (tests/monitor/nonresident-core-fixture.c built for
//! the VM's architecture) maps a file of 256 pages, reads them and has the
//! kernel reclaim them (MADV_PAGEOUT), so they hold data but are not in
//! memory. Two live cores of it are taken: one resident-only, one with Read
//! non-resident pages. The first must count the file's pages as not kept and
//! read none in; the second must have read pages in (one read can bring
//! neighbours along: the kernel's fault-around), carry CORE_NONRESIDENT, and
//! its file's mapping must hold every page's bytes ("page N" at each page).
//! Every program is benign; the data folder must be new and disposable.
use antinomie_monitor_core::*;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

const PAGES: u32 = 256;

struct Driver {
    backend: Backend,
    snapshot: Snapshot,
    replies: BTreeMap<u64, Result<String, String>>,
    output: BTreeMap<String, Vec<u8>>,
    scale: u64,
}

impl Driver {
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
                Notification::Terminal { run_id, data, .. } => {
                    self.output.entry(run_id).or_default().extend(data)
                }
                _ => {}
            }
        }
    }
    fn command(&mut self, command: Command, seconds: u64) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(seconds * self.scale);
        loop {
            self.receive();
            if let Some(reply) = self.replies.remove(&id) {
                return reply;
            }
            if Instant::now() >= deadline {
                return Err(format!("command {id} timed out"));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn wait(
        &mut self,
        label: &str,
        seconds: u64,
        ready: impl Fn(&Snapshot) -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds * self.scale);
        loop {
            self.receive();
            if ready(&self.snapshot) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{label} timed out: {:?}", self.snapshot.last_error));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    /// Take a live core of `target` and wait until it is final.
    fn core(
        &mut self,
        vm_id: &str,
        target: &observation::GuestProcessIdentity,
        nonresident: bool,
    ) -> Result<ProcessCoreCapture, String> {
        let old: Vec<String> = self
            .snapshot
            .process_cores
            .iter()
            .map(|core| core.id.clone())
            .collect();
        self.command(
            Command::DumpProcessCore {
                request: ProcessCoreRequest {
                    vm_id: vm_id.into(),
                    target: target.clone(),
                    max_size: 64 << 20,
                    timeout_ms: 30_000,
                    read_nonresident: nonresident,
                    ..Default::default()
                },
            },
            60,
        )?;
        self.wait("final core", 180, |snapshot| {
            snapshot
                .process_cores
                .iter()
                .any(|core| !old.contains(&core.id) && core.state.is_terminal())
        })?;
        self.snapshot
            .process_cores
            .iter()
            .find(|core| !old.contains(&core.id))
            .cloned()
            .ok_or_else(|| "core record missing".into())
    }
}

/// The bytes the fixture's data mapping holds in `path`: the pages whose
/// first bytes read "page N", out of how many pages the mapping has.
fn pages_with_data(path: &std::path::Path) -> Result<(u64, u64), String> {
    let core = core_dump::CoreDump::open(path).map_err(|error| error.to_string())?;
    let file = core
        .files
        .iter()
        .find(|file| file.path.ends_with("nonresident-data"))
        .ok_or("the core has no mapping of the fixture's file")?;
    let pages = (file.end - file.start) / 4096;
    let mut found = 0;
    for page in 0..pages {
        let bytes: Vec<u8> = core
            .read_virtual(file.start + page * 4096, 16)
            .unwrap_or_default()
            .into_iter()
            .map_while(|byte| byte)
            .collect();
        if bytes.starts_with(format!("page {page}").as_bytes()) {
            found += 1;
        }
    }
    Ok((found, pages))
}

fn coverage(core: &ProcessCoreCapture) -> Result<CoreCoverage, String> {
    core.coverage.clone().ok_or_else(|| {
        format!(
            "no coverage counts in the core record {:?}",
            core.guest_status
        )
    })
}

fn check(bundle: &str, data: &str, fixture: &str) -> Result<(), String> {
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("the check needs a new disposable data folder".into());
    }
    let arm64 = fs::read_to_string(PathBuf::from(bundle).join("bundle.json"))
        .is_ok_and(|text| text.contains("\"arm64\""));
    let mut d = Driver {
        backend: Backend::new(BackendOptions {
            bundle_dir: PathBuf::from(bundle),
            data_dir: data,
            headless: true,
            serial_console: true,
            capture_quota_size: 512 * 1024 * 1024,
            ..Default::default()
        })?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        output: BTreeMap::new(),
        scale: if arm64 { 8 } else { 1 },
    };
    d.command(
        Command::Create(VmConfig {
            name: "core coverage check".into(),
            cpus: 2,
            ram_mib: 1024,
            disk_gib: 1,
            ..Default::default()
        }),
        120,
    )?;
    d.wait("VM publication", 10, |s| !s.vms.is_empty())?;
    let vm_id = d.snapshot.vms[0].id.clone();
    d.command(
        Command::Start {
            vm_id: vm_id.clone(),
        },
        300,
    )?;
    d.wait("guest", 180, |s| {
        s.guest_kernel.as_ref().and_then(|k| k.revision).is_some()
            && s.guest_core_limits.is_some()
            && s.serial_log
                .as_ref()
                .and_then(|p| fs::read(p).ok())
                .is_some_and(|log| log.windows(19).any(|w| w == b"BusyBox guest ready"))
    })?;
    if !d.snapshot.guest_core_limits.is_some_and(|l| l.nonresident) {
        return Err("this base does not offer the non-resident policy (revision 22)".into());
    }
    d.command(
        Command::Upload {
            source: PathBuf::from(fixture),
            destination: "/root/nonresident-core-fixture".into(),
            overwrite: true,
            executable: true,
        },
        120,
    )?;
    let known: Vec<String> = d.snapshot.runs.iter().map(|r| r.id.clone()).collect();
    d.command(
        Command::Execute(ExecRequest {
            path: "/root/nonresident-core-fixture".into(),
            // The program's arguments after its name.
            args: vec!["/root".into(), PAGES.to_string()],
            uid: 0,
            gid: 0,
            cwd: "/root".into(),
            ..Default::default()
        }),
        60,
    )?;
    d.wait("run publication", 15, |s| {
        s.runs.iter().any(|r| !known.contains(&r.id))
    })?;
    let run = d
        .snapshot
        .runs
        .iter()
        .find(|r| !known.contains(&r.id))
        .cloned()
        .ok_or("run missing")?;
    let id = run.id.clone();
    d.wait("fixture ready", 60, |_| true)?;
    let deadline = Instant::now() + Duration::from_secs(60 * d.scale);
    while !d
        .output
        .get(&id)
        .is_some_and(|out| String::from_utf8_lossy(out).contains("NONRESIDENT READY"))
    {
        d.receive();
        if Instant::now() > deadline {
            return Err("the fixture did not say it was ready".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
    d.command(Command::ListProcesses { after_pid: 0 }, 30)?;
    let target = d
        .snapshot
        .process_page
        .as_ref()
        .and_then(|page| page.processes.iter().find(|p| p.identity.tgid == run.pid))
        .ok_or("the fixture is not in the process list")?
        .identity
        .clone();
    let mut errors = Vec::new();
    let resident = d.core(&vm_id, &target, false)?;
    let counts = coverage(&resident)?;
    println!(
        "RESIDENT core {:?}: {:?}, reason {:?}",
        resident.state, counts, resident.reason
    );
    if counts.pages_unavailable.unwrap_or(0) < PAGES * 3 / 4 || counts.pages_read_in != 0 {
        errors.push(format!(
            "resident-only: expected at least {} pages not kept and none read in, got {counts:?}",
            PAGES * 3 / 4
        ));
    } else {
        println!("PASS resident-only core counts the reclaimed pages as not kept");
    }
    let read_in = d.core(&vm_id, &target, true)?;
    let counts = coverage(&read_in)?;
    println!(
        "NONRESIDENT core {:?}: {:?}, reason {:?}",
        read_in.state, counts, read_in.reason
    );
    let flags = read_in
        .guest_status
        .as_ref()
        .and_then(|status| status["flags"].as_u64())
        .unwrap_or(0);
    // One read can bring a run of neighbouring file pages in (the kernel's
    // fault-around), so the count is of the reads, not of the pages: the
    // pages' bytes in the file below are the proof.
    if counts.pages_read_in == 0 || flags & 0x400 == 0 || flags & 0x40 != 0 {
        errors.push(format!(
            "non-resident: expected pages read in and flag 0x400, got {counts:?}, flags {flags:#x}"
        ));
    } else {
        println!("PASS non-resident core read the reclaimed pages in");
    }
    match read_in.file.as_deref().map(pages_with_data) {
        Some(Ok((found, pages))) if found == u64::from(PAGES) && pages == u64::from(PAGES) => {
            println!("PASS non-resident core holds all {PAGES} pages' bytes")
        }
        Some(Ok((found, pages))) => errors.push(format!(
            "non-resident core holds {found} of {pages} data pages"
        )),
        Some(Err(error)) => errors.push(error),
        None => errors.push("the non-resident core has no file".into()),
    }
    if let Some(Ok((found, _))) = resident.file.as_deref().map(pages_with_data) {
        println!("resident-only core holds {found} of {PAGES} data pages");
    }
    let _ = d.command(Command::StopRun { run_id: id.clone() }, 30);
    let _ = d.command(Command::Stop, 120);
    let _ = d.wait("VM stop", 120, |s| s.state == VmState::Stopped);
    let _ = d.command(Command::Close, 30);
    if errors.is_empty() {
        println!("CORE-COVERAGE-CHECK DONE");
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [bundle, data, fixture] = args.as_slice() else {
        eprintln!("usage: core-coverage-check BUNDLE NEW_DATA_DIR FIXTURE");
        std::process::exit(2);
    };
    if let Err(error) = check(bundle, data, fixture) {
        println!("FAIL {error}");
        std::process::exit(1);
    }
}
