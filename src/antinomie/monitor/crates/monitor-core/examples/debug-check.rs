// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM qualification of the guest debug engine and the RSP server.
//!
//!   debug-check spike BUNDLE NEW_DATA_DIR FIXTURE   (P0: engine through the backend trait)
//!   debug-check gdb   BUNDLE NEW_DATA_DIR FIXTURE   (P1: a real gdb through the RSP server)
//!   debug-check stress BUNDLE NEW_DATA_DIR FIXTURE  (thread churn, soak, vfork timeout, exec)
//!   debug-check p2 BUNDLE NEW_DATA_DIR FIXTURE_DIR [test ...]   (phase 2, see debug-p2/mod.rs)
//!   debug-check p3 BUNDLE NEW_DATA_DIR FIXTURE_DIR [test ...]   (phase 3, see debug-p3/mod.rs)
//!
//! FIXTURE is the static `tests/monitor/debug-fixture` program. The data folder
//! must be new and disposable. One BusyBox VM, one vCPU (a Debian base: its
//! minimum RAM and disk and a throwaway account).
use antinomie_monitor_core::{
    debug::{
        BreakpointKind, DebugBackend, DebugError, DetachMode, KernelDebugBackend, ResumeAction,
        StopKind, TargetState, WatchAccess, amd64,
    },
    *,
};
#[path = "debug-a32/mod.rs"]
mod a32;
#[path = "debug-p2/mod.rs"]
mod p2;
#[path = "debug-p3/mod.rs"]
mod p3;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::Command as Process,
    thread,
    time::{Duration, Instant},
};

struct Driver {
    backend: Backend,
    snapshot: Snapshot,
    replies: BTreeMap<u64, Result<String, String>>,
    output: BTreeMap<String, String>,
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
                    self.output
                        .entry(run_id)
                        .or_default()
                        .push_str(&String::from_utf8_lossy(&data));
                }
                _ => {}
            }
        }
    }
    fn command(&mut self, command: Command) -> Result<String, String> {
        self.command_within(command, 120)
    }
    fn command_within(&mut self, command: Command, seconds: u64) -> Result<String, String> {
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
        let deadline = Instant::now() + Duration::from_secs(secs(seconds));
        loop {
            self.receive();
            if ready(&self.snapshot) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{label} timed out: {:?}", self.snapshot.last_error));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn output(&self, run: &str) -> &str {
        self.output.get(run).map_or("", String::as_str)
    }
    fn wait_text(&mut self, run: &str, needle: &str, seconds: u64) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(secs(seconds));
        loop {
            self.receive();
            if self.output(run).contains(needle) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "output never contained {needle:?}; tail: {}",
                    tail(self.output(run), 600)
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn tail(text: &str, count: usize) -> String {
    let start = text.len().saturating_sub(count);
    text[text.ceil_char_boundary(start)..].to_string()
}

struct Setup {
    driver: Driver,
    run: RunSummary,
    target: GuestProcessIdentity,
    hot: u64,
    tf_probe: u64,
    counters: u64,
    magic: u64,
}

fn symbol(line: &str, name: &str) -> Result<u64, String> {
    let value = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&format!("{name}=0x")))
        .ok_or(format!("symbol {name} missing in {line:?}"))?;
    u64::from_str_radix(value, 16).map_err(|e| e.to_string())
}

/// A running disposable VM with the BusyBox base, one vCPU (or a Debian base:
/// its minimum RAM and disk, a throwaway account, ready at its serial login).
fn boot(bundle: &str, data: &str) -> Result<Driver, String> {
    boot_with(bundle, data, None)
}

/// The base's guest profile when it asks for an account (Debian).
fn account_guest(bundle: &str) -> Option<GuestProfile> {
    fs::read_to_string(PathBuf::from(bundle).join("bundle.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|bundle| serde_json::from_value::<GuestProfile>(bundle["guest"].clone()).ok())
        .filter(|guest| guest.requires_credentials)
}

fn boot_with(bundle: &str, data: &str, stop_grace: Option<Duration>) -> Result<Driver, String> {
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("qualification needs a new disposable data folder".into());
    }
    let _ = ARCH.set(read_bundle_arch(bundle));
    let guest = account_guest(bundle);
    let mut driver = Driver {
        backend: Backend::new(BackendOptions {
            bundle_dir: PathBuf::from(bundle),
            data_dir: data,
            headless: true,
            capture_quota_size: 512 * 1024 * 1024,
            stop_grace,
            // A host without KVM (a cloud VM) runs x86-64 guests under TCG.
            force_tcg: std::env::var_os("ANTINOMIE_FORCE_TCG").is_some(),
            // A Debian guest's login prompt on the serial port says it is up.
            serial_console: guest.is_some(),
            ..Default::default()
        })?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        output: BTreeMap::new(),
    };
    let vm = VmConfig {
        name: "Debugger qualification".into(),
        cpus: 1,
        ram_mib: guest
            .as_ref()
            .map_or(512, |guest| guest.min_ram_mib.max(512)),
        disk_gib: guest.as_ref().map_or(1, |guest| guest.min_disk_gib.max(1)),
        ..Default::default()
    };
    let (create, seconds) = match &guest {
        Some(_) => {
            let mut random = [0u8; 16];
            fs::File::open("/dev/urandom")
                .and_then(|mut source| std::io::Read::read_exact(&mut source, &mut random))
                .map_err(|error| error.to_string())?;
            let password = random.iter().map(|byte| format!("{byte:02x}")).collect();
            (
                Command::CreateWithCredentials {
                    vm,
                    credentials: GuestCredentials::new("debugqa".into(), password)?,
                },
                // The account is made offline (x86-64) or in a provisioning boot (arm64).
                900,
            )
        }
        None => (Command::Create(vm), 60),
    };
    driver.command_within(create, seconds)?;
    driver.wait("VM publication", 10, |snapshot| !snapshot.vms.is_empty())?;
    let vm_id = driver.snapshot.vms[0].id.clone();
    driver.command(Command::Start { vm_id })?;
    let marker: &[u8] = if guest.is_some() {
        b" login: "
    } else {
        b"BusyBox guest ready"
    };
    driver.wait(
        "revision-17 guest",
        if guest.is_some() { 300 } else { 90 },
        |snapshot| {
            snapshot
                .guest_kernel
                .as_ref()
                .and_then(|kernel| kernel.revision)
                .is_some_and(|revision| revision >= 17)
                && snapshot
                    .serial_log
                    .as_ref()
                    .and_then(|path| fs::read(path).ok())
                    .is_some_and(|log| log.windows(marker.len()).any(|part| part == marker))
        },
    )?;
    Ok(driver)
}

fn setup(bundle: &str, data: &str, fixture: &str, ticks: u32) -> Result<Setup, String> {
    let mut driver = boot(bundle, data)?;
    driver.command(Command::Upload {
        source: PathBuf::from(fixture),
        destination: "/tmp/debug-fixture".into(),
        overwrite: false,
        executable: true,
    })?;
    let launched = launch(&mut driver, ticks)?;
    Ok(Setup {
        hot: symbol(&launched.symbols, "hot")?,
        tf_probe: symbol(&launched.symbols, "tf_probe")?,
        counters: symbol(&launched.symbols, "counters")?,
        magic: symbol(&launched.symbols, "magic")?,
        driver,
        run: launched.run,
        target: launched.target,
    })
}

struct Launched {
    run: RunSummary,
    target: GuestProcessIdentity,
    symbols: String,
}

/// Start the fixture and find its exact guest identity.
fn launch(driver: &mut Driver, ticks: u32) -> Result<Launched, String> {
    launch_with(driver, ticks, 2, "")
}

fn launch_with(
    driver: &mut Driver,
    ticks: u32,
    workers: u32,
    mode: &str,
) -> Result<Launched, String> {
    launch_program(
        driver,
        "/tmp/debug-fixture",
        vec![ticks.to_string(), workers.to_string(), mode.into()],
        false,
    )
}

/// Start a program of the guest and find its exact identity. `debug_on_start`
/// stops it before its first user instruction, so it prints no symbols line.
fn launch_program(
    driver: &mut Driver,
    path: &str,
    args: Vec<String>,
    debug_on_start: bool,
) -> Result<Launched, String> {
    let known: Vec<String> = driver
        .snapshot
        .runs
        .iter()
        .map(|run| run.id.clone())
        .collect();
    driver.command(Command::Execute(ExecRequest {
        path: path.into(),
        args,
        uid: 0,
        gid: 0,
        debug_on_start,
        ..Default::default()
    }))?;
    driver.wait("fixture run", 10, |snapshot| {
        snapshot.runs.iter().any(|run| !known.contains(&run.id))
    })?;
    let run_id = driver
        .snapshot
        .runs
        .iter()
        .find(|run| !known.contains(&run.id))
        .ok_or("new run missing")?
        .id
        .clone();
    if !debug_on_start {
        driver.wait_text(&run_id, "symbols ", 20)?;
    }
    driver.wait("run identity", 10, |snapshot| {
        snapshot
            .runs
            .iter()
            .any(|run| run.id == run_id && run.pid != 0 && run.root_task_cookie != 0)
    })?;
    let run = driver
        .snapshot
        .runs
        .iter()
        .find(|run| run.id == run_id)
        .cloned()
        .ok_or("run missing")?;
    let symbols = driver
        .output(&run.id)
        .lines()
        .find(|line| line.starts_with("symbols "))
        .unwrap_or_default()
        .to_string();
    driver.command(Command::ListProcesses { after_pid: 0 })?;
    driver.wait("process identity", 10, |snapshot| {
        snapshot.process_page.as_ref().is_some_and(|page| {
            page.processes.iter().any(|process| {
                process.identity.tgid == run.pid
                    && process.identity.task_cookie == run.root_task_cookie
            })
        })
    })?;
    let target = driver
        .snapshot
        .process_page
        .as_ref()
        .and_then(|page| {
            page.processes.iter().find(|process| {
                process.identity.tgid == run.pid
                    && process.identity.task_cookie == run.root_task_cookie
            })
        })
        .ok_or("exact target missing")?
        .identity
        .clone();
    Ok(Launched {
        run,
        target,
        symbols,
    })
}

fn nonce(seed: u64) -> [u64; 2] {
    [seed | 1, seed.wrapping_mul(0x9e37_79b9_7f4a_7c15)]
}

// ---- P0 ---------------------------------------------------------------------

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    values[values.len() / 2]
}

fn wait_state(
    backend: &mut KernelDebugBackend,
    seconds: u64,
) -> Result<antinomie_monitor_core::debug::StopEvent, String> {
    let deadline = Instant::now() + Duration::from_secs(secs(seconds));
    loop {
        match backend.state().map_err(|e| e.to_string())? {
            TargetState::Stopped(event) => return Ok(event),
            TargetState::Exited { wait_status } => {
                return Err(format!("target exited ({wait_status:#x})"));
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "no stop in {seconds}s; failure {:?}",
                backend.take_failure()
            ));
        }
        thread::sleep(Duration::from_micros(500));
    }
}

fn u64_of(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().expect("eight bytes"))
}
fn user_regs(backend: &mut KernelDebugBackend, tid: u32) -> Result<Vec<u8>, String> {
    backend
        .read_regset(tid, amd64::NT_PRSTATUS)
        .map(|blob| blob.data)
        .map_err(|e| e.to_string())
}
const RIP: usize = 128;
const RSP: usize = 152;
const RAX: usize = 80;
const RDI: usize = 112;
const EFLAGS: usize = 144;

// ---- the guest's architecture ---------------------------------------------------

/// The base's guest architecture (bundle.json `arch`; x86-64 when absent), set
/// at boot. An arm64 base runs under TCG: every guest wait is scaled.
static ARCH: std::sync::OnceLock<GuestArch> = std::sync::OnceLock::new();
fn guest_arch() -> GuestArch {
    ARCH.get().copied().unwrap_or_default()
}
fn on_aarch64() -> bool {
    guest_arch() == GuestArch::AARCH64
}
/// A guest wait of `seconds` on an x86-64 guest, scaled for the base.
fn secs(seconds: u64) -> u64 {
    seconds * u64::from(guest_arch().time_scale())
}
fn read_bundle_arch(bundle: &str) -> GuestArch {
    fs::read_to_string(PathBuf::from(bundle).join("bundle.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|bundle| serde_json::from_value(bundle["arch"].clone()).ok())
        .unwrap_or_default()
}
/// Offsets in the NT_PRSTATUS blob: x86-64 `user_regs_struct`, aarch64
/// `user_pt_regs` (x0..x30 at 0, sp 248, pc 256, pstate 264).
fn pc_at() -> usize {
    if on_aarch64() { 256 } else { RIP }
}
/// The system call's result and a function's first argument and result.
fn ret_at() -> usize {
    if on_aarch64() { 0 } else { RAX }
}
fn arg0_at() -> usize {
    if on_aarch64() { 0 } else { RDI }
}
/// EFLAGS, or PSTATE (the SPSR copy a ptrace reader sees).
fn flags_at() -> usize {
    if on_aarch64() { 264 } else { EFLAGS }
}
/// The step flag a program must never see: TF, or PSTATE.SS.
fn step_flag() -> u64 {
    if on_aarch64() { 1 << 21 } else { 0x100 }
}
/// gdb's name for an x86-64 register on the guest's architecture.
fn gdb_reg(x86: &'static str) -> &'static str {
    if !on_aarch64() {
        return x86;
    }
    match x86 {
        "rip" => "pc",
        "rsp" => "sp",
        "eflags" => "cpsr",
        "rax" | "rdi" => "x0",
        "fs_base" => "tpidr",
        other => other,
    }
}
/// `info registers` prints the name padded to 15 columns.
fn gdb_reg_line(x86: &'static str, value: u64) -> String {
    format!("{:<15}0x{value:x}", gdb_reg(x86))
}
fn gdb_name() -> &'static str {
    if on_aarch64() { "gdb-multiarch" } else { "gdb" }
}
/// The bytes a breakpoint takes, and whether code read back is one: INT3, or a
/// BRK (any immediate) at an aligned word.
fn bp_bytes() -> usize {
    if on_aarch64() { 4 } else { 1 }
}
fn is_breakpoint(code: &[u8]) -> bool {
    if on_aarch64() {
        code.len() >= 4
            && u32::from_le_bytes(code[..4].try_into().expect("four bytes")) & 0xffe0_001f
                == 0xd420_0000
    } else {
        code.first() == Some(&0xcc)
    }
}
/// Let the guest run for `ms` of x86-64 time, scaled for the base.
fn run_for(ms: u64) {
    thread::sleep(Duration::from_millis(ms * secs(1)));
}
/// Bytes from one instruction to the next in the fixtures' fixed sequences.
fn insn(x86: u64) -> u64 {
    if on_aarch64() { 4 } else { x86 }
}

fn spike(bundle: &str, data: &str, fixture: &str) -> Result<(), String> {
    let mut setup = setup(bundle, data, fixture, 240)?;
    let mut evidence = serde_json::Map::new();
    let link = setup.driver.backend.debug_link();
    let mut dbg = KernelDebugBackend::attach(Box::new(link), &setup.target, nonce(0x5eed), false)
        .map_err(|e| format!("attach: {e}"))?;
    println!("caps: {:?}", dbg.caps());
    let (hot, tf_probe, counters, magic) = (setup.hot, setup.tf_probe, setup.counters, setup.magic);
    let run = setup.run.id.clone();

    // 1. Stop every thread of the tagged process, no ptrace.
    let threads = dbg.threads().map_err(|e| e.to_string())?;
    if threads.len() != 3 {
        return Err(format!("expected 3 threads, saw {threads:?}"));
    }
    let started = Instant::now();
    dbg.interrupt().map_err(|e| e.to_string())?;
    let event = wait_state(&mut dbg, 5)?;
    let stop_ms = started.elapsed().as_secs_f64() * 1000.0;
    let threads = dbg.threads().map_err(|e| e.to_string())?;
    if !threads.iter().all(|thread| thread.stopped) || threads.len() != 3 {
        return Err(format!("not every thread stopped: {threads:?}"));
    }
    let before = dbg.read_memory(counters, 16).map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_millis(400));
    let after = dbg.read_memory(counters, 16).map_err(|e| e.to_string())?;
    if before != after {
        return Err("counters moved while the group was stopped".into());
    }
    println!("PASS P0.1 stop: 3/3 threads stopped in {stop_ms:.2} ms, memory frozen ({event:?})");
    evidence.insert("stop_ms".into(), stop_ms.into());

    // 2. Registers and memory, read and write.
    for thread in &threads {
        let regs = user_regs(&mut dbg, thread.tid)?;
        let (rip, rsp) = (u64_of(&regs, RIP), u64_of(&regs, RSP));
        if regs.len() != amd64::USER_REGS_SIZE || rip != thread.pc || rsp < 0x7000_0000_0000 {
            return Err(format!(
                "bad registers for {}: rip {rip:#x} rsp {rsp:#x}",
                thread.tid
            ));
        }
        dbg.read_memory(rip, 1)
            .map_err(|e| format!("rip unreadable: {e}"))?;
        let fp = dbg
            .read_regset(thread.tid, amd64::NT_PRFPREG)
            .map_err(|e| e.to_string())?;
        if fp.data.len() != amd64::FXSAVE_SIZE {
            return Err("FXSAVE image has the wrong size".into());
        }
    }
    let value = u64_of(&dbg.read_memory(magic, 8).map_err(|e| e.to_string())?, 0);
    if value != 0x1111 {
        return Err(format!("magic reads {value:#x}"));
    }
    dbg.write_memory(magic, &0x2222u64.to_le_bytes())
        .map_err(|e| e.to_string())?;
    if u64_of(&dbg.read_memory(magic, 8).map_err(|e| e.to_string())?, 0) != 0x2222 {
        return Err("memory write did not read back".into());
    }
    println!("PASS P0.2 registers and memory: 3 threads read, magic 0x1111 -> 0x2222 written");

    // Running again: counters advance, and the sample reports the new value.
    dbg.resume(ResumeAction::Continue)
        .map_err(|e| e.to_string())?;
    setup.driver.wait_text(&run, "magic=0x2222", 10)?;
    dbg.interrupt().map_err(|e| e.to_string())?;
    wait_state(&mut dbg, 5)?;
    let later = dbg.read_memory(counters, 16).map_err(|e| e.to_string())?;
    if later == after {
        return Err("counters did not advance after resume".into());
    }
    println!("PASS resume: counters advanced and the sample saw the written magic");

    // 3. Breakpoint: caught before the task sees SIGTRAP; original bytes shown.
    dbg.set_breakpoint(hot, 1).map_err(|e| e.to_string())?;
    let mut hits = 0;
    let mut main_tid = 0;
    let mut hit_latency = Vec::new();
    for round in 0..8 {
        let at = Instant::now();
        dbg.resume(ResumeAction::Continue)
            .map_err(|e| e.to_string())?;
        let event = wait_state(&mut dbg, 5)?;
        hit_latency.push(at.elapsed().as_secs_f64() * 1000.0);
        match event.kind {
            StopKind::Breakpoint { addr } if addr == hot && event.pc == hot => hits += 1,
            other => return Err(format!("unexpected stop {other:?} at {:#x}", event.pc)),
        }
        main_tid = event.tid;
        let regs = user_regs(&mut dbg, event.tid)?;
        if u64_of(&regs, RIP) != hot {
            return Err("rip was not rewound to the breakpoint".into());
        }
        let code = dbg.read_memory(hot, 4).map_err(|e| e.to_string())?;
        if code[0] == 0xcc || code[..3] != [0x48, 0x89, 0xf8] {
            return Err(format!(
                "breakpoint byte visible while stopped: {code:02x?}"
            ));
        }
        if round == 3 {
            // Register write: the argument becomes 1000, so hot returns 3000 + magic.
            let mut writable = dbg
                .read_regset(event.tid, amd64::NT_PRSTATUS)
                .map_err(|e| e.to_string())?;
            writable.data[RDI..RDI + 8].copy_from_slice(&1000u64.to_le_bytes());
            dbg.write_regset(event.tid, &writable)
                .map_err(|e| e.to_string())?;
        }
    }
    println!(
        "PASS P0.3 breakpoint: {hits}/8 hits at hot, pc rewound, bytes shadowed while stopped; median continue->hit {:.2} ms",
        median(hit_latency.clone())
    );
    evidence.insert("continue_to_hit_ms".into(), median(hit_latency).into());

    // 4. Single-step, with TF hidden from the task. First at the breakpoint.
    let mut step_latency = Vec::new();
    let expected = [hot + 3, hot + 7, hot + 14];
    for expect in expected {
        let at = Instant::now();
        dbg.resume(ResumeAction::Step { tid: main_tid })
            .map_err(|e| e.to_string())?;
        let event = wait_state(&mut dbg, 5)?;
        step_latency.push(at.elapsed().as_secs_f64() * 1000.0);
        if event.kind != StopKind::Step || event.pc != expect {
            return Err(format!(
                "step stopped at {:#x} {:?}, wanted {expect:#x}",
                event.pc, event.kind
            ));
        }
        let regs = user_regs(&mut dbg, event.tid)?;
        if u64_of(&regs, EFLAGS) & 0x100 != 0 {
            return Err("TF visible in the stopped registers".into());
        }
    }
    println!(
        "PASS P0.4a single-step: hot+3, +7, +14, TF clear in every stop; median {:.2} ms",
        median(step_latency.clone())
    );
    evidence.insert("step_ms".into(), median(step_latency).into());
    // Now the popped flags: tf_probe is pushfq; pop rax; ret.
    dbg.clear_breakpoint(hot, 1).map_err(|e| e.to_string())?;
    dbg.set_breakpoint(tf_probe, 1).map_err(|e| e.to_string())?;
    dbg.resume(ResumeAction::Continue)
        .map_err(|e| e.to_string())?;
    let event = wait_state(&mut dbg, 10)?;
    if event.pc != tf_probe {
        return Err(format!("expected tf_probe, stopped at {:#x}", event.pc));
    }
    let tid = event.tid;
    dbg.resume(ResumeAction::Step { tid })
        .map_err(|e| e.to_string())?;
    wait_state(&mut dbg, 5)?;
    let regs = user_regs(&mut dbg, tid)?;
    let pushed = u64_of(
        &dbg.read_memory(u64_of(&regs, RSP), 8)
            .map_err(|e| e.to_string())?,
        0,
    );
    if pushed & 0x100 != 0 {
        return Err(format!("TF visible in the pushed flags {pushed:#x}"));
    }
    dbg.resume(ResumeAction::Step { tid })
        .map_err(|e| e.to_string())?;
    wait_state(&mut dbg, 5)?;
    let rax = u64_of(&user_regs(&mut dbg, tid)?, RAX);
    if rax & 0x100 != 0 {
        return Err(format!("TF visible in popped rax {rax:#x}"));
    }
    println!("PASS P0.4b TF hidden: pushfq stored {pushed:#x}, rax {rax:#x}, TF clear");
    dbg.clear_breakpoint(tf_probe, 1)
        .map_err(|e| e.to_string())?;

    // 5. The engine costs.
    let tid = threads[0].tid;
    let mut regs_ms = Vec::new();
    let mut mem_ms = Vec::new();
    for _ in 0..50 {
        let at = Instant::now();
        user_regs(&mut dbg, tid)?;
        dbg.read_regset(tid, amd64::NT_PRFPREG)
            .map_err(|e| e.to_string())?;
        regs_ms.push(at.elapsed().as_secs_f64() * 1000.0);
        let at = Instant::now();
        dbg.read_memory(hot & !0xfff, 2048)
            .map_err(|e| e.to_string())?;
        mem_ms.push(at.elapsed().as_secs_f64() * 1000.0);
    }
    println!(
        "measure: registers (2 sets) median {:.2} ms, 2 KiB memory median {:.2} ms",
        median(regs_ms.clone()),
        median(mem_ms.clone())
    );
    evidence.insert("registers_ms".into(), median(regs_ms).into());
    evidence.insert("memory_2k_ms".into(), median(mem_ms).into());

    // Detach, then the sample must finish normally and report what it saw.
    let at = Instant::now();
    dbg.detach(DetachMode::Resume).map_err(|e| e.to_string())?;
    evidence.insert(
        "detach_ms".into(),
        (at.elapsed().as_secs_f64() * 1000.0).into(),
    );
    setup.driver.wait_text(&run, "done sigtrap=0", 40)?;
    let text = setup.driver.output(&run).to_string();
    let ticks: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("tick "))
        .collect();
    let engine: Vec<&str> = ticks
        .iter()
        .copied()
        .filter(|line| line.contains("magic=0x2222"))
        .collect();
    // TracerPid must be 0 for as long as the sample has not asked to be traced
    // itself; afterwards it is the parent the sample chose, not the debugger.
    let before: Vec<&&str> = engine
        .iter()
        .filter(|line| line.contains("traceme=-9"))
        .collect();
    for line in &engine {
        for needle in ["sigtrap=0", "int3_mem=0", "tf=0"] {
            if !line.contains(needle) {
                return Err(format!("anti-debug check failed ({needle}): {line}"));
            }
        }
    }
    for line in &before {
        if !line.contains("tracer=0") {
            return Err(format!("TracerPid is not 0 while debugged: {line}"));
        }
    }
    let traceme: Vec<&&str> = engine
        .iter()
        .filter(|line| line.contains("traceme=0"))
        .collect();
    let direct = engine
        .iter()
        .filter(|line| line.contains("int3_direct=1"))
        .count();
    let rewritten = text.contains(&format!("hot={}", 3 * 1000 + 0x2222));
    println!(
        "PASS anti-debug: {} lines under debug: SIGTRAP 0, int3 via /proc/self/mem 0, TF 0; TracerPid 0 on {} lines before the sample's own PTRACE_TRACEME; PTRACE_TRACEME succeeded on {} lines; direct loads saw the engine byte on {direct} lines",
        engine.len(),
        before.len(),
        traceme.len()
    );
    if before.is_empty() {
        return Err("no TracerPid sample was taken under the debugger".into());
    }
    if traceme.is_empty() {
        return Err("PTRACE_TRACEME did not succeed while debugged".into());
    }
    if !rewritten {
        return Err("register write did not change the sample's result".into());
    }
    println!("PASS register write: rdi=1000 at a breakpoint made hot() return 3000 + magic");
    setup.driver.wait("run exit", 20, |snapshot| {
        snapshot.runs.iter().any(|run| {
            run.execution
                .as_ref()
                .is_some_and(|e| e.root_exit.is_some())
        })
    })?;
    println!("PASS sample finished normally after detach");
    evidence.insert("direct_int3_lines".into(), direct.into());
    fs::write(
        PathBuf::from(data).join("debug-spike-result.json"),
        serde_json::to_vec_pretty(&evidence).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    setup.driver.command(Command::Stop).ok();
    Ok(())
}

// ---- P1 ---------------------------------------------------------------------

/// The fixture's architecture, from its ELF header: aarch64 sessions use
/// gdb-multiarch and aarch64 register names.
fn aarch64_fixture(fixture: &str) -> bool {
    fs::read(fixture).is_ok_and(|elf| elf.len() > 20 && elf[18] == 183 && elf[19] == 0)
}
fn gdb_program(fixture: &str) -> &'static str {
    if aarch64_fixture(fixture) {
        "gdb-multiarch"
    } else {
        "gdb"
    }
}
fn pc_name(fixture: &str) -> &'static str {
    if aarch64_fixture(fixture) {
        "pc"
    } else {
        "rip"
    }
}

fn gdb(bundle: &str, data: &str, fixture: &str) -> Result<(), String> {
    let mut setup = setup(bundle, data, fixture, 200)?;
    let run = setup.run.id.clone();
    setup.driver.command(Command::DebugAttach {
        identity: setup.target.clone(),
    })?;
    let info = setup
        .driver
        .snapshot
        .debug
        .clone()
        .ok_or("snapshot lacks the debug session")?;
    println!("endpoint: {}", info.gdb_command);
    // The process must keep running until a debugger connects.
    let before = setup.driver.output(&run).len();
    thread::sleep(Duration::from_millis(600));
    setup.driver.receive();
    if setup.driver.output(&run).len() == before {
        return Err("the sample stalled after attach".into());
    }
    let aarch64 = aarch64_fixture(fixture);
    let target = format!("target remote 127.0.0.1:{}", info.tcp_port);
    let file = format!("file {fixture}");
    let x86_script = [
        "set pagination off",
        "set confirm off",
        "set style enabled off",
        &file,
        &target,
        "info threads",
        "info registers rip rsp eflags fs_base orig_rax",
        "x/8xb hot",
        "x/2i $pc",
        "break hot",
        "continue",
        "info registers rip",
        "x/3i $pc",
        "x/4xb hot",
        "stepi",
        "p/x $pc",
        "p/x (long)magic",
        "delete",
        "tbreak tf_probe",
        "continue",
        "p/x $eflags",
        "detach",
    ];
    // aarch64 adds what x86-64's P1 session leaves to the phase 2 checks: a
    // hardware breakpoint, a read watch (hot loads magic) and a write watch
    // (a worker thread counts in counters[0]). Breakpoints go on the exact
    // addresses: gdb's aarch64 prologue analysis would put `break hot` on its
    // second instruction, and the fixture has no debug information for types.
    let aarch64_script = [
        "set pagination off",
        "set confirm off",
        "set style enabled off",
        &file,
        &target,
        "info threads",
        "info registers pc sp cpsr tpidr",
        "x/8xb hot",
        "x/2i $pc",
        "break *hot",
        "continue",
        "info registers pc",
        "x/3i $pc",
        "x/4xb hot",
        "stepi",
        "p/x $pc",
        "p/x (long)magic",
        "delete",
        "hbreak *hot",
        "continue",
        "p/x $pc",
        "delete",
        "rwatch *(long *)&magic",
        "continue",
        "delete",
        "watch *(long *)&counters",
        "continue",
        "delete",
        "tbreak *tf_probe",
        "continue",
        "p/x $cpsr",
        "detach",
    ];
    let script: &[&str] = if aarch64 {
        &aarch64_script
    } else {
        &x86_script
    };
    let mut command = Process::new(gdb_program(fixture));
    command.arg("-nx").arg("-batch");
    for line in script {
        command.arg("-ex").arg(line);
    }
    let output = command.output().map_err(|e| format!("gdb: {e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("---- gdb ----\n{text}---- end gdb ----");
    fs::write(PathBuf::from(data).join("gdb-session.txt"), &text).map_err(|e| e.to_string())?;
    let needles: Vec<String> = if aarch64 {
        vec![
            format!("hit Breakpoint 1, 0x{:016x} in hot ()", setup.hot),
            "in tf_probe ()".into(),
            "tpidr".into(),
            // mov x1, x0 (aa0003e1), with the engine's BRK hidden.
            format!("0x{:x} <hot>:\t0xe1\t0x03\t0x00\t0xaa", setup.hot),
            "$2 = 0x1111".into(),
            format!("$3 = 0x{:x}", setup.hot),
            "Hardware read watchpoint".into(),
            "Value = 4369".into(),
            "Hardware watchpoint".into(),
            "detached]".into(),
        ]
    } else {
        vec![
            format!("hit Breakpoint 1, 0x{:016x} in hot ()", setup.hot),
            format!(
                "hit Temporary breakpoint 2, 0x{:016x} in tf_probe ()",
                setup.tf_probe
            ),
            "fs_base".into(),
            "orig_rax".into(),
            format!("0x{:x} <hot>:\t0x48\t0x89\t0xf8", setup.hot),
            "$2 = 0x1111".into(),
            "detached]".into(),
        ]
    };
    for needle in &needles {
        if !text.contains(needle) {
            return Err(format!("gdb session lacks {needle:?}"));
        }
    }
    if text.contains("Cannot access memory") || text.contains("Remote connection closed") {
        return Err("gdb reported a memory or connection failure".into());
    }
    // A second client over the Unix socket still works after the first detached.
    setup.driver.receive();
    let status = setup
        .driver
        .snapshot
        .debug
        .as_ref()
        .map(|info| info.target_state.clone());
    println!("server state after detach: {status:?}");
    let reply = unix_query(&info.unix_socket, b"+$?#3f", secs(5))?;
    println!("unix socket reply: {reply:?}");
    if !reply.contains("T05thread:") {
        return Err("the Unix socket did not answer a stop query".into());
    }
    // Detach for good; the sample runs to completion.
    setup.driver.command(Command::DebugDetach { kill: false })?;
    setup.driver.wait_text(&run, "done sigtrap=0", 60)?;
    let text = setup.driver.output(&run).to_string();
    for line in text.lines().filter(|line| line.starts_with("tick ")) {
        // After its own PTRACE_TRACEME the sample's TracerPid is the parent it chose.
        let needles: &[&str] = if line.contains("traceme=-9") {
            &["tracer=0", "sigtrap=0"]
        } else {
            &["sigtrap=0"]
        };
        for needle in needles {
            if !line.contains(needle) {
                return Err(format!("sample saw the debugger ({needle}): {line}"));
            }
        }
    }
    setup.driver.wait("run exit", 30, |snapshot| {
        snapshot.runs.iter().any(|run| {
            run.execution
                .as_ref()
                .is_some_and(|e| e.root_exit.is_some())
        })
    })?;
    println!("PASS P1 main session");
    scenarios(&mut setup.driver, fixture)?;
    println!(
        "PASS P1: gdb attached, read registers and memory, hit a breakpoint, stepped, detached; the sample finished normally; exit, kill, client death and interrupt behave"
    );
    setup.driver.command(Command::Stop).ok();
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [mode, bundle, data, dir, only @ ..] = args.as_slice()
        && (mode == "p2" || mode == "p3")
    {
        let result = if mode == "p2" {
            p2::run(bundle, data, dir, only)
        } else {
            p3::run(bundle, data, dir, only)
        };
        if let Err(error) = result {
            eprintln!("FAIL {error}");
            std::process::exit(1);
        }
        return;
    }
    let [mode, bundle, data, fixture] = args.as_slice() else {
        eprintln!("usage: debug-check spike|gdb|stress|a32 BUNDLE NEW_DATA_DIR FIXTURE");
        std::process::exit(2);
    };
    let result = match mode.as_str() {
        "spike" => spike(bundle, data, fixture),
        "gdb" => gdb(bundle, data, fixture),
        "stress" => stress(bundle, data, fixture),
        "a32" => a32::run(bundle, data, fixture),
        other => Err(format!("unknown mode {other}")),
    };
    if let Err(error) = result {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}

fn run_ended(driver: &mut Driver, run: &str, seconds: u64) -> Result<WaitStatus, String> {
    let id = run.to_string();
    driver.wait("run exit", seconds, |snapshot| {
        snapshot.runs.iter().any(|run| {
            run.id == id
                && run
                    .execution
                    .as_ref()
                    .is_some_and(|e| e.root_exit.is_some())
        })
    })?;
    driver
        .snapshot
        .runs
        .iter()
        .find(|run| run.id == id)
        .and_then(|run| run.execution.as_ref())
        .and_then(|execution| execution.root_exit.clone())
        .ok_or_else(|| "no exit".to_string())
}

fn attach(driver: &mut Driver, target: &GuestProcessIdentity) -> Result<DebugSessionInfo, String> {
    driver.command(Command::DebugAttach {
        identity: target.clone(),
    })?;
    driver
        .snapshot
        .debug
        .clone()
        .ok_or_else(|| "snapshot lacks the debug session".into())
}

fn gdb_batch(port: u16, fixture: &str, lines: &[&str]) -> Process {
    let mut command = Process::new(gdb_program(fixture));
    command.arg("-nx").arg("-batch");
    for line in [
        "set pagination off",
        "set confirm off",
        &format!("file {fixture}"),
        &format!("target remote 127.0.0.1:{port}"),
    ] {
        command.arg("-ex").arg(line);
    }
    for line in lines {
        command.arg("-ex").arg(line);
    }
    command
}

/// Send `request` to an RSP server's Unix socket and collect up to 200 bytes of
/// its answer for at most `seconds` (what `socat` did, without the tool).
fn unix_query(path: &std::path::Path, request: &[u8], seconds: u64) -> Result<String, String> {
    use std::io::{Read, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    stream.write_all(request).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut reply = Vec::new();
    let mut buffer = [0u8; 200];
    while reply.len() < 200 {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        stream
            .set_read_timeout(Some(left))
            .map_err(|e| e.to_string())?;
        match stream.read(&mut buffer[..200 - reply.len()]) {
            Ok(0) | Err(_) => break,
            Ok(count) => reply.extend_from_slice(&buffer[..count]),
        }
        // A whole stop reply: `$...#xx`.
        if let Some(end) = reply.iter().position(|&b| b == b'#')
            && reply.len() >= end + 3
            && reply.contains(&b'$')
        {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&reply).into_owned())
}

/// Everything a child writes to its two pipes, as it arrives (stdout and
/// stderr interleaved), so a caller can watch for a line while it runs.
fn collect(
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
) -> std::sync::Arc<std::sync::Mutex<Vec<u8>>> {
    use std::io::Read;
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    fn pump(mut pipe: impl Read + Send + 'static, seen: std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(used) = pipe.read(&mut buffer) {
                if used == 0 {
                    break;
                }
                seen.lock().unwrap().extend_from_slice(&buffer[..used]);
            }
        });
    }
    if let Some(pipe) = stdout {
        pump(pipe, seen.clone());
    }
    if let Some(pipe) = stderr {
        pump(pipe, seen.clone());
    }
    seen
}

fn text_of(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// More behavior through the real gdb, one fixture run each.
fn scenarios(driver: &mut Driver, fixture: &str) -> Result<(), String> {
    // 1. The process ends under the debugger: gdb says so and the server ends.
    let launched = launch(driver, 40)?;
    let info = attach(driver, &launched.target)?;
    let output = gdb_batch(info.tcp_port, fixture, &["continue"])
        .output()
        .map_err(|e| e.to_string())?;
    let text = text_of(&output);
    if !text.contains("exited normally") {
        return Err(format!("gdb did not report a normal exit:\n{text}"));
    }
    run_ended(driver, &launched.run.id, 30)?;
    driver.command(Command::DebugDetach { kill: false })?;
    println!("PASS exit under the debugger reported as 'exited normally'");

    // 2. gdb's kill ends the process (SIGKILL).
    let launched = launch(driver, 400)?;
    let info = attach(driver, &launched.target)?;
    let output = gdb_batch(info.tcp_port, fixture, &["kill"])
        .output()
        .map_err(|e| e.to_string())?;
    let text = text_of(&output);
    println!("kill session: {}", tail(&text, 300));
    let status = run_ended(driver, &launched.run.id, 30)?;
    println!("PASS gdb kill ended the process: {status:?}");
    driver.command(Command::DebugDetach { kill: false })?;

    // 3. gdb dies while the process runs: it keeps running, breakpoints gone,
    //    and a new gdb can attach.
    let launched = launch(driver, 120)?;
    let info = attach(driver, &launched.target)?;
    let mut doomed = gdb_batch(
        info.tcp_port,
        fixture,
        &["break hot", "continue", "continue", "continue"],
    )
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .spawn()
    .map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_millis(2500));
    doomed.kill().map_err(|e| e.to_string())?;
    let _ = doomed.wait();
    let before = driver.output(&launched.run.id).matches("tick ").count();
    thread::sleep(Duration::from_millis(1500));
    driver.receive();
    let after = driver.output(&launched.run.id).matches("tick ").count();
    if after <= before {
        return Err("the process stalled after its debugger died".into());
    }
    let pc = pc_name(fixture);
    let registers = format!("info registers {pc}");
    let output = gdb_batch(info.tcp_port, fixture, &[&registers, "detach"])
        .output()
        .map_err(|e| e.to_string())?;
    let text = text_of(&output);
    if !text.contains(pc) || !text.contains("detached") {
        return Err(format!("reattach failed:\n{text}"));
    }
    driver.command(Command::DebugDetach { kill: false })?;
    driver.wait_text(&launched.run.id, "done sigtrap=0", 60)?;
    println!(
        "PASS debugger death: the process kept running ({before} -> {after} ticks), a new gdb attached, no SIGTRAP"
    );

    // 4. Interrupt: SIGINT to gdb while the process runs stops it.
    let launched = launch(driver, 150)?;
    let info = attach(driver, &launched.target)?;
    let mut child = gdb_batch(info.tcp_port, fixture, &["continue", &registers, "detach"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    // The interrupt must come while gdb waits for the process. gdb 17 takes a
    // SIGINT that arrives earlier (while it connects and reads the stopped
    // frame) as a Quit of that command, and `continue` then says "The program
    // is not being run". Batch mode prints no "Continuing.", so the line that
    // says where the connection stopped (`0x... in main ()`) is the cue: the
    // `continue` follows at once.
    let seen = collect(child.stdout.take(), child.stderr.take());
    let deadline = Instant::now() + Duration::from_secs(60);
    let connected = |text: &str| {
        text.lines()
            .any(|line| line.starts_with("0x") && line.trim_end().ends_with(" ()"))
    };
    while !connected(&String::from_utf8_lossy(&seen.lock().unwrap())) {
        if Instant::now() > deadline || child.try_wait().map_err(|e| e.to_string())?.is_some() {
            let text = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
            let _ = child.kill();
            return Err(format!("gdb never connected to the process:\n{text}"));
        }
        thread::sleep(Duration::from_millis(50));
    }
    thread::sleep(Duration::from_millis(1500));
    let _ = Process::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status();
    child.wait().map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_millis(200));
    let text = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
    if !text.contains("SIGINT") || !text.contains(pc) {
        return Err(format!("interrupt did not stop the process:\n{text}"));
    }
    driver.command(Command::DebugDetach { kill: false })?;
    driver.wait_text(&launched.run.id, "done sigtrap=0", 60)?;
    println!(
        "PASS interrupt: Ctrl-C stopped the running process, registers read, detached, sample finished"
    );
    Ok(())
}

fn attach_backend(
    driver: &mut Driver,
    launched: &Launched,
    seed: u64,
) -> Result<KernelDebugBackend, String> {
    KernelDebugBackend::attach(
        Box::new(driver.backend.debug_link()),
        &launched.target,
        nonce(seed),
        false,
    )
    .map_err(|e| format!("attach: {e}"))
}

fn stress(bundle: &str, data: &str, fixture: &str) -> Result<(), String> {
    let mut setup = setup(bundle, data, fixture, 200)?;
    let driver = &mut setup.driver;
    // Only the boot and the symbol addresses were needed from this first run.
    driver.command(Command::StopRun {
        run_id: setup.run.id.clone(),
    })?;
    run_ended(driver, &setup.run.id, 30)?;

    // 1. Threads created and ended while the process runs hit breakpoints too.
    let launched = launch_with(driver, 160, 2, "churn")?;
    let hot = symbol(&launched.symbols, "hot")?;
    let mut dbg = attach_backend(driver, &launched, 11)?;
    let initial: Vec<u32> = dbg
        .threads()
        .map_err(|e| e.to_string())?
        .iter()
        .map(|t| t.tid)
        .collect();
    dbg.interrupt().map_err(|e| e.to_string())?;
    wait_state(&mut dbg, 5)?;
    dbg.set_breakpoint(hot, 1).map_err(|e| e.to_string())?;
    let mut tids = std::collections::BTreeSet::new();
    for _ in 0..40 {
        dbg.resume(ResumeAction::Continue)
            .map_err(|e| e.to_string())?;
        let event = wait_state(&mut dbg, 10)?;
        if !matches!(event.kind, StopKind::Breakpoint { addr } if addr == hot) {
            return Err(format!("unexpected stop {event:?}"));
        }
        tids.insert(event.tid);
    }
    let fresh = tids.iter().filter(|tid| !initial.contains(tid)).count();
    if fresh < 2 {
        return Err(format!(
            "no breakpoint was hit by a thread created while running: {tids:?} vs {initial:?}"
        ));
    }
    dbg.clear_breakpoint(hot, 1).map_err(|e| e.to_string())?;
    dbg.detach(DetachMode::Resume).map_err(|e| e.to_string())?;
    driver.wait_text(&launched.run.id, "done sigtrap=0", 60)?;
    println!(
        "PASS churn: {fresh} threads created while the process ran were stopped at the breakpoint (no SIGTRAP), {} distinct threads seen",
        tids.len()
    );

    // 2. Soak: many threads, repeated stop and resume.
    let launched = launch_with(driver, 700, 32, "")?;
    let mut dbg = attach_backend(driver, &launched, 22)?;
    let mut latency = Vec::new();
    for round in 0..60 {
        let at = Instant::now();
        dbg.interrupt().map_err(|e| e.to_string())?;
        wait_state(&mut dbg, 10).map_err(|e| format!("round {round}: {e}"))?;
        latency.push(at.elapsed().as_secs_f64() * 1000.0);
        let threads = dbg.threads().map_err(|e| e.to_string())?;
        if threads.len() != 33 || !threads.iter().all(|thread| thread.stopped) {
            return Err(format!(
                "round {round}: {} threads, not all stopped",
                threads.len()
            ));
        }
        for thread in threads.iter().take(3) {
            user_regs(&mut dbg, thread.tid)?;
        }
        dbg.resume(ResumeAction::Continue)
            .map_err(|e| e.to_string())?;
        thread::sleep(Duration::from_millis(30));
    }
    println!(
        "PASS soak: 60 stops of 33 threads, median {:.1} ms, worst {:.1} ms",
        median(latency.clone()),
        latency.iter().cloned().fold(0.0, f64::max)
    );
    dbg.interrupt().map_err(|e| e.to_string())?;
    wait_state(&mut dbg, 10)?;
    dbg.detach(DetachMode::Kill).map_err(|e| e.to_string())?;
    run_ended(driver, &launched.run.id, 30)?;

    // 3. A thread that cannot park (vfork parent) is reported, never waited for.
    let launched = launch_with(driver, 200, 2, "vfork")?;
    let mut dbg = attach_backend(driver, &launched, 33)?;
    // Round 8 vforks (and the parent is blocked for 6 s); round 4 prints just before.
    driver.wait_text(&launched.run.id, "tick 4 ", 30)?;
    thread::sleep(Duration::from_millis(800));
    dbg.interrupt().map_err(|e| e.to_string())?;
    let started = Instant::now();
    let outcome = wait_state(&mut dbg, 4);
    let reported = outcome
        .as_ref()
        .err()
        .is_some_and(|error| error.contains("did not stop in time"));
    println!(
        "vfork parent: stop attempt after {:.1} s -> {:?}",
        started.elapsed().as_secs_f64(),
        outcome.as_ref().err()
    );
    if !reported {
        return Err("a stop that could not complete was not reported".into());
    }
    if !matches!(
        dbg.state().map_err(|e| e.to_string())?,
        TargetState::Running
    ) {
        return Err("a failed stop must leave the process running".into());
    }
    thread::sleep(Duration::from_secs(7));
    dbg.interrupt().map_err(|e| e.to_string())?;
    wait_state(&mut dbg, 10)?;
    let threads = dbg.threads().map_err(|e| e.to_string())?;
    if !threads.iter().all(|thread| thread.stopped) {
        return Err("threads not all stopped after the vfork child ended".into());
    }
    dbg.detach(DetachMode::Resume).map_err(|e| e.to_string())?;
    driver.wait_text(&launched.run.id, "done sigtrap=0", 60)?;
    println!(
        "PASS vfork: the stop that could not complete was reported and left the process running; the next stop worked"
    );

    // 4. exec replaces the image: the session says so, and detaching still works.
    let launched = launch_with(driver, 200, 2, "exec")?;
    let mut dbg = attach_backend(driver, &launched, 44)?;
    driver.wait_text(&launched.run.id, "execd", 30)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match dbg.state().map_err(|e| e.to_string())? {
            TargetState::Replaced => break,
            TargetState::Exited { .. } => break,
            _ if Instant::now() >= deadline => return Err("exec was not noticed".into()),
            _ => thread::sleep(Duration::from_millis(50)),
        }
    }
    dbg.detach(DetachMode::Resume).map_err(|e| e.to_string())?;
    run_ended(driver, &launched.run.id, 30)?;
    println!("PASS exec: the address-space change ended the session cleanly");
    driver.command(Command::Stop).ok();
    Ok(())
}
