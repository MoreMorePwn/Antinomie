// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM qualification of the guest debug engine and the RSP server.
//!
//!   debug-check spike BUNDLE NEW_DATA_DIR FIXTURE   (P0: engine through the backend trait)
//!   debug-check gdb   BUNDLE NEW_DATA_DIR FIXTURE   (P1: a real gdb through the RSP server)
//!   debug-check stress BUNDLE NEW_DATA_DIR FIXTURE  (thread churn, soak, vfork timeout, exec)
//!
//! FIXTURE is the static `tests/monitor/debug-fixture` program. The data folder
//! must be new and disposable. One BusyBox VM, one vCPU.
use antinomie_monitor_core::{
    debug::{
        DebugBackend, DetachMode, KernelDebugBackend, ResumeAction, StopKind, TargetState, amd64,
    },
    *,
};
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
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(120);
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
        let deadline = Instant::now() + Duration::from_secs(seconds);
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
        let deadline = Instant::now() + Duration::from_secs(seconds);
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

fn setup(bundle: &str, data: &str, fixture: &str, ticks: u32) -> Result<Setup, String> {
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("qualification needs a new disposable data folder".into());
    }
    let mut driver = Driver {
        backend: Backend::new(BackendOptions {
            bundle_dir: PathBuf::from(bundle),
            data_dir: data,
            headless: true,
            capture_quota_size: 512 * 1024 * 1024,
            ..Default::default()
        })?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        output: BTreeMap::new(),
    };
    driver.command(Command::Create(VmConfig {
        name: "Debugger qualification".into(),
        cpus: 1,
        ram_mib: 512,
        disk_gib: 1,
        ..Default::default()
    }))?;
    driver.wait("VM publication", 10, |snapshot| !snapshot.vms.is_empty())?;
    let vm_id = driver.snapshot.vms[0].id.clone();
    driver.command(Command::Start { vm_id })?;
    driver.wait("revision-17 guest", 90, |snapshot| {
        snapshot
            .guest_kernel
            .as_ref()
            .and_then(|kernel| kernel.revision)
            .is_some_and(|revision| revision >= 17)
            && snapshot
                .serial_log
                .as_ref()
                .and_then(|path| fs::read(path).ok())
                .is_some_and(|log| log.windows(19).any(|part| part == b"BusyBox guest ready"))
    })?;
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
    let known: Vec<String> = driver
        .snapshot
        .runs
        .iter()
        .map(|run| run.id.clone())
        .collect();
    driver.command(Command::Execute(ExecRequest {
        path: "/tmp/debug-fixture".into(),
        args: vec![ticks.to_string(), workers.to_string(), mode.into()],
        uid: 0,
        gid: 0,
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
    driver.wait_text(&run_id, "symbols hot=", 20)?;
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
        .ok_or("symbols line")?
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
    let deadline = Instant::now() + Duration::from_secs(seconds);
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
    let script = [
        "set pagination off",
        "set confirm off",
        "set style enabled off",
        &format!("file {fixture}"),
        &format!("target remote 127.0.0.1:{}", info.tcp_port),
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
    let mut command = Process::new("gdb");
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
    for needle in [
        &format!("hit Breakpoint 1, 0x{:016x} in hot ()", setup.hot),
        &format!(
            "hit Temporary breakpoint 2, 0x{:016x} in tf_probe ()",
            setup.tf_probe
        ),
        "fs_base",
        "orig_rax",
        &format!("0x{:x} <hot>:\t0x48\t0x89\t0xf8", setup.hot),
        "$2 = 0x1111",
        "detached]",
    ] {
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
    let socat = Process::new("sh")
        .arg("-c")
        .arg(format!(
            "printf '+$?#3f' | timeout 5 socat - UNIX-CONNECT:{} | head -c 200",
            info.unix_socket.display()
        ))
        .output()
        .map_err(|e| e.to_string())?;
    let reply = String::from_utf8_lossy(&socat.stdout).to_string();
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
    let [mode, bundle, data, fixture] = args.as_slice() else {
        eprintln!("usage: debug-check spike|gdb|stress BUNDLE NEW_DATA_DIR FIXTURE");
        std::process::exit(2);
    };
    let result = match mode.as_str() {
        "spike" => spike(bundle, data, fixture),
        "gdb" => gdb(bundle, data, fixture),
        "stress" => stress(bundle, data, fixture),
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
    let mut command = Process::new("gdb");
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
    let output = gdb_batch(info.tcp_port, fixture, &["info registers rip", "detach"])
        .output()
        .map_err(|e| e.to_string())?;
    let text = text_of(&output);
    if !text.contains("rip") || !text.contains("detached") {
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
    let child = gdb_batch(
        info.tcp_port,
        fixture,
        &["continue", "info registers rip", "detach"],
    )
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .spawn()
    .map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_millis(2500));
    let _ = Process::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status();
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    let text = text_of(&output);
    if !text.contains("SIGINT") || !text.contains("rip") {
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
