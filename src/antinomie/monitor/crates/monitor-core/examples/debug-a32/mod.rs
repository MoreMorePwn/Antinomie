// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! `debug-check a32 BUNDLE NEW_DATA_DIR FIXTURE`: the guest debug engine on a
//! 32-bit ARM program of an arm64 guest (contract revision 21), with
//! `tests/monitor/aarch32-debug-fixture` (built with arm-linux-gnueabihf-gcc).
//!
//! The host has no AArch32 debugger yet, so the check speaks to the engine
//! itself: CAPS must offer AARCH32; the compat NT_PRSTATUS is 18 words (r0-r15,
//! cpsr, orig_r0); an A32 breakpoint (4 bytes) and a Thumb one (2 bytes),
//! planted with BP_SET, stop the program at their address in the right state
//! (CPSR.T clear, then set); a hardware step from each moves the pc by one
//! instruction, and the program then runs to its end.
//!
//! Then the host's own AArch32 support (ANT-T0297): a gdb-multiarch session
//! through the app's RSP server (the `arm` target description, an ARM and a
//! Thumb breakpoint chosen by gdb from the symbols, stepping), and the ELF32
//! exit core of the `crash` mode opened by the core reader (registers, VFP,
//! mappings, files, ARM/Thumb disassembly at the pc).
use super::*;
use antinomie_monitor_core::core_dump::{CoreDump, EM_ARM};
use antinomie_monitor_core::debug::{GuestLink, wire};

const CAP_AARCH32: u32 = 4096;
const PSR_T: u32 = 1 << 5;

fn word(data: &[u8], index: usize) -> u32 {
    u32::from_le_bytes(
        data[index * 4..index * 4 + 4]
            .try_into()
            .expect("four bytes"),
    )
}

fn hex(line: &str, name: &str) -> Result<u64, String> {
    let value = line
        .split_whitespace()
        .find_map(|field| field.strip_prefix(&format!("{name}=0x")))
        .ok_or_else(|| format!("{name} missing from {line:?}"))?;
    u64::from_str_radix(value, 16).map_err(|e| e.to_string())
}

/// PC and CPSR of a stopped thread, from the compat NT_PRSTATUS.
fn pc_cpsr(dbg: &mut KernelDebugBackend, tid: u32) -> Result<(u32, u32), String> {
    let regs = dbg
        .read_regset(tid, 1)
        .map_err(|e| format!("NT_PRSTATUS: {e}"))?
        .data;
    if regs.len() != 72 {
        return Err(format!(
            "compat NT_PRSTATUS has {} bytes, not 72",
            regs.len()
        ));
    }
    Ok((word(&regs, 15), word(&regs, 16)))
}

/// BP_SET or BP_CLEAR of the engine with an explicit length.
fn raw_breakpoint(
    link: &mut impl GuestLink,
    session: u64,
    addr: u64,
    len: u32,
    set: bool,
) -> Result<(), String> {
    let status = link
        .request(wire::STATUS, &wire::status_request(session))
        .map_err(|e| format!("{e:?}"))?;
    let status = wire::parse_status(&status)?;
    let request = wire::breakpoint_request(session, addr, len, status.generation);
    link.request(if set { wire::BP_SET } else { wire::BP_CLEAR }, &request)
        .map(|_| ())
        .map_err(|e| {
            format!(
                "BP {} {addr:#x}/{len}: {e:?}",
                if set { "set" } else { "clear" }
            )
        })
}

fn stop_at(
    dbg: &mut KernelDebugBackend,
    addr: u64,
    thumb: bool,
    evidence: &mut Vec<String>,
) -> Result<u32, String> {
    dbg.resume(ResumeAction::Continue)
        .map_err(|e| e.to_string())?;
    let event = wait_state(dbg, 60)?;
    if !matches!(event.kind, StopKind::Breakpoint { addr: hit } if hit == addr) {
        return Err(format!("expected a breakpoint at {addr:#x}, got {event:?}"));
    }
    let (pc, cpsr) = pc_cpsr(dbg, event.tid)?;
    if u64::from(pc) != addr || (cpsr & PSR_T != 0) != thumb {
        return Err(format!(
            "stopped at pc {pc:#x} cpsr {cpsr:#x}, wanted {addr:#x} thumb {thumb}"
        ));
    }
    evidence.push(format!("breakpoint {addr:#x} thumb={thumb} cpsr={cpsr:#x}"));
    Ok(event.tid)
}

fn step_from(
    dbg: &mut KernelDebugBackend,
    tid: u32,
    from: u64,
    sizes: &[u64],
    evidence: &mut Vec<String>,
) -> Result<(), String> {
    dbg.resume(ResumeAction::Step { tid })
        .map_err(|e| e.to_string())?;
    let event = wait_state(dbg, 60)?;
    let (pc, cpsr) = pc_cpsr(dbg, event.tid)?;
    if event.kind != StopKind::Step || !sizes.iter().any(|size| from + size == u64::from(pc)) {
        return Err(format!("step from {from:#x}: {event:?}, pc {pc:#x}"));
    }
    evidence.push(format!("step {from:#x} -> {pc:#x} cpsr={cpsr:#x}"));
    Ok(())
}

pub fn run(bundle: &str, data: &str, fixture: &str) -> Result<(), String> {
    let mut driver = boot(bundle, data)?;
    driver.command(Command::Upload {
        source: PathBuf::from(fixture),
        destination: "/tmp/a32fix".into(),
        overwrite: false,
        executable: true,
    })?;
    let launched = launch_program(
        &mut driver,
        "/tmp/a32fix",
        vec!["loop".into(), "400".into()],
        false,
    )?;
    let (arm, thumb) = (
        hex(&launched.symbols, "arm")?,
        hex(&launched.symbols, "thumb")?,
    );
    let mut link = driver.backend.debug_link();
    let caps = link
        .request(wire::CAPS, &wire::caps_request())
        .map_err(|e| format!("CAPS: {e:?}"))?;
    let flags = u32::from_le_bytes(caps[8..12].try_into().expect("four bytes"));
    if flags & CAP_AARCH32 == 0 {
        return Err(format!("CAPS flags {flags:#x} lack AARCH32"));
    }
    let mut dbg = attach_backend(&mut driver, &launched, 0xa32)?;
    let session = dbg.session();
    let mut evidence = Vec::new();
    dbg.interrupt().map_err(|e| e.to_string())?;
    let event = wait_state(&mut dbg, 30)?;
    let (pc, cpsr) = pc_cpsr(&mut dbg, event.tid)?;
    evidence.push(format!("interrupt pc={pc:#x} cpsr={cpsr:#x}"));

    raw_breakpoint(&mut link, session, arm, 4, true)?;
    let tid = stop_at(&mut dbg, arm, false, &mut evidence)?;
    step_from(&mut dbg, tid, arm, &[4], &mut evidence)?;
    raw_breakpoint(&mut link, session, arm, 4, false)?;

    raw_breakpoint(&mut link, session, thumb, 2, true)?;
    let tid = stop_at(&mut dbg, thumb, true, &mut evidence)?;
    step_from(&mut dbg, tid, thumb, &[2, 4], &mut evidence)?;
    raw_breakpoint(&mut link, session, thumb, 2, false)?;
    // A misaligned A32 breakpoint is refused.
    if raw_breakpoint(&mut link, session, arm + 2, 4, true).is_ok() {
        return Err("a misaligned A32 breakpoint was accepted".into());
    }

    dbg.detach(DetachMode::Resume).map_err(|e| e.to_string())?;
    let status = run_ended(&mut driver, &launched.run.id, secs(120))?;
    if status != (WaitStatus::Exited { code: 0 }) {
        return Err(format!("fixture ended {status:?}"));
    }
    for line in &evidence {
        println!("RESULT {line}");
    }
    println!("PASS a32 engine");
    gdb_session(&mut driver, data, fixture)?;
    println!("PASS a32 gdb");
    exit_core(&mut driver)?;
    println!("PASS a32 core");
    println!("PASS a32");
    Ok(())
}

/// gdb-multiarch against the app's server: the host recognises the AArch32 task
/// at its first stop, gdb gets the arm description, plants the ARM trap
/// (Z0 kind 4) and the Thumb one (kind 2 or 3) by the symbols' low bits, and
/// steps.
fn gdb_session(driver: &mut Driver, data: &str, fixture: &str) -> Result<(), String> {
    let launched = launch_program(
        driver,
        "/tmp/a32fix",
        vec!["loop".into(), "4000".into()],
        false,
    )?;
    let (arm, thumb) = (
        hex(&launched.symbols, "arm")?,
        hex(&launched.symbols, "thumb")?,
    );
    let info = attach(driver, &launched.target)?;
    println!("endpoint: {}", info.gdb_command);
    let target = format!("target remote 127.0.0.1:{}", info.tcp_port);
    // The symbols tell gdb which of the two functions is Thumb (the trap kind).
    let file = format!("file {fixture}");
    let mut command = std::process::Command::new("gdb-multiarch");
    command.arg("-nx").arg("-batch");
    let breaks = [
        format!("break *{arm:#x}"),
        format!("break *{:#x}", thumb | 1),
    ];
    let script = [
        "set pagination off",
        "set confirm off",
        "set style enabled off",
        file.as_str(),
        target.as_str(),
        "show architecture",
        "info registers r0 sp lr pc cpsr",
        &breaks[0],
        &breaks[1],
        "continue",
        "echo AT1\\n",
        "p/x $pc",
        "p/x $cpsr",
        "x/2i $pc",
        "stepi",
        "echo STEP1\\n",
        "p/x $pc",
        "continue",
        "echo AT2\\n",
        "p/x $pc",
        "p/x $cpsr",
        "x/2i $pc",
        "stepi",
        "echo STEP2\\n",
        "p/x $pc",
        "delete",
        "detach",
    ];
    for line in script {
        command.arg("-ex").arg(line);
    }
    let output = command
        .output()
        .map_err(|e| format!("gdb-multiarch: {e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("---- gdb ----\n{text}---- end gdb ----");
    fs::write(PathBuf::from(data).join("a32-gdb-session.txt"), &text).map_err(|e| e.to_string())?;
    // The values `p/x` printed after a marker line.
    let after = |tag: &str, count: usize| -> Result<Vec<u64>, String> {
        let start = text
            .find(&format!("{tag}\n"))
            .ok_or(format!("no {tag} marker"))?;
        let values: Vec<u64> = text[start..]
            .lines()
            .skip(1)
            .filter_map(|line| line.split(" = 0x").nth(1))
            .take(count)
            .filter_map(|hex| u64::from_str_radix(hex.trim(), 16).ok())
            .collect();
        (values.len() == count)
            .then_some(values)
            .ok_or(format!("{tag}: values missing"))
    };
    if !text.contains("detached]") || !text.contains("arm") {
        return Err("the gdb session did not detach cleanly or is not an arm target".into());
    }
    let (at1, at2) = (after("AT1", 2)?, after("AT2", 2)?);
    let (step1, step2) = (after("STEP1", 1)?, after("STEP2", 1)?);
    println!("gdb: arm trap {at1:x?} thumb trap {at2:x?} steps {step1:x?} {step2:x?}");
    // The state at each trap: the ARM address with CPSR.T clear, the Thumb one with it set.
    if at1[0] != arm || at1[1] & u64::from(PSR_T) != 0 {
        return Err("the ARM breakpoint stopped elsewhere or in Thumb state".into());
    }
    if at2[0] != thumb || at2[1] & u64::from(PSR_T) == 0 {
        return Err("the Thumb breakpoint stopped elsewhere or in ARM state".into());
    }
    if step1[0] != arm + 4 || ![thumb + 2, thumb + 4].contains(&step2[0]) {
        return Err("stepi did not move by one ARM and one Thumb instruction".into());
    }
    if text.contains("Cannot access memory") || text.contains("Remote connection closed") {
        return Err("gdb reported a memory or connection failure".into());
    }
    driver.command(Command::DebugDetach { kill: false })?;
    let status = run_ended(driver, &launched.run.id, secs(300))?;
    println!("gdb run ended {status:?}");
    Ok(())
}

/// The `crash` mode's exit core: the guest writes an ELF32 core, the host reads it.
fn exit_core(driver: &mut Driver) -> Result<(), String> {
    let known: Vec<String> = driver.snapshot.runs.iter().map(|r| r.id.clone()).collect();
    driver.command(Command::Execute(ExecRequest {
        path: "/tmp/a32fix".into(),
        args: vec!["crash".into()],
        uid: 0,
        gid: 0,
        core_dump_on_exit: true,
        ..Default::default()
    }))?;
    driver.wait("crash run", 10, |s| {
        s.runs.iter().any(|r| !known.contains(&r.id))
    })?;
    let run = driver
        .snapshot
        .runs
        .iter()
        .find(|r| !known.contains(&r.id))
        .cloned()
        .ok_or("the crash run is missing")?;
    driver.wait("exit core", 300, |_| {
        RunArtifacts::load(&run.directory).is_ok_and(|a| {
            a.is_some_and(|a| {
                matches!(
                    a.core_state,
                    RunArtifactState::Complete
                        | RunArtifactState::Partial
                        | RunArtifactState::Failed
                        | RunArtifactState::Interrupted
                )
            })
        })
    })?;
    let artifacts = RunArtifacts::load(&run.directory)?.ok_or("no artifact metadata")?;
    if artifacts.core_state != RunArtifactState::Complete {
        return Err(format!(
            "the exit core is {:?}: {:?} {:?}",
            artifacts.core_state, artifacts.core_reason, artifacts.issues
        ));
    }
    let path = artifacts.core_dump.ok_or("the core file is missing")?;
    let core = CoreDump::open(&path).map_err(|e| format!("host reader: {e}"))?;
    let thread = core.threads.first().ok_or("no thread in the core")?;
    let pc = thread.register("pc").ok_or("no pc")?;
    let cpsr = thread.register("cpsr").ok_or("no cpsr")?;
    println!(
        "core: machine {} threads {} mappings {} files {} auxv {} pc {pc:#x} cpsr {cpsr:#x} signal {}",
        core.machine,
        core.threads.len(),
        core.mappings.len(),
        core.files.len(),
        core.auxv.len(),
        thread.signal
    );
    if core.machine != EM_ARM
        || thread.signal != 11
        || thread.register("fpscr").is_none()
        || core.mappings.is_empty()
        || core.auxv.is_empty()
        || !core.files.iter().any(|f| f.path.ends_with("a32fix"))
    {
        return Err(
            "the ELF32 core lacks registers, VFP, mappings, auxv or the program's file".into(),
        );
    }
    let listing = core
        .disassemble(pc, 32)
        .map_err(|e| format!("disassembly: {e}"))?;
    println!("{listing}");
    let expected = if cpsr & u64::from(PSR_T) != 0 {
        "Thumb mode"
    } else {
        "ARM mode"
    };
    if !listing.contains(expected) || listing.lines().count() < 3 {
        return Err(format!("the listing at pc is not {expected}"));
    }
    Ok(())
}
