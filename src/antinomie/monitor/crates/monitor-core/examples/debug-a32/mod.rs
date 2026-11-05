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
use super::*;
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
    println!("PASS a32");
    Ok(())
}
