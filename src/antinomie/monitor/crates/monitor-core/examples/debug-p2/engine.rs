// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Engine-level phase 2 tests through the `DebugBackend` trait: stepping across
//! a system call and a repeated string instruction, signals, a breakpoint a
//! forked child inherits, and latency.
use super::*;

const RCX: usize = 88;
const RSI: usize = 104;
const RDI_AT: usize = 112;

fn main_tid(prog: &mut Prog) -> Result<u32, String> {
    Ok(prog.dbg.threads().map_err(|e| e.to_string())?[0].tid)
}

/// One user instruction means one: across SYSCALL and across REP MOVSB.
pub fn step(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("p2fix", "step", 400, 0)?;
    prog.stop()?;
    let (syscall, after, rep, after_rep) = (
        prog.sym("step_syscall_insn")?,
        prog.sym("step_after_syscall")?,
        prog.sym("step_rep_insn")?,
        prog.sym("step_after_rep")?,
    );
    let pid = u64::from(
        context
            .driver
            .output(&prog.launched.run.id)
            .lines()
            .find_map(|line| {
                line.split("pid=")
                    .nth(1)
                    .and_then(|rest| rest.trim().parse::<u32>().ok())
            })
            .ok_or("pid line")?,
    );
    let entry = prog.sym("step_syscall")?;
    let event = prog.run_to(entry)?;
    let tid = event.tid;
    let mut times = Vec::new();
    let pc = prog.step(tid)?;
    if pc != syscall {
        return Err(format!("mov $39 stepped to {pc:#x}, wanted {syscall:#x}"));
    }
    let at = Instant::now();
    let pc = prog.step(tid)?;
    times.push(at.elapsed().as_secs_f64() * 1000.0);
    if pc != after {
        return Err(format!(
            "stepping SYSCALL ended at {pc:#x}, wanted {after:#x} (one instruction, not two)"
        ));
    }
    let rax = u64_of(&prog.regs(tid)?, RAX);
    if rax != pid {
        return Err(format!("getpid returned {rax}, wanted {pid}"));
    }
    for want in [after + 2, after + 3] {
        let pc = prog.step(tid)?;
        if pc != want {
            return Err(format!("stepped to {pc:#x}, wanted {want:#x}"));
        }
    }
    // Over REP MOVSB: one step retires the whole copy.
    let event = prog.run_to(prog.sym("step_rep")?)?;
    let tid = event.tid;
    for _ in 0..3 {
        prog.step(tid)?;
    }
    let before = prog.regs(tid)?;
    if u64_of(&before, RIP) != rep || u64_of(&before, RCX) != 4096 {
        return Err("not at the rep with rcx 4096".into());
    }
    let at = Instant::now();
    let pc = prog.step(tid)?;
    times.push(at.elapsed().as_secs_f64() * 1000.0);
    let regs = prog.regs(tid)?;
    if pc != after_rep
        || u64_of(&regs, RCX) != 0
        || u64_of(&regs, RSI) != u64_of(&before, RSI) + 4096
    {
        return Err(format!(
            "stepping REP MOVSB ended at {pc:#x} rcx {} (wanted {after_rep:#x} and rcx 0)",
            u64_of(&regs, RCX)
        ));
    }
    // A breakpoint on those instructions is stepped over the same way, and the
    // next round hits it again.
    for target in [syscall, rep] {
        prog.dbg
            .set_breakpoint(target, 1)
            .map_err(|e| e.to_string())?;
    }
    let mut hits = BTreeMap::<u64, u32>::new();
    for _ in 0..6 {
        prog.dbg
            .resume(ResumeAction::Continue)
            .map_err(|e| e.to_string())?;
        let event = wait_state(&mut prog.dbg, 15)?;
        match event.kind {
            StopKind::Breakpoint { addr } => *hits.entry(addr).or_default() += 1,
            other => return Err(format!("unexpected stop {other:?}")),
        }
    }
    if hits.get(&syscall).copied().unwrap_or(0) < 2 || hits.get(&rep).copied().unwrap_or(0) < 2 {
        return Err(format!(
            "breakpoints at SYSCALL and REP were not stepped over: {hits:?}"
        ));
    }
    prog.dbg
        .clear_breakpoint(syscall, 1)
        .and_then(|_| prog.dbg.clear_breakpoint(rep, 1))
        .map_err(|e| e.to_string())?;
    context.finish(prog)?;
    Ok(format!(
        "SYSCALL stepped to the next instruction (rax = pid), REP MOVSB retired in one step (rcx 0), breakpoints on both stepped over; {:.1} ms per step",
        median(times)
    ))
}

fn wait_signal(prog: &mut Prog, seconds: u64) -> Result<(u32, u32, u64), String> {
    let event = wait_state(&mut prog.dbg, seconds)?;
    match event.kind {
        StopKind::Signal { signal } => Ok((event.tid, signal, event.pc)),
        other => Err(format!(
            "expected a signal stop, got {other:?} at {:#x}",
            event.pc
        )),
    }
}

/// The largest tf_in_frame the sample reported (its handler counts frames whose
/// saved flags had the trap flag set).
fn tf_in_frames(output: &str) -> u32 {
    output
        .lines()
        .filter_map(|line| line.split("tf_in_frame=").nth(1))
        .filter_map(|rest| rest.split_whitespace().next()?.parse::<u32>().ok())
        .max()
        .unwrap_or(0)
}

fn tick_value(output: &str, round: u32, field: &str) -> Option<u32> {
    let prefix = format!("tick {round} ");
    output
        .lines()
        .find(|line| line.starts_with(&prefix))
        .and_then(|line| line.split(&format!("{field}=")).nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
}

/// A signal stops the group before delivery; the debugger passes or drops it.
pub fn signals(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("p2fix", "signal", 300, 0)?;
    prog.stop()?;
    let round_now = prog.sym("round_now")?;
    let round_of = |prog: &mut Prog| -> Result<u64, String> {
        Ok(u64_of(
            &prog
                .dbg
                .read_memory(round_now, 8)
                .map_err(|e| e.to_string())?,
            0,
        ))
    };
    prog.dbg
        .resume(ResumeAction::Continue)
        .map_err(|e| e.to_string())?;
    let (tid, signal, pc) = wait_signal(&mut prog, 15)?;
    if signal != 10 {
        return Err(format!("first signal was {signal}, wanted SIGUSR1"));
    }
    let first_round = round_of(&mut prog)?;
    let listed = prog.dbg.threads().map_err(|e| e.to_string())?;
    if !listed
        .iter()
        .any(|thread| thread.tid == tid && thread.signal == 10)
    {
        return Err(format!("thread list does not name the signal: {listed:?}"));
    }
    let regs = prog.regs(tid)?;
    if u64_of(&regs, RIP) != pc || u64_of(&regs, EFLAGS) & 0x100 != 0 {
        return Err("registers at a signal stop are wrong".into());
    }
    // Drop it: the handler must not run for this round.
    prog.dbg
        .resume(ResumeAction::Continue)
        .map_err(|e| e.to_string())?;
    let (_, signal, _) = wait_signal(&mut prog, 15)?;
    if signal != 10 || round_of(&mut prog)? != first_round + 1 {
        return Err(format!(
            "second signal was {signal} in round {}",
            round_of(&mut prog)?
        ));
    }
    // Pass the second one; its handler runs.
    prog.dbg
        .resume(ResumeAction::ContinueSignal { tid, signal: 10 })
        .map_err(|e| e.to_string())?;
    let (_, signal, _) = wait_signal(&mut prog, 15)?;
    if signal != 10 || round_of(&mut prog)? != first_round + 2 {
        return Err(format!(
            "third signal was {signal} in round {}",
            round_of(&mut prog)?
        ));
    }
    context.driver.wait_text(
        &prog.launched.run.id,
        &format!("tick {} ", first_round + 1),
        15,
    )?;
    let output = context.driver.output(&prog.launched.run.id).to_string();
    let (before, dropped, passed) = (
        first_round
            .checked_sub(1)
            .and_then(|round| tick_value(&output, round as u32, "usr1"))
            .unwrap_or(0),
        tick_value(&output, first_round as u32, "usr1").ok_or("dropped tick")?,
        tick_value(&output, first_round as u32 + 1, "usr1").ok_or("passed tick")?,
    );
    if first_round > 0 && (dropped != before || passed != before + 1) {
        return Err(format!(
            "usr1 count was {before} before round {first_round}; after a dropped then a passed signal it is {dropped} then {passed}"
        ));
    }
    // Pass the rest until the handled SIGSEGV of round 5 (a synchronous fault).
    let mut segv = 0;
    for _ in 0..40 {
        prog.dbg
            .resume(ResumeAction::ContinueSignal { tid, signal: 10 })
            .map_err(|e| e.to_string())?;
        let (_, signal, _) = wait_signal(&mut prog, 15)?;
        if signal == 11 {
            segv += 1;
            break;
        }
    }
    if segv == 0 {
        return Err("the SIGSEGV of round 5 was never reported".into());
    }
    let at_fault = prog.regs(tid)?;
    // Dropping a fault repeats it at the same instruction.
    prog.dbg
        .resume(ResumeAction::Continue)
        .map_err(|e| e.to_string())?;
    let (_, again, pc_again) = wait_signal(&mut prog, 15)?;
    if again != 11 || pc_again != u64_of(&at_fault, RIP) {
        return Err(format!(
            "a dropped SIGSEGV did not repeat: {again} at {pc_again:#x}"
        ));
    }
    // Passing it runs the handler, which jumps out.
    prog.dbg
        .resume(ResumeAction::ContinueSignal { tid, signal: 11 })
        .map_err(|e| e.to_string())?;
    let (_, next, _) = wait_signal(&mut prog, 15)?;
    if next != 10 {
        return Err(format!(
            "after the handled fault the next signal was {next}"
        ));
    }
    context
        .driver
        .wait_text(&prog.launched.run.id, "segv=1", 15)?;
    let output = context.driver.output(&prog.launched.run.id).to_string();
    if output.contains("segv=2") {
        return Err("the SIGSEGV handler ran more than once".into());
    }
    if tf_in_frames(&output) != 0 {
        return Err("the handler saw TF in its frame".into());
    }
    context.finish(prog)?;
    Ok("SIGUSR1 stops reported with the thread's signal, dropped and passed; SIGSEGV dropped repeats at the same pc, passed reaches the handler".into())
}

/// A step that delivers a signal stops at the handler's first instruction, and a
/// storm of signals during single steps never leaves the trap flag in a frame.
pub fn signal_step(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("p2fix", "signal", 600, 1)?;
    prog.stop()?;
    let handler = prog.sym("on_usr1")?;
    let tid = main_tid(&mut prog)?;
    let mut into_handler = 0;
    let mut signals = 0;
    let mut steps = 0;
    // The pinger thread signals the main thread every 1.5 ms. Everything runs
    // for a few milliseconds, then stops: a signal is then pending for the main
    // thread, and the steps that follow meet it.
    for _ in 0..70 {
        prog.dbg
            .resume(ResumeAction::Continue)
            .map_err(|e| e.to_string())?;
        thread::sleep(Duration::from_millis(5));
        prog.dbg.interrupt().map_err(|e| e.to_string())?;
        let mut event = wait_state(&mut prog.dbg, 15)?;
        for _ in 0..3 {
            if let StopKind::Signal { signal } = event.kind {
                signals += 1;
                prog.dbg
                    .resume(ResumeAction::StepSignal {
                        tid: event.tid,
                        signal,
                    })
                    .map_err(|e| e.to_string())?;
                let stepped = wait_state(&mut prog.dbg, 15)?;
                if stepped.kind != StopKind::Step {
                    return Err(format!("a step into a handler ended as {:?}", stepped.kind));
                }
                if signal == 10 && stepped.pc == handler {
                    into_handler += 1;
                } else if signal == 10 {
                    return Err(format!(
                        "step with SIGUSR1 stopped at {:#x}, handler is {handler:#x}",
                        stepped.pc
                    ));
                }
                event = stepped;
            }
            let regs = prog.regs(event.tid)?;
            if u64_of(&regs, EFLAGS) & 0x100 != 0 {
                return Err(format!("TF visible after {:?}", event.kind));
            }
            prog.dbg
                .resume(ResumeAction::Step { tid })
                .map_err(|e| e.to_string())?;
            event = wait_state(&mut prog.dbg, 15)?;
            if event.kind == StopKind::Step {
                steps += 1;
            }
        }
    }
    prog.dbg
        .resume(ResumeAction::Continue)
        .map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_millis(1500));
    context.driver.receive();
    let output = context.driver.output(&prog.launched.run.id).to_string();
    if tf_in_frames(&output) != 0 {
        return Err("a signal frame saved the engine's trap flag".into());
    }
    if signals == 0 || into_handler == 0 {
        return Err(format!(
            "no signal met a step ({signals} signals, {into_handler} handler entries)"
        ));
    }
    context.finish(prog)?;
    Ok(format!(
        "{steps} plain steps, {signals} signals met a step, {into_handler} steps stopped at the handler's first instruction, TF never in a register or a frame"
    ))
}

/// A breakpoint in memory when the process forks is a byte in the child's copy.
pub fn forkbp(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("p2fix", "fork", 60, 0)?;
    prog.stop()?;
    let target = prog.sym("hw_code")?;
    prog.dbg
        .set_breakpoint(target, 1)
        .map_err(|e| e.to_string())?;
    let mut hits = 0;
    let mut passed = 0;
    for _ in 0..40 {
        prog.dbg
            .resume(ResumeAction::Continue)
            .map_err(|e| e.to_string())?;
        let mut event = wait_state(&mut prog.dbg, 20)?;
        // A debugger passes the signals gdb's `handle` table says nostop (SIGCHLD,
        // SIGALRM, SIGWINCH, ...) and goes on, as gdb does. glibc's fork() blocks
        // every signal around the clone: a child that exits before the parent
        // unblocks them leaves a queued SIGCHLD, which the engine shows to the
        // debugger exactly as a tracer would see it.
        while let StopKind::Signal { signal } = event.kind {
            let quiet = u8::try_from(signal)
                .is_ok_and(|number| !signal_policy::default_action(number).stop);
            if !quiet {
                return Err(format!("unexpected stop {:?}", event.kind));
            }
            passed += 1;
            prog.dbg
                .resume(ResumeAction::ContinueSignal {
                    tid: event.tid,
                    signal,
                })
                .map_err(|e| e.to_string())?;
            event = wait_state(&mut prog.dbg, 20)?;
        }
        if !matches!(event.kind, StopKind::Breakpoint { .. }) {
            return Err(format!("unexpected stop {:?}", event.kind));
        }
        hits += 1;
        context.driver.receive();
        let output = context.driver.output(&prog.launched.run.id);
        if output.matches("child exit=").count() >= 2 {
            break;
        }
    }
    thread::sleep(Duration::from_millis(500));
    context.driver.receive();
    let output = context.driver.output(&prog.launched.run.id).to_string();
    let children = output.matches("child exit=0 sig=0").count();
    if output.contains("sig=5") || children == 0 {
        return Err(format!(
            "forked children did not survive the inherited breakpoint ({children} clean exits, {hits} hits):\n{}",
            tail(&output, 400)
        ));
    }
    prog.dbg
        .clear_breakpoint(target, 1)
        .map_err(|e| e.to_string())?;
    context.finish(prog)?;
    Ok(format!(
        "{children} forked children ran hw_code() with the parent's breakpoint byte in their memory and exited cleanly (no SIGTRAP); {hits} parent hits, {passed} queued SIGCHLD passed on like gdb does"
    ))
}

/// What a debugger waits for.
pub fn latency(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("p2fix", "threads", 900, 3)?;
    let tid = main_tid(&mut prog)?;
    let mut stop_ms = Vec::new();
    let mut regs2 = Vec::new();
    let mut regs_batch = Vec::new();
    let mut mem = Vec::new();
    let mut status = Vec::new();
    let mut step = Vec::new();
    let worker = prog.sym("worker")?;
    for _ in 0..30 {
        let at = Instant::now();
        prog.dbg.interrupt().map_err(|e| e.to_string())?;
        wait_state(&mut prog.dbg, 10)?;
        stop_ms.push(at.elapsed().as_secs_f64() * 1000.0);
        let at = Instant::now();
        user_regs(&mut prog.dbg, tid).map_err(|e| format!("general registers: {e}"))?;
        prog.dbg
            .read_regset(tid, amd64::NT_PRFPREG)
            .map_err(|e| format!("FXSAVE: {e}"))?;
        regs2.push(at.elapsed().as_secs_f64() * 1000.0);
        let at = Instant::now();
        prog.dbg
            .read_regsets(tid, &[amd64::NT_PRSTATUS, amd64::NT_PRFPREG])
            .map_err(|e| format!("batched registers: {e}"))?;
        regs_batch.push(at.elapsed().as_secs_f64() * 1000.0);
        let at = Instant::now();
        prog.dbg
            .read_memory(worker & !0xfff, 2048)
            .map_err(|e| e.to_string())?;
        mem.push(at.elapsed().as_secs_f64() * 1000.0);
        let at = Instant::now();
        prog.dbg.state().map_err(|e| e.to_string())?;
        status.push(at.elapsed().as_secs_f64() * 1000.0);
        let at = Instant::now();
        prog.dbg
            .resume(ResumeAction::Step { tid })
            .map_err(|e| e.to_string())?;
        wait_state(&mut prog.dbg, 10)?;
        step.push(at.elapsed().as_secs_f64() * 1000.0);
        prog.dbg
            .resume(ResumeAction::Continue)
            .map_err(|e| e.to_string())?;
        thread::sleep(Duration::from_millis(20));
    }
    let at = Instant::now();
    prog.dbg.interrupt().map_err(|e| e.to_string())?;
    wait_state(&mut prog.dbg, 10)?;
    prog.dbg
        .detach(DetachMode::Resume)
        .map_err(|e| e.to_string())?;
    let detach = at.elapsed().as_secs_f64() * 1000.0;
    let run = prog.launched.run.id.clone();
    let mut prog = prog;
    context.driver.command(Command::StopRun {
        run_id: run.clone(),
    })?;
    run_ended(&mut context.driver, &run, 30)?;
    let _ = &mut prog;
    Ok(format!(
        "median ms: status {:.2}, 2 KiB memory {:.2}, two register sets one by one {:.2}, in one request {:.2}, stop {:.2}, step {:.2}; stop+detach {detach:.1}",
        median(status),
        median(mem),
        median(regs2),
        median(regs_batch),
        median(stop_ms),
        median(step)
    ))
}

fn insert(prog: &mut Prog, kind: BreakpointKind, addr: u64, len: u32) -> Result<(), String> {
    prog.dbg
        .insert_breakpoint(kind, addr, len)
        .map_err(|e| format!("{kind:?} {addr:#x}: {e}"))
}
fn remove(prog: &mut Prog, kind: BreakpointKind, addr: u64, len: u32) -> Result<(), String> {
    prog.dbg
        .remove_breakpoint(kind, addr, len)
        .map_err(|e| format!("{kind:?} {addr:#x}: {e}"))
}
fn resume_and_wait(prog: &mut Prog) -> Result<antinomie_monitor_core::debug::StopEvent, String> {
    prog.dbg
        .resume(ResumeAction::Continue)
        .map_err(|e| e.to_string())?;
    wait_state(&mut prog.dbg, 20)
}

/// Debug-register breakpoints and watchpoints, and what the program can see.
pub fn hw(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("p2fix", "hw", 400, 0)?;
    let caps = prog.dbg.caps().clone();
    if caps.hardware_breakpoints == 0 || caps.hardware_watchpoints == 0 {
        return Err(format!("the guest offers no debug registers: {caps:?}"));
    }
    prog.stop()?;
    let (code, after_write, after_read, watched, other) = (
        prog.sym("hw_code")?,
        prog.sym("hw_after_write")?,
        prog.sym("hw_after_read")?,
        prog.sym("watched")?,
        prog.sym("watched_other")?,
    );
    // An instruction breakpoint: hit before the instruction, at every call, and
    // resuming does not stop on it again at once.
    insert(&mut prog, BreakpointKind::Hardware, code, 1)?;
    let mut pcs = Vec::new();
    for _ in 0..4 {
        let event = resume_and_wait(&mut prog)?;
        match event.kind {
            StopKind::HardwareBreakpoint { addr } if addr == code && event.pc == code => {}
            other => {
                return Err(format!(
                    "expected a hardware breakpoint at {code:#x}, got {other:?} at {:#x}",
                    event.pc
                ));
            }
        }
        pcs.push(event.pc);
    }
    // The next step after a hit goes to the next instruction.
    let tid = prog.dbg.threads().map_err(|e| e.to_string())?[0].tid;
    let pc = prog.step(tid)?;
    if pc != after_write {
        return Err(format!(
            "stepped off the hardware breakpoint to {pc:#x}, wanted {after_write:#x}"
        ));
    }
    // A watchpoint that fires with the step is the report, not the step.
    insert(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        watched,
        8,
    )?;
    remove(&mut prog, BreakpointKind::Hardware, code, 1)?;
    let event = resume_and_wait(&mut prog)?;
    match event.kind {
        StopKind::Watchpoint {
            addr,
            access: WatchAccess::Write,
        } if addr == watched && event.pc == after_write => {}
        other => {
            return Err(format!(
                "expected a write watchpoint, got {other:?} at {:#x}",
                event.pc
            ));
        }
    }
    let value = u64_of(
        &prog
            .dbg
            .read_memory(watched, 8)
            .map_err(|e| e.to_string())?,
        0,
    );
    // Data written by the instruction that fired is already there.
    let regs = prog.regs(event.tid)?;
    if value != u64_of(&regs, RDI_AT) {
        return Err(format!(
            "watched holds {value}, rdi {}",
            u64_of(&regs, RDI_AT)
        ));
    }
    remove(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        watched,
        8,
    )?;
    // Access watch: the write, then the read of the same round.
    insert(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Access),
        watched,
        8,
    )?;
    let mut seen = Vec::new();
    for _ in 0..4 {
        let event = resume_and_wait(&mut prog)?;
        match event.kind {
            StopKind::Watchpoint {
                addr,
                access: WatchAccess::Access,
            } if addr == watched => seen.push(event.pc),
            other => return Err(format!("expected an access watchpoint, got {other:?}")),
        }
    }
    if !(seen.contains(&after_write) && seen.contains(&after_read)) {
        return Err(format!(
            "access hits at {seen:x?}, wanted both {after_write:#x} and {after_read:#x}"
        ));
    }
    remove(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Access),
        watched,
        8,
    )?;
    // A write by another instruction (the main loop) and a narrower watch.
    insert(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        other,
        8,
    )?;
    let event = resume_and_wait(&mut prog)?;
    if !matches!(event.kind, StopKind::Watchpoint { addr, .. } if addr == other) {
        return Err(format!(
            "expected a watch on watched_other, got {:?}",
            event.kind
        ));
    }
    remove(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        other,
        8,
    )?;
    // Running free again, with the sample reporting what it sees.
    prog.dbg
        .resume(ResumeAction::Continue)
        .map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_millis(600));
    context.driver.receive();
    let output = context.driver.output(&prog.launched.run.id).to_string();
    if !output.contains("tick ") {
        return Err("the sample produced no output".into());
    }
    context.finish(prog)?;
    Ok(format!(
        "hbreak hit {} times at hw_code without retriggering on resume; write watch fired after the store with the new value; access watch saw the write and the read; a step that fired a watchpoint reported the watchpoint",
        pcs.len()
    ))
}

pub fn slots(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("p2fix", "hw", 400, 0)?;
    prog.stop()?;
    let code = prog.sym("hw_code")?;
    let watched = prog.sym("watched")?;
    let other = prog.sym("watched_other")?;
    let free = prog.dbg.caps().hardware_breakpoints;
    if free != 4 {
        return Err(format!("expected 4 debug registers, caps say {free}"));
    }
    insert(&mut prog, BreakpointKind::Hardware, code, 1)?;
    insert(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        watched,
        8,
    )?;
    insert(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        other,
        4,
    )?;
    insert(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Access),
        other + 8,
        2,
    )?;
    let refused =
        prog.dbg
            .insert_breakpoint(BreakpointKind::Watch(WatchAccess::Write), other + 16, 1);
    if !matches!(refused, Err(DebugError::NoSlots)) {
        return Err(format!(
            "a fifth request was not refused cleanly: {refused:?}"
        ));
    }
    // Refused for a reason that is not the pool.
    remove(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Access),
        other + 8,
        2,
    )?;
    for (kind, addr, len) in [
        (BreakpointKind::Watch(WatchAccess::Write), other + 1, 4),
        (BreakpointKind::Watch(WatchAccess::Write), other, 3),
        (BreakpointKind::Hardware, code, 2),
    ] {
        let result = prog.dbg.insert_breakpoint(kind, addr, len);
        if result.is_ok() {
            return Err(format!("{kind:?} {addr:#x} length {len} should be refused"));
        }
    }
    insert(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        other + 16,
        1,
    )?;
    // Same request twice is one slot; the freed slot comes back.
    insert(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        other + 16,
        1,
    )?;
    remove(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        other + 16,
        1,
    )?;
    insert(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        other + 24,
        1,
    )?;
    for (kind, addr, len) in [
        (BreakpointKind::Hardware, code, 1),
        (BreakpointKind::Watch(WatchAccess::Write), watched, 8),
        (BreakpointKind::Watch(WatchAccess::Write), other, 4),
        (BreakpointKind::Watch(WatchAccess::Write), other + 24, 1),
    ] {
        remove(&mut prog, kind, addr, len)?;
    }
    // The pool is whole again, and execution still works.
    insert(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        watched,
        8,
    )?;
    let event = resume_and_wait(&mut prog)?;
    if !matches!(event.kind, StopKind::Watchpoint { .. }) {
        return Err(format!(
            "no watchpoint after the pool was refilled: {:?}",
            event.kind
        ));
    }
    remove(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        watched,
        8,
    )?;
    context.finish(prog)?;
    Ok("four debug registers taken by mixed kinds, the fifth refused as NoSlots (E1c to a client), misaligned and odd lengths refused as invalid, slots freed and reused".into())
}

/// A watch on a variable that each of several threads writes: every thread of
/// the group has the debug registers.
pub fn hwthreads(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("p2fix", "threads", 600, 4)?;
    prog.stop()?;
    let counters = prog.sym("counters")?;
    let threads = prog.dbg.threads().map_err(|e| e.to_string())?;
    if threads.len() != 5 {
        return Err(format!("expected 5 threads, saw {}", threads.len()));
    }
    for slot in 0..4u64 {
        insert(
            &mut prog,
            BreakpointKind::Watch(WatchAccess::Write),
            counters + 8 * slot,
            8,
        )?;
    }
    let mut writers = BTreeMap::<u32, u32>::new();
    for _ in 0..24 {
        let event = resume_and_wait(&mut prog)?;
        if !matches!(event.kind, StopKind::Watchpoint { .. }) {
            return Err(format!("unexpected stop {:?}", event.kind));
        }
        *writers.entry(event.tid).or_default() += 1;
    }
    if writers.len() < 3 {
        return Err(format!(
            "only {} threads reached their watchpoints: {writers:?}",
            writers.len()
        ));
    }
    for slot in 0..4u64 {
        remove(
            &mut prog,
            BreakpointKind::Watch(WatchAccess::Write),
            counters + 8 * slot,
            8,
        )?;
    }
    context.finish(prog)?;
    Ok(format!(
        "{} different threads fired watchpoints on their own counters",
        writers.len()
    ))
}

/// Code the program rewrites while a breakpoint is in it.
pub fn smc(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("p2fix", "smc", 200, 0)?;
    prog.stop()?;
    let page = prog.sym("smc")?;
    // Software breakpoint on the byte the program rewrites every round.
    prog.dbg
        .set_breakpoint(page + 1, 1)
        .map_err(|e| e.to_string())?;
    prog.dbg
        .resume(ResumeAction::Continue)
        .map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_millis(1200));
    context.driver.receive();
    prog.dbg.interrupt().map_err(|e| e.to_string())?;
    let stopped = wait_state(&mut prog.dbg, 15);
    thread::sleep(Duration::from_millis(400));
    context.driver.receive();
    let output = context.driver.output(&prog.launched.run.id).to_string();
    let printed = output
        .lines()
        .rev()
        .find_map(|line| {
            let hex = line.split("smc=").nth(1)?;
            u8::from_str_radix(hex.trim(), 16).ok()
        })
        .ok_or("no smc line")?;
    stopped?;
    let current = prog.dbg.read_memory(page, 6).map_err(|e| e.to_string())?;
    if output.contains("MISMATCH") {
        return Err("the sample's rewritten code was damaged".into());
    }
    if current[1] != printed && current[1] != printed.wrapping_add(1) {
        return Err(format!(
            "the byte under the breakpoint is {:#x}, the program last wrote {:#x}: the engine put back stale code",
            current[1], printed
        ));
    }
    prog.dbg
        .clear_breakpoint(page + 1, 1)
        .map_err(|e| e.to_string())?;
    // The same page with an instruction breakpoint in the debug registers fires
    // at every call even though the bytes change each time.
    insert(&mut prog, BreakpointKind::Hardware, page, 1)?;
    let mut versions = Vec::new();
    for _ in 0..3 {
        let event = resume_and_wait(&mut prog)?;
        if !matches!(event.kind, StopKind::HardwareBreakpoint { .. }) || event.pc != page {
            return Err(format!(
                "expected hbreak at the rewritten code, got {:?} at {:#x}",
                event.kind, event.pc
            ));
        }
        let code = prog.dbg.read_memory(page, 6).map_err(|e| e.to_string())?;
        if code[0] != 0xb8 || code[5] != 0xc3 {
            return Err(format!("the code at the breakpoint is {code:02x?}"));
        }
        versions.push(code[1]);
    }
    remove(&mut prog, BreakpointKind::Hardware, page, 1)?;
    context.finish(prog)?;
    Ok(format!(
        "a software breakpoint in rewritten code left the program's own bytes ({:#x}); an hbreak fired on every call of the rewritten function (versions {versions:?})",
        current[1]
    ))
}

/// What the program can see of the debugger: nothing it checks for, and the
/// direct read of its own code shows a software breakpoint but not a hardware one.
pub fn anti(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("p2fix", "anti", 120, 0)?;
    prog.stop()?;
    let probe = prog.sym("step_syscall")?;
    let watched = prog.sym("watched")?;
    insert(&mut prog, BreakpointKind::Hardware, probe, 1)?;
    insert(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        watched,
        8,
    )?;
    prog.dbg
        .resume(ResumeAction::Continue)
        .map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_millis(2500));
    prog.stop()?;
    remove(&mut prog, BreakpointKind::Hardware, probe, 1)?;
    prog.dbg
        .set_breakpoint(probe, 1)
        .map_err(|e| e.to_string())?;
    let mark = {
        context.driver.receive();
        context.driver.output(&prog.launched.run.id).len()
    };
    prog.dbg
        .resume(ResumeAction::Continue)
        .map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_millis(2500));
    prog.stop()?;
    context.driver.receive();
    let text = context.driver.output(&prog.launched.run.id).to_string();
    let (hardware, software) = text.split_at(mark.min(text.len()));
    let ticks = |part: &str| -> Vec<String> {
        part.lines()
            .filter(|l| l.starts_with("tick "))
            .map(str::to_string)
            .collect()
    };
    let (hw_lines, sw_lines) = (ticks(hardware), ticks(software));
    if hw_lines.len() < 10 || sw_lines.len() < 10 {
        return Err(format!(
            "too few probe lines: {} and {}",
            hw_lines.len(),
            sw_lines.len()
        ));
    }
    for line in hw_lines.iter().chain(&sw_lines) {
        for needle in ["sigtrap=0", "int3_mem=0", "tf=0"] {
            if !line.contains(needle) {
                return Err(format!("the program saw the debugger ({needle}): {line}"));
            }
        }
        if line.contains("traceme=-9") && !line.contains("tracer=0") {
            return Err(format!("TracerPid is set: {line}"));
        }
    }
    if let Some(line) = hw_lines.iter().find(|l| !l.contains("int3_direct=0")) {
        return Err(format!(
            "a hardware breakpoint left a byte in the code: {line}"
        ));
    }
    let direct = sw_lines
        .iter()
        .filter(|l| !l.contains("int3_direct=0"))
        .count();
    if !text.contains("dr child_dr7=0x0") {
        return Err("the traced child's debug registers were not as expected".into());
    }
    prog.dbg
        .clear_breakpoint(probe, 1)
        .map_err(|e| e.to_string())?;
    remove(
        &mut prog,
        BreakpointKind::Watch(WatchAccess::Write),
        watched,
        8,
    )?;
    context.finish(prog)?;
    Ok(format!(
        "{} lines under hardware breakpoints and {} under a software one: TracerPid 0, no SIGTRAP, no 0xCC through /proc/self/mem, TF clear; direct reads of the code saw no byte with hardware breakpoints and the engine's byte on {direct} software lines (documented)",
        hw_lines.len(),
        sw_lines.len()
    ))
}
