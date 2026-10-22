// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The engine's own worker under programs that end or block while it acts: a
//! group killed while it is stopped, a thread that exits in a step, steps of a
//! vfork and of a call that blocks, and a CLONE_VFORK child without CLONE_VM
//! (the 0.7.0 audit's FF-14, FF-15, FF-16 and FF-21). An engine that oopses
//! leaves its report in the kernel log; one that waits without bound never
//! answers again.
use super::*;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// The guest kernel log has no oops, BUG or warning.
fn kernel_log_clean(context: &mut Context) -> Result<(), String> {
    context.driver.receive();
    let Some(path) = context.driver.snapshot.serial_log.clone() else {
        return Err("no serial log".into());
    };
    let log = String::from_utf8_lossy(&fs::read(&path).map_err(text)?).into_owned();
    for marker in [
        "Oops",
        "BUG:",
        "general protection fault",
        "WARNING:",
        "Call Trace",
    ] {
        if let Some(at) = log.find(marker) {
            let start = log[..at].rfind('\n').unwrap_or(0);
            return Err(format!(
                "the guest kernel reported {marker:?}:\n{}",
                log[start..].chars().take(1500).collect::<String>()
            ));
        }
    }
    Ok(())
}

/// The engine still attaches to, stops and lets go of another program.
fn engine_alive(context: &mut Context) -> Result<(), String> {
    let mut prog = context.start("fork", 40, 0, None)?;
    prog.stop()?;
    context.finish(prog)
}

/// Poll a backend until it is anything but in transition.
fn settle(backend: &mut KernelDebugBackend, seconds: u64) -> Result<TargetState, String> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        let state = backend.state().map_err(text)?;
        if state != TargetState::Transition {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "still in transition after {seconds} s; failure {:?}",
                backend.take_failure()
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Run to a breakpoint at `site`, then take the breakpoint out.
fn stop_at(prog: &mut Prog, site: u64, seconds: u64) -> Result<StopEvent, String> {
    prog.dbg.set_breakpoint(site, 1).map_err(text)?;
    let event = prog.go(seconds)?;
    if !matches!(event.kind, StopKind::Breakpoint { addr } if addr == site) {
        return Err(format!("stopped as {:?} at {:#x}", event.kind, event.pc));
    }
    prog.dbg.clear_breakpoint(site, 1).map_err(text)?;
    Ok(event)
}

/// FF-14: the group is killed (its own timer's SIGKILL) while the debugger holds
/// it at a breakpoint; Continue must not touch the dead threads' registers.
pub fn killed_stop(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("killtimer", 3000, 0, None)?;
    prog.stop()?;
    let site = prog.sym("parent_site")?;
    prog.dbg.set_breakpoint(site, 1).map_err(text)?;
    let event = prog.go(10)?;
    if !matches!(event.kind, StopKind::Breakpoint { addr } if addr == site) {
        return Err(format!("stopped as {:?}", event.kind));
    }
    // The timer fires while the program is stopped.
    thread::sleep(Duration::from_secs(4));
    let resumed = prog.dbg.resume(ResumeAction::Continue);
    let state = settle(&mut prog.dbg, 15)?;
    let status = match state {
        TargetState::Exited { wait_status } => wait_status,
        other => return Err(format!("after Continue the killed group is {other:?}")),
    };
    if status & 0x7f != 9 {
        return Err(format!("the group ended with {status:#x}, not SIGKILL"));
    }
    run_ended(&mut context.driver, &prog.launched.run.id, 30)?;
    prog.kids.clear();
    drop(prog);
    kernel_log_clean(context)?;
    engine_alive(context)?;
    kernel_log_clean(context)?;
    Ok(format!(
        "a group SIGKILLed at a breakpoint stop reads as exited ({status:#x}); Continue ({}) did not oops the engine, which attaches again",
        match resumed {
            Ok(()) => "accepted".to_string(),
            Err(error) => format!("refused: {error}"),
        }
    ))
}

/// FF-15: a thread steps its own exit system call. Five times, since the step's
/// end races the exiting thread's stack being freed.
pub fn exit_step(context: &mut Context) -> Result<String, String> {
    let mut outcomes = Vec::new();
    for round in 0..5 {
        println!("exit-step round {round}");
        let mut prog = context.start("exitstep", 400, 0, None)?;
        prog.stop()?;
        let site = prog.sym("exit_syscall")?;
        let event = stop_at(&mut prog, site, 15)?;
        prog.dbg
            .resume(ResumeAction::Step { tid: event.tid })
            .map_err(text)?;
        let state = settle(&mut prog.dbg, 15)?;
        if matches!(state, TargetState::Running) {
            prog.stop()?;
        }
        let threads = prog.dbg.threads().map_err(text)?;
        if threads.iter().any(|thread| thread.tid == event.tid) {
            return Err(format!(
                "the thread that exited is still listed: {threads:?}"
            ));
        }
        outcomes.push(match state {
            TargetState::Running => "ran on".to_string(),
            TargetState::Stopped(stop) => format!("{:?}", stop.kind),
            other => format!("{other:?}"),
        });
        context.finish(prog)?;
        kernel_log_clean(context)?;
    }
    Ok(format!(
        "a thread that stepped its exit system call left cleanly 5 times (after the step: {}), no kernel report",
        outcomes.join(", ")
    ))
}

/// FF-16: stepping a vfork the debugger follows stops the parent in the kernel
/// at once (VFORK), instead of the engine's worker waiting for the child;
/// stepping a call that blocks lets the group run until it returns, and DETACH
/// with kill is taken while the step is under way.
pub fn blocking_steps(context: &mut Context) -> Result<String, String> {
    // (a) A followed vfork.
    let mut prog = context.start("vforkstep", 8, 0, Some(follow()))?;
    let site = prog.sym("vfork_syscall")?;
    let event = stop_at(&mut prog, site, 15)?;
    let started = Instant::now();
    prog.dbg
        .resume(ResumeAction::Step { tid: event.tid })
        .map_err(text)?;
    let stop = wait_for(&mut prog.dbg, 10)?;
    let child = match stop.kind {
        StopKind::Vfork { child } => child,
        other => return Err(format!("the stepped vfork stopped as {other:?}")),
    };
    let took = started.elapsed().as_millis();
    if !child.shared_memory {
        return Err("a vfork child (CLONE_VM) reported without shared memory".into());
    }
    let mut kid = prog
        .dbg
        .adopt_child(&child)
        .map_err(|e| format!("adopt: {e}"))?;
    wait_for(kid.as_mut(), 10)?;
    kid.detach(DetachMode::Resume).map_err(text)?;
    let next = prog.go(15)?;
    if !matches!(next.kind, StopKind::VforkDone { .. }) {
        return Err(format!(
            "after the child let go the parent stopped as {:?}",
            next.kind
        ));
    }
    prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
    if let Err(error) = context.wait_output(&prog, "vfork child exit=5", 15) {
        return Err(format!(
            "{error}\nthe parent is {:?}, threads {:?}",
            prog.dbg.state(),
            prog.dbg.threads()
        ));
    }
    context.wait_output(&prog, "done", 15)?;
    context.finish(prog)?;

    // (b) A call that blocks: DETACH with kill while the step is under way.
    let mut prog = context.start("pausestep", 8, 0, None)?;
    prog.stop()?;
    let site = prog.sym("pause_syscall")?;
    let event = stop_at(&mut prog, site, 15)?;
    prog.dbg
        .resume(ResumeAction::Step { tid: event.tid })
        .map_err(text)?;
    prog.dbg
        .detach(DetachMode::Kill)
        .map_err(|e| format!("DETACH with kill during a step: {e}"))?;
    run_ended(&mut context.driver, &prog.launched.run.id, 30)?;
    prog.kids.clear();
    drop(prog);

    // (c) The same step left alone: the group runs while the call blocks, and
    // a stop request ends it.
    let mut prog = context.start("pausestep", 8, 0, None)?;
    prog.stop()?;
    let site = prog.sym("pause_syscall")?;
    let event = stop_at(&mut prog, site, 15)?;
    prog.dbg
        .resume(ResumeAction::Step { tid: event.tid })
        .map_err(text)?;
    thread::sleep(Duration::from_millis(3500));
    let state = settle(&mut prog.dbg, 10)?;
    if state != TargetState::Running {
        return Err(format!(
            "3.5 s into a step of pause() the group is {state:?}, not running"
        ));
    }
    let stopped = prog.stop()?;
    context.finish(prog)?;
    kernel_log_clean(context)?;
    engine_alive(context)?;
    Ok(format!(
        "a stepped vfork stopped as VFORK in {took} ms (child shared, adopted and let go, then VFORK_DONE, the program finished); DETACH with kill was taken during a step of pause(); a step of pause() left the group running after 3.5 s and a stop ended it ({:?})",
        stopped.kind
    ))
}

/// FF-21: clone(CLONE_VFORK) without CLONE_VM gives the child its own memory.
pub fn vfork_own_memory(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("vforknovm", 4, 0, Some(follow()))?;
    let child_site = prog.sym("child_site")?;
    prog.dbg.set_breakpoint(child_site, 1).map_err(text)?;
    let event = prog.go(15)?;
    let child = match event.kind {
        StopKind::Vfork { child } => child,
        other => return Err(format!("expected a vfork stop, got {other:?}")),
    };
    if child.shared_memory {
        return Err("a CLONE_VFORK child without CLONE_VM reported as sharing memory".into());
    }
    let mut kid = prog
        .dbg
        .adopt_child(&child)
        .map_err(|e| format!("adopt: {e}"))?;
    wait_for(kid.as_mut(), 10)?;
    if !kid.guest_breakpoints().map_err(text)?.is_empty() {
        prog.kids.push(kid);
        return Err("the child's session holds its parent's breakpoint table".into());
    }
    let code = kid.read_memory(child_site, 1).map_err(text)?;
    if code[0] == 0xcc {
        prog.kids.push(kid);
        return Err("the child's memory holds the parent's breakpoint byte".into());
    }
    kid.set_breakpoint(child_site, 1).map_err(text)?;
    let mut hits = 0;
    for _ in 0..2 {
        kid.resume(ResumeAction::Continue).map_err(text)?;
        let stop = wait_for(kid.as_mut(), 15)?;
        if !matches!(stop.kind, StopKind::Breakpoint { addr } if addr == child_site) {
            prog.kids.push(kid);
            return Err(format!("the child stopped as {:?}", stop.kind));
        }
        hits += 1;
    }
    kid.clear_breakpoint(child_site, 1).map_err(text)?;
    kid.resume(ResumeAction::Continue).map_err(text)?;
    let status = wait_exit(kid.as_mut(), 15)?;
    if status >> 8 != 7 {
        prog.kids.push(kid);
        return Err(format!("the child exited with {status:#x}"));
    }
    let _ = kid.detach(DetachMode::Resume);
    prog.dbg.clear_breakpoint(child_site, 1).map_err(text)?;
    // The parent's vfork returned while its session was stopped: that is the
    // next stop, then it goes on.
    let done = prog.go(15)?;
    if !matches!(done.kind, StopKind::VforkDone { .. }) {
        return Err(format!(
            "the parent stopped as {:?}, wanted VFORK_DONE",
            done.kind
        ));
    }
    prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
    context.wait_output(&prog, "child exit=7 sig=0", 15)?;
    context.finish(prog)?;
    Ok(format!(
        "a CLONE_VFORK child without CLONE_VM has its own memory (no shared flag, no inherited table or byte), hit its own breakpoint {hits} times and exited 7"
    ))
}
