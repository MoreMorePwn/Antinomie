// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Engine-level phase 3 tests through the `DebugBackend` trait: following fork,
//! vfork and exec, non-stop, hardware breakpoints in new threads, re-adopting a
//! session, and the SIGCHLD that made `forkbp` flaky.
use super::*;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn expect_fork(event: &StopEvent) -> Result<ChildRef, String> {
    match event.kind {
        StopKind::Fork { child } | StopKind::Vfork { child } => Ok(child),
        other => Err(format!(
            "expected a fork stop, got {other:?} at {:#x}",
            event.pc
        )),
    }
}

/// A followed child, adopted and stopped before its first instruction after the
/// fork.
fn adopt_kid(prog: &mut Prog, child: &ChildRef) -> Result<Box<dyn DebugBackend>, String> {
    let mut kid = prog
        .dbg
        .adopt_child(child)
        .map_err(|e| format!("adopt: {e}"))?;
    let event = wait_for(kid.as_mut(), 10)?;
    if event.tid != child.tgid {
        return Err(format!(
            "the child's first stop is thread {} not {}",
            event.tid, child.tgid
        ));
    }
    Ok(kid)
}

fn rax(regs: &[u8]) -> u64 {
    u64_of(regs, RAX)
}

fn regs_of(backend: &mut dyn DebugBackend, tid: u32) -> Result<Vec<u8>, String> {
    backend
        .read_regset(tid, amd64::NT_PRSTATUS)
        .map(|blob| blob.data)
        .map_err(text)
}

/// Resume a backend and wait for its next stop.
fn resume_wait(backend: &mut dyn DebugBackend, seconds: u64) -> Result<StopEvent, String> {
    backend.resume(ResumeAction::Continue).map_err(text)?;
    wait_for(backend, seconds)
}

/// fork: the parent stops at the fork, the child is held parked at its start.
/// Follow the child (parent detached), follow the parent (child detached), and
/// hold both.
pub fn fork_follow(context: &mut Context) -> Result<String, String> {
    // (a) Follow the child, let the parent go.
    let mut prog = context.start("fork", 60, 0, Some(follow()))?;
    let (child_site, parent_site) = (prog.sym("child_site")?, prog.sym("parent_site")?);
    prog.dbg.set_breakpoint(child_site, 1).map_err(text)?;
    let event = prog.go(20)?;
    let child = expect_fork(&event)?;
    if child.shared_memory || child.tgid == 0 {
        return Err(format!("a fork child {child:?}"));
    }
    let parent_regs = prog.regs(event.tid)?;
    if rax(&parent_regs) != u64::from(child.tgid) {
        return Err(format!(
            "the parent's fork returned {} for child {}",
            rax(&parent_regs),
            child.tgid
        ));
    }
    let mut kid = adopt_kid(&mut prog, &child)?;
    let kid_regs = regs_of(kid.as_mut(), child.tgid)?;
    if rax(&kid_regs) != 0 || u64_of(&kid_regs, RIP) != event.pc {
        return Err(format!(
            "the child starts with rax {} at {:#x}, the parent is at {:#x}",
            rax(&kid_regs),
            u64_of(&kid_regs, RIP),
            event.pc
        ));
    }
    if !kid.guest_breakpoints().map_err(text)?.is_empty() {
        return Err("the child still holds the breakpoints it inherited".into());
    }
    let code = kid.read_memory(child_site, 1).map_err(text)?;
    if code[0] == 0xcc {
        return Err("the child's memory holds the parent's breakpoint byte".into());
    }
    prog.dbg.detach(DetachMode::Resume).map_err(text)?;
    kid.set_breakpoint(child_site, 1).map_err(text)?;
    let mut hits = 0;
    for _ in 0..2 {
        let stop = resume_wait(kid.as_mut(), 15)?;
        if !matches!(stop.kind, StopKind::Breakpoint { addr } if addr == child_site) {
            return Err(format!("the child stopped as {:?}", stop.kind));
        }
        hits += 1;
    }
    kid.resume(ResumeAction::Continue).map_err(text)?;
    let status = wait_exit(kid.as_mut(), 15)?;
    if status >> 8 != 7 {
        return Err(format!("the child exited with status {status:#x}"));
    }
    context.wait_output(&prog, "child exit=7 sig=0", 15)?;
    let _ = kid.detach(DetachMode::Resume);
    prog.kids.clear();
    context.driver.command(Command::StopRun {
        run_id: prog.launched.run.id.clone(),
    })?;
    run_ended(&mut context.driver, &prog.launched.run.id, 30)?;
    drop(prog);

    // (b) Follow the parent, let the child go.
    let mut prog = context.start("fork", 60, 0, Some(follow()))?;
    prog.dbg.set_breakpoint(child_site, 1).map_err(text)?;
    prog.dbg.set_breakpoint(parent_site, 1).map_err(text)?;
    let mut forks = 0;
    let mut parent_hits = 0;
    let mut action = ResumeAction::Continue;
    for _ in 0..40 {
        prog.dbg.resume(action).map_err(text)?;
        let event = wait_for(&mut prog.dbg, 20)?;
        action = ResumeAction::Continue;
        match event.kind {
            StopKind::Fork { child } => {
                let mut kid = adopt_kid(&mut prog, &child)?;
                kid.detach(DetachMode::Resume).map_err(text)?;
                forks += 1;
            }
            StopKind::Breakpoint { addr } if addr == parent_site => parent_hits += 1,
            // A detached child's exit can deliver SIGCHLD between forks.
            // Preserve that delivery, as the standalone signal test does.
            StopKind::Signal { signal: 17 } => {
                action = ResumeAction::ContinueSignal {
                    tid: event.tid,
                    signal: 17,
                };
            }
            other => return Err(format!("the parent stopped as {other:?}")),
        }
        if forks == 2 {
            break;
        }
    }
    if forks < 2 {
        return Err(format!("{forks} forks in 40 stops"));
    }
    prog.dbg.clear_breakpoint(parent_site, 1).map_err(text)?;
    prog.dbg.clear_breakpoint(child_site, 1).map_err(text)?;
    prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
    context.wait_output(&prog, "child exit=7 sig=0", 15)?;
    let output = context.output(&prog);
    if output.contains("sig=5") || output.contains("sig=11") {
        return Err(format!(
            "a detached child died of a signal:\n{}",
            tail(&output, 400)
        ));
    }
    context.finish(prog)?;

    // (c) Hold both: the child stays where the fork put it.
    let mut prog = context.start("fork", 60, 0, Some(follow()))?;
    let event = prog.go(20)?;
    let child = expect_fork(&event)?;
    let mut kid = adopt_kid(&mut prog, &child)?;
    prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
    thread::sleep(Duration::from_millis(600));
    let state = kid.state().map_err(text);
    let printed = context.output(&prog);
    if !matches!(state, Ok(TargetState::Stopped(_))) {
        prog.kids.push(kid);
        return Err(format!("the held child ran: {state:?}"));
    }
    // (A child that forked before the debugger was attached ran free and printed.)
    let mine = format!("child pid={}", child.tgid);
    if printed.contains(&mine) {
        prog.kids.push(kid);
        return Err(format!("a held child printed:\n{}", tail(&printed, 300)));
    }
    kid.resume(ResumeAction::Continue).map_err(text)?;
    context.wait_output(&prog, &mine, 15)?;
    context.wait_output(&prog, "child exit=7", 15)?;
    prog.kids.push(kid);
    context.finish(prog)?;
    Ok(format!(
        "the parent stops at fork with the child's identity; the child starts at the fork point (rax 0, no inherited breakpoint bytes); followed child hit its breakpoint {hits} times and exited 7; {forks} children detached ran clean, {parent_hits} parent hits; a held child stays stopped"
    ))
}

/// vfork: the parent is stopped in the kernel, the child shares its memory until
/// it execs.
pub fn vfork_follow(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("vfork", 60, 0, Some(follow()))?;
    let leaf_site = prog.sym("leaf_site")?;
    let event = prog.go(20)?;
    let child = match event.kind {
        StopKind::Vfork { child } => child,
        other => return Err(format!("expected a vfork stop, got {other:?}")),
    };
    if !child.shared_memory {
        return Err("a vfork child reported without shared memory".into());
    }
    let threads = prog.dbg.threads().map_err(text)?;
    let sleeper = threads
        .iter()
        .find(|thread| thread.tid == event.tid)
        .ok_or("the vforking thread is not listed")?;
    if !sleeper.stopped || !sleeper.vfork_wait {
        return Err(format!("the vforking thread is {sleeper:?}"));
    }
    let mut kid = adopt_kid(&mut prog, &child)?;
    let parent_view = prog.dbg.read_memory(leaf_site, 8).map_err(text)?;
    let child_view = kid.read_memory(leaf_site, 8).map_err(text)?;
    if parent_view != child_view {
        return Err("the vfork child does not see its parent's memory".into());
    }
    // A breakpoint set through the child is the parent's too: one shared table.
    kid.set_breakpoint(leaf_site, 1).map_err(text)?;
    if !prog
        .dbg
        .guest_breakpoints()
        .map_err(text)?
        .iter()
        .any(|held| held.addr == leaf_site)
    {
        return Err("the parent's table lacks the child's breakpoint".into());
    }
    kid.clear_breakpoint(leaf_site, 1).map_err(text)?;
    // Let the child run to its exec; the parent is let go (not followed).
    let stop = resume_wait(kid.as_mut(), 15)?;
    if stop.kind != StopKind::Exec {
        return Err(format!(
            "the child stopped as {:?}, wanted its exec",
            stop.kind
        ));
    }
    let path = kid.exec_path().ok_or("no exec path")?;
    if path != "/tmp/p3fix" {
        return Err(format!("the exec path is {path:?}"));
    }
    prog.dbg.detach(DetachMode::Resume).map_err(text)?;
    kid.set_breakpoint(leaf_site, 1).map_err(text)?;
    let stop = resume_wait(kid.as_mut(), 15)?;
    if !matches!(stop.kind, StopKind::Breakpoint { addr } if addr == leaf_site) {
        return Err(format!("the exec'd child stopped as {:?}", stop.kind));
    }
    kid.clear_breakpoint(leaf_site, 1).map_err(text)?;
    kid.resume(ResumeAction::Continue).map_err(text)?;
    let status = wait_exit(kid.as_mut(), 15)?;
    if status >> 8 != 5 {
        return Err(format!("the leaf exited with {status:#x}"));
    }
    if let Err(error) = context.wait_output(&prog, "vfork child exit=5", 8) {
        context.driver.receive();
        let run = context
            .driver
            .snapshot
            .runs
            .iter()
            .find(|run| run.id == prog.launched.run.id)
            .map(|run| format!("{:?}", run.execution));
        return Err(format!("{error}\nrun: {run:?}"));
    }
    let _ = kid.detach(DetachMode::Resume);
    prog.kids.clear();
    context.driver.command(Command::StopRun {
        run_id: prog.launched.run.id.clone(),
    })?;
    run_ended(&mut context.driver, &prog.launched.run.id, 30)?;
    drop(prog);

    // Follow the parent, let the child go: the parent reports vfork done.
    let mut prog = context.start("vfork", 60, 0, Some(follow()))?;
    let event = prog.go(20)?;
    let child = match event.kind {
        StopKind::Vfork { child } => child,
        other => return Err(format!("expected a vfork stop, got {other:?}")),
    };
    let mut kid = adopt_kid(&mut prog, &child)?;
    kid.detach(DetachMode::Resume).map_err(text)?;
    let done = prog.go(15)?;
    match done.kind {
        StopKind::VforkDone { child_tgid } if child_tgid == child.tgid => {}
        other => return Err(format!("expected vfork done, got {other:?}")),
    }
    // The stop at vfork done holds the parent; let it go and it reports the child.
    prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
    context.wait_output(&prog, "vfork child exit=5", 15)?;
    context.finish(prog)?;
    Ok("the parent stops in vfork (thread asleep, listed stopped), the child shares memory and one breakpoint table, its exec is an event with the path and drops the table, the exec'd child hits a breakpoint and exits 5; with the child detached the parent reports vfork done".into())
}

/// exec keeps the session when asked to.
pub fn exec_event(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("exec", 8, 3, Some(follow()))?;
    let (parent_site, leaf_site) = (prog.sym("parent_site")?, prog.sym("leaf_site")?);
    prog.dbg.set_breakpoint(parent_site, 1).map_err(text)?;
    prog.dbg.set_breakpoint(leaf_site, 1).map_err(text)?;
    // The breakpoint at parent_site is hit every round; run to the exec.
    let mut event;
    let mut rounds = 0;
    loop {
        event = prog.go(20)?;
        if event.kind == StopKind::Exec {
            break;
        }
        rounds += 1;
        if rounds > 20 || !matches!(event.kind, StopKind::Breakpoint { .. }) {
            return Err(format!("stopped as {:?}", event.kind));
        }
    }
    let path = prog.dbg.exec_path().ok_or("no exec path")?;
    if path != "/tmp/p3fix" {
        return Err(format!("the exec path is {path:?}"));
    }
    let pid = prog.launched.run.pid;
    if event.tid != pid {
        return Err(format!(
            "the exec'd thread is {} not the leader {pid}",
            event.tid
        ));
    }
    let threads = prog.dbg.threads().map_err(text)?;
    if threads.len() != 1 || !threads[0].stopped {
        return Err(format!("after the exec: {threads:?}"));
    }
    if !prog.dbg.guest_breakpoints().map_err(text)?.is_empty() {
        return Err("breakpoints survived the exec".into());
    }
    // The new image (a leaf): a breakpoint in it works.
    prog.dbg.set_breakpoint(leaf_site, 1).map_err(text)?;
    let mut hits = 0;
    loop {
        let stop = prog.go(15)?;
        match stop.kind {
            StopKind::Breakpoint { addr } if addr == leaf_site => hits += 1,
            other => return Err(format!("the new image stopped as {other:?}")),
        }
        if hits == 3 {
            break;
        }
    }
    prog.dbg.clear_breakpoint(leaf_site, 1).map_err(text)?;
    prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
    let status = wait_exit(&mut prog.dbg, 15)?;
    if status >> 8 != 5 {
        return Err(format!("the leaf exited with {status:#x}"));
    }
    let _ = prog.dbg.detach(DetachMode::Resume);
    Ok(format!(
        "exec of a 4-thread program was an event (path {path}, the exec'ing thread is the leader, one thread left, breakpoints dropped) and the session went on: {hits} breakpoint hits in the new image, exit 5"
    ))
}

/// Without the option an exec still ends the session, as in phase 2.
pub fn exec_legacy(context: &mut Context) -> Result<String, String> {
    // Attach to the old image before releasing its exec. A short running
    // fixture can otherwise reach the replacement image before attach finishes.
    let mut prog = context.start("exec-gated", 3, 0, None)?;
    if prog.dbg.state().map_err(text)? != TargetState::Running {
        return Err("the pre-exec fixture was not running at attach".into());
    }
    context.driver.command(Command::TerminalInput {
        run_id: prog.launched.run.id.clone(),
        data: b"g\n".to_vec(),
    })?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match prog.dbg.state().map_err(text)? {
            TargetState::Replaced => break,
            TargetState::Exited { .. } => return Err("exited".into()),
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err("the exec was not noticed".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok("without the exec option the session still ends with the address-space change".into())
}

/// Non-stop: one thread stops and the others run.
pub fn nonstop(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start(
        "nonstop",
        400,
        4,
        Some(SessionOptions {
            nonstop: true,
            ..follow()
        }),
    )?;
    let work = prog.sym("work")?;
    let counters = prog.sym("counters")?;
    prog.dbg.set_breakpoint(work, 1).map_err(text)?;
    prog.dbg
        .thread_action(None, ThreadAction::Continue { signal: 0 })
        .map_err(text)?;
    let mut seen = Vec::new();
    let mut acknowledged = 0;
    let deadline = Instant::now() + Duration::from_secs(20);
    while seen.len() < 3 {
        let batch = prog.dbg.events(acknowledged).map_err(text)?;
        for event in batch.events {
            acknowledged = acknowledged.max(event.sequence);
            if matches!(event.kind, StopKind::Breakpoint { addr } if addr == work)
                && !seen.contains(&event.tid)
            {
                seen.push(event.tid);
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("only {} threads reported: {seen:?}", seen.len()));
        }
        thread::sleep(Duration::from_millis(2));
    }
    prog.dbg.events(acknowledged).map_err(text)?;
    let threads = prog.dbg.threads().map_err(text)?;
    let stopped: Vec<u32> = threads
        .iter()
        .filter(|t| t.stopped)
        .map(|t| t.tid)
        .collect();
    let running = threads.iter().filter(|t| !t.stopped).count();
    if stopped.len() < 3 {
        return Err(format!("stopped {stopped:?} of {threads:?}"));
    }
    // Memory of the running process can be read; a stopped thread has registers.
    prog.dbg.read_memory(counters, 64).map_err(text)?;
    let regs = prog.regs(seen[0])?;
    if u64_of(&regs, RIP) != work {
        return Err(format!(
            "the stopped thread is at {:#x}, not {work:#x}",
            u64_of(&regs, RIP)
        ));
    }
    // A thread that is running has no registers to give.
    if let Some(runner) = threads.iter().find(|t| !t.stopped)
        && user_regs(&mut prog.dbg, runner.tid).is_ok()
    {
        return Err("registers of a running thread".into());
    }
    // Take the breakpoint out and run one thread; the others stay stopped.
    prog.dbg.clear_breakpoint(work, 1).map_err(text)?;
    let code = prog.dbg.read_memory(work, 1).map_err(text)?;
    if code[0] == 0xcc {
        return Err("the byte is still in after BP_CLEAR".into());
    }
    let tid = seen[0];
    let affected = prog
        .dbg
        .thread_action(Some(tid), ThreadAction::Step { signal: 0 })
        .map_err(text)?;
    if affected != 1 {
        return Err(format!("a step applied to {affected} threads"));
    }
    let step = loop {
        let batch = prog.dbg.events(acknowledged).map_err(text)?;
        if let Some(event) = batch.events.iter().find(|e| e.tid == tid) {
            acknowledged = acknowledged.max(event.sequence);
            break *event;
        }
        thread::sleep(Duration::from_millis(2));
    };
    if step.kind != StopKind::Step {
        return Err(format!("the step ended as {:?}", step.kind));
    }
    let regs = prog.regs(tid)?;
    if u64_of(&regs, EFLAGS) & 0x100 != 0 {
        return Err("TF after a step".into());
    }
    let others_still: Vec<u32> = prog
        .dbg
        .threads()
        .map_err(text)?
        .iter()
        .filter(|t| t.stopped && t.tid != tid)
        .map(|t| t.tid)
        .collect();
    if others_still.len() + 1 < stopped.len() {
        return Err("a step resumed other stopped threads".into());
    }
    // Run every thread but one: the counters of the runners move, the held one's
    // does not.
    let before = prog.dbg.read_memory(counters, 32).map_err(text)?;
    for thread in prog.dbg.threads().map_err(text)? {
        if thread.stopped && thread.tid != tid {
            prog.dbg
                .thread_action(Some(thread.tid), ThreadAction::Continue { signal: 0 })
                .map_err(text)?;
        }
    }
    thread::sleep(Duration::from_millis(300));
    let after = prog.dbg.read_memory(counters, 32).map_err(text)?;
    let slot = |data: &[u8], index: usize| u64_of(data, index * 8);
    let moved = (0..4)
        .filter(|i| slot(&after, *i) != slot(&before, *i))
        .count();
    if moved != 3 {
        return Err(format!(
            "{moved} of 4 counters moved while one thread was held (before {before:02x?}, after {after:02x?})"
        ));
    }
    let second = after;
    // Stop everything, then run everything.
    prog.dbg
        .thread_action(None, ThreadAction::Stop)
        .map_err(text)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while prog.dbg.threads().map_err(text)?.iter().any(|t| !t.stopped) {
        if Instant::now() >= deadline {
            return Err("not every thread stopped".into());
        }
        thread::sleep(Duration::from_millis(2));
    }
    let batch = prog.dbg.events(acknowledged).map_err(text)?;
    if !batch.events.iter().any(|e| e.kind == StopKind::Interrupt) {
        return Err(format!(
            "stop requests reported no event: {:?}",
            batch.events
        ));
    }
    prog.dbg
        .thread_action(None, ThreadAction::Continue { signal: 0 })
        .map_err(text)?;
    thread::sleep(Duration::from_millis(200));
    let third = prog.dbg.read_memory(counters, 64).map_err(text)?;
    if third == second {
        return Err("nothing ran after the continue".into());
    }
    prog.dbg.detach(DetachMode::Resume).map_err(text)?;
    context.wait_output(&prog, "tick 3", 15)?;
    let output = context.output(&prog);
    if output.contains("Trace/breakpoint") || output.contains("sig=5") {
        return Err("a breakpoint killed the program".into());
    }
    context.driver.command(Command::StopRun {
        run_id: prog.launched.run.id.clone(),
    })?;
    run_ended(&mut context.driver, &prog.launched.run.id, 30)?;
    Ok(format!(
        "{} threads hit a breakpoint and stopped one by one while {running} kept running; memory read with threads running, registers only of stopped ones; one thread stepped alone; stop-all and continue-all reported and worked; detach left the program running",
        seen.len()
    ))
}

/// A thread created while the group runs gets the hardware breakpoints before
/// its first instruction.
pub fn hw_new_threads(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("spawn", 400, 3, Some(follow()))?;
    let watched = prog.sym("watched")?;
    prog.dbg
        .insert_breakpoint(BreakpointKind::Watch(WatchAccess::Write), watched, 8)
        .map_err(text)?;
    let mut tids = Vec::new();
    let mut event = prog.go(20)?;
    for _ in 0..12 {
        match event.kind {
            StopKind::Watchpoint { addr, .. } if addr == watched => {
                if !tids.contains(&event.tid) {
                    tids.push(event.tid);
                }
            }
            other => return Err(format!("stopped as {other:?}")),
        }
        // No stop in between: the next thread is created while the group runs.
        event = prog.go(20)?;
    }
    if tids.len() < 8 {
        return Err(format!(
            "only {} different new threads fired: {tids:?}",
            tids.len()
        ));
    }
    prog.dbg
        .remove_breakpoint(BreakpointKind::Watch(WatchAccess::Write), watched, 8)
        .map_err(text)?;
    context.finish(prog)?;
    Ok(format!(
        "{} different threads, each created while the group ran, fired the write watchpoint on their first store",
        tids.len()
    ))
}

/// The SIGCHLD that made `forkbp` flaky: a signal that was blocked when the
/// child exited is queued, and the engine shows it to the debugger as a tracer
/// would see it; gdb passes it silently (handle SIGCHLD nostop noprint pass).
pub fn sigchld(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("chld", 400, 0, None)?;
    prog.stop()?;
    let mut seen = 0;
    for _ in 0..5 {
        let event = prog.go(20)?;
        match event.kind {
            StopKind::Signal { signal: 17 } => seen += 1,
            other => return Err(format!("stopped as {other:?}, wanted SIGCHLD")),
        }
        // Continue passing it, as gdb does for SIGCHLD.
        prog.dbg
            .resume(ResumeAction::ContinueSignal {
                tid: event.tid,
                signal: 17,
            })
            .map_err(text)?;
        thread::sleep(Duration::from_millis(100));
        prog.stop()?;
    }
    context.finish(prog)?;
    Ok(format!(
        "{seen} queued SIGCHLD stops reported (the child exited while the parent had the signal blocked, as glibc's fork leaves it for an instant), each passed on"
    ))
}

/// A session found again after the debugger that held it is gone.
pub fn readopt(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("nonstop", 600, 2, None)?;
    let work = prog.sym("work")?;
    prog.stop()?;
    prog.dbg.set_breakpoint(work, 1).map_err(text)?;
    let event = prog.go(20)?;
    if !matches!(event.kind, StopKind::Breakpoint { .. }) {
        return Err(format!("stopped as {:?}", event.kind));
    }
    let session = prog.dbg.session_id();
    let target = prog.launched.target.clone();
    let regs_before = prog.regs(event.tid)?;
    // The debugger forgets the session: its backend is gone, the guest's is not.
    let mut link = context.driver.backend.debug_link();
    let sessions = KernelDebugBackend::list_sessions(&mut link).map_err(text)?;
    let found = sessions
        .iter()
        .find(|info| info.session == session)
        .ok_or("the session is not listed")?;
    if found.tgid != target.tgid || found.task_cookie != target.task_cookie {
        return Err(format!("listed as {found:?}"));
    }
    let caps = KernelDebugBackend::probe(&mut link).map_err(text)?;
    if !caps.adopt {
        return Err("the guest does not offer adoption".into());
    }
    let attached = KernelDebugBackend::adopt_session(&mut link, caps, &target, nonce(0xad07))
        .map_err(|e| format!("adopt: {e}"))?;
    let mut again =
        KernelDebugBackend::new(Box::new(context.driver.backend.debug_link()), attached);
    let state = again.state().map_err(text)?;
    let TargetState::Stopped(stop) = state else {
        return Err(format!("the adopted session is {state:?}"));
    };
    if stop.tid != event.tid || stop.pc != event.pc {
        return Err(format!("adopted at {stop:?}, was {event:?}"));
    }
    let held = again.guest_breakpoints().map_err(text)?;
    if !held
        .iter()
        .any(|b| b.addr == work && b.kind == BreakpointKind::Software)
    {
        return Err(format!("breakpoints after adoption: {held:?}"));
    }
    if regs_of(&mut again, event.tid)? != regs_before {
        return Err("registers differ after adoption".into());
    }
    again.clear_breakpoint(work, 1).map_err(text)?;
    again.resume(ResumeAction::Continue).map_err(text)?;
    thread::sleep(Duration::from_millis(300));
    context.wait_output(&prog, "tick 2", 15)?;
    again.detach(DetachMode::Kill).map_err(text)?;
    run_ended(&mut context.driver, &prog.launched.run.id, 30)?;
    Ok("a debugger that lost its backend listed the guest's sessions, adopted its own by identity with a new nonce, saw the same stop, registers and breakpoint table, and continued it".into())
}

/// Stop of a run whose group cannot be stopped (job control holds every thread):
/// the engine takes its breakpoint bytes out anyway, so a program that outlives
/// the Stop does not find them.
pub fn stop_run_bytes(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("stopself", 40, 0, Some(follow()))?;
    let child_site = prog.sym("child_site")?;
    prog.dbg.set_breakpoint(child_site, 1).map_err(text)?;
    prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
    context.wait_output(&prog, "stopping myself", 20)?;
    thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    context.driver.command(Command::StopRun {
        run_id: prog.launched.run.id.clone(),
    })?;
    // The program was stopped by job control and ignores SIGTERM; its watchdog
    // continues it after 6 s, before the 12 s grace period ends.
    let waited = context.wait_output(&prog, "child_site survived", 14);
    let output = context.output(&prog);
    let elapsed = started.elapsed().as_secs_f64();
    if let Err(error) = waited {
        return Err(format!(
            "the program did not live through Stop ({error}); output tail: {}",
            tail(&output, 300)
        ));
    }
    if output.contains("Trace/breakpoint") {
        return Err("a breakpoint byte killed the program".into());
    }
    let _ = prog.dbg.detach(DetachMode::Kill);
    prog.kids.clear();
    run_ended(&mut context.driver, &prog.launched.run.id, 30)?;
    Ok(format!(
        "Stop reached a group job control held (no thread could park, the debugger gave up after its 3 s): the engine's breakpoint byte was taken out anyway and the program called the breakpointed function {elapsed:.1} s after Stop without a trap"
    ))
}

/// Stops at random moments of a program that forks every few rounds: every fork
/// is reported exactly once (a fork that was cut by the stop is reported when the
/// debugger resumes), and the event's pc is where the thread really is.
pub fn fork_stress(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("fork", 1_000_000, 0, Some(follow()))?;
    let mut forks = 0u32;
    let mut stops = 0u32;
    let mut seed = 0x9e37_79b9u32;
    let started = Instant::now();
    // A signal gdb's table passes silently, owed to the next resume.
    let mut owed: Option<(u32, u32)> = None;
    let mut seen = std::collections::BTreeSet::new();
    while started.elapsed() < Duration::from_secs(14) {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let action = match owed.take() {
            Some((tid, signal)) => ResumeAction::ContinueSignal { tid, signal },
            None => ResumeAction::Continue,
        };
        prog.dbg.resume(action).map_err(text)?;
        thread::sleep(Duration::from_millis(5 + u64::from(seed >> 24) % 70));
        prog.dbg.interrupt().map_err(text)?;
        // Whatever stops the program first answers the request: the interrupt, or
        // an event that was in flight (a fork that was cut by the request is
        // reported when the debugger resumes, exactly once).
        let event = wait_state(&mut prog.dbg, 15)?;
        stops += 1;
        if std::env::var_os("P3_TRACE").is_some() {
            eprintln!(
                "stress stop {stops}: {:?} tid {} pc {:#x}",
                event.kind, event.tid, event.pc
            );
        }
        let regs = prog.regs(event.tid)?;
        if u64_of(&regs, RIP) != event.pc && !matches!(event.kind, StopKind::Interrupt) {
            return Err(format!(
                "{:?}: the event says pc {:#x}, the thread is at {:#x}",
                event.kind,
                event.pc,
                u64_of(&regs, RIP)
            ));
        }
        match event.kind {
            StopKind::Fork { child } => {
                forks += 1;
                if !seen.insert(child.tgid) {
                    return Err(format!(
                        "the fork of child {} was reported twice",
                        child.tgid
                    ));
                }
                let mut kid = adopt_kid(&mut prog, &child)?;
                kid.detach(DetachMode::Resume).map_err(text)?;
            }
            StopKind::Interrupt => {}
            // glibc blocks signals around fork: a quick child leaves a queued
            // SIGCHLD, which gdb's table passes silently.
            StopKind::Signal { signal }
                if u8::try_from(signal).is_ok_and(|n| {
                    !antinomie_monitor_core::debug::signal_policy::default_action(n).stop
                }) =>
            {
                owed = Some((event.tid, signal));
            }
            other => return Err(format!("stopped as {other:?}")),
        }
    }
    prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
    thread::sleep(Duration::from_millis(600));
    let output = context.output(&prog);
    // The guest's terminal keeps only its tail; some children must have ended.
    let reaped = output.matches("child exit=7").count();
    if forks < 10 || reaped == 0 {
        return Err(format!(
            "{forks} forks seen, {reaped} children reaped in the tail"
        ));
    }
    context.finish(prog)?;
    Ok(format!(
        "{stops} stops at random moments, {forks} forks reported (each child exactly once, children ran on and exited), event pcs matched the threads"
    ))
}
