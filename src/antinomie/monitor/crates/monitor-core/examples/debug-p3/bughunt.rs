// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The 0.9.0 bug hunt's debug engine findings (ANT-T0584, guest patches 0094
//! to 0096): a Debug on start launch whose exec failed (KDBG-2), a program
//! that starts and ends more threads than the engine has records (KDBG-3), and
//! the image an exec leaves behind a session that does not follow it (KDBG-4).
use super::*;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn input(context: &mut Context, prog: &Prog, line: &str) -> Result<(), String> {
    context
        .driver
        .command(Command::TerminalInput {
            run_id: prog.launched.run.id.clone(),
            data: line.as_bytes().to_vec(),
        })
        .map(|_| ())
}

/// KDBG-2: Debug on start of a file the guest cannot execute leaves no session
/// behind; the next Debug on start is not refused as busy.
pub fn failed_start(context: &mut Context) -> Result<String, String> {
    context.driver.command(Command::Upload {
        source: context.dir.join("p3fix"),
        destination: "/tmp/p3noexec".into(),
        overwrite: true,
        executable: false,
    })?;
    let refused = context.driver.command(Command::Execute(ExecRequest {
        path: "/tmp/p3noexec".into(),
        args: vec!["leaf".into()],
        uid: 0,
        gid: 0,
        debug_on_start: true,
        ..Default::default()
    }));
    let why = match refused {
        Ok(message) => return Err(format!("a file without an execute bit started: {message}")),
        Err(why) => why,
    };
    // The guest (patch 0094), or the host for an older base, ended the
    // session made for the launch.
    let mut link = context.driver.backend.debug_link();
    let left = KernelDebugBackend::list_sessions(&mut link).map_err(text)?;
    if let Some(session) = left
        .iter()
        .find(|session| session.child_pending && session.parent_session == 0)
    {
        return Err(format!("the failed launch left a session: {session:?}"));
    }
    let launched = launch_program(&mut context.driver, "/tmp/p3fix", vec!["leaf".into()], true)?;
    if context.driver.snapshot.debug.is_none() {
        return Err("the second Debug on start left no debugger session".into());
    }
    context
        .driver
        .command(Command::DebugDetach { kill: true })?;
    run_ended(&mut context.driver, &launched.run.id, 40)?;
    Ok(format!(
        "the launch was refused ({why}) with no session left in the guest ({} listed); the next Debug on start stopped its program",
        left.len()
    ))
}

/// The fixture's threads that call churn_site (thread 1100, past the engine's
/// 1024 records, then every 100th).
fn churn_hits(threads: u32) -> Vec<u32> {
    (1100..threads).step_by(100).collect()
}

/// KDBG-3, all-stop: 2000 threads start and end while the group runs with a
/// breakpoint in place; the threads past the 1024th still stop at it.
pub fn thread_churn(context: &mut Context) -> Result<String, String> {
    const THREADS: u32 = 2000;
    let mut prog = context.start("churn", THREADS, 0, None)?;
    context.wait_output(&prog, "churn ready", 20)?;
    let site = prog.sym("churn_site")?;
    prog.stop()?;
    prog.dbg.set_breakpoint(site, 1).map_err(text)?;
    prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
    input(context, &prog, "g\n")?;
    let mut tids = Vec::new();
    for index in churn_hits(THREADS) {
        let event = wait_for(&mut prog.dbg, 120)?;
        if !matches!(event.kind, StopKind::Breakpoint { addr } if addr == site) || event.pc != site
        {
            return Err(format!(
                "thread {index} stopped as {:?} at {:#x}",
                event.kind, event.pc
            ));
        }
        if tids.contains(&event.tid) {
            return Err(format!("thread {} stopped twice", event.tid));
        }
        tids.push(event.tid);
        prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
        context.wait_output(&prog, &format!("churn joined {index}"), 60)?;
        input(context, &prog, "g\n")?;
    }
    context.wait_output(&prog, &format!("churn done {THREADS}"), 120)?;
    let status = run_ended(&mut context.driver, &prog.launched.run.id, 60)?;
    if status != (WaitStatus::Exited { code: 0 }) {
        return Err(format!("the fixture ended {status:?}"));
    }
    Ok(format!(
        "{THREADS} threads started and ended under one session; the {} that reached the breakpoint (from the 1100th on) each stopped there, none died of SIGTRAP",
        tids.len()
    ))
}

/// KDBG-3, non-stop: no stop ever reaps the records of the group, so only
/// the engine's own reaping keeps a record for each new thread.
pub fn thread_churn_nonstop(context: &mut Context) -> Result<String, String> {
    const THREADS: u32 = 2000;
    let mut prog = context.start(
        "churn",
        THREADS,
        0,
        Some(SessionOptions {
            nonstop: true,
            ..follow()
        }),
    )?;
    context.wait_output(&prog, "churn ready", 20)?;
    let site = prog.sym("churn_site")?;
    prog.dbg.set_breakpoint(site, 1).map_err(text)?;
    prog.dbg
        .thread_action(None, ThreadAction::Continue { signal: 0 })
        .map_err(text)?;
    input(context, &prog, "g\n")?;
    let mut tids = Vec::new();
    let mut acknowledged = 0;
    for index in churn_hits(THREADS) {
        let deadline = Instant::now() + Duration::from_secs(secs(120));
        let tid = 'found: loop {
            let batch = prog.dbg.events(acknowledged).map_err(text)?;
            if let Some(status) = batch.exited {
                return Err(format!(
                    "the fixture exited ({status:#x}) before thread {index}"
                ));
            }
            for event in batch.events {
                acknowledged = acknowledged.max(event.sequence);
                match event.kind {
                    StopKind::Breakpoint { addr } if addr == site && !tids.contains(&event.tid) => {
                        break 'found event.tid;
                    }
                    StopKind::Breakpoint { .. } | StopKind::Interrupt => {}
                    other => return Err(format!("thread {} stopped as {other:?}", event.tid)),
                }
            }
            if Instant::now() >= deadline {
                return Err(format!("thread {index} never stopped at the breakpoint"));
            }
            thread::sleep(Duration::from_millis(2));
        };
        tids.push(tid);
        // The byte stays in memory in non-stop: out while the thread runs on,
        // in again before the next thread is started.
        prog.dbg.clear_breakpoint(site, 1).map_err(text)?;
        prog.dbg
            .thread_action(Some(tid), ThreadAction::Continue { signal: 0 })
            .map_err(text)?;
        context.wait_output(&prog, &format!("churn joined {index}"), 60)?;
        prog.dbg.set_breakpoint(site, 1).map_err(text)?;
        input(context, &prog, "g\n")?;
    }
    context.wait_output(&prog, &format!("churn done {THREADS}"), 120)?;
    let status = run_ended(&mut context.driver, &prog.launched.run.id, 60)?;
    if status != (WaitStatus::Exited { code: 0 }) {
        return Err(format!("the fixture ended {status:?}"));
    }
    Ok(format!(
        "non-stop: {THREADS} threads started and ended, the {} that reached the breakpoint each stopped alone, none died of SIGTRAP",
        tids.len()
    ))
}

/// KDBG-4: a session without the exec option ends at the program's exec; the
/// new image's handled SIGCHLD is delivered with no detach, and its run ends.
pub fn exec_signal(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("exec-chld", 0, 0, None)?;
    if prog.dbg.state().map_err(text)? != TargetState::Running {
        return Err("the pre-exec fixture was not running at attach".into());
    }
    input(context, &prog, "g\n")?;
    let deadline = Instant::now() + Duration::from_secs(secs(20));
    loop {
        match prog.dbg.state().map_err(text)? {
            TargetState::Replaced => break,
            TargetState::Exited { .. } => return Err("exited before the exec was noticed".into()),
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err("the exec was not noticed".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    // No detach: the session is over, the new image must not wait for one.
    context.wait_output(&prog, "leafchld reaped", 30)?;
    let status = run_ended(&mut context.driver, &prog.launched.run.id, 30)?;
    if status != (WaitStatus::Exited { code: 5 }) {
        return Err(format!("the new image ended {status:?}"));
    }
    match prog.dbg.state().map_err(text)? {
        TargetState::Replaced => {}
        other => return Err(format!("the session reads {other:?} after the run ended")),
    }
    Ok("after an exec the session does not follow, the new image's SIGCHLD reached its handler with no detach and the run ended (exit 5)".into())
}
