// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The 0.9.0 bug hunt's low debug engine findings (ANT-T0582, guest patches
//! 0099 to 0103): a forked child no session can follow (KDBG-1, residual), a
//! stop asked for while a continue is under way (KDBG-6), io_uring's workers
//! under a stop (KDBG-8), and the record a vfork child leaves behind when it
//! execs (KDBG-9).
use super::*;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn input(context: &mut Context, prog: &Prog, line: &str) -> Result<(), String> {
    let sent = context.driver.command(Command::TerminalInput {
        run_id: prog.launched.run.id.clone(),
        data: line.as_bytes().to_vec(),
    });
    sent.map(|_| ()).map_err(|why| {
        let output = context.output(prog);
        let tail: Vec<&str> = output.lines().rev().take(6).collect();
        format!("sending {line:?}: {why}; the run's last lines: {tail:?}")
    })
}

/// The number after `name=` in a fixture line.
fn number(line: &str, name: &str) -> Option<i64> {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(name)?.strip_prefix('='))
        .and_then(|value| value.parse().ok())
}

/// The last line of the run's output that starts with `prefix`.
fn line_of(context: &mut Context, prog: &Prog, prefix: &str) -> Result<String, String> {
    context
        .output(prog)
        .lines()
        .rev()
        .find(|line| line.starts_with(prefix))
        .map(str::to_string)
        .ok_or_else(|| format!("no {prefix:?} line"))
}

fn all_stop() -> SessionOptions {
    SessionOptions {
        fork: false,
        exec: false,
        nonstop: false,
    }
}

/// A signal gdb's table passes silently (glibc's fork leaves a queued SIGCHLD).
fn passed_silently(signal: u32) -> bool {
    u8::try_from(signal)
        .is_ok_and(|n| !antinomie_monitor_core::debug::signal_policy::default_action(n).stop)
}

/// KDBG-1, residual: with the FORK option on, more children than the guest
/// has debug sessions. The children nobody can follow run on with the
/// program's own bytes and exit; none dies of the engine's breakpoint.
pub fn fork_full(context: &mut Context) -> Result<String, String> {
    const CHILDREN: u32 = 24;
    let mut prog = context.start("forkfill", CHILDREN, 0, Some(follow()))?;
    let site = prog.sym("child_site")?;
    prog.dbg.set_breakpoint(site, 1).map_err(text)?;
    prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
    input(context, &prog, "g\n")?;
    let mut forks = 0u32;
    let deadline = Instant::now() + Duration::from_secs(secs(120));
    loop {
        if context.output(&prog).contains("forkfill exits=") {
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!("forkfill did not finish ({forks} forks reported)"));
        }
        match prog.dbg.state().map_err(text)? {
            TargetState::Stopped(event) => {
                let action = match event.kind {
                    StopKind::Fork { .. } => {
                        // Left unadopted: the child stays parked in its session.
                        forks += 1;
                        ResumeAction::Continue
                    }
                    StopKind::Signal { signal } if passed_silently(signal) => {
                        ResumeAction::ContinueSignal {
                            tid: event.tid,
                            signal,
                        }
                    }
                    other => return Err(format!("stopped as {other:?}")),
                };
                prog.dbg.resume(action).map_err(text)?;
            }
            TargetState::Exited { wait_status } => {
                // It prints its counts just before it exits: the line may
                // still be on its way.
                context
                    .wait_output(&prog, "forkfill exits=", 10)
                    .map_err(|_| {
                        format!("the parent exited ({wait_status:#x}) without its counts")
                    })?;
                break;
            }
            _ => thread::sleep(Duration::from_millis(2)),
        }
    }
    let line = line_of(context, &prog, "forkfill exits=")?;
    let (exits, traps, other) = (
        number(&line, "exits").unwrap_or(-1),
        number(&line, "traps").unwrap_or(-1),
        number(&line, "other").unwrap_or(-1),
    );
    if forks == 0 || forks >= CHILDREN {
        return Err(format!(
            "{forks} of {CHILDREN} forks were reported: the session limit was not reached ({line})"
        ));
    }
    if traps != 0 || other != 0 || exits != i64::from(CHILDREN - forks) {
        return Err(format!(
            "{forks} children held in sessions, the rest ended as: {line}"
        ));
    }
    // The parent may have exited already; its detach lets the parked
    // children go (they exit 7) and the run ends.
    let _ = prog.dbg.detach(DetachMode::Kill);
    run_ended(&mut context.driver, &prog.launched.run.id, 60)?;
    Ok(format!(
        "{forks} children held in sessions, the {exits} no session could follow ran past the breakpoint and exited 7, none by SIGTRAP"
    ))
}

/// KDBG-6: STOP right after CONT, again and again; every STOP ends in a stop,
/// including those that reach the guest while the group is still being resumed.
pub fn cont_stop(context: &mut Context) -> Result<String, String> {
    const ROUNDS: u32 = 300;
    let mut prog = context.start("nonstop", 1_000_000, 2, Some(all_stop()))?;
    for round in 0..ROUNDS {
        prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
        prog.dbg.interrupt().map_err(text)?;
        let event = wait_state(&mut prog.dbg, 10)
            .map_err(|why| format!("round {round}: the STOP after a CONT was lost: {why}"))?;
        if !matches!(event.kind, StopKind::Interrupt) {
            return Err(format!("round {round}: stopped as {:?}", event.kind));
        }
    }
    context.finish(prog)?;
    Ok(format!(
        "{ROUNDS} STOPs sent right after a CONT each ended in a stop"
    ))
}

/// KDBG-8: a stop of a program whose io_uring request is blocked on an io-wq
/// worker (an OPENAT of a FIFO with no writer) leaves the request alone: it
/// completes with a descriptor when a writer comes, not with -EINTR.
pub fn uring_stop(context: &mut Context) -> Result<String, String> {
    let mut prog = context.start("uringfifo", 0, 0, None)?;
    context.wait_output(&prog, "uring waiting", 20)?;
    run_for(300);
    prog.stop()?;
    let tid = prog.launched.target.tgid;
    let threads = prog.dbg.threads().map_err(text)?;
    let listed: Vec<u32> = threads.iter().map(|t| t.tid).collect();
    if listed != [tid] {
        return Err(format!(
            "the stopped program lists threads {listed:?}, its only program thread is {tid} (an io-wq worker was taken in)"
        ));
    }
    prog.dbg.resume(ResumeAction::Continue).map_err(text)?;
    input(context, &prog, "g\n")?;
    context.wait_output(&prog, "uring openat res=", 20)?;
    let line = line_of(context, &prog, "uring openat res=")?;
    let res = number(&line, "res").ok_or_else(|| format!("no result in {line:?}"))?;
    if res < 0 {
        return Err(format!(
            "the blocked OPENAT failed with {res} after the stop ({line})"
        ));
    }
    let status = run_ended(&mut context.driver, &prog.launched.run.id, 30)?;
    if status != (WaitStatus::Exited { code: 0 }) {
        return Err(format!("the fixture ended {status:?}"));
    }
    Ok(format!(
        "a stop and continue left the io-wq worker's blocked OPENAT alone (only thread {tid} listed); it completed with descriptor {res}"
    ))
}

/// KDBG-9: a vfork child the session does not follow stops on a signal in the
/// shared memory (so it has a record there), then execs. Its new image is no
/// thread of the program: THREADS does not list it, and it runs on its own.
pub fn vfork_exec_left(context: &mut Context) -> Result<String, String> {
    const SIGUSR1: u32 = 10;
    let mut prog = context.start(
        "vforksig",
        0,
        0,
        Some(SessionOptions {
            nonstop: true,
            ..all_stop()
        }),
    )?;
    let parent = prog.launched.target.tgid;
    prog.dbg
        .thread_action(None, ThreadAction::Continue { signal: 0 })
        .map_err(text)?;
    input(context, &prog, "g\n")?;
    // The child's signal stop: only that thread parks (non-stop).
    let deadline = Instant::now() + Duration::from_secs(secs(30));
    let mut acknowledged = 0;
    let child = 'found: loop {
        let batch = prog.dbg.events(acknowledged).map_err(text)?;
        if let Some(status) = batch.exited {
            return Err(format!(
                "the fixture exited ({status:#x}) before the child's signal"
            ));
        }
        for event in batch.events {
            acknowledged = acknowledged.max(event.sequence);
            match event.kind {
                StopKind::Signal { signal } if signal == SIGUSR1 && event.tid != parent => {
                    break 'found event.tid;
                }
                StopKind::Interrupt => {}
                other => return Err(format!("thread {} stopped as {other:?}", event.tid)),
            }
        }
        if Instant::now() >= deadline {
            return Err("the vfork child's SIGUSR1 never stopped it".into());
        }
        thread::sleep(Duration::from_millis(5));
    };
    prog.dbg
        .thread_action(Some(child), ThreadAction::Continue { signal: SIGUSR1 })
        .map_err(text)?;
    context.wait_output(&prog, "leafread pid=", 30)?;
    // The record goes when the worker reaps it, right after the exec.
    let deadline = Instant::now() + Duration::from_secs(secs(10));
    loop {
        let threads = prog.dbg.threads().map_err(text)?;
        let foreign: Vec<u32> = threads
            .iter()
            .map(|t| t.tid)
            .filter(|&tid| tid != parent)
            .collect();
        if foreign.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "after its exec the vfork child {child} is still listed among the program's threads: {foreign:?}"
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
    input(context, &prog, "x\n")?;
    context.wait_output(&prog, "vfork child exit=5 sig=0", 20)?;
    let status = run_ended(&mut context.driver, &prog.launched.run.id, 30)?;
    if status != (WaitStatus::Exited { code: 0 }) {
        return Err(format!("the fixture ended {status:?}"));
    }
    Ok(format!(
        "the vfork child {child} stopped on SIGUSR1 in the shared memory, then exec'd: its new image left the program's thread list and exited 5 on its own"
    ))
}
