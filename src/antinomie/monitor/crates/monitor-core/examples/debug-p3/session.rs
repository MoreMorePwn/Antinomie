// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Phase 3 at the app level: a debugger session through a transport reconnect and
//! through a VM snapshot. The app's panel controller owns the session; the test
//! drives it the way the panel does (`Command::DebugUi`) and reads the view.
use super::*;
use antinomie_monitor_core::{
    SnapshotRequest, VmSnapshotMode,
    debug::view::{DebugAction, DebugRequest, DebugView, RunState, StopReason},
};
use std::sync::Arc;

struct Panel {
    next: u64,
}
impl Panel {
    fn view(driver: &mut Driver) -> Option<Arc<DebugView>> {
        driver.receive();
        driver.snapshot.debug_view.clone()
    }
    fn wait(
        driver: &mut Driver,
        what: &str,
        seconds: u64,
        done: impl Fn(&DebugView) -> bool,
    ) -> Result<Arc<DebugView>, String> {
        let until = Instant::now() + Duration::from_secs(seconds);
        loop {
            if let Some(view) = Self::view(driver)
                && done(&view)
            {
                return Ok(view);
            }
            if Instant::now() >= until {
                return Err(format!(
                    "the panel never showed {what}: {:?}",
                    Self::view(driver).map(|view| (view.run.clone(), view.notice.clone()))
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn send(&mut self, driver: &mut Driver, action: DebugAction) -> Result<(), String> {
        let sequence = Self::view(driver)
            .and_then(|view| view.run.stopped_sequence())
            .unwrap_or(0);
        self.next += 1;
        let id = self.next;
        // A panel request has no command result; the view's `handled` answers it.
        driver.backend.send(Command::DebugUi(DebugRequest {
            id,
            sequence,
            action,
        }))?;
        Self::wait(driver, "the request handled", 20, |view| view.handled >= id).map(|_| ())
    }
    fn stopped_at_breakpoint(driver: &mut Driver, addr: u64) -> Result<Arc<DebugView>, String> {
        Self::wait(driver, "a breakpoint stop", 40, |view| {
            matches!(
                view.run,
                RunState::Stopped {
                    reason: StopReason::Breakpoint { addr: hit, .. },
                    ..
                } if hit == addr
            ) && !view.loading
        })
    }
}

struct Attached {
    run: String,
    work: u64,
    panel: Panel,
}

/// A threaded fixture with the panel stopped at a breakpoint in `work`.
fn stopped_at_work(context: &mut Context) -> Result<Attached, String> {
    let launched = launch_program(
        &mut context.driver,
        "/tmp/p3fix",
        vec!["nonstop".into(), "900".into(), "2".into()],
        false,
    )?;
    let work = parse_symbols(&launched.symbols)
        .get("work")
        .copied()
        .ok_or("no work symbol")?;
    attach(&mut context.driver, &launched.target)?;
    let mut panel = Panel { next: 0 };
    Panel::wait(&mut context.driver, "the first view", 20, |view| {
        matches!(view.run, RunState::Running { .. })
    })?;
    panel.send(&mut context.driver, DebugAction::Stop)?;
    Panel::wait(&mut context.driver, "a stop", 20, |view| {
        view.run.stopped_sequence().is_some() && !view.loading
    })?;
    panel.send(
        &mut context.driver,
        DebugAction::AddBreakpoint {
            addr: work,
            kind: antinomie_monitor_core::debug::BreakpointKind::Software,
        },
    )?;
    panel.send(&mut context.driver, DebugAction::Continue)?;
    Panel::stopped_at_breakpoint(&mut context.driver, work)?;
    Ok(Attached {
        run: launched.run.id,
        work,
        panel,
    })
}

fn finish(context: &mut Context, attached: &Attached) -> Result<(), String> {
    let _ = context.driver.command(Command::DebugDetach { kill: true });
    // The kill above may have ended it already.
    let _ = context.driver.command(Command::StopRun {
        run_id: attached.run.clone(),
    });
    run_ended(&mut context.driver, &attached.run, 40).map(|_| ())
}

/// A transport reconnect keeps the debug session: the process stays stopped at its
/// breakpoint, the panel reads the state again, and the breakpoint still fires.
pub fn reconnect(context: &mut Context) -> Result<String, String> {
    let mut attached = stopped_at_work(context)?;
    let before = Panel::view(&mut context.driver).ok_or("no view")?;
    let (RunState::Stopped { tid, pc, .. }, breakpoints) =
        (before.run.clone(), before.breakpoints.len())
    else {
        return Err("not stopped".into());
    };
    context.driver.command(Command::ReconnectTransport)?;
    // The panel reads the guest again and finds the same stop.
    let after = Panel::wait(
        &mut context.driver,
        "the same stop after the reconnect",
        40,
        |view| {
            matches!(view.run, RunState::Stopped { tid: t, pc: p, .. } if t == tid && p == pc)
                && !view.loading
                && view.registers.is_some()
        },
    )?;
    if after.breakpoints.len() != breakpoints {
        return Err(format!(
            "breakpoints after the reconnect: {:?}",
            after.breakpoints
        ));
    }
    if context.driver.snapshot.debug.is_none() {
        return Err("the reconnect dropped the debug session".into());
    }
    // And it still works: continue to the next hit.
    attached
        .panel
        .send(&mut context.driver, DebugAction::Continue)?;
    Panel::stopped_at_breakpoint(&mut context.driver, attached.work)?;
    finish(context, &attached)?;
    Ok("a transport reconnect kept the debug session: the panel read the same stop (thread, pc, registers), the breakpoint list was intact and the breakpoint fired again after a continue".into())
}

fn vm_id(context: &Context) -> Result<String, String> {
    context
        .driver
        .snapshot
        .vms
        .first()
        .map(|vm| vm.id.clone())
        .ok_or_else(|| "no VM".to_string())
}

fn take_full_snapshot(context: &mut Context, name: &str) -> Result<String, String> {
    let id = vm_id(context)?;
    context.driver.command(Command::CreateVmSnapshot {
        vm_id: id.clone(),
        request: SnapshotRequest {
            name: name.into(),
            description: String::new(),
            mode: VmSnapshotMode::Full,
        },
    })?;
    context
        .driver
        .wait("snapshot publication", 120, |snapshot| {
            snapshot
                .vm_snapshot_trees
                .get(&id)
                .is_some_and(|tree| tree.nodes.iter().any(|node| node.name == name))
        })?;
    context
        .driver
        .snapshot
        .vm_snapshot_trees
        .get(&id)
        .and_then(|tree| tree.nodes.iter().find(|node| node.name == name))
        .map(|node| node.id.clone())
        .ok_or_else(|| "snapshot missing".to_string())
}

fn restore(context: &mut Context, snapshot_id: String) -> Result<(), String> {
    let id = vm_id(context)?;
    context.driver.command(Command::RestoreVmSnapshot {
        vm_id: id,
        snapshot_id,
        boot_from_disk: false,
        save_current: None,
        confirmed: true,
    })?;
    context.driver.wait("the restored guest", 120, |snapshot| {
        snapshot.state == antinomie_monitor_core::VmState::Running
    })
}

/// A VM snapshot is allowed while a debugger is attached. Restoring it brings the
/// guest back to the stop: the same panel reads it again, and the process still
/// answers to its breakpoint.
pub fn snapshot_with_debugger(context: &mut Context) -> Result<String, String> {
    let mut attached = stopped_at_work(context)?;
    let before = Panel::view(&mut context.driver).ok_or("no view")?;
    let RunState::Stopped { tid, pc, .. } = before.run.clone() else {
        return Err("not stopped".into());
    };
    let snapshot_id = take_full_snapshot(context, "Stopped at a breakpoint")?;
    // Let it run on: the guest moves away from the snapshot.
    attached
        .panel
        .send(&mut context.driver, DebugAction::Continue)?;
    Panel::stopped_at_breakpoint(&mut context.driver, attached.work)?;
    restore(context, snapshot_id)?;
    let after = Panel::wait(&mut context.driver, "the snapshot's stop", 60, |view| {
        matches!(view.run, RunState::Stopped { tid: t, pc: p, .. } if t == tid && p == pc)
            && !view.loading
            && view.registers.is_some()
    })?;
    if after.breakpoints.is_empty() {
        return Err("the breakpoint list was lost".into());
    }
    attached
        .panel
        .send(&mut context.driver, DebugAction::Continue)?;
    Panel::stopped_at_breakpoint(&mut context.driver, attached.work)?;
    finish(context, &attached)?;
    Ok("a full snapshot was taken at a breakpoint with the debugger attached; after the process ran on and the snapshot was restored the same panel showed the same stop and the breakpoint fired again".into())
}

/// The app's debugger is gone (detached) when a snapshot that held a session is
/// restored: the guest still has it, and the app takes it over again.
pub fn snapshot_readopt(context: &mut Context) -> Result<String, String> {
    let attached = stopped_at_work(context)?;
    let before = Panel::view(&mut context.driver).ok_or("no view")?;
    let RunState::Stopped { tid, pc, .. } = before.run.clone() else {
        return Err("not stopped".into());
    };
    let snapshot_id = take_full_snapshot(context, "Session at a breakpoint")?;
    context
        .driver
        .command(Command::DebugDetach { kill: false })?;
    if context.driver.snapshot.debug.is_some() {
        return Err("detach left the session".into());
    }
    restore(context, snapshot_id)?;
    context
        .driver
        .wait("the debugger to be adopted", 60, |snapshot| {
            snapshot.debug.is_some()
        })?;
    let after = Panel::wait(&mut context.driver, "the snapshot's stop", 60, |view| {
        matches!(view.run, RunState::Stopped { tid: t, pc: p, .. } if t == tid && p == pc)
            && !view.loading
            && view.registers.is_some()
    })?;
    if after.breakpoints.is_empty() {
        return Err(format!(
            "the breakpoints the guest held were not shown: {:?}",
            after.breakpoints
        ));
    }
    finish(context, &attached)?;
    Ok("a snapshot that held a debug session was restored after the app had detached: the app found the guest's session, took it over and showed the same stop with the guest's breakpoint".into())
}
