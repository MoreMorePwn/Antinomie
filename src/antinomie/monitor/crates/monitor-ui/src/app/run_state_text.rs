// SPDX-License-Identifier: GPL-3.0-only
//! The words for a run's state, its root exit and its execution evidence,
//! as Run History, the Samples page and Trace show them.
use antinomie_monitor_core::{RunState, RunSummary, WaitStatus};

pub(super) fn run_status(run: &RunSummary) -> &'static str {
    match run.state {
        RunState::Unknown => "Unknown",
        RunState::Running => "Running",
        RunState::StopRequested => "Stop requested",
        RunState::Finished => "Finished",
        RunState::Stopped => "Stopped",
        RunState::TerminalClosed => "PTY closed",
        RunState::Finalized => "Recording ended",
        RunState::FailedToStart => "Failed to start",
        RunState::LaunchUnconfirmed => "Launch unconfirmed",
        RunState::Interrupted => "Interrupted",
    }
}

pub(super) fn root_exit(run: &RunSummary) -> String {
    // A program that never ran has no exit to be unknown.
    match run.state {
        RunState::FailedToStart => return "Not started".into(),
        RunState::LaunchUnconfirmed => return "Not recorded".into(),
        _ => {}
    }
    match run
        .execution
        .as_ref()
        .and_then(|status| status.root_exit.as_ref())
    {
        Some(WaitStatus::Exited { code }) => format!("Exit {code}"),
        Some(WaitStatus::Signaled {
            signal,
            core_dumped,
        }) => format!(
            "Signal {signal}{}",
            if *core_dumped { " (core)" } else { "" }
        ),
        None => "Unknown".into(),
    }
}

pub(super) fn execution_detail(run: &RunSummary) -> String {
    match &run.execution {
        Some(status) => format!(
            "{}; {} live tasks; {} pending async; {} total tasks; {} async losses; flags {:#x}; generation {}{}",
            run_status(run),
            status.live_task_count,
            status.pending_async_count,
            status.total_task_count,
            status.async_loss_count,
            status.flags,
            status.generation,
            if status.kill_escalated() {
                "; Stop needed SIGKILL after the grace period"
            } else {
                ""
            }
        ),
        None => format!(
            "{}; full-tree execution evidence unavailable",
            run_status(run)
        ),
    }
}
