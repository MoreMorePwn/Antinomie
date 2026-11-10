// SPDX-License-Identifier: GPL-3.0-only
//! The words for a run's state, its root exit and its execution evidence,
//! as Run History, the Samples page and Trace show them.
use antinomie_monitor_core::{RunState, RunSummary};

pub(super) fn run_status(run: &RunSummary) -> std::borrow::Cow<'static, str> {
    // A run held open for a persisted copy still captures: not "Finished".
    if let Some(held) = crate::run_state_line::held(run) {
        return held.into();
    }
    // The words say what happened: a VM stop that cut a live tree is not a
    // failure of the sample, and Stop run is the user's own act.
    if crate::run_state_line::ended_by_vm_stop(run) {
        return "Ended by VM stop".into();
    }
    let words: &'static str = match run.state {
        RunState::Unknown => "Unknown",
        RunState::Running => "Running",
        RunState::StopRequested => "Stop requested",
        RunState::Finished => "Finished",
        RunState::Stopped => "Stopped by you",
        RunState::TerminalClosed => "PTY closed",
        RunState::Finalized => "Recording ended",
        RunState::FailedToStart => "Failed to start",
        RunState::LaunchUnconfirmed => "Launch unconfirmed",
        RunState::Interrupted => "Interrupted",
    };
    words.into()
}

pub(super) fn root_exit(run: &RunSummary) -> String {
    antinomie_monitor_core::samples::root_exit_words(run)
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
