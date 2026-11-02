// SPDX-License-Identifier: GPL-3.0-only
//! The run's overall state in words, beside the Network route line of Triage:
//! "Running · 12:34 elapsed", "Finished after 5:02 (exit 0)", "Still recording:
//! 10 processes alive". The words are Run History's.
use antinomie_monitor_core::{RunState, RunSummary, WaitStatus};

/// A duration as `m:ss`, or `h:mm:ss` from an hour.
pub(crate) fn clock(milliseconds: u64) -> String {
    let seconds = milliseconds / 1000;
    let (hours, minutes, seconds) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{}:{seconds:02}", minutes)
    }
}

/// The state line of `run`. `now_ms` is the host time (Unix ms), `ended_ms`
/// when the process tree ended if known, `alive` the processes the index saw
/// no exit for.
pub(crate) fn describe(
    run: &RunSummary,
    now_ms: u64,
    ended_ms: Option<u64>,
    alive: Option<u64>,
) -> String {
    let elapsed = |end: u64| run.started_ms.map(|start| clock(end.saturating_sub(start)));
    let after = |text: &str| match run.started_ms.zip(ended_ms) {
        Some((start, end)) => format!("{text} after {}", clock(end.saturating_sub(start))),
        None => text.to_owned(),
    };
    let root = run
        .execution
        .as_ref()
        .and_then(|status| status.root_exit.as_ref());
    let exit = match root {
        Some(WaitStatus::Exited { code }) => Some(format!("exit {code}")),
        Some(WaitStatus::Signaled { signal, .. }) => Some(format!("signal {signal}")),
        None => None,
    };
    let live = run
        .execution
        .as_ref()
        .map_or(0, |status| status.live_task_count);
    let running = |word: &str| match elapsed(now_ms) {
        Some(time) => format!("{word} · {time} elapsed"),
        None => word.to_owned(),
    };
    match run.state {
        // The root program is gone and its children keep the run open.
        RunState::Running | RunState::StopRequested | RunState::TerminalClosed
            if root.is_some() && live.max(alive.unwrap_or(0)) > 0 =>
        {
            let count = live.max(alive.unwrap_or(0));
            let plural = if count == 1 { "process" } else { "processes" };
            let time =
                elapsed(now_ms).map_or_else(String::new, |time| format!(" · {time} elapsed"));
            format!("Still recording: {count} {plural} alive{time}")
        }
        RunState::Running => running("Running"),
        RunState::StopRequested => running("Stop requested"),
        RunState::TerminalClosed => running("PTY closed"),
        RunState::Finished => match exit {
            Some(exit) => format!("{} ({exit})", after("Finished")),
            None => after("Finished"),
        },
        RunState::Stopped => after("Stopped by the user"),
        RunState::Finalized => after("Recording ended"),
        RunState::Interrupted => after("Interrupted"),
        RunState::FailedToStart => format!(
            "Failed to start: {}",
            run.recording_error
                .as_deref()
                .unwrap_or("no reason was recorded")
        ),
        RunState::LaunchUnconfirmed => "Launch unconfirmed".into(),
        RunState::Unknown => "State unknown".into(),
    }
}

/// Whether the line changes with the clock: the run is going.
pub(crate) fn ticks(run: &RunSummary) -> bool {
    matches!(
        run.state,
        RunState::Running | RunState::StopRequested | RunState::TerminalClosed
    )
}

/// The host clock, Unix milliseconds.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_millis() as u64)
}
