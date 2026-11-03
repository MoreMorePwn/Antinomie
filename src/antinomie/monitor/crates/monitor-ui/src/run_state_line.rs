// SPDX-License-Identifier: GPL-3.0-only
//! The run's overall state in words, beside the Network route line of Triage:
//! "Running · 12:34 elapsed", "Finished after 5:02 (exit 0)", "Still recording:
//! 10 processes alive". The words are Run History's.
use crate::widgets::Tone;
use antinomie_monitor_core::{RunState, RunSummary, WaitStatus};
use eframe::egui::{self, Color32};

/// The state line of `run`. `now_ms` is the host time (Unix ms), `ended_ms`
/// when the process tree ended if known, `alive` the processes the index saw
/// no exit for.
pub(crate) fn describe(
    run: &RunSummary,
    now_ms: u64,
    ended_ms: Option<u64>,
    alive: Option<u64>,
) -> String {
    let elapsed = |end: u64| {
        run.started_ms
            .map(|start| crate::time_format::elapsed(end.saturating_sub(start)))
    };
    let after = |text: &str| match run.started_ms.zip(ended_ms) {
        Some((start, end)) => format!(
            "{text} after {}",
            crate::time_format::elapsed(end.saturating_sub(start))
        ),
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
        _ if run.state.is_live() && root.is_some() && live.max(alive.unwrap_or(0)) > 0 => {
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
    run.state.is_live()
}

/// How a run ended, as its toast says it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Ending {
    /// The root exited with code 0.
    Success,
    /// The root exited with another code.
    Exit(u8),
    /// The program was a `timeout` and its limit ran out (exit 124).
    TimeLimit,
    /// Stopped with the Stop button.
    Stopped,
    /// The root died of a signal (a crash, or a kill from inside the guest).
    Signal { signal: u8, core: bool },
    /// The tree ended and the guest never recorded the root's status.
    Unknown,
}

/// The signals that mean the program crashed rather than was told to stop.
pub(crate) fn crash_signal(signal: u8) -> bool {
    matches!(signal, 4 | 5 | 6 | 7 | 8 | 11 | 31)
}

pub(crate) fn ending(run: &RunSummary) -> Option<Ending> {
    match run.state {
        RunState::Stopped => return Some(Ending::Stopped),
        RunState::Finished => {}
        _ => return None,
    }
    let program = run.request.path.rsplit('/').next().unwrap_or_default();
    Some(
        match run
            .execution
            .as_ref()
            .and_then(|execution| execution.root_exit.as_ref())
        {
            Some(WaitStatus::Exited { code: 0 }) => Ending::Success,
            // coreutils exits 124; BusyBox's timeout re-raises the SIGTERM it sent.
            Some(WaitStatus::Exited { code: 124 }) if program == "timeout" => Ending::TimeLimit,
            Some(WaitStatus::Signaled { signal: 15, .. }) if program == "timeout" => {
                Ending::TimeLimit
            }
            Some(WaitStatus::Exited { code }) => Ending::Exit(*code),
            Some(WaitStatus::Signaled {
                signal,
                core_dumped,
            }) => Ending::Signal {
                signal: *signal,
                core: *core_dumped,
            },
            None => Ending::Unknown,
        },
    )
}

/// The colour of a run's state words, the one palette the run-finished toast
/// (green success, amber crash or kill), the Triage state line, Run History,
/// the Samples window's Runs and the VM Summary share. Colour never stands
/// alone: the state words stay beside it.
pub(crate) fn color(run: &RunSummary) -> Color32 {
    crate::widgets::fg_or_muted(state_tone(run))
}

/// [`color`] as a tone; `None` is plain grey (stopped, state unknown).
fn state_tone(run: &RunSummary) -> Option<Tone> {
    // Saving stopped part way: the recording is incomplete (the badge says so).
    if run.recording_error.is_some() && !run.state.never_recorded() && !ticks(run) {
        return Some(Tone::Warn);
    }
    match run.state {
        RunState::Running | RunState::StopRequested | RunState::TerminalClosed => {
            Some(Tone::Accent)
        }
        RunState::FailedToStart | RunState::Interrupted => Some(Tone::Error),
        RunState::LaunchUnconfirmed => Some(Tone::Warn),
        RunState::Stopped | RunState::Unknown => None,
        RunState::Finalized => Some(Tone::Neutral),
        RunState::Finished => match ending(run)? {
            Ending::Success => Some(Tone::Good),
            Ending::TimeLimit => Some(Tone::Info),
            Ending::Signal { .. } => Some(Tone::Warn),
            Ending::Exit(_) | Ending::Unknown | Ending::Stopped => Some(Tone::Neutral),
        },
    }
}

/// The state words in their colour.
pub(crate) fn text(run: &RunSummary, words: &str) -> egui::RichText {
    egui::RichText::new(words).color(color(run))
}
