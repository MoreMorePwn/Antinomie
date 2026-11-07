// SPDX-License-Identifier: GPL-3.0-only
//! The run's overall state in words, beside the Network route line of Triage:
//! "Running · 12 min 34 s elapsed", "Ran for 5 min 2 s · exit 0", "Still
//! recording: 10 processes alive". The words are Run History's.
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
            .map(|start| crate::time_format::duration_ms(end.saturating_sub(start)))
    };
    let after = |text: &str| match run.started_ms.zip(ended_ms) {
        Some((start, end)) => format!(
            "{text} after {}",
            crate::time_format::duration_ms(end.saturating_sub(start))
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
        RunState::Finished => {
            let ran = match run.started_ms.zip(ended_ms) {
                Some((start, end)) => format!(
                    "Ran for {}",
                    crate::time_format::duration_ms(end.saturating_sub(start))
                ),
                None => "Finished".to_owned(),
            };
            match exit {
                Some(exit) => format!("{ran} · {exit}"),
                None => ran,
            }
        }
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

/// The start and end times of `run` for the tooltip of its state line, in the
/// host zone; `None` when the run has no start time.
pub(crate) fn times(run: &RunSummary, ended_ms: Option<u64>) -> Option<String> {
    let start = run.started_ms?;
    let at = |ms: u64| crate::time_format::local_seconds(ms / 1000);
    Some(match ended_ms {
        Some(end) if !run.state.is_live() => format!("Started {}\nEnded {}", at(start), at(end)),
        _ => format!("Started {}", at(start)),
    })
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
/// the Samples window's Runs and the VM Overview share. Colour never stands
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
            // Finished, but the program did not succeed: amber, as a crash is.
            Ending::Signal { .. } | Ending::Exit(_) => Some(Tone::Warn),
            Ending::Unknown | Ending::Stopped => Some(Tone::Neutral),
        },
    }
}

/// The state words in their colour.
pub(crate) fn text(run: &RunSummary, words: &str) -> egui::RichText {
    egui::RichText::new(words).color(color(run))
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{ExecRequest, RunExecution};

    fn finished() -> RunSummary {
        RunSummary {
            environment: None,
            reduced: None,
            boot_wait: None,
            triggers: None,
            started_ms: Some(1_700_000_000_000),
            clock_anchor: None,
            id: "r".into(),
            vm_id: "vm".into(),
            boot_id: "b".into(),
            session_id: 1,
            root_task_cookie: 1,
            pid: 1,
            request: ExecRequest::default(),
            directory: std::path::PathBuf::new(),
            terminal_eof: false,
            state: RunState::Finished,
            recording_error: None,
            machine: None,
            route: None,
            execution: Some(RunExecution {
                generation: 1,
                live_task_count: 0,
                pending_async_count: 0,
                flags: 0,
                root_wait_status: None,
                root_exit: Some(WaitStatus::Exited { code: 0 }),
                async_loss_count: 0,
                total_task_count: 1,
            }),
            analysis: None,
            notes: Vec::new(),
        }
    }

    #[test]
    fn a_finished_run_says_how_long_it_ran_and_how_it_ended() {
        let run = finished();
        let end = 1_700_000_000_000 + (3 * 60 + 52) * 1000;
        assert_eq!(
            describe(&run, end, Some(end), None),
            "Ran for 3 min 52 s · exit 0"
        );
        assert_eq!(describe(&run, end, None, None), "Finished · exit 0");
        let stopped = RunSummary {
            state: RunState::Stopped,
            ..run.clone()
        };
        assert_eq!(
            describe(&stopped, end, Some(end), None),
            "Stopped by the user after 3 min 52 s"
        );
    }

    #[test]
    fn a_finished_run_that_did_not_exit_zero_is_amber_and_the_rest_keep_their_colours() {
        let with_exit = |state, exit: Option<WaitStatus>| {
            let mut run = finished();
            run.state = state;
            if let Some(execution) = run.execution.as_mut() {
                execution.root_exit = exit;
            }
            color(&run)
        };
        let warn = crate::widgets::fg_or_muted(Some(Tone::Warn));
        let good = crate::widgets::fg_or_muted(Some(Tone::Good));
        assert_eq!(
            with_exit(RunState::Finished, Some(WaitStatus::Exited { code: 0 })),
            good
        );
        assert_eq!(
            with_exit(RunState::Finished, Some(WaitStatus::Exited { code: 1 })),
            warn
        );
        assert_eq!(
            with_exit(
                RunState::Finished,
                Some(WaitStatus::Signaled {
                    signal: 9,
                    core_dumped: false
                })
            ),
            warn
        );
        assert_ne!(good, warn);
        // Failed and Interrupted keep theirs; Interrupted with exit 0 is not amber.
        let error = crate::widgets::fg_or_muted(Some(Tone::Error));
        assert_eq!(
            with_exit(RunState::Interrupted, Some(WaitStatus::Exited { code: 1 })),
            error
        );
        assert_eq!(with_exit(RunState::FailedToStart, None), error);
    }

    #[test]
    fn the_times_go_in_the_tooltip() {
        let run = finished();
        let tip = times(&run, Some(1_700_000_232_000)).unwrap();
        assert!(tip.starts_with("Started 20"), "{tip}");
        assert!(tip.contains("\nEnded 20"), "{tip}");
        assert!(times(
            &RunSummary {
                started_ms: None,
                ..run
            },
            None
        )
        .is_none());
    }
}
