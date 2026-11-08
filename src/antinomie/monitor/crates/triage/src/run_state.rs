// SPDX-License-Identifier: GPL-3.0-only
//! The run's overall state in words, beside the Network route line of Triage
//! and in the exported report: "Running · 12 min 34 s elapsed", "Ran for 5 min
//! 2 s · exit 0", "Still recording: 10 processes alive". The words are Run
//! History's; their colours are the GUI's.
use antinomie_monitor_core::{RunState, RunSummary, WaitStatus};

/// The state line of `run`. `now_ms` is the host time (Unix ms), `ended_ms`
/// when the process tree ended if known, `alive` the processes the index saw
/// no exit for.
pub fn describe(
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
    let with_detail = |head: String| match detail(run) {
        Some(detail) => format!("{head} · {detail}"),
        None => head,
    };
    let running = |word: &str| match elapsed(now_ms) {
        Some(time) => format!("{word} · {time} elapsed"),
        None => word.to_owned(),
    };
    match run.state {
        RunState::StopRequested => running("Stopping"),
        // The root program is gone and its children keep the run open.
        _ if run.state.is_live() && root.is_some() && live.max(alive.unwrap_or(0)) > 0 => {
            let count = live.max(alive.unwrap_or(0));
            let plural = if count == 1 { "process" } else { "processes" };
            let time =
                elapsed(now_ms).map_or_else(String::new, |time| format!(" · {time} elapsed"));
            format!("Still recording: {count} {plural} alive{time}")
        }
        RunState::Running => running("Running"),
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
        RunState::Stopped => match run.started_ms.zip(run.stopped_at_ms) {
            // The moment Stop run was pressed; the tree's end only when it took
            // noticeably longer.
            Some((start, stopped)) => {
                let mut head = format!(
                    "Stopped by you at {}",
                    crate::time_format::duration_ms(stopped.saturating_sub(start))
                );
                if let Some(late) = ended_ms
                    .map(|end| end.saturating_sub(stopped))
                    .filter(|late| *late >= 2000)
                {
                    head.push_str(&format!(
                        " · tree ended {} later",
                        crate::time_format::duration_ms(late)
                    ));
                }
                with_detail(head)
            }
            None => with_detail(after("Stopped by you")),
        },
        RunState::Finalized | RunState::Interrupted if ended_by_vm_stop(run) => {
            with_detail(after("Ended by VM stop"))
        }
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

/// How the run ended in a line for a list or a report: "Not started", "Stopped
/// by you at 6 min 25 s · root exited 0", "Ended by VM stop", "Exit 255",
/// "Signal 11 (SIGSEGV)". Without the clock-dependent words of [`describe`].
pub fn exit_summary(run: &RunSummary) -> String {
    let root = run
        .execution
        .as_ref()
        .and_then(|status| status.root_exit.as_ref());
    let exit = || match root {
        Some(WaitStatus::Exited { code }) => format!("Exit {code}"),
        Some(WaitStatus::Signaled { signal, .. }) => {
            format!("Signal {signal} ({})", crate::run_end::signal_name(*signal))
        }
        None => "Unknown".to_owned(),
    };
    match run.state {
        RunState::FailedToStart => "Not started".into(),
        RunState::LaunchUnconfirmed => "Not recorded".into(),
        _ if run.state.is_live() => "Running".into(),
        RunState::Stopped => {
            let at = run
                .started_ms
                .zip(run.stopped_at_ms)
                .map(|(start, stopped)| {
                    format!(
                        " at {}",
                        crate::time_format::duration_ms(stopped.saturating_sub(start))
                    )
                })
                .unwrap_or_default();
            match detail(run) {
                Some(detail) => format!("Stopped by you{at} · {detail}"),
                None => format!("Stopped by you{at}"),
            }
        }
        _ if ended_by_vm_stop(run) => match detail(run) {
            Some(detail) => format!("Ended by VM stop · {detail}"),
            None => "Ended by VM stop".into(),
        },
        _ => exit(),
    }
}

/// Whether the VM stopped (or the app closed) while the run's process tree was
/// still alive: the recording was cut there, whatever the root had done.
pub fn ended_by_vm_stop(run: &RunSummary) -> bool {
    matches!(run.state, RunState::Finalized | RunState::Interrupted)
        && run
            .execution
            .as_ref()
            .is_some_and(|status| status.live_task_count > 0 || status.root_exit.is_none())
}

/// What the root did and what was left, for a run Stop run or a VM stop ended:
/// "root exited 0 · 1 process still running". `None` when the guest never
/// reported the run's status.
pub fn detail(run: &RunSummary) -> Option<String> {
    let status = run.execution.as_ref()?;
    let root = match status.root_exit.as_ref() {
        Some(WaitStatus::Exited { code }) => format!("root exited {code}"),
        Some(WaitStatus::Signaled { signal, .. }) => format!("root killed by signal {signal}"),
        None => "root had not exited".to_owned(),
    };
    let left = status.live_task_count;
    if left == 0 {
        return Some(root);
    }
    let plural = if left == 1 { "process" } else { "processes" };
    Some(format!("{root} · {left} {plural} still running"))
}

/// The start and end times of `run` for the tooltip of its state line, in the
/// host zone; `None` when the run has no start time.
pub fn times(run: &RunSummary, ended_ms: Option<u64>) -> Option<String> {
    let start = run.started_ms?;
    let at = |ms: u64| crate::time_format::local_seconds(ms / 1000);
    let pressed = run
        .stopped_at_ms
        .map_or_else(String::new, |ms| format!("\nStop run pressed {}", at(ms)));
    Some(match ended_ms {
        Some(end) if !run.state.is_live() => {
            format!("Started {}{pressed}\nEnded {}", at(start), at(end))
        }
        _ => format!("Started {}{pressed}", at(start)),
    })
}

/// Whether the line changes with the clock: the run is going.
pub fn ticks(run: &RunSummary) -> bool {
    run.state.is_live()
}

/// How a run ended, as its toast says it.
#[derive(Debug, PartialEq, Eq)]
pub enum Ending {
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
pub fn crash_signal(signal: u8) -> bool {
    matches!(signal, 4 | 5 | 6 | 7 | 8 | 11 | 31)
}

pub fn ending(run: &RunSummary) -> Option<Ending> {
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
