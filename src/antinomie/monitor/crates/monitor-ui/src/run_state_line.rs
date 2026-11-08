// SPDX-License-Identifier: GPL-3.0-only
//! The run's overall state in words, beside the Network route line of Triage:
//! "Running · 12 min 34 s elapsed", "Ran for 5 min 2 s · exit 0", "Still
//! recording: 10 processes alive". The words are Run History's.
use crate::widgets::Tone;
use antinomie_monitor_core::{RunState, RunSummary};
// The words are `antinomie_triage::run_state`'s: the report says them too.
pub(crate) use antinomie_triage::run_state::*;
use eframe::egui::{self, Color32};

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
    use antinomie_monitor_core::WaitStatus;
    use antinomie_monitor_core::{ExecRequest, RunExecution};

    fn finished() -> RunSummary {
        RunSummary {
            environment: None,
            reduced: None,
            boot_wait: None,
            triggers: None,
            stopped_by_user: false,
            stopped_at_ms: None,
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
            "Stopped by you after 3 min 52 s · root exited 0"
        );
    }

    fn with_live(state: RunState, root: Option<WaitStatus>, live: u64) -> RunSummary {
        let mut run = finished();
        run.state = state;
        let execution = run.execution.as_mut().unwrap();
        execution.root_exit = root;
        execution.live_task_count = live;
        run
    }

    #[test]
    fn a_vm_stop_over_a_live_child_says_what_happened() {
        // The report's "Interrupted · Exit 0": the root exited 0, a child lived.
        let end = 1_700_000_060_000;
        for state in [RunState::Interrupted, RunState::Finalized] {
            let run = with_live(state, Some(WaitStatus::Exited { code: 0 }), 1);
            assert!(ended_by_vm_stop(&run));
            assert_eq!(
                describe(&run, end, Some(end), None),
                "Ended by VM stop after 1 min 0 s · root exited 0 · 1 process still running"
            );
        }
        let many = with_live(RunState::Finalized, Some(WaitStatus::Exited { code: 3 }), 4);
        assert_eq!(
            describe(&many, 0, None, None),
            "Ended by VM stop · root exited 3 · 4 processes still running"
        );
        let running = with_live(RunState::Interrupted, None, 2);
        assert_eq!(
            describe(&running, 0, None, None),
            "Ended by VM stop · root had not exited · 2 processes still running"
        );
        // A recording that ended with nothing alive is only that.
        let quiet = with_live(RunState::Finalized, Some(WaitStatus::Exited { code: 0 }), 0);
        assert!(!ended_by_vm_stop(&quiet));
        assert_eq!(describe(&quiet, 0, None, None), "Recording ended");
    }

    #[test]
    fn stop_run_reads_as_the_users_act_even_when_the_root_had_exited() {
        let run = with_live(RunState::Stopped, Some(WaitStatus::Exited { code: 0 }), 0);
        assert_eq!(
            describe(&run, 0, None, None),
            "Stopped by you · root exited 0"
        );
        let signalled = with_live(
            RunState::Stopped,
            Some(WaitStatus::Signaled {
                signal: 15,
                core_dumped: false,
            }),
            0,
        );
        assert_eq!(
            describe(&signalled, 0, None, None),
            "Stopped by you · root killed by signal 15"
        );
        // The press time is shown, and the tree's end only when it was late.
        let mut pressed = run.clone();
        pressed.stopped_at_ms = Some(1_700_000_000_000 + 309_000);
        let end = 1_700_000_000_000 + 312_000;
        assert_eq!(
            describe(&pressed, end, Some(end), None),
            "Stopped by you at 5 min 9 s · tree ended 3 s later · root exited 0"
        );
        assert_eq!(
            describe(&pressed, end, Some(end - 1500), None),
            "Stopped by you at 5 min 9 s · root exited 0"
        );
        assert_eq!(
            describe(&pressed, end, Some(end + 600_000), None),
            "Stopped by you at 5 min 9 s · tree ended 10 min 3 s later · root exited 0"
        );
        // Waiting for the guest to report the end.
        let stopping = with_live(
            RunState::StopRequested,
            Some(WaitStatus::Exited { code: 0 }),
            1,
        );
        assert_eq!(
            describe(&stopping, 1_700_000_005_000, None, None),
            "Stopping · 5 s elapsed"
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
