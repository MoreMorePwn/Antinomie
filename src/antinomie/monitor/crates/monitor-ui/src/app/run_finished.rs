// SPDX-License-Identifier: GPL-3.0-only
//! The toast of a run that ended: "Run 3 finished" with the program, how long
//! it took and how it ended, and the way to its Triage (and to its sample).
//! One toast per run, raised when the run's tree really ended (a root that
//! exits while children live on keeps the run going, and Triage says "still
//! recording"); a run that failed to start has its own error toast.
use super::*;
use crate::{
    activity::Level,
    run_state_line::{clock, crash_signal, ending, now_ms, Ending},
    toasts::{self, Action, Then},
    workspace::{LibraryPage, Panel},
};
use antinomie_monitor_core::typed_fields::signal_name;
use std::collections::HashSet;

/// What the app remembers between frames: the runs it saw going, and the runs
/// it already toasted.
#[derive(Clone, Default)]
struct Seen {
    going: HashSet<String>,
    announced: HashSet<String>,
}

/// The level, the success colour, the title and the closing words of a toast.
fn words(number: usize, ending: &Ending) -> (Level, bool, String, String) {
    let run = format!("Run {number}");
    match ending {
        Ending::Success => (
            Level::Info,
            true,
            format!("{run} finished"),
            "exit 0".into(),
        ),
        Ending::Exit(code) => (
            Level::Info,
            false,
            format!("{run} finished"),
            format!("exit {code}"),
        ),
        Ending::TimeLimit => (
            Level::Info,
            false,
            format!("{run} reached its time limit"),
            "the timeout program stopped it".into(),
        ),
        Ending::Stopped => (
            Level::Info,
            false,
            format!("{run} stopped"),
            "stopped by the user".into(),
        ),
        Ending::Signal { signal, core } => {
            let name = format!("{} ({signal})", signal_name(u64::from(*signal)));
            let tail = if *core { ", core dumped" } else { "" };
            if crash_signal(*signal) {
                (
                    Level::Warn,
                    false,
                    format!("{run} crashed"),
                    format!("ended by {name}{tail}"),
                )
            } else {
                (
                    Level::Warn,
                    false,
                    format!("{run} was killed"),
                    format!("ended by {name}{tail}"),
                )
            }
        }
        Ending::Unknown => (
            Level::Info,
            false,
            format!("{run} finished"),
            "exit status not recorded".into(),
        ),
    }
}

impl MonitorApp {
    /// Raise the toast of every run that ended since the last frame.
    pub(super) fn run_finished_toasts(&self, ctx: &egui::Context) {
        let started = ctx.data_mut(|data| {
            *data.get_temp_mut_or_insert_with(egui::Id::new("run-finished-since"), now_ms)
        });
        let mut due = Vec::new();
        ctx.data_mut(|data| {
            let seen = data.get_temp_mut_or_default::<Seen>(egui::Id::new("run-finished-seen"));
            for run in &self.snapshot.runs {
                if run.state.is_live() {
                    seen.going.insert(run.id.clone());
                    continue;
                }
                // A run first met already ended counts when it began after
                // the app did (a program that ran and exited between frames).
                let ours =
                    seen.going.contains(&run.id) || run.started_ms.is_some_and(|ms| ms >= started);
                if ours && ending(run).is_some() && seen.announced.insert(run.id.clone()) {
                    due.push(run.clone());
                }
            }
        });
        if self.settings.toast_run_finished {
            for run in due {
                self.toast_run(ctx, &run);
            }
        }
    }

    /// "Run 3" is the run's place among its VM's runs, by start.
    fn run_number(&self, run: &RunSummary) -> usize {
        let mut ids: HashSet<&str> = HashSet::new();
        for other in self.history.iter().chain(&self.snapshot.runs) {
            if other.vm_id == run.vm_id && other.started_ms <= run.started_ms {
                ids.insert(other.id.as_str());
            }
        }
        ids.insert(run.id.as_str());
        ids.len()
    }

    fn toast_run(&self, ctx: &egui::Context, run: &RunSummary) {
        let Some(ending) = ending(run) else { return };
        let (level, success, title, tail) = words(self.run_number(run), &ending);
        let program = run
            .request
            .path
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or(&run.request.path);
        let took = run
            .started_ms
            .map(|start| clock(now_ms().saturating_sub(start)));
        let detail = [Some(program.to_owned()), took, Some(tail)]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ");
        let triage = Action {
            label: "Open Triage".into(),
            panel: Panel::Triage,
            then: Some(Then::Run {
                vm_id: run.vm_id.clone(),
                run_id: run.id.clone(),
            }),
        };
        let sample = run.request.sample.as_ref().map(|sample| Action {
            label: "Open sample".into(),
            panel: Panel::Library(LibraryPage::Samples),
            then: Some(Then::Sample(sample.sha256.clone())),
        });
        toasts::push_run(ctx, level, success, &title, &detail, [Some(triage), sample]);
    }

    /// Carry out a clicked toast link: select what it names, then bring its
    /// panel forward.
    pub(super) fn follow_toast_action(&mut self, action: Action) {
        match &action.then {
            Some(Then::Run { vm_id, run_id }) => {
                if let Some(run) = self
                    .snapshot
                    .runs
                    .iter()
                    .chain(&self.history)
                    .find(|run| run.id == *run_id && run.vm_id == *vm_id)
                    .cloned()
                {
                    self.open_sample_run(&run, action.panel.clone(), None);
                }
            }
            Some(Then::Sample(sha256)) => {
                self.samples_page.open_detail(sha256);
                self.focus_panel = Some(action.panel.clone());
            }
            None => self.focus_panel = Some(action.panel.clone()),
        }
    }
}
