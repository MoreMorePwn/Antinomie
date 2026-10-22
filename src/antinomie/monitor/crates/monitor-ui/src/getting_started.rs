// SPDX-License-Identifier: GPL-3.0-only
//! Help > Getting started: what a first analysis needs, one step at a time.
//! This module holds the steps, what is remembered between launches and the
//! rules for showing the window; the window itself is `app::getting_started`.
use antinomie_monitor_core::VmConfig;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, VecDeque},
    time::Instant,
};

/// The window's egui ID (Escape closes it).
pub(crate) const WINDOW_ID: &str = "getting_started";

/// The documentation page for a first run.
pub(crate) const DOCS_URL: &str =
    "https://antinomie.moremorepwn.blog/docs/getting-started/first-run/";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Step {
    #[default]
    Base,
    Vm,
    Dependencies,
    Tools,
    Rules,
    Finish,
}

impl Step {
    pub(crate) const ALL: [Step; 6] = [
        Step::Base,
        Step::Vm,
        Step::Dependencies,
        Step::Tools,
        Step::Rules,
        Step::Finish,
    ];

    /// The name saved in the settings.
    pub(crate) fn id(self) -> &'static str {
        match self {
            Step::Base => "base",
            Step::Vm => "vm",
            Step::Dependencies => "dependencies",
            Step::Tools => "tools",
            Step::Rules => "rules",
            Step::Finish => "finish",
        }
    }

    pub(crate) fn from_id(id: &str) -> Option<Step> {
        Step::ALL.into_iter().find(|step| step.id() == id)
    }

    pub(crate) fn title(self) -> &'static str {
        match self {
            Step::Base => "Base image",
            Step::Vm => "First VM",
            Step::Dependencies => "Dependencies",
            Step::Tools => "Analysis tools",
            Step::Rules => "Rules",
            Step::Finish => "Finish",
        }
    }

    pub(crate) fn next(self) -> Step {
        Step::ALL
            .into_iter()
            .find(|step| *step > self)
            .unwrap_or(Step::Finish)
    }

    pub(crate) fn previous(self) -> Step {
        Step::ALL
            .into_iter()
            .rev()
            .find(|step| *step < self)
            .unwrap_or(Step::Base)
    }
}

/// What is remembered between launches (part of the app's settings).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Progress {
    /// The window has opened by itself once; it never does again.
    pub seen: bool,
    /// The last step was reached and finished.
    pub finished: bool,
    /// "Don't show again": no automatic opening, whatever else happens.
    pub dont_show: bool,
    /// Steps skipped, by [`Step::id`].
    pub skipped: BTreeSet<String>,
    /// The step the window was on when it closed.
    pub step: String,
}

impl Progress {
    /// Open by itself at launch: the first start, with no VM and no base,
    /// unless the walk-through was finished or switched off.
    pub(crate) fn opens_on_launch(&self, vms: usize, bases: usize) -> bool {
        !self.seen && !self.finished && !self.dont_show && vms == 0 && bases == 0
    }

    pub(crate) fn is_skipped(&self, step: Step) -> bool {
        self.skipped.contains(step.id())
    }

    pub(crate) fn skip(&mut self, step: Step) {
        self.skipped.insert(step.id().to_owned());
    }

    /// Doing a step after skipping it takes the skip back.
    pub(crate) fn unskip(&mut self, step: Step) {
        self.skipped.remove(step.id());
    }

    pub(crate) fn remembered_step(&self) -> Step {
        Step::from_id(&self.step).unwrap_or_default()
    }
}

/// What the host has now; read again every time the window opens.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    pub bases: usize,
    pub vms: usize,
    /// `None` until the dependency check finishes.
    pub dependencies_ready: Option<bool>,
    pub tools_total: usize,
    pub tools_missing: usize,
    /// Rule engines with an installed pack; `None` until the registry loads.
    pub rule_engines: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Done,
    Skipped,
    Pending,
}

impl Status {
    pub(crate) fn word(self) -> &'static str {
        match self {
            Status::Done => "Ready",
            Status::Skipped => "Skipped",
            Status::Pending => "Not done",
        }
    }
}

/// How many rule engines a complete setup has a pack for.
pub(crate) const RULE_ENGINES: usize = 3;

pub(crate) fn status(step: Step, facts: &Facts, progress: &Progress) -> Status {
    let done = match step {
        Step::Base => facts.bases > 0,
        Step::Vm => facts.vms > 0,
        Step::Dependencies => facts.dependencies_ready == Some(true),
        Step::Tools => facts.tools_total > 0 && facts.tools_missing == 0,
        Step::Rules => facts.rule_engines == Some(RULE_ENGINES),
        Step::Finish => progress.finished,
    };
    if done {
        Status::Done
    } else if progress.is_skipped(step) {
        Status::Skipped
    } else {
        Status::Pending
    }
}

/// The window's own state; nothing here is saved.
#[derive(Default)]
pub(crate) struct GettingStarted {
    pub open: bool,
    pub step: Step,
    /// The auto-open rule has been applied this run.
    pub decided: bool,
    /// The app has received its first state from the backend.
    pub snapshot_seen: bool,
    /// The base catalog was asked for since the window opened.
    pub catalog_requested: bool,
    /// The first VM's settings, apart from the New VM dialog's.
    pub draft: Option<VmConfig>,
    /// A VM is being created: when, and how many VMs there were.
    pub vm_pending: Option<(Instant, usize)>,
    pub vm_error: Option<String>,
    /// Why the catalog or the tools could not be asked for.
    pub base_error: Option<String>,
    pub tool_error: Option<String>,
    /// Tools still to install, and the one asked for last.
    pub tool_queue: VecDeque<String>,
    pub tool_inflight: Option<String>,
    /// Rule packs ticked for download (`None`: the defaults), and the ones
    /// still to install, one at a time.
    pub rules_chosen: Option<BTreeSet<String>>,
    pub rule_queue: VecDeque<String>,
    /// The engine tab of the rules step (an index of `ENGINES`).
    pub rules_engine: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_install_opens_the_window_once() {
        let fresh = Progress::default();
        assert!(fresh.opens_on_launch(0, 0));
        // Already opened by itself once.
        assert!(!Progress {
            seen: true,
            ..fresh.clone()
        }
        .opens_on_launch(0, 0));
    }

    #[test]
    fn a_vm_a_base_or_a_finished_flag_keeps_it_closed() {
        let fresh = Progress::default();
        assert!(!fresh.opens_on_launch(1, 0));
        assert!(!fresh.opens_on_launch(0, 1));
        assert!(!Progress {
            finished: true,
            ..fresh.clone()
        }
        .opens_on_launch(0, 0));
        assert!(!Progress {
            dont_show: true,
            ..fresh
        }
        .opens_on_launch(0, 0));
    }

    #[test]
    fn progress_survives_the_settings_round_trip() {
        let mut progress = Progress::default();
        progress.skip(Step::Rules);
        progress.skip(Step::Tools);
        progress.unskip(Step::Tools);
        progress.step = Step::Dependencies.id().into();
        progress.seen = true;
        progress.dont_show = true;
        let text = serde_json::to_string(&progress).unwrap();
        let back: Progress = serde_json::from_str(&text).unwrap();
        assert_eq!(back, progress);
        assert!(back.is_skipped(Step::Rules) && !back.is_skipped(Step::Tools));
        assert_eq!(back.remembered_step(), Step::Dependencies);
        // Settings saved before this existed load as a fresh walk-through.
        assert_eq!(
            serde_json::from_str::<Progress>("{}").unwrap(),
            Progress::default()
        );
        assert_eq!(
            Progress {
                step: "gone".into(),
                ..Progress::default()
            }
            .remembered_step(),
            Step::Base
        );
    }

    #[test]
    fn steps_follow_each_other_and_stop_at_the_ends() {
        assert_eq!(Step::Base.next(), Step::Vm);
        assert_eq!(Step::Rules.next(), Step::Finish);
        assert_eq!(Step::Finish.next(), Step::Finish);
        assert_eq!(Step::Base.previous(), Step::Base);
        assert_eq!(Step::Finish.previous(), Step::Rules);
        for step in Step::ALL {
            assert_eq!(Step::from_id(step.id()), Some(step));
        }
    }

    #[test]
    fn live_facts_decide_what_is_done_and_done_beats_skipped() {
        let mut progress = Progress::default();
        let mut facts = Facts::default();
        assert_eq!(status(Step::Base, &facts, &progress), Status::Pending);
        progress.skip(Step::Base);
        assert_eq!(status(Step::Base, &facts, &progress), Status::Skipped);
        facts.bases = 1;
        assert_eq!(status(Step::Base, &facts, &progress), Status::Done);
        facts.tools_total = 3;
        facts.tools_missing = 1;
        assert_eq!(status(Step::Tools, &facts, &progress), Status::Pending);
        facts.tools_missing = 0;
        assert_eq!(status(Step::Tools, &facts, &progress), Status::Done);
        facts.rule_engines = Some(2);
        assert_eq!(status(Step::Rules, &facts, &progress), Status::Pending);
        facts.rule_engines = Some(RULE_ENGINES);
        assert_eq!(status(Step::Rules, &facts, &progress), Status::Done);
        facts.dependencies_ready = None;
        assert_eq!(
            status(Step::Dependencies, &facts, &progress),
            Status::Pending
        );
    }
}
