// SPDX-License-Identifier: GPL-3.0-only
//! The Run column of the Core dumps and Memory tabs: which run a core or a
//! memory dump belongs to, as its short id and sample name, and how sure that
//! link is. A click on it opens the run in Triage.
use antinomie_monitor_core::{provenance::Certainty, RunSummary};
use std::collections::HashMap;

/// A run as the column names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunName {
    /// The first 8 hex of its id.
    pub short: String,
    /// The sample the run executed: its library name, else the program's file name.
    pub sample: String,
}

/// The runs of the selected VM by id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RunNames {
    by_id: HashMap<String, RunName>,
}

impl RunNames {
    pub(crate) fn of(runs: &[RunSummary]) -> Self {
        let by_id = runs
            .iter()
            .map(|run| {
                let sample = run
                    .request
                    .sample
                    .as_ref()
                    .map(|sample| sample.name.clone())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| {
                        run.request
                            .path
                            .rsplit('/')
                            .next()
                            .unwrap_or_default()
                            .to_owned()
                    });
                (
                    run.id.clone(),
                    RunName {
                        short: short(&run.id),
                        sample,
                    },
                )
            })
            .collect();
        Self { by_id }
    }

    pub(crate) fn get(&self, id: &str) -> Option<&RunName> {
        self.by_id.get(id)
    }
}

pub(crate) fn short(id: &str) -> String {
    id.chars().take(8).collect()
}

/// What the Run column shows for one core or memory dump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunCell {
    pub text: String,
    pub tip: String,
    /// The run a click opens in Triage; none for "Not in a run" and "VM-wide".
    pub run_id: Option<String>,
}

/// The cell for a dump linked to `run_id` (exact), to the runs live while it
/// was written (`live_runs`, by time) or to none. `certainty` is the record's.
pub(crate) fn cell(
    run_id: Option<&str>,
    live_runs: &[String],
    certainty: Certainty,
    names: &RunNames,
) -> RunCell {
    let named = |id: &str| match names.get(id) {
        Some(run) if run.sample.is_empty() => run.short.clone(),
        Some(run) => format!("{} \u{b7} {}", run.short, run.sample),
        None => format!("{} \u{b7} run not listed", short(id)),
    };
    if let Some(id) = run_id {
        return RunCell {
            text: named(id),
            tip: format!(
                "Run {id}\nLink: {}. Click to open this run in Triage.",
                certainty.label()
            ),
            run_id: Some(id.to_owned()),
        };
    }
    if let Some(first) = live_runs.first() {
        let more = live_runs.len() - 1;
        let text = if more == 0 {
            format!("by time: {}", named(first))
        } else {
            format!("by time: {} +{more}", named(first))
        };
        return RunCell {
            text,
            tip: format!(
                "Taken while {} live: {}.\nThe time is the only link; the dump holds the whole VM. Click to open the first in Triage.",
                if live_runs.len() == 1 { "this run was" } else { "these runs were" },
                live_runs.iter().map(|id| named(id)).collect::<Vec<_>>().join(", ")
            ),
            run_id: Some(first.clone()),
        };
    }
    if certainty == Certainty::VmWide {
        return RunCell {
            text: "VM-wide".into(),
            tip: "A dump of the whole VM, taken while no run was live.".into(),
            run_id: None,
        };
    }
    RunCell {
        text: "Not in a run".into(),
        tip: "No run is known for this dump (taken by hand, imported, or saved before runs were linked).".into(),
        run_id: None,
    }
}

/// A run for tests: its id and the program it ran.
#[cfg(test)]
pub(crate) use antinomie_triage::report_export::fixtures::test_run;

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> RunNames {
        let mut names = RunNames::default();
        names.by_id.insert(
            "f9c3d854547992ccfc7f6670b3cc7866".into(),
            RunName {
                short: "f9c3d854".into(),
                sample: "bpfdoor.elf".into(),
            },
        );
        names
    }

    #[test]
    fn an_exact_link_names_the_run_and_its_sample_and_opens_it() {
        let cell = cell(
            Some("f9c3d854547992ccfc7f6670b3cc7866"),
            &[],
            Certainty::Exact,
            &names(),
        );
        assert_eq!(cell.text, "f9c3d854 \u{b7} bpfdoor.elf");
        assert_eq!(
            cell.run_id.as_deref(),
            Some("f9c3d854547992ccfc7f6670b3cc7866")
        );
        assert!(cell.tip.contains("exact"));
    }

    #[test]
    fn time_vm_wide_and_none_read_in_their_own_words() {
        let timed = cell(
            None,
            &["f9c3d854547992ccfc7f6670b3cc7866".into(), "other".into()],
            Certainty::ByTime,
            &names(),
        );
        assert_eq!(timed.text, "by time: f9c3d854 \u{b7} bpfdoor.elf +1");
        assert!(timed.run_id.is_some());
        let wide = cell(None, &[], Certainty::VmWide, &names());
        assert_eq!((wide.text.as_str(), wide.run_id), ("VM-wide", None));
        let none = cell(None, &[], Certainty::Unknown, &names());
        assert_eq!(none.text, "Not in a run");
        let gone = cell(Some("abcdef0123456789"), &[], Certainty::Exact, &names());
        assert_eq!(gone.text, "abcdef01 \u{b7} run not listed");
    }
}
