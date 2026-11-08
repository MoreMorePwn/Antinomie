// SPDX-License-Identifier: GPL-3.0-only
//! Which run a network capture segment belongs to, read from what the runs
//! saved: no capture file is touched and nothing is written, so segments
//! recorded by earlier releases link too.
//!
//! A run that started its own capture lists the segment in its
//! `artifacts.json`: that is the run's claim on the capture, and the link is
//! exact. Any other run whose time window overlaps the segment's was live
//! while it wrote: those are the "live runs", linked by time alone. A segment
//! no run overlaps holds the whole VM's traffic with no run behind it.
use crate::{
    RunSummary,
    network::NetworkCapture,
    provenance::{Certainty, Provenance},
};
use std::{collections::HashMap, path::PathBuf};

/// Most runs read for one listing; the newest are kept.
pub const RUN_LIMIT: usize = 256;

/// A run as a capture sees it: when it was live and which segments it owns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunWindow {
    pub run_id: String,
    pub vm_id: String,
    pub boot_id: String,
    /// Host Unix milliseconds; `None` when the run never recorded a start.
    pub started_ms: Option<u64>,
    /// `None` while the run is going or when its end was not recorded.
    pub ended_ms: Option<u64>,
    /// File names of the capture segments the run's artifacts list.
    pub owned: Vec<String>,
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The capture a pcap's saved summary describes (`<id>.json` beside it), with
/// `file` set to the pcap; `None` when there is no readable summary.
pub fn saved_capture(pcap: &std::path::Path) -> Option<NetworkCapture> {
    let file = std::fs::File::open(pcap.with_extension("json")).ok()?;
    let mut capture: NetworkCapture =
        serde_json::from_reader(std::io::BufReader::new(std::io::Read::take(file, 1 << 20)))
            .ok()?;
    capture.file = pcap.to_path_buf();
    Some(capture)
}

/// The windows of `runs`, newest [`RUN_LIMIT`] of them, from each run's
/// folder (`artifacts.json` and the manifest's times).
pub fn run_windows(runs: &[RunSummary]) -> Vec<RunWindow> {
    let mut newest: Vec<&RunSummary> = runs.iter().collect();
    newest.sort_by_key(|run| std::cmp::Reverse(run.started_ms));
    newest.truncate(RUN_LIMIT);
    newest
        .into_iter()
        .map(|run| {
            let facts = crate::recording::run_filter_facts(
                &run.directory,
                &run.id,
                &run.vm_id,
                &run.boot_id,
            )
            .ok();
            let owned = crate::RunArtifacts::load(&run.directory)
                .ok()
                .flatten()
                .map(|artifacts| {
                    artifacts
                        .network_captures
                        .iter()
                        .map(|path| file_name(path))
                        .collect()
                })
                .unwrap_or_default();
            RunWindow {
                run_id: run.id.clone(),
                vm_id: run.vm_id.clone(),
                boot_id: run.boot_id.clone(),
                started_ms: run
                    .started_ms
                    .or_else(|| facts.as_ref().and_then(|facts| facts.started_ms)),
                ended_ms: facts.and_then(|facts| facts.ended_ms),
                owned,
            }
        })
        .collect()
}

/// When a run was live, as a closed span: an unknown end reads as the start,
/// widened to the segments the run itself owns (it was live while they wrote).
fn span(run: &RunWindow, captures: &[NetworkCapture]) -> Option<(u64, u64)> {
    let start = run.started_ms?;
    let mut end = run.ended_ms.unwrap_or(start).max(start);
    if run.ended_ms.is_none() {
        for capture in captures
            .iter()
            .filter(|capture| run.owned.contains(&file_name(&capture.file)))
        {
            end = end.max(capture.stopped_ms.unwrap_or(capture.started_ms));
        }
    }
    Some((start, end))
}

/// The link of one capture segment to the runs of its VM.
pub fn link(capture: &NetworkCapture, runs: &[RunWindow], all: &[NetworkCapture]) -> Provenance {
    let name = file_name(&capture.file);
    let window = (capture.started_ms, capture.stopped_ms);
    let (from, to) = (capture.started_ms, capture.stopped_ms.unwrap_or(u64::MAX));
    let owner = runs.iter().find(|run| run.owned.contains(&name));
    let mut live: Vec<&RunWindow> = runs
        .iter()
        .filter(|run| owner.is_none_or(|owner| owner.run_id != run.run_id))
        .filter(|run| span(run, all).is_some_and(|(start, end)| start <= to && end >= from))
        .collect();
    live.sort_by_key(|run| run.started_ms);
    let live_ids: Vec<String> = live.iter().map(|run| run.run_id.clone()).collect();
    if let Some(owner) = owner {
        return Provenance::run_capture(
            &owner.vm_id,
            &capture.boot_id,
            &owner.run_id,
            live_ids,
            window,
        );
    }
    let certainty = if capture.started_ms == 0 {
        Certainty::Unknown
    } else if live_ids.is_empty() {
        Certainty::VmWide
    } else {
        Certainty::ByTime
    };
    let mut found = Provenance::by_hand("", &capture.boot_id, None, live_ids, capture.started_ms);
    found.certainty = certainty;
    found.to_ms = window.1;
    found
}

/// The link of every capture, by pcap file.
pub fn capture_links(
    captures: &[NetworkCapture],
    runs: &[RunWindow],
) -> HashMap<PathBuf, Provenance> {
    captures
        .iter()
        .map(|capture| (capture.file.clone(), link(capture, runs, captures)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(id: &str, from: u64, to: Option<u64>) -> NetworkCapture {
        NetworkCapture {
            id: id.into(),
            boot_id: "b".into(),
            file: PathBuf::from(format!("/rec/boots/b/captures/{id}.pcap")),
            started_ms: from,
            stopped_ms: to,
            ..NetworkCapture::default()
        }
    }

    fn run(id: &str, from: u64, to: Option<u64>, owned: &[&str]) -> RunWindow {
        RunWindow {
            run_id: id.into(),
            vm_id: "v".into(),
            boot_id: "b".into(),
            started_ms: Some(from),
            ended_ms: to,
            owned: owned.iter().map(|name| format!("{name}.pcap")).collect(),
        }
    }

    #[test]
    fn the_run_that_started_a_segment_owns_it_exactly() {
        let all = [capture("c1", 1_000, Some(2_000))];
        let runs = [run("r1", 1_000, Some(2_000), &["c1"])];
        let found = link(&all[0], &runs, &all);
        assert_eq!(found.certainty, Certainty::Exact);
        assert_eq!(found.run_id.as_deref(), Some("r1"));
        assert!(found.live_runs.is_empty());
    }

    #[test]
    fn a_hand_started_segment_is_linked_by_time_to_every_run_live_in_it() {
        let all = [capture("hand", 1_000, Some(9_000))];
        let runs = [
            run("early", 500, Some(1_500), &[]),
            run("inside", 3_000, Some(4_000), &[]),
            run("later", 9_500, Some(10_000), &[]),
        ];
        let found = link(&all[0], &runs, &all);
        assert_eq!(found.certainty, Certainty::ByTime);
        assert_eq!(found.run_id, None);
        assert_eq!(found.live_runs, ["early", "inside"]);
    }

    #[test]
    fn two_runs_on_one_vm_share_a_segment_by_time_and_each_owns_its_own() {
        let all = [
            capture("a", 1_000, Some(5_000)),
            capture("b", 4_000, Some(8_000)),
        ];
        let runs = [
            run("one", 1_000, Some(5_000), &["a"]),
            run("two", 4_000, Some(8_000), &["b"]),
        ];
        let first = link(&all[0], &runs, &all);
        assert_eq!(first.run_id.as_deref(), Some("one"));
        // The other run was live while the first segment wrote its last second.
        assert_eq!(first.live_runs, ["two"]);
        let second = link(&all[1], &runs, &all);
        assert_eq!(second.run_id.as_deref(), Some("two"));
        assert_eq!(second.live_runs, ["one"]);
    }

    #[test]
    fn a_segment_no_run_overlaps_is_vm_wide_and_a_timeless_one_is_unknown() {
        let all = [
            capture("idle", 20_000, Some(21_000)),
            capture("old", 0, None),
        ];
        let runs = [run("r", 1_000, Some(2_000), &[])];
        assert_eq!(link(&all[0], &runs, &all).certainty, Certainty::VmWide);
        assert_eq!(link(&all[1], &runs, &all).certainty, Certainty::Unknown);
    }

    #[test]
    fn a_run_without_a_recorded_end_is_live_for_its_own_segments_only() {
        let all = [
            capture("own", 1_000, Some(6_000)),
            capture("far", 50_000, Some(60_000)),
        ];
        let runs = [run("r", 1_000, None, &["own"])];
        assert_eq!(link(&all[1], &runs, &all).certainty, Certainty::VmWide);
        let map = capture_links(&all, &runs);
        assert_eq!(map[&all[0].file].run_id.as_deref(), Some("r"));
    }
}
