// SPDX-License-Identifier: GPL-3.0-only
//! Which run each capture belongs to, and which process made each packet.
//!
//! The Run line of a capture row and the Made by column of the packet list
//! follow the dumps' Run column: the link comes from the runs' own records
//! (a run lists the segment it started; any other run live in the segment's
//! time window is linked by time), so captures recorded by earlier releases
//! link too.
use super::*;
use antinomie_monitor_core::{
    network_link,
    provenance::{Certainty, Provenance},
    RunSummary,
};
use antinomie_triage::net_attr::{NetAttribution, Source};

/// What the Run line of a capture says.
pub(super) struct CaptureRun {
    pub text: String,
    pub tip: String,
    /// The run a click opens in Triage.
    pub run_id: Option<String>,
}

/// The label of each packet, kept while the capture and the calls stay.
#[derive(Default)]
pub(super) struct MadeBy {
    path: Option<PathBuf>,
    calls: usize,
    labels: HashMap<u64, Source>,
}

/// The runs a listing was linked against, and what it was linked for.
#[derive(Default)]
pub(super) struct Links {
    runs: Option<Arc<Vec<RunSummary>>>,
    stamp: Vec<(PathBuf, u64, Option<u64>)>,
    pub(super) by_file: HashMap<PathBuf, Provenance>,
}

impl NetworkView {
    /// The runs of the VM, the run Triage has selected and that run's
    /// network calls, once per frame.
    pub(crate) fn set_runs(
        &mut self,
        runs: &Arc<Vec<RunSummary>>,
        triage_run: Option<String>,
        attribution: Option<(String, Arc<NetAttribution>)>,
    ) {
        if !self
            .names_for
            .as_ref()
            .is_some_and(|known| Arc::ptr_eq(known, runs))
        {
            self.run_names = crate::run_link::RunNames::of(runs);
            self.names_for = Some(Arc::clone(runs));
        }
        self.triage_run = triage_run;
        let same = match (&self.attribution, &attribution) {
            (Some((run, held)), Some((id, new))) => run == id && Arc::ptr_eq(held, new),
            (None, None) => true,
            _ => false,
        };
        if !same {
            self.attribution = attribution;
            self.made_by.borrow_mut().labels.clear();
        }
    }

    /// Link every capture of the list (and the running one) to the runs.
    pub(super) fn refresh_links(&mut self, active: Option<&NetworkCapture>) {
        let Some(runs) = self.names_for.clone() else {
            return;
        };
        let mut all: Vec<NetworkCapture> = self.captures.clone();
        if let Some(active) = active
            && !all.iter().any(|capture| capture.file == active.file)
        {
            all.push(active.clone());
        }
        let stamp: Vec<(PathBuf, u64, Option<u64>)> = all
            .iter()
            .map(|capture| (capture.file.clone(), capture.started_ms, capture.stopped_ms))
            .collect();
        let known = self
            .links
            .runs
            .as_ref()
            .is_some_and(|held| Arc::ptr_eq(held, &runs));
        if known && self.links.stamp == stamp {
            return;
        }
        let windows = network_link::run_windows(&runs);
        self.links = Links {
            runs: Some(runs),
            stamp,
            by_file: network_link::capture_links(&all, &windows),
        };
    }

    pub(super) fn link_of(&self, capture: &NetworkCapture) -> Option<&Provenance> {
        self.links.by_file.get(&capture.file)
    }

    /// The Run line of a capture's row and its tooltip.
    pub(super) fn run_line(&self, capture: &NetworkCapture) -> CaptureRun {
        let (run, live, certainty) = self
            .link_of(capture)
            .map_or((None, Vec::new(), Certainty::Unknown), |link| {
                (link.run_id.clone(), link.live_runs.clone(), link.certainty)
            });
        let cell = crate::run_link::cell(run.as_deref(), &live, certainty, &self.run_names);
        let verb = match certainty {
            Certainty::Exact => "Captured during",
            _ => "Captured",
        };
        CaptureRun {
            text: format!("Run: {}", cell.text),
            tip: format!("{verb} the run below.\n{}", cell.tip),
            run_id: cell.run_id,
        }
    }

    /// The attribution that applies to the capture on screen: Triage's run
    /// is linked to it and its calls are loaded.
    fn attribution_here(&self) -> Option<&Arc<NetAttribution>> {
        let (run, attribution) = self.attribution.as_ref()?;
        let path = self.list.path.as_ref()?;
        let link = self.links.by_file.get(path)?;
        link.concerns(run).then_some(attribution)
    }

    /// Whether the packet list has a Made by column.
    pub(super) fn has_made_by(&self) -> bool {
        self.attribution_here().is_some()
    }

    /// What made `packet`: its process, the base image, or nothing known.
    pub(super) fn made_by(&self, packet: &NetworkPacket) -> Option<Source> {
        let attribution = self.attribution_here()?;
        let mut held = self.made_by.borrow_mut();
        if held.path != self.list.path || held.calls != attribution.calls().len() {
            held.path.clone_from(&self.list.path);
            held.calls = attribution.calls().len();
            held.labels.clear();
        }
        if let Some(found) = held.labels.get(&packet.number) {
            return Some(found.clone());
        }
        let (Some(from), Some(to)) = (packet.src_ip, packet.dst_ip) else {
            return Some(Source::Unattributed);
        };
        let source = match packet.transport {
            Some(transport) => attribution.source_of_packet(
                matches!(transport, Transport::Udp),
                [
                    (from, packet.src_port.unwrap_or(0)),
                    (to, packet.dst_port.unwrap_or(0)),
                ],
                packet.time_us,
            ),
            // ICMP and the like carry no ports: no call names them.
            None => Source::Unattributed,
        };
        if held.labels.len() < 100_000 {
            held.labels.insert(packet.number, source.clone());
        }
        Some(source)
    }

    /// The text the `source` quick filter compares and the column shows.
    pub(super) fn made_by_text(&self, packet: &NetworkPacket) -> String {
        self.made_by(packet)
            .map(|source| source.label())
            .unwrap_or_default()
    }
}
