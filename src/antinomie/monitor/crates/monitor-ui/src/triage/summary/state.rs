// SPDX-License-Identifier: GPL-3.0-only
//! What the Summary keeps between frames: the Relationships box's choices, the
//! lists' open states and the derived data (graph, layout, indicators,
//! candidates), rebuilt only when the scan or the detections change.
use super::super::{digest, rules::Tier, ArchiveScan, TriageView};
use super::indicators::Indicators;
use super::insight::{self, Candidate, Key as KeyFinding};
use super::relations::{
    canvas,
    facts::facts_of,
    layout::Layout,
    model::{self, Graph, Interest},
};
use antinomie_monitor_core::analysis::detection::State as Scanned;

/// Processes, files and endpoints each the Compact view shows at most.
pub(super) const PER_KIND: usize = 15;

/// What the Relationships box shows: the best of each kind, or all of it.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(in crate::triage) enum Mode {
    #[default]
    Compact,
    Full,
}

/// Everything derived from the scan and the detections.
pub(super) struct Built {
    key: String,
    pub graph: Graph,
    pub shown: Vec<usize>,
    pub compact: Layout,
    pub full: Option<Layout>,
    pub indicators: Indicators,
    pub key_total: usize,
    pub keys: Vec<KeyFinding>,
    pub candidates: Vec<Candidate>,
    pub tags: Vec<&'static str>,
    pub mismatches: usize,
    pub interest: Vec<Interest>,
}

#[derive(Default)]
pub(in crate::triage) struct State {
    pub mode: Mode,
    pub view: canvas::View,
    pub full_view: canvas::View,
    /// Key findings: every finding in a scrolling list.
    pub keys_open: bool,
    /// Indicators: the categories listed past their first few.
    pub more: [bool; 4],
    /// The last Copy or Export said in words.
    pub status: Option<String>,
    pub(super) built: Option<Built>,
    pub thumb: super::thumb::Thumb,
    /// The run's screenshot was clicked: the app opens it.
    pub open_screenshot: Option<std::path::PathBuf>,
}

/// What the detections of the run were when `Built` was made.
fn detection_key(view: &TriageView) -> String {
    view.detection
        .results
        .iter()
        .map(|result| match result {
            None => "n".to_owned(),
            Some(Err(_)) => "e".to_owned(),
            Some(Ok(report)) => format!(
                "{}{}",
                report.findings.len(),
                matches!(report.state, Scanned::Complete | Scanned::Partial)
            ),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn scan_key(scan: &ArchiveScan) -> String {
    format!(
        "{}|{}|{}|{}",
        scan.stamp,
        scan.findings.len(),
        scan.process.len(),
        scan.ioc.is_some()
    )
}

impl Built {
    pub(super) fn current(&self, view: &TriageView, scan: &ArchiveScan) -> bool {
        self.key == format!("{}|{}", scan_key(scan), detection_key(view))
    }

    pub(super) fn of(view: &TriageView, scan: &ArchiveScan, packed: bool) -> Self {
        let key = format!("{}|{}", scan_key(scan), detection_key(view));
        let facts = facts_of(scan);
        let graph = Graph::build(&facts);
        let shown = graph.compact(PER_KIND);
        let compact = Layout::of(&graph, &shown);
        let hits = digest::detections(&view.detection.results).unwrap_or_default();
        let geo = |endpoint: &str| -> (String, String) {
            scan.new_tabs
                .endpoints
                .iter()
                .find(|row| row.first().is_some_and(|cell| cell.text == endpoint))
                .map(|row| {
                    let text = |at: usize| row.get(at).map(|c| c.text.clone()).unwrap_or_default();
                    (text(4), text(5))
                })
                .unwrap_or_default()
        };
        let indicators = scan
            .ioc
            .as_ref()
            .map(|ioc| Indicators::of(&ioc.indicators, geo))
            .unwrap_or_default();
        let candidates = insight::family_candidates(&hits);
        let mut names: Vec<String> = hits.iter().map(|hit| hit.title.clone()).collect();
        names.extend(hits.iter().map(|hit| hit.family.clone()));
        names.extend(candidates.iter().map(|candidate| candidate.name.clone()));
        let tags = insight::behaviour_tags(&insight::TagInput {
            findings: insight::tag_findings(&scan.findings),
            names,
            packed,
        });
        let (key_total, keys) = insight::key_findings(&scan.findings, usize::MAX);
        let mismatches = facts.procs.iter().filter(|proc| proc.mismatch).count();
        let interest = model::interest(&facts, 5);
        Self {
            key,
            graph,
            shown,
            compact,
            full: None,
            indicators,
            key_total,
            keys,
            candidates,
            tags,
            mismatches,
            interest,
        }
    }

    /// The layout of the whole graph, made when Full is first shown.
    pub(super) fn full_layout(&mut self) -> &Layout {
        let (graph, full) = (&self.graph, &mut self.full);
        full.get_or_insert_with(|| {
            let all: Vec<usize> = (0..graph.nodes.len()).collect();
            Layout::of(graph, &all)
        })
    }
}

/// Counts of the four tiers as tiles: HIGH, MEDIUM, LOW, info.
pub(super) fn tier_tiles(tiers: [u64; 4]) -> [(Tier, u64); 4] {
    [
        (Tier::High, tiers[Tier::High.index()]),
        (Tier::Medium, tiers[Tier::Medium.index()]),
        (Tier::Low, tiers[Tier::Low.index()]),
        (Tier::Info, tiers[Tier::Info.index()]),
    ]
}
