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
    group::Rendered,
    model::{self, Graph, Interest},
};
use antinomie_monitor_core::analysis::detection::State as Scanned;
use eframe::egui;
use std::collections::BTreeSet;
use std::sync::{mpsc, Arc};

/// Processes, files and endpoints each the Compact view shows at most.
pub(super) const PER_KIND: usize = 15;

/// What the Relationships box shows: the best of each kind, or all of it.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(in crate::triage) enum Mode {
    #[default]
    Compact,
    Full,
}

/// The Full view: not made until it is first shown, and made off the UI
/// thread when the graph is big.
enum Full {
    Unmade,
    Making(BTreeSet<String>, mpsc::Receiver<Rendered>),
    Made(BTreeSet<String>, Rendered),
}

/// A graph with fewer nodes and edges than this lays out inside a frame.
const MAKE_HERE: usize = 3000;

/// Everything derived from the scan and the detections.
pub(super) struct Built {
    key: String,
    pub graph: Arc<Graph>,
    compact: Rendered,
    compact_toggled: BTreeSet<String>,
    full: Full,
    pub indicators: Indicators,
    pub key_total: usize,
    pub keys: Vec<KeyFinding>,
    pub candidates: Vec<Candidate>,
    pub tags: Vec<&'static str>,
    pub interest: Vec<Interest>,
}

#[derive(Default)]
pub(in crate::triage) struct State {
    pub mode: Mode,
    pub view: canvas::View,
    pub full_view: canvas::View,
    /// The groups the reader flipped from how a view starts (Compact shut,
    /// Full open), one set per mode.
    pub toggled: [BTreeSet<String>; 2],
    /// The Relationships window is open, with its own pan and zoom.
    pub window_open: bool,
    /// The run it was opened for; it closes when another run is shown.
    pub window_run: Option<String>,
    pub window_view: canvas::View,
    pub window_full_view: canvas::View,
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
        let compact = Rendered::compact(&graph, &BTreeSet::new(), PER_KIND);
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
        let interest = model::interest(&facts, 5);
        Self {
            key,
            graph: Arc::new(graph),
            compact,
            compact_toggled: BTreeSet::new(),
            full: Full::Unmade,
            indicators,
            key_total,
            keys,
            candidates,
            tags,
            interest,
        }
    }

    /// Make what `mode` shows ready for `toggled`: Compact at once, Full
    /// when it is first shown, on a thread for a big graph.
    pub(super) fn prepare(&mut self, mode: Mode, toggled: &BTreeSet<String>, ctx: &egui::Context) {
        match mode {
            Mode::Compact => {
                if self.compact_toggled != *toggled {
                    self.compact = Rendered::compact(&self.graph, toggled, PER_KIND);
                    self.compact_toggled = toggled.clone();
                }
            }
            Mode::Full => self.prepare_full(toggled, ctx),
        }
    }

    fn prepare_full(&mut self, toggled: &BTreeSet<String>, ctx: &egui::Context) {
        if let Full::Making(wanted, rx) = &self.full {
            match rx.try_recv() {
                Ok(rendered) => self.full = Full::Made(wanted.clone(), rendered),
                Err(mpsc::TryRecvError::Empty) => {
                    if wanted == toggled {
                        ctx.request_repaint_after(std::time::Duration::from_millis(60));
                        return;
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => self.full = Full::Unmade,
            }
        }
        if matches!(&self.full, Full::Made(made, _) if made == toggled) {
            return;
        }
        if self.graph.nodes.len() + self.graph.edges.len() <= MAKE_HERE {
            self.full = Full::Made(toggled.clone(), Rendered::full(&self.graph, toggled));
            return;
        }
        let (graph, wanted, repaint) = (self.graph.clone(), toggled.clone(), ctx.clone());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rendered = Rendered::full(&graph, &wanted);
            let _ = tx.send(rendered);
            repaint.request_repaint();
        });
        self.full = Full::Making(toggled.clone(), rx);
        ctx.request_repaint_after(std::time::Duration::from_millis(60));
    }

    /// What `mode` shows, once `prepare` has made it.
    pub(super) fn rendered(&self, mode: Mode) -> Option<&Rendered> {
        match mode {
            Mode::Compact => Some(&self.compact),
            Mode::Full => match &self.full {
                Full::Made(_, rendered) => Some(rendered),
                _ => None,
            },
        }
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
