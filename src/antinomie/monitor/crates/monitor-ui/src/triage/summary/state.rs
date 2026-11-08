// SPDX-License-Identifier: GPL-3.0-only
//! What the Summary keeps between frames: the Relationships box's choices, the
//! lists' open states and the derived data (graph, layout, indicators,
//! candidates), rebuilt only when the scan or the detections change.
use super::super::{digest, net_tabs, rules::Tier, ArchiveScan, TriageView};
use super::indicators::Indicators;
use super::insight::{self, Key as KeyFinding};
use super::relations::fold::FoldGraph;
use super::relations::{
    canvas,
    facts::facts_of,
    fold,
    group::Rendered,
    model::{self, Graph, Interest},
};
use crate::triage::family::{self, Candidate};
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
/// thread when the graph is big. The one shown stays on screen while the
/// next is made.
#[derive(Default)]
struct Full {
    made: Option<(BTreeSet<String>, Box<Rendered>)>,
    making: Option<(BTreeSet<String>, mpsc::Receiver<Rendered>)>,
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
    /// The Full view's open nodes (see `fold`), for the run: shared by the
    /// box and the window, kept when the mode changes.
    pub open: BTreeSet<String>,
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
    /// The Compact view's groups the reader opened.
    pub toggled: BTreeSet<String>,
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

    pub(super) fn of(
        view: &TriageView,
        scan: &ArchiveScan,
        packed: bool,
        specimen: Option<&str>,
    ) -> Self {
        let key = format!("{}|{}", scan_key(scan), detection_key(view));
        let facts = facts_of(scan);
        let graph = Graph::build(&facts);
        let compact = Rendered::compact(&graph, &BTreeSet::new(), PER_KIND);
        let open = graph.default_open();
        let hits = digest::detections(&view.detection.results).unwrap_or_default();
        let geo = |endpoint: &str| -> (String, String) {
            scan.new_tabs
                .endpoints
                .iter()
                .find(|row| row.first().is_some_and(|cell| cell.text == endpoint))
                .map(|row| {
                    let text = |at: usize| row.get(at).map(|c| c.text.clone()).unwrap_or_default();
                    (
                        text(net_tabs::ENDPOINT_COUNTRY),
                        text(net_tabs::ENDPOINT_ORGANIZATION),
                    )
                })
                .unwrap_or_default()
        };
        let indicators = scan
            .ioc
            .as_ref()
            .map(|ioc| Indicators::of(&ioc.indicators, geo))
            .unwrap_or_default();
        let bazaar = specimen
            .zip(view.scan_request.data_dir.as_deref())
            .and_then(|(sha256, dir)| antinomie_monitor_core::samples::recorded_info(dir, sha256));
        let candidates = family::family_candidates(
            &hits,
            bazaar
                .as_ref()
                .map(|info| family::Bazaar {
                    signature: info.signature.as_deref(),
                    tags: &info.tags,
                })
                .unwrap_or_default(),
        );
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
            full: Full::default(),
            open,
            indicators,
            key_total,
            keys,
            candidates,
            tags,
            interest,
        }
    }

    /// Make what `mode` shows ready: Compact for `toggled` at once, Full for
    /// the open nodes when it is first shown or they change; on a thread for
    /// a big graph.
    pub(super) fn prepare(&mut self, mode: Mode, toggled: &BTreeSet<String>, ctx: &egui::Context) {
        match mode {
            Mode::Compact => {
                if self.compact_toggled != *toggled {
                    self.compact = Rendered::compact(&self.graph, toggled, PER_KIND);
                    self.compact_toggled = toggled.clone();
                }
            }
            Mode::Full => self.prepare_full(ctx),
        }
    }

    fn prepare_full(&mut self, ctx: &egui::Context) {
        if let Some((wanted, rx)) = &self.full.making {
            match rx.try_recv() {
                Ok(rendered) => {
                    self.full.made = Some((wanted.clone(), Box::new(rendered)));
                    self.full.making = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    if *wanted == self.open {
                        ctx.request_repaint_after(std::time::Duration::from_millis(60));
                        return;
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => self.full.making = None,
            }
        }
        if let Some((made, rendered)) = &self.full.made {
            if *made == self.open {
                return;
            }
            // Only nodes opened or closed, no group: the grouped graph stays.
            if !fold::groups_differ(made, &self.open) {
                let next = rendered.refold(&self.open);
                self.full.made = Some((self.open.clone(), Box::new(next)));
                self.full.making = None;
                return;
            }
        }
        if self.graph.nodes.len() + self.graph.edges.len() <= MAKE_HERE {
            let rendered = Rendered::full(&self.graph, &self.open);
            self.full.made = Some((self.open.clone(), Box::new(rendered)));
            self.full.making = None;
            return;
        }
        let (graph, wanted, repaint) = (self.graph.clone(), self.open.clone(), ctx.clone());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rendered = Rendered::full(&graph, &wanted);
            let _ = tx.send(rendered);
            repaint.request_repaint();
        });
        self.full.making = Some((self.open.clone(), rx));
        ctx.request_repaint_after(std::time::Duration::from_millis(60));
    }

    /// What `mode` shows, once `prepare` has made it.
    pub(super) fn rendered(&self, mode: Mode) -> Option<&Rendered> {
        match mode {
            Mode::Compact => Some(&self.compact),
            Mode::Full => self.full.made.as_ref().map(|(_, rendered)| &**rendered),
        }
    }

    /// Open the node `id` if it is closed, close it if it is open.
    pub(super) fn flip(&mut self, id: &str) {
        if !self.open.remove(id) {
            self.open.insert(id.to_owned());
        }
    }

    /// Open everything (the view still draws about 800 nodes).
    pub(super) fn expand_all(&mut self) {
        self.open = self.graph.expanded(super::relations::group::FULL_CAP);
    }

    /// Back to the root, the paths to the findings and what is under them.
    pub(super) fn collapse_all(&mut self) {
        self.open = self.graph.default_open();
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
