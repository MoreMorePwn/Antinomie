// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's Lineage section: the graph of where the sample came from and
//! what it dropped, downloaded, ran or loaded, merged across its runs, with
//! its bar (system binaries, levels, run filter), a details line for the
//! selected node and the per-run table behind a clicked edge label.
use super::{parts, *};
use antinomie_monitor_core::samples::{
    build_lineage, EdgeKind, Known, LineageGraph, LineageOptions, NodeKind, NoteRef, RefKind,
    RunLineage,
};
use std::collections::BTreeSet;

mod canvas;
mod labels;

/// What a click in the section asks of the window.
pub(super) enum Out {
    /// Open another library sample's window.
    OpenSample(String),
    /// Open a run in Triage.
    OpenRun(usize),
    /// Promote a file of the runs into the library.
    Promote {
        path: String,
        sha256: String,
        /// The image that wrote it, when an edge says so.
        writer: String,
        /// The runs it was seen in, ascending.
        runs: Vec<usize>,
    },
}

/// The graph's options and view, kept while the window is open.
pub(super) struct State {
    hide_system: bool,
    parents: usize,
    children: usize,
    run: Option<usize>,
    expanded: BTreeSet<String>,
    selected: Option<String>,
    edge: Option<(String, String)>,
    view: canvas::View,
    cached: Option<Cached>,
    /// The node the right-click menu is open on.
    context: Option<String>,
    /// The node that keeps its place on screen when the layout changes: the
    /// one just expanded or collapsed, else the sample.
    anchor: Option<String>,
    /// A node a note's chip asked for: shown, selected and centred at the
    /// next draw.
    centre: Option<String>,
    /// Where each node's centre was in the viewport at the last draw.
    screen: std::collections::BTreeMap<String, egui::Vec2>,
}

struct Cached {
    options: LineageOptions,
    /// Which read of the sample it was built from.
    data: *const Data,
    graph: LineageGraph,
    layout: canvas::Layout,
}

impl Default for State {
    fn default() -> Self {
        Self {
            hide_system: true,
            parents: 1,
            children: 1,
            run: None,
            expanded: BTreeSet::new(),
            selected: None,
            edge: None,
            view: canvas::View::default(),
            cached: None,
            context: None,
            anchor: None,
            centre: None,
            screen: std::collections::BTreeMap::new(),
        }
    }
}

impl State {
    /// Show, select and centre the node `id` at the next draw.
    pub(super) fn focus_node(&mut self, id: &str) {
        self.selected = Some(id.to_owned());
        self.centre = Some(id.to_owned());
    }

    /// Bring the node asked for by `focus_node` into the graph (more levels,
    /// system binaries shown) and centre the view on it.
    fn apply_focus(&mut self, data: &Data, viewport: egui::Vec2) {
        let Some(id) = self.centre.take() else {
            return;
        };
        let mut more = 0;
        while !self
            .cached
            .as_ref()
            .is_some_and(|cached| cached.layout.at.contains_key(&id))
            && more < 6
        {
            self.parents += 1;
            self.children += 1;
            self.hide_system = false;
            self.refresh(data);
            more += 1;
        }
        if let Some(at) = self
            .cached
            .as_ref()
            .and_then(|cached| cached.layout.at.get(&id))
        {
            self.view.offset = viewport * 0.5 - at.center().to_vec2() * self.view.zoom;
            self.view.fitted = true;
        }
    }

    fn options(&self, data: &Data) -> LineageOptions {
        LineageOptions {
            system: Arc::clone(&data.system),
            hide_system: self.hide_system,
            parents: self.parents,
            children: self.children,
            run: self.run,
            expanded: self.expanded.clone(),
        }
    }

    /// The graph for the current options and read of the sample.
    fn refresh(&mut self, data: &Data) {
        let options = self.options(data);
        let stale = self
            .cached
            .as_ref()
            .is_none_or(|cached| cached.options != options || !std::ptr::eq(cached.data, data));
        if stale {
            let runs: Vec<RunLineage<'_>> = data
                .runs
                .iter()
                .map(|entry| RunLineage {
                    number: entry.number,
                    sample: entry
                        .run
                        .request
                        .sample
                        .as_ref()
                        .map_or("", |sample| sample.sha256.as_str()),
                    sample_path: entry.run.request.path.as_str(),
                    lineage: entry
                        .digest
                        .as_ref()
                        .and_then(|digest| digest.lineage.as_ref()),
                })
                .collect();
            let known = |sha: &str| {
                data.known.get(sha).map(|(name, verdict)| Known {
                    name: name.clone(),
                    verdict: verdict.clone(),
                })
            };
            let graph = build_lineage(&data.record.sha256, &runs, &data.links, &known, &options);
            let layout = canvas::Layout::of(&graph);
            // A level or node was added or removed: the anchor stays where it
            // was on screen, the rest of the graph moves around it.
            let toggled = self
                .cached
                .as_ref()
                .is_some_and(|cached| cached.options.expanded != options.expanded);
            let anchor = match (&self.anchor, toggled) {
                (Some(id), true) => id.clone(),
                _ => data.record.sha256.clone(),
            };
            if self.cached.is_some() && self.view.fitted {
                if let (Some(at), Some(rect)) = (self.screen.get(&anchor), layout.at.get(&anchor)) {
                    self.view.offset = *at - rect.center().to_vec2() * self.view.zoom;
                }
            }
            self.cached = Some(Cached {
                options,
                data: data as *const Data,
                graph,
                layout,
            });
        }
    }
}

#[cfg(test)]
impl State {
    pub(super) fn set_levels(&mut self, parents: usize, children: usize, hide: bool) {
        self.parents = parents;
        self.children = children;
        self.hide_system = hide;
    }

    /// The graph for the current options.
    pub(super) fn graph_for_test(&mut self, data: &Data) -> Option<LineageGraph> {
        self.refresh(data);
        self.cached.as_ref().map(|cached| cached.graph.clone())
    }
}

impl State {
    /// Expand or collapse one node's neighbours; it keeps its place.
    fn toggle(&mut self, id: String) {
        self.anchor = Some(id.clone());
        if !self.expanded.remove(&id) {
            self.expanded.insert(id);
        }
    }
}

/// What the right-click menu of a node asks for.
enum Act {
    Open(String),
    Promote(Out),
    Toggle(String),
}

/// The Add to Samples… request for a file seen in runs: where it was, the
/// runs it was in and the program that wrote it.
fn promote_out(graph: &LineageGraph, node: &antinomie_monitor_core::samples::LineageNode) -> Out {
    let mut runs: Vec<usize> = graph
        .edges
        .iter()
        .filter(|edge| edge.from == node.id || edge.to == node.id)
        .flat_map(|edge| edge.runs.iter().copied())
        .collect();
    runs.sort_unstable();
    runs.dedup();
    let writer = graph
        .edges
        .iter()
        .filter(|edge| edge.to == node.id && edge.kinds.contains_key(&EdgeKind::Dropped))
        .find_map(|edge| graph.nodes.iter().find(|n| n.id == edge.from))
        .map(|parent| parent.path.clone())
        .unwrap_or_default();
    Out::Promote {
        path: node.path.clone(),
        sha256: node.sha256.clone(),
        writer,
        runs,
    }
}

/// The right-click menu of a node.
fn node_menu(
    ui: &mut egui::Ui,
    node: &antinomie_monitor_core::samples::LineageNode,
    graph: &LineageGraph,
    data: &Data,
    expanded: &BTreeSet<String>,
    act: &mut Option<Act>,
) {
    if matches!(node.kind, NodeKind::Library { .. })
        && node.id != data.record.sha256
        && ui.button("Open sample").clicked()
    {
        *act = Some(Act::Open(node.id.clone()));
        ui.close_menu();
    }
    if matches!(node.kind, NodeKind::Captured | NodeKind::Lost)
        && !node.path.is_empty()
        && ui.button("Add to Samples…").clicked()
    {
        *act = Some(Act::Promote(promote_out(graph, node)));
        ui.close_menu();
    }
    if matches!(node.kind, NodeKind::Command) && ui.button("Copy command line").clicked() {
        ui.ctx().copy_text(node.path.clone());
        ui.close_menu();
    }
    if !node.sha256.is_empty() && ui.button("Copy SHA-256").clicked() {
        ui.ctx().copy_text(node.sha256.clone());
        ui.close_menu();
    }
    let hidden = node.hidden_parents + node.hidden_children;
    if hidden > 0 {
        if ui.button(format!("Expand (+{hidden})")).clicked() {
            *act = Some(Act::Toggle(node.id.clone()));
            ui.close_menu();
        }
    } else if expanded.contains(&node.id) && ui.button("Collapse").clicked() {
        *act = Some(Act::Toggle(node.id.clone()));
        ui.close_menu();
    }
    if node.id != data.record.sha256 {
        super::notes::menu_item(ui, || {
            NoteRef::new(RefKind::Lineage, node.id.clone(), node.label.clone())
        });
    }
}

/// "dropped ×4 · executed ×4 · 4 runs": what an edge label stands for.
pub(super) fn edge_summary(edge: &antinomie_monitor_core::samples::LineageEdge) -> String {
    let kinds = EdgeKind::ALL
        .iter()
        .filter_map(|kind| {
            edge.kinds
                .get(kind)
                .map(|n| format!("{} ×{n}", kind.label()))
        })
        .collect::<Vec<_>>()
        .join(" · ");
    format!(
        "{kinds} · {}",
        antinomie_monitor_core::samples::runs_label(&edge.runs)
    )
}

fn stepper(ui: &mut egui::Ui, label: &str, value: &mut usize, max: usize) {
    ui.label(RichText::new(label).color(theme::muted()));
    if ui
        .add_enabled(*value > 0, egui::Button::new("−").small())
        .on_hover_text(format!("One level fewer of {}", label.to_lowercase()))
        .clicked()
    {
        *value -= 1;
    }
    ui.label(value.to_string());
    if ui
        .add_enabled(*value < max, egui::Button::new("+").small())
        .on_hover_text(if *value < max {
            format!("One more level of {}", label.to_lowercase())
        } else {
            "No deeper level exists".to_owned()
        })
        .clicked()
    {
        *value += 1;
    }
}

/// Draw the section; returns a click for the window to carry out.
pub(super) fn section(ui: &mut egui::Ui, state: &mut State, data: &Data) -> Option<Out> {
    let mut out = None;
    parts::section(ui, "Lineage", None, |ui| {
        let triaged = data.rollup.triaged;
        let has_lineage = data
            .runs
            .iter()
            .any(|entry| entry.digest.as_ref().is_some_and(|d| d.lineage.is_some()));
        if !has_lineage && data.links.is_empty() {
            parts::muted_line(
                ui,
                if data.runs.is_empty() {
                    "Never run."
                } else if triaged == 0 {
                    "Not triaged yet."
                } else {
                    "No lineage recorded for these runs."
                },
            );
            return;
        }
        let (hidden, max_parents, max_children) = {
            state.refresh(data);
            let graph = &state.cached.as_ref().expect("just built").graph;
            (graph.hidden_system, graph.max_parents, graph.max_children)
        };
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut state.hide_system, "Hide system binaries")
                .on_hover_text(
                    "Programs of the base image (a system path, a known hash, never written by a run) are left out; what they did is shown under the program that ran them",
                );
            if state.hide_system && hidden > 0 {
                ui.label(RichText::new(format!("{hidden} hidden")).small().color(theme::muted()));
            }
            ui.separator();
            stepper(ui, "Parents", &mut state.parents, max_parents);
            stepper(ui, "Children", &mut state.children, max_children);
            ui.separator();
            let label = state.run.map_or("All runs".to_owned(), parts::run_name);
            egui::ComboBox::from_id_salt("sample_lineage_run")
                .selected_text(label)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut state.run, None, "All runs");
                    for entry in data.runs.iter().rev() {
                        ui.selectable_value(
                            &mut state.run,
                            Some(entry.number),
                            parts::run_name(entry.number),
                        );
                    }
                });
        });
        ui.horizontal(canvas::legend);
        let width = ui.available_width();
        let rect = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(width, canvas::HEIGHT));
        let sample = data.record.sha256.clone();
        // Read the graph again when an option changed this frame.
        state.refresh(data);
        state.apply_focus(data, rect.size());
        let mut act = None;
        let (hit, screen) = {
            let State {
                cached,
                view,
                selected,
                edge,
                expanded,
                context,
                ..
            } = &mut *state;
            let cached = cached.as_ref().expect("just built");
            let expanded: &BTreeSet<String> = expanded;
            let graph = &cached.graph;
            let mut menu =
                |ui: &mut egui::Ui, node: &antinomie_monitor_core::samples::LineageNode| {
                    node_menu(ui, node, graph, data, expanded, &mut act);
                };
            let hit = canvas::show(
                ui,
                rect,
                graph,
                &cached.layout,
                view,
                selected.as_deref(),
                edge.as_ref(),
                expanded,
                &sample,
                context,
                &mut menu,
            );
            let screen: std::collections::BTreeMap<String, egui::Vec2> = cached
                .layout
                .at
                .iter()
                .map(|(id, at)| (id.clone(), view.offset + at.center().to_vec2() * view.zoom))
                .collect();
            (hit, screen)
        };
        state.screen = screen;
        match act {
            Some(Act::Open(id)) => out = Some(Out::OpenSample(id)),
            Some(Act::Promote(promote)) => out = Some(promote),
            Some(Act::Toggle(id)) => state.toggle(id),
            None => {}
        }
        if let Some(id) = hit.badge {
            state.toggle(id);
        } else if let Some(edge) = hit.edge {
            state.edge = Some(edge);
        } else if let Some(id) = hit.node {
            state.selected = Some(id);
            state.edge = None;
        } else if hit.background {
            state.selected = None;
            state.edge = None;
        }
        if let Some(id) = hit.open {
            if data.known.contains_key(&id) && id != sample {
                out = Some(Out::OpenSample(id));
            }
        }
        ui.add_space(4.0);
        details(ui, state, data, &mut out);
    });
    out
}

/// The line under the graph: the selected node's path and hashes, or the
/// table of the selected edge.
fn details(ui: &mut egui::Ui, state: &mut State, data: &Data, out: &mut Option<Out>) {
    let Some(cached) = state.cached.as_ref() else {
        return;
    };
    if let Some((from, to)) = &state.edge {
        if let Some(edge) = cached
            .graph
            .edges
            .iter()
            .find(|edge| edge.from == *from && edge.to == *to)
        {
            ui.label(RichText::new(edge_summary(edge)));
            if edge.per_run.is_empty() {
                parts::muted_line(ui, "Seen in the library's origins, not in a run.");
            }
            egui::Grid::new("sample_lineage_edge")
                .striped(true)
                .show(ui, |ui| {
                    ui.label(RichText::new("Run").color(theme::muted()));
                    for kind in EdgeKind::ALL
                        .iter()
                        .filter(|kind| edge.kinds.contains_key(kind))
                    {
                        ui.label(RichText::new(kind.label()).color(theme::muted()));
                    }
                    ui.end_row();
                    for (number, kinds) in &edge.per_run {
                        if widgets::link(ui, parts::run_name(*number)).clicked() {
                            *out = Some(Out::OpenRun(*number));
                        }
                        for kind in EdgeKind::ALL
                            .iter()
                            .filter(|kind| edge.kinds.contains_key(kind))
                        {
                            ui.label(kinds.get(kind).map_or("–".to_owned(), u32::to_string));
                        }
                        ui.end_row();
                    }
                });
            return;
        }
    }
    let Some(node) = state
        .selected
        .as_ref()
        .and_then(|id| cached.graph.nodes.iter().find(|node| node.id == *id))
    else {
        parts::muted_line(
            ui,
            "Click a node for its path and hash, a label for its runs.",
        );
        return;
    };
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(&node.label).strong());
        if !node.path.is_empty() {
            ui.label(RichText::new(&node.path).monospace().small());
        }
        if node.sha256.is_empty() {
            ui.label(theme::hint_text("hash unknown"));
        } else {
            ui.label(RichText::new(&node.sha256).monospace().small());
            if ui
                .small_button(egui_phosphor::regular::COPY)
                .on_hover_text("Copy SHA-256")
                .clicked()
            {
                ui.ctx().copy_text(node.sha256.clone());
            }
        }
        match &node.kind {
            NodeKind::Library { .. } if node.id != data.record.sha256 => {
                if widgets::link(ui, "Open sample ›").clicked() {
                    *out = Some(Out::OpenSample(node.id.clone()));
                }
            }
            NodeKind::Captured | NodeKind::Lost if !node.path.is_empty() => {
                let ask = ui
                    .button("Add to Samples…")
                    .on_hover_text("Read the file from a run's saved disk and add it")
                    .clicked();
                if ask {
                    *out = Some(promote_out(&cached.graph, node));
                }
            }
            _ => {}
        }
    });
}

#[cfg(test)]
mod default_tests {
    use super::*;

    #[test]
    fn system_binaries_are_hidden_until_the_box_is_unticked() {
        // The spec's round 4 decision: the graph opens without them.
        assert!(State::default().hide_system);
        assert!(LineageOptions::default().hide_system);
    }
}
