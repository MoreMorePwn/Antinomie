// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's Lineage section: the graph of where the sample came from and
//! what it dropped, downloaded, ran or loaded, merged across its runs, with
//! its bar (system binaries, levels, run filter), a details line for the
//! selected node and the per-run table behind a clicked edge label.
use super::{parts, *};
use antinomie_monitor_core::samples::{
    build_lineage, EdgeKind, Known, LineageGraph, LineageOptions, NodeKind, RunLineage,
};
use std::collections::BTreeSet;

mod canvas;

/// What a click in the section asks of the window.
pub(super) enum Out {
    /// Open another library sample's window.
    OpenSample(String),
    /// Open a run in Triage.
    OpenRun(usize),
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
        }
    }
}

impl State {
    fn options(&self) -> LineageOptions {
        LineageOptions {
            hide_system: self.hide_system,
            parents: self.parents,
            children: self.children,
            run: self.run,
            expanded: self.expanded.clone(),
        }
    }

    /// The graph for the current options and read of the sample.
    fn refresh(&mut self, data: &Data) {
        let options = self.options();
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
        let State {
            cached,
            view,
            selected,
            edge,
            expanded,
            ..
        } = &mut *state;
        let cached = cached.as_ref().expect("just built");
        let hit = canvas::show(
            ui,
            rect,
            &cached.graph,
            &cached.layout,
            view,
            selected.as_deref(),
            edge.as_ref(),
            expanded,
            &sample,
        );
        if let Some(id) = hit.badge {
            if !state.expanded.remove(&id) {
                state.expanded.insert(id);
            }
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
            let summary = EdgeKind::ALL
                .iter()
                .filter_map(|kind| {
                    edge.kinds
                        .get(kind)
                        .map(|n| format!("{} ×{n}", kind.label()))
                })
                .collect::<Vec<_>>()
                .join(" · ");
            ui.label(RichText::new(format!(
                "{summary} · {}",
                antinomie_monitor_core::samples::runs_label(&edge.runs)
            )));
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
            NodeKind::Captured | NodeKind::Lost => {
                ui.add_enabled(false, egui::Button::new("Add to Samples…"))
                    .on_disabled_hover_text(
                        "Needs a saved copy of the file; comes with the file viewer",
                    );
            }
            _ => {}
        }
    });
}
