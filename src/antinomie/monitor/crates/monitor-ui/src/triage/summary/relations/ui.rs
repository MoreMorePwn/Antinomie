// SPDX-License-Identifier: GPL-3.0-only
//! The Relationships box of the Summary and its full-graph window.
use super::super::state::{Mode, State};
use super::super::{panels::boxed, Act};
use super::canvas;
use super::chart;
use super::model::NodeKind;
use super::timeline_view;
use crate::theme;
use eframe::egui::{self, RichText};

/// Height of the graph viewport in the Summary.
const HEIGHT: f32 = 280.0;

/// What a click on a node asks for.
pub(in crate::triage) fn node_act(kind: &NodeKind) -> Act {
    match kind {
        NodeKind::Process(key) => Act::Process(*key),
        NodeKind::File(_) => Act::File,
        NodeKind::Endpoint(_) => Act::Endpoint,
        NodeKind::Victim(_) => Act::Go(super::super::Destination::Findings),
    }
}

pub(in crate::triage) fn show(ui: &mut egui::Ui, state: &mut State, acts: &mut Vec<Act>) {
    let Some(built) = state.built.as_mut() else {
        return;
    };
    let total = built.graph.nodes.len();
    let shown = built.shown.len();
    let mode = std::cell::Cell::new(state.mode);
    let mut open_full = false;
    boxed(
        ui,
        "Relationships",
        acts,
        |ui, _| {
            let mut now = mode.get();
            ui.selectable_value(&mut now, Mode::Graph, "Graph");
            ui.selectable_value(&mut now, Mode::Timeline, "Timeline");
            mode.set(now);
            if now == Mode::Graph {
                if ui
                    .add_enabled(total > 0, egui::Button::new("Open full graph"))
                    .on_hover_text("Every process, file and endpoint of the run, in a window")
                    .clicked()
                {
                    open_full = true;
                }
                crate::mermaid::button(ui, || chart::mermaid(&built.graph, &built.shown));
            }
        },
        |ui, acts| match mode.get() {
            Mode::Graph => {
                if total == 0 {
                    ui.weak("No processes were recorded.");
                    return;
                }
                if shown < total {
                    ui.label(
                        RichText::new(format!(
                            "{shown} of {total} nodes, chosen by their findings. Drag to pan; Ctrl and the wheel zoom."
                        ))
                        .small()
                        .color(theme::muted()),
                    );
                }
                let out = canvas::show(
                    ui,
                    ui.id().with("summary-relations"),
                    &built.graph,
                    &built.small,
                    &mut state.view,
                    HEIGHT,
                    false,
                );
                if let Some(node) = out.clicked {
                    acts.push(node_act(&built.graph.nodes[node].kind));
                }
            }
            Mode::Timeline => {
                if let Some(key) =
                    timeline_view::show(ui, ui.id().with("summary-timeline"), &built.timeline)
                {
                    acts.push(Act::Process(key));
                }
            }
        },
    );
    state.mode = mode.get();
    if open_full {
        state.full_open = true;
    }
}

/// The window with every node.
pub(in crate::triage) fn window(ctx: &egui::Context, state: &mut State, acts: &mut Vec<Act>) {
    if !state.full_open {
        return;
    }
    let mut open = true;
    let Some(built) = state.built.as_mut() else {
        return;
    };
    built.full_layout();
    let Some(layout) = built.full.as_ref() else {
        return;
    };
    crate::widgets::window("Relationships")
        .id(egui::Id::new("summary-relations-window"))
        .open(&mut open)
        .default_size(egui::vec2(900.0, 620.0))
        .show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{} nodes, {} edges",
                        built.graph.nodes.len(),
                        built.graph.edges.len()
                    ))
                    .color(theme::muted()),
                );
                let all: Vec<usize> = (0..built.graph.nodes.len()).collect();
                crate::mermaid::button(ui, || chart::mermaid(&built.graph, &all));
            });
            let height = (ui.available_height() - 8.0).max(200.0);
            let out = canvas::show(
                ui,
                egui::Id::new("summary-relations-full"),
                &built.graph,
                layout,
                &mut state.full_view,
                height,
                true,
            );
            if let Some(node) = out.clicked {
                acts.push(node_act(&built.graph.nodes[node].kind));
            }
        });
    state.full_open = open;
}
