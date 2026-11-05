// SPDX-License-Identifier: GPL-3.0-only
//! The Relationships box of the Summary: the Compact view (the best of each
//! kind) and the Full view (every node), both in the box.
use super::super::state::{Mode, State};
use super::super::{panels::boxed, Act};
use super::canvas;
use super::chart;
use super::model::NodeKind;
use crate::theme;
use eframe::egui::{self, RichText};

/// Height of the graph viewport in the Summary.
const HEIGHT: f32 = 340.0;

/// What a click on a node asks for.
pub(in crate::triage) fn node_act(kind: &NodeKind) -> Act {
    match kind {
        NodeKind::Process(key) => Act::Process(*key),
        NodeKind::File(_) => Act::File,
        NodeKind::Endpoint(_) => Act::Endpoint,
        NodeKind::Victim(_) => Act::Go(super::super::Destination::Findings),
    }
}

/// Height of the Full view's viewport.
const FULL_HEIGHT: f32 = 560.0;

pub(in crate::triage) fn show(ui: &mut egui::Ui, state: &mut State, acts: &mut Vec<Act>) {
    let Some(built) = state.built.as_mut() else {
        return;
    };
    built.full_layout();
    let total = built.graph.nodes.len();
    let mode = std::cell::Cell::new(state.mode);
    boxed(
        ui,
        "Relationships",
        acts,
        |ui, _| {
            let mut now = mode.get();
            ui.selectable_value(&mut now, Mode::Compact, "Compact")
                .on_hover_text("The best 15 processes, files and endpoints, with what joins them");
            ui.selectable_value(&mut now, Mode::Full, "Full")
                .on_hover_text("Every process, file and endpoint of the run");
            mode.set(now);
            let full = now == Mode::Full;
            let all: Vec<usize> = (0..total).collect();
            crate::mermaid::button(ui, || {
                chart::mermaid(&built.graph, if full { &all } else { &built.shown })
            });
        },
        |ui, acts| {
            if total == 0 {
                ui.weak("No processes were recorded.");
                return;
            }
            let (layout, view, height, id) = match mode.get() {
                Mode::Compact => (&built.compact, &mut state.view, HEIGHT, "summary-relations"),
                Mode::Full => (
                    built.full.as_ref().unwrap_or(&built.compact),
                    &mut state.full_view,
                    FULL_HEIGHT,
                    "summary-relations-full",
                ),
            };
            let shown = layout.at.len();
            ui.label(
                RichText::new(format!(
                    "{shown} of {total} nodes. Processes to the right, files below, network to the left. Drag to pan; Ctrl and the wheel zoom."
                ))
                .small()
                .color(theme::muted()),
            );
            let out = canvas::show(ui, ui.id().with(id), &built.graph, layout, view, height);
            if let Some(node) = out.clicked {
                acts.push(node_act(&built.graph.nodes[node].kind));
            }
        },
    );
    state.mode = mode.get();
}
