// SPDX-License-Identifier: GPL-3.0-only
//! The Relationships box of the Summary: the Compact view (the best of each
//! kind) and the Full view (every group open, up to a cap), both in the box,
//! and the same graph in a window of its own.
use super::super::state::{Built, Mode, State};
use super::super::{panels::boxed, Act};
use super::canvas;
use super::chart;
use super::model::NodeKind;
use crate::theme;
use eframe::egui::{self, RichText};
use std::collections::BTreeSet;

/// Height of the graph viewport in the Summary.
const HEIGHT: f32 = 340.0;
/// Height of the Full view's viewport.
const FULL_HEIGHT: f32 = 560.0;

/// What a click on a node asks for.
pub(in crate::triage) fn node_act(kind: &NodeKind) -> Act {
    match kind {
        NodeKind::Process(key) => Act::Process(*key),
        NodeKind::File(_) => Act::File,
        NodeKind::Endpoint(_) => Act::Endpoint,
        NodeKind::Victim(_) => Act::Go(super::super::Destination::Findings),
        // A group opens or shuts; it is handled where it is clicked.
        NodeKind::Group(_) => Act::Go(super::super::Destination::Findings),
    }
}

fn slot(mode: Mode) -> usize {
    match mode {
        Mode::Compact => 0,
        Mode::Full => 1,
    }
}

/// Compact | Full, Mermaid and, in the box, the button that opens the window.
fn header(ui: &mut egui::Ui, mode: &mut Mode, built: &Built, pop_out: bool) -> bool {
    ui.selectable_value(mode, Mode::Compact, "Compact")
        .on_hover_text("The best 15 processes, files and endpoints, with what joins them");
    ui.selectable_value(mode, Mode::Full, "Full").on_hover_text(
        "Every group open, up to about 800 nodes; click a group to shut it or to open one that did not fit",
    );
    if let Some(rendered) = built.rendered(*mode) {
        crate::mermaid::button(ui, || chart::mermaid(&rendered.graph, &rendered.shown));
    }
    pop_out
        && ui
            .add(egui::Button::new(egui_phosphor::regular::ARROW_SQUARE_OUT).frame(false))
            .on_hover_text("Open the relationships in their own window")
            .clicked()
}

/// Where and how a graph is drawn.
struct Pane<'a> {
    mode: Mode,
    toggled: &'a mut BTreeSet<String>,
    view: &'a mut canvas::View,
    height: f32,
    salt: &'a str,
}

/// The note above the graph and the graph itself.
fn graph(ui: &mut egui::Ui, built: &Built, pane: Pane<'_>, acts: &mut Vec<Act>) {
    let Pane {
        mode,
        toggled,
        view,
        height,
        salt,
    } = pane;
    let Some(rendered) = built.rendered(mode) else {
        let (rect, _) = ui.allocate_exact_size(
            egui::vec2(ui.available_width(), height),
            egui::Sense::hover(),
        );
        ui.scope_builder(
            egui::UiBuilder::new()
                .max_rect(rect)
                .layout(egui::Layout::centered_and_justified(
                    egui::Direction::LeftToRight,
                )),
            |ui| {
                ui.horizontal(|ui| {
                    theme::spinner(ui);
                    ui.weak("Laying out\u{2026}");
                });
            },
        );
        return;
    };
    let drawn = rendered.drawn;
    let total = rendered.total;
    let mut note = format!(
        "{} of {} nodes. Each process has what it started, wrote and contacted to its right.",
        crate::values::thousands(drawn as u64),
        crate::values::thousands(total as u64),
    );
    if rendered.shut > 0 {
        note.push_str(" A stacked box stands for several; click it to open them.");
    }
    note.push_str(" Drag to pan; Ctrl and the wheel zoom.");
    ui.label(RichText::new(note).small().color(theme::muted()));
    let out = canvas::show(
        ui,
        ui.id().with(salt),
        &rendered.graph,
        &rendered.layout,
        view,
        height,
    );
    if let Some(node) = out.clicked {
        match &rendered.graph.nodes[node].kind {
            NodeKind::Group(info) => {
                if !toggled.remove(&info.id) {
                    toggled.insert(info.id.clone());
                }
                ui.ctx().request_repaint();
            }
            kind => acts.push(node_act(kind)),
        }
    }
}

pub(in crate::triage) fn show(ui: &mut egui::Ui, state: &mut State, acts: &mut Vec<Act>) {
    let State {
        built,
        mode,
        view,
        full_view,
        toggled,
        window_open,
        ..
    } = state;
    let Some(built) = built.as_mut() else {
        return;
    };
    let total = built.graph.nodes.len();
    built.prepare(*mode, &toggled[slot(*mode)], ui.ctx());
    let now = std::cell::Cell::new(*mode);
    let pop_out = std::cell::Cell::new(false);
    let built = &*built;
    boxed(
        ui,
        "Relationships",
        acts,
        |ui, _| {
            let mut next = now.get();
            pop_out.set(header(ui, &mut next, built, true));
            now.set(next);
        },
        |ui, acts| {
            if total == 0 {
                ui.weak("No processes were recorded.");
                return;
            }
            let mode = now.get();
            let (view, height, salt) = match mode {
                Mode::Compact => (view, HEIGHT, "summary-relations"),
                Mode::Full => (full_view, FULL_HEIGHT, "summary-relations-full"),
            };
            let pane = Pane {
                mode,
                toggled: &mut toggled[slot(mode)],
                view,
                height,
                salt,
            };
            graph(ui, built, pane, acts);
        },
    );
    *mode = now.get();
    *window_open |= pop_out.get();
}

/// The same graph filling a window: its own pan and zoom, the mode and the
/// open groups of the box.
pub(in crate::triage) fn show_window(ui: &mut egui::Ui, state: &mut State, acts: &mut Vec<Act>) {
    let State {
        built,
        mode,
        toggled,
        window_view,
        window_full_view,
        ..
    } = state;
    let Some(built) = built.as_mut() else {
        ui.weak("No run is open.");
        return;
    };
    if built.graph.nodes.is_empty() {
        ui.weak("No processes were recorded.");
        return;
    }
    built.prepare(*mode, &toggled[slot(*mode)], ui.ctx());
    let built = &*built;
    ui.horizontal_wrapped(|ui| {
        header(ui, mode, built, false);
    });
    ui.add_space(4.0);
    let (view, salt) = match *mode {
        Mode::Compact => (window_view, "relations-window"),
        Mode::Full => (window_full_view, "relations-window-full"),
    };
    // The note takes a line; the rest is the graph.
    let height = (ui.available_height() - 24.0).max(200.0);
    let pane = Pane {
        mode: *mode,
        toggled: &mut toggled[slot(*mode)],
        view,
        height,
        salt,
    };
    graph(ui, built, pane, acts);
}
