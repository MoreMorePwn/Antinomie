// SPDX-License-Identifier: GPL-3.0-only
//! The snapshot graph: one drawing for the Snapshots window and the VM
//! Summary box. The base image is the root, each checkpoint hangs from its
//! parent, and a "You are here" node marks where the next snapshot attaches.
use super::{graph_layout, mode_label};
use crate::theme;
use antinomie_monitor_core::VmSnapshotTree;
use eframe::egui;
use std::collections::BTreeMap;

const NODE_WIDTH: f32 = 210.0;
const NODE_HEIGHT: f32 = 84.0;
const COLUMN_STEP: f32 = 252.0;
const ROW_STEP: f32 = 108.0;

/// Pan and zoom of one graph; `fit` asks for a fresh fit on the next paint.
pub(super) struct GraphView {
    pub(super) zoom: f32,
    pub(super) pan: egui::Vec2,
    pub(super) fit: bool,
}

impl Default for GraphView {
    fn default() -> Self {
        Self {
            zoom: 1.0,
            pan: egui::Vec2::ZERO,
            fit: true,
        }
    }
}

/// Height that shows the whole graph at about three quarters size, between `min` and `max`.
pub(super) fn natural_height(tree: &VmSnapshotTree, min: f32, max: f32) -> f32 {
    let rows = graph_layout(tree)
        .iter()
        .map(|item| item.row + 1)
        .max()
        .unwrap_or(0)
        + 1;
    (rows as f32 * ROW_STEP * 0.75 + 32.0).clamp(min, max)
}

/// Paint the graph in a box `height` tall and the width available. With
/// `interactive` off, the box does not pan or zoom (it stays fitted); nodes
/// still select.
pub(super) fn paint(
    ui: &mut egui::Ui,
    tree: &VmSnapshotTree,
    selected: &mut Option<String>,
    view: &mut GraphView,
    height: f32,
    interactive: bool,
) {
    let size = egui::vec2(ui.available_width().max(100.0), height);
    let (rect, response) = ui.allocate_exact_size(
        size,
        if interactive {
            egui::Sense::click_and_drag()
        } else {
            egui::Sense::hover()
        },
    );
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 6.0, theme::bg());
    painter.rect_stroke(
        rect,
        6.0,
        egui::Stroke::new(1.0_f32, theme::line_soft()),
        egui::StrokeKind::Inside,
    );
    let items = graph_layout(tree);
    let points: BTreeMap<&str, egui::Pos2> = items
        .iter()
        .map(|item| {
            (
                tree.nodes[item.index].id.as_str(),
                egui::pos2(
                    (item.depth + 1) as f32 * COLUMN_STEP,
                    item.row as f32 * ROW_STEP,
                ),
            )
        })
        .collect();
    let current_parent = tree
        .active_parent_id
        .as_deref()
        .and_then(|id| points.get(id))
        .copied()
        .unwrap_or(egui::Pos2::ZERO);
    let current_row = items
        .iter()
        .map(|item| item.row)
        .max()
        .map_or(0, |row| row + 1);
    let current = egui::pos2(
        current_parent.x + COLUMN_STEP,
        current_row as f32 * ROW_STEP,
    );
    if view.fit || !interactive {
        let max_x = points.values().map(|p| p.x).fold(current.x, f32::max) + NODE_WIDTH;
        let max_y = points.values().map(|p| p.y).fold(current.y, f32::max) + NODE_HEIGHT;
        view.zoom = ((rect.width() - 32.0) / max_x.max(1.0))
            .min((rect.height() - 32.0) / max_y.max(1.0))
            .clamp(0.001, 1.2);
        view.pan = egui::vec2(16.0, 16.0);
        view.fit = false;
    }
    if interactive && response.dragged() {
        view.pan += response.drag_delta();
    }
    if interactive && response.hovered() {
        let scroll = ui.input(|input| input.smooth_scroll_delta);
        if ui.input(|input| input.modifiers.ctrl || input.modifiers.command) {
            view.zoom = (view.zoom * (scroll.y * 0.002).exp()).clamp(0.001, 2.0);
        } else {
            view.pan += scroll;
        }
    }
    let transform = |point: egui::Pos2| rect.min + view.pan + point.to_vec2() * view.zoom;
    let node_size = egui::vec2(NODE_WIDTH, NODE_HEIGHT) * view.zoom;
    let font_size = ui.style().text_styles[&egui::TextStyle::Body].size * view.zoom;
    let edge = |parent: egui::Pos2, child: egui::Pos2, color| {
        let start = transform(parent) + egui::vec2(node_size.x, node_size.y * 0.5);
        let end = transform(child) + egui::vec2(0.0, node_size.y * 0.5);
        let x = (start.x + end.x) * 0.5;
        painter.add(egui::Shape::line(
            vec![start, egui::pos2(x, start.y), egui::pos2(x, end.y), end],
            egui::Stroke::new(1.5_f32, color),
        ));
    };
    for item in &items {
        let node = &tree.nodes[item.index];
        let point = points[&node.id.as_str()];
        let parent = node
            .parent_id
            .as_deref()
            .and_then(|id| points.get(id))
            .copied()
            .unwrap_or(egui::Pos2::ZERO);
        edge(parent, point, theme::line());
    }
    edge(current_parent, current, theme::good());
    paint_node(
        &painter,
        egui::Rect::from_min_size(transform(egui::Pos2::ZERO), node_size),
        "Base image",
        "Initial disk",
        theme::line(),
        false,
        font_size,
    );
    for item in &items {
        let node = &tree.nodes[item.index];
        let node_rect = egui::Rect::from_min_size(transform(points[&node.id.as_str()]), node_size);
        let is_selected = selected.as_deref() == Some(&node.id);
        let color = if is_selected {
            theme::blue()
        } else if !node.compatible {
            theme::warn()
        } else {
            theme::line()
        };
        paint_node(
            &painter,
            node_rect,
            if node.deleted {
                "Hidden checkpoint"
            } else {
                &node.name
            },
            mode_label(node.mode),
            color,
            is_selected,
            font_size,
        );
        if node_rect.intersects(rect) {
            let hit = ui.interact(
                node_rect.intersect(rect),
                response.id.with(&node.id),
                egui::Sense::click(),
            );
            if hit.clicked() {
                *selected = Some(node.id.clone());
            }
            hit.on_hover_text(format!("{}\n{}", node.name, node.description));
        }
    }
    paint_node(
        &painter,
        egui::Rect::from_min_size(transform(current), node_size),
        "You are here",
        "Unsaved changes",
        theme::good(),
        false,
        font_size,
    );
    if interactive {
        response.on_hover_text(
            "Drag to pan. Scroll to pan; Ctrl + scroll to zoom. Use Tree for keyboard navigation.",
        );
    }
}

fn paint_node(
    painter: &egui::Painter,
    rect: egui::Rect,
    name: &str,
    detail: &str,
    color: egui::Color32,
    selected: bool,
    font_size: f32,
) {
    painter.rect_filled(
        rect,
        4.0,
        if selected {
            theme::palette().selection
        } else {
            theme::raised()
        },
    );
    painter.rect_stroke(
        rect,
        4.0,
        egui::Stroke::new(if selected { 2.0_f32 } else { 1.0_f32 }, color),
        egui::StrokeKind::Inside,
    );
    if rect.height() < 20.0 {
        painter.circle_filled(rect.center(), 2.0, color);
        return;
    }
    let font = egui::FontId::proportional(font_size.clamp(12.0, 24.0));
    // Room between the text and the node's border, growing with the zoom.
    let pad = (rect.height() * 0.1).clamp(4.0, 12.0);
    let mut job = egui::text::LayoutJob::simple(
        name.to_owned(),
        font,
        theme::text(),
        (rect.width() - 2.0 * pad).max(1.0),
    );
    job.wrap.max_rows = 1;
    let galley = painter.layout_job(job);
    let clip = painter.with_clip_rect(painter.clip_rect().intersect(rect.shrink(pad / 2.0)));
    clip.galley(rect.min + egui::vec2(pad, pad), galley, theme::text());
    if rect.height() >= 32.0 {
        clip.text(
            rect.left_bottom() + egui::vec2(pad, -pad),
            egui::Align2::LEFT_BOTTOM,
            detail,
            egui::FontId::proportional((font_size * 0.81).clamp(12.0, 24.0)),
            if color == theme::line() {
                theme::muted()
            } else {
                color
            },
        );
    }
}
