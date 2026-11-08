// SPDX-License-Identifier: GPL-3.0-only
//! The snapshot graph: one drawing for the Snapshots window and the VM
//! Overview box. The base image is the root, each checkpoint hangs from its
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
            egui::Sense::click()
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
        // Ctrl and the wheel (or a pinch) zoom; the plain wheel is left to the
        // page that holds the graph.
        let pinch = ui.input(|input| input.zoom_delta());
        if pinch != 1.0 {
            view.zoom = (view.zoom * pinch).clamp(0.001, 2.0);
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
    let response = if interactive {
        response
            .on_hover_text("Drag to pan. Ctrl + scroll to zoom. Use Tree for keyboard navigation.")
    } else {
        response
    };
    response.context_menu(|ui| crate::mermaid::menu_item(ui, || super::mermaid::of(tree)));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn page(ctx: &egui::Context, view: &mut GraphView, time: f64, events: Vec<egui::Event>) -> f32 {
        let tree = super::super::tests::fixture();
        let mut marker = 0.0;
        let _ = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(800.0, 400.0),
                )),
                time: Some(time),
                events,
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        marker = ui.cursor().min.y;
                        paint(ui, &tree, &mut None, view, 300.0, true);
                        ui.allocate_space(egui::vec2(10.0, 2000.0));
                    });
                });
            },
        );
        marker
    }

    fn turn(
        ctx: &egui::Context,
        view: &mut GraphView,
        time: &mut f64,
        modifiers: egui::Modifiers,
    ) -> f32 {
        let mut marker = 0.0;
        for n in 0..30 {
            let events = if n == 0 {
                vec![
                    egui::Event::PointerMoved(egui::pos2(300.0, 150.0)),
                    egui::Event::MouseWheel {
                        phase: egui::TouchPhase::Move,
                        unit: egui::MouseWheelUnit::Point,
                        delta: egui::vec2(0.0, if modifiers.command { 60.0 } else { -60.0 }),
                        modifiers,
                    },
                ]
            } else {
                vec![]
            };
            *time += 0.02;
            marker = page(ctx, view, *time, events);
        }
        marker
    }

    #[test]
    fn the_plain_wheel_scrolls_the_page_and_ctrl_wheel_zooms_the_graph() {
        let ctx = egui::Context::default();
        let mut view = GraphView::default();
        let start = page(&ctx, &mut view, 0.0, vec![]);
        page(&ctx, &mut view, 0.02, vec![]);
        let mut time = 0.02;
        let (zoom, pan) = (view.zoom, view.pan);
        let marker = turn(&ctx, &mut view, &mut time, egui::Modifiers::NONE);
        assert_eq!(
            (view.zoom, view.pan),
            (zoom, pan),
            "the plain wheel leaves the view"
        );
        assert!(
            marker < start - 20.0,
            "the page scrolled: {start} -> {marker}"
        );
        turn(&ctx, &mut view, &mut time, egui::Modifiers::COMMAND);
        assert!(
            view.zoom > zoom,
            "Ctrl and the wheel zoom: {zoom} -> {}",
            view.zoom
        );
    }
}
