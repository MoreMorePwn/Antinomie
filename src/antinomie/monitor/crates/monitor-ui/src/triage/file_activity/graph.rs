// SPDX-License-Identifier: GPL-3.0-only
//! One file's history as a graph: a node for each stretch of the same
//! operation by the same process, joined in the order the calls happened, on a
//! lane for each process. Open, read, write, rename and delete read left to
//! right; a change of lane is a different process taking over.
use super::{Activity, FileActivity, Kind};
use crate::theme;
use eframe::egui::{self, pos2, vec2, Align2, Color32, Rect, Sense, Stroke};
use std::ops::Range;

/// Nodes drawn; the events after them share one last node.
pub(super) const NODES_MAX: usize = 60;
const NODE_WIDTH: f32 = 112.0;
const NODE_HEIGHT: f32 = 30.0;
const GAP: f32 = 36.0;
const LANE_HEIGHT: f32 = 54.0;
const GUTTER: f32 = 150.0;

/// A stretch of events drawn as one box.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Node {
    pub kind: Kind,
    pub process: u32,
    /// Indices into the file's events.
    pub events: Range<usize>,
    pub failed: bool,
    pub lane: usize,
    /// The events after the node limit, which are no one operation.
    pub rest: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Layout {
    /// Process indices, one per lane, in order of first appearance.
    pub lanes: Vec<u32>,
    pub nodes: Vec<Node>,
}

/// Merge runs of the same operation by the same process into nodes.
pub(super) fn layout(file: &FileActivity) -> Layout {
    let mut layout = Layout::default();
    for (index, event) in file.events.iter().enumerate() {
        let failed = event.success == Some(false);
        if let Some(last) = layout.nodes.last_mut() {
            if last.rest
                || (last.kind == event.kind
                    && last.process == event.process
                    && last.failed == failed)
            {
                last.events.end = index + 1;
                continue;
            }
        }
        layout.nodes.push(Node {
            kind: event.kind,
            process: event.process,
            events: index..index + 1,
            failed,
            lane: 0,
            // Past the limit, every later call joins one last node.
            rest: layout.nodes.len() >= NODES_MAX,
        });
    }
    for node in &mut layout.nodes {
        let lane = match layout.lanes.iter().position(|lane| *lane == node.process) {
            Some(lane) => lane,
            None => {
                layout.lanes.push(node.process);
                layout.lanes.len() - 1
            }
        };
        node.lane = lane;
    }
    layout
}

/// The color of an operation's node.
pub(super) fn tint(kind: Kind) -> Color32 {
    match kind {
        Kind::Open => theme::info(),
        Kind::Create => theme::good(),
        Kind::Read => theme::bright_blue(),
        Kind::Write | Kind::Resize => theme::warn(),
        Kind::Rename | Kind::Link => theme::primary(),
        Kind::Delete => theme::error(),
        Kind::Exec => theme::error(),
        Kind::Attributes | Kind::Map | Kind::Probe | Kind::Other => theme::muted(),
    }
}

fn label(node: &Node) -> String {
    let count = node.events.len();
    let mut text = if node.rest {
        format!("+{count} more")
    } else if count > 1 {
        format!("{} ×{count}", node.kind.verb())
    } else {
        node.kind.verb().to_owned()
    };
    if node.failed {
        text.push_str(" ✗");
    }
    text
}

/// Where a node sits, relative to the graph's top left.
fn place(node_index: usize, node: &Node) -> Rect {
    let x = GUTTER + node_index as f32 * (NODE_WIDTH + GAP);
    let y = node.lane as f32 * LANE_HEIGHT + (LANE_HEIGHT - NODE_HEIGHT) / 2.0;
    Rect::from_min_size(pos2(x, y), vec2(NODE_WIDTH, NODE_HEIGHT))
}

/// Draw the graph; a click on a node selects it. Returns the node under the
/// pointer's click, if any.
pub(super) fn show(
    ui: &mut egui::Ui,
    activity: &Activity,
    file: &FileActivity,
    layout: &Layout,
    selected: Option<usize>,
) -> Option<usize> {
    let mut clicked = None;
    let width = GUTTER + layout.nodes.len() as f32 * (NODE_WIDTH + GAP);
    let height = layout.lanes.len().max(1) as f32 * LANE_HEIGHT;
    egui::ScrollArea::horizontal()
        .id_salt("file-activity-graph")
        .auto_shrink([false, true])
        .show(ui, |ui| {
            let (area, _) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
            let painter = ui.painter_at(area);
            let origin = area.min.to_vec2();
            // Lanes: a rule and the process's name at the left.
            for (lane, process) in layout.lanes.iter().enumerate() {
                let top = area.top() + lane as f32 * LANE_HEIGHT;
                painter.hline(
                    area.x_range(),
                    top + LANE_HEIGHT,
                    Stroke::new(1.0_f32, theme::line_soft()),
                );
                painter.text(
                    pos2(area.left() + 4.0, top + LANE_HEIGHT / 2.0),
                    Align2::LEFT_CENTER,
                    clip(&activity.process_label(*process), 20),
                    egui::TextStyle::Small.resolve(ui.style()),
                    theme::muted(),
                );
            }
            for (index, pair) in layout.nodes.windows(2).enumerate() {
                let from = place(index, &pair[0]).translate(origin);
                let to = place(index + 1, &pair[1]).translate(origin);
                edge(&painter, from.right_center(), to.left_center());
            }
            for (index, node) in layout.nodes.iter().enumerate() {
                let rect = place(index, node).translate(origin);
                let id = ui.id().with(("file-activity-node", index));
                let response = ui.interact(rect, id, Sense::click());
                let tint = if node.failed {
                    theme::muted()
                } else {
                    tint(node.kind)
                };
                let hot = response.hovered() || selected == Some(index);
                painter.rect(
                    rect,
                    6.0,
                    tint.gamma_multiply(if hot { 0.40 } else { 0.22 }),
                    Stroke::new(
                        if selected == Some(index) {
                            2.0_f32
                        } else {
                            1.0
                        },
                        tint,
                    ),
                    egui::StrokeKind::Inside,
                );
                painter.text(
                    rect.center(),
                    Align2::CENTER_CENTER,
                    label(node),
                    egui::TextStyle::Body.resolve(ui.style()),
                    theme::text(),
                );
                if response.clicked() {
                    clicked = Some(index);
                }
                response.on_hover_text(tooltip(file, node));
            }
        });
    clicked
}

/// An arrow from `from` to `to`: out, across and in, so a lane change does
/// not cut through the nodes between.
fn edge(painter: &egui::Painter, from: egui::Pos2, to: egui::Pos2) {
    let stroke = Stroke::new(1.5_f32, theme::muted());
    let middle = (from.x + to.x) / 2.0;
    painter.line_segment([from, pos2(middle, from.y)], stroke);
    painter.line_segment([pos2(middle, from.y), pos2(middle, to.y)], stroke);
    painter.line_segment([pos2(middle, to.y), to], stroke);
    painter.add(egui::Shape::convex_polygon(
        vec![to, to + vec2(-6.0, -3.5), to + vec2(-6.0, 3.5)],
        theme::muted(),
        Stroke::NONE,
    ));
}

fn clip(text: &str, chars: usize) -> String {
    if text.chars().count() <= chars {
        text.to_owned()
    } else {
        let mut short: String = text.chars().take(chars.saturating_sub(1)).collect();
        short.push('…');
        short
    }
}

/// What the hover on a node says: how many calls, how many octets.
pub(super) fn tooltip(file: &FileActivity, node: &Node) -> String {
    let events = &file.events[node.events.clone()];
    let moved: u64 = events.iter().filter_map(|event| event.len).sum();
    let mut text = format!(
        "{} call{}",
        events.len(),
        if events.len() == 1 { "" } else { "s" }
    );
    if matches!(node.kind, Kind::Read | Kind::Write) && !node.rest {
        text.push_str(&format!(", {moved} B"));
    }
    if node.failed {
        text.push_str(", refused by the kernel");
    }
    text.push_str("\nClick for the calls");
    text
}
