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
/// Room for the process names, which stay at the left while the nodes scroll.
const GUTTER: f32 = 190.0;
/// Space kept between a process name and the first node.
const NAME_PAD: f32 = 8.0;

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
    let x = GUTTER + GAP / 2.0 + node_index as f32 * (NODE_WIDTH + GAP);
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
    let width = GUTTER + GAP + layout.nodes.len() as f32 * (NODE_WIDTH + GAP);
    let height = layout.lanes.len().max(1) as f32 * LANE_HEIGHT;
    egui::ScrollArea::horizontal()
        .id_salt("file-activity-graph")
        .auto_shrink([false, true])
        .show(ui, |ui| {
            let (area, _) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
            let origin = area.min.to_vec2();
            // The names stay at the left edge of what is on screen; nodes that
            // scroll past them are cut off there instead of running under them.
            let left = ui.clip_rect().left().max(area.left());
            let gutter = Rect::from_min_max(
                pos2(left, area.top()),
                pos2((left + GUTTER).min(area.right()), area.bottom()),
            );
            let plot = ui.painter_at(area).with_clip_rect(Rect::from_min_max(
                pos2(gutter.right(), area.top()),
                area.right_bottom(),
            ));
            let painter = ui.painter_at(area);
            for lane in 0..layout.lanes.len() {
                painter.hline(
                    area.x_range(),
                    area.top() + (lane + 1) as f32 * LANE_HEIGHT,
                    Stroke::new(1.0_f32, theme::line_soft()),
                );
            }
            for (index, pair) in layout.nodes.windows(2).enumerate() {
                let from = place(index, &pair[0]).translate(origin);
                let to = place(index + 1, &pair[1]).translate(origin);
                edge(&plot, from.right_center(), to.left_center());
            }
            for (index, node) in layout.nodes.iter().enumerate() {
                let rect = place(index, node).translate(origin);
                // A node hidden behind the names cannot be reached.
                if rect.right() <= gutter.right() {
                    continue;
                }
                let id = ui.id().with(("file-activity-node", index));
                let response = ui.interact(rect.intersect(plot.clip_rect()), id, Sense::click());
                let tint = if node.failed {
                    theme::muted()
                } else {
                    tint(node.kind)
                };
                let hot = response.hovered() || selected == Some(index);
                plot.rect(
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
                plot.text(
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
            // The gutter over the nodes: a solid ground, then one name per lane,
            // cut to the room with its whole text on hover.
            painter.rect_filled(gutter, 0.0, ui.visuals().panel_fill);
            painter.vline(
                gutter.right(),
                gutter.y_range(),
                Stroke::new(1.0_f32, theme::line_soft()),
            );
            let font = egui::TextStyle::Small.resolve(ui.style());
            for (lane, process) in layout.lanes.iter().enumerate() {
                let top = area.top() + lane as f32 * LANE_HEIGHT;
                let full = activity.process_label(*process);
                let shown = fit(&painter, &full, &font, GUTTER - 2.0 * NAME_PAD);
                let at = pos2(gutter.left() + NAME_PAD, top + LANE_HEIGHT / 2.0);
                let rect = painter.text(
                    at,
                    Align2::LEFT_CENTER,
                    &shown,
                    font.clone(),
                    theme::muted(),
                );
                if shown != full {
                    let id = ui.id().with(("file-activity-lane", lane));
                    ui.interact(rect.expand2(vec2(NAME_PAD, 4.0)), id, Sense::hover())
                        .on_hover_text(full);
                }
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

/// `text` cut with an ellipsis to fit `width` points in `font`.
pub(super) fn fit(painter: &egui::Painter, text: &str, font: &egui::FontId, width: f32) -> String {
    let measure = |text: &str| {
        painter
            .layout_no_wrap(text.to_owned(), font.clone(), Color32::WHITE)
            .size()
            .x
    };
    if measure(text) <= width {
        return text.to_owned();
    }
    let chars: Vec<char> = text.chars().collect();
    // The longest start that still fits with the ellipsis.
    let (mut low, mut high) = (0, chars.len());
    while low < high {
        let middle = (low + high).div_ceil(2);
        let candidate: String = chars[..middle].iter().chain(['…'].iter()).collect();
        if measure(&candidate) <= width {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    chars[..low].iter().chain(['…'].iter()).collect()
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
