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
        Kind::Write | Kind::Resize => theme::neutral_accent(),
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

/// Where the graph is looked at: dragging its background moves it and
/// Ctrl + wheel (or a pinch) zooms about the pointer, as in the other graphs;
/// a double click puts it back.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(in crate::triage) struct View {
    /// Where the graph's origin sits from the top left of the area.
    pub pan: egui::Vec2,
    pub zoom: f32,
}

impl Default for View {
    fn default() -> Self {
        Self {
            pan: egui::Vec2::ZERO,
            zoom: 1.0,
        }
    }
}

const MIN_ZOOM: f32 = 0.3;
const MAX_ZOOM: f32 = 3.0;
/// The tallest the graph's area grows with its lanes.
const AREA_MAX_HEIGHT: f32 = 320.0;

impl View {
    /// Zoom by `factor` keeping the graph point under `pivot` (relative to the
    /// area, past the gutter) where it is.
    fn zoom_about(&mut self, pivot: egui::Vec2, factor: f32) {
        let zoom = (self.zoom * factor).clamp(MIN_ZOOM, MAX_ZOOM);
        let factor = zoom / self.zoom;
        self.pan = pivot - (pivot - self.pan) * factor;
        self.zoom = zoom;
    }
}

/// Where a node sits in the graph's own units, from its top left, with the
/// gutter not counted: the view moves and scales these.
fn place(node_index: usize, node: &Node) -> Rect {
    let x = GAP / 2.0 + node_index as f32 * (NODE_WIDTH + GAP);
    let y = node.lane as f32 * LANE_HEIGHT + (LANE_HEIGHT - NODE_HEIGHT) / 2.0;
    Rect::from_min_size(pos2(x, y), vec2(NODE_WIDTH, NODE_HEIGHT))
}

/// Draw the graph; a click on a node selects it and a drag of the background
/// moves the view. Returns the node under the pointer's click, if any.
pub(super) fn show(
    ui: &mut egui::Ui,
    activity: &Activity,
    file: &FileActivity,
    layout: &Layout,
    selected: Option<usize>,
    view: &mut View,
) -> Option<usize> {
    let mut clicked = None;
    let height =
        (layout.lanes.len().max(1) as f32 * LANE_HEIGHT).clamp(2.0 * LANE_HEIGHT, AREA_MAX_HEIGHT);
    let (area, background) =
        ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click_and_drag());
    let background = background.on_hover_cursor(if ui.input(|input| input.pointer.any_down()) {
        egui::CursorIcon::Grabbing
    } else {
        egui::CursorIcon::Grab
    });
    if background.dragged() {
        view.pan += background.drag_delta();
    }
    if background.double_clicked() {
        *view = View::default();
    }
    let gutter = Rect::from_min_max(
        area.min,
        pos2((area.left() + GUTTER).min(area.right()), area.bottom()),
    );
    if background.hovered() {
        let pinch = ui.input(|input| input.zoom_delta());
        if pinch != 1.0 {
            let pointer = ui.input(|input| input.pointer.hover_pos());
            let pivot = pointer.map_or(area.size() / 2.0, |at| at - gutter.right_top());
            view.zoom_about(vec2(pivot.x, pivot.y), pinch);
        }
    }
    background.context_menu(|ui| {
        crate::mermaid::menu_item(ui, || {
            mermaid(layout, |process| activity.process_label(process))
        });
        if ui.button("Reset the view").clicked() {
            *view = View::default();
            ui.close();
        }
    });
    let zoom = view.zoom;
    // The graph's origin: past the gutter, moved by the pan.
    let origin = pos2(gutter.right(), area.top()).to_vec2() + view.pan;
    let at = |rect: Rect| {
        Rect::from_min_size(
            (rect.min.to_vec2() * zoom + origin).to_pos2(),
            rect.size() * zoom,
        )
    };
    // The nodes that move past the names are cut off there instead of running
    // under them.
    let plot = ui.painter_at(area).with_clip_rect(Rect::from_min_max(
        pos2(gutter.right(), area.top()),
        area.right_bottom(),
    ));
    let painter = ui.painter_at(area);
    for lane in 0..layout.lanes.len() {
        let y = origin.y + (lane + 1) as f32 * LANE_HEIGHT * zoom;
        plot.hline(
            plot.clip_rect().x_range(),
            y,
            Stroke::new(1.0_f32, theme::line_soft()),
        );
    }
    for (index, pair) in layout.nodes.windows(2).enumerate() {
        let from = at(place(index, &pair[0]));
        let to = at(place(index + 1, &pair[1]));
        edge(&plot, from.right_center(), to.left_center());
    }
    let mut body = egui::TextStyle::Body.resolve(ui.style());
    body.size = (body.size * zoom).clamp(6.0, 40.0);
    for (index, node) in layout.nodes.iter().enumerate() {
        let rect = at(place(index, node));
        // A node out of sight cannot be reached.
        if rect.right() <= gutter.right() || rect.left() >= area.right() {
            continue;
        }
        let id = ui.id().with(("file-activity-node", index));
        let response = ui.interact(
            rect.intersect(plot.clip_rect()),
            id,
            Sense::click_and_drag(),
        );
        // A drag that began on a node moves the graph too.
        if response.dragged() {
            view.pan += response.drag_delta();
        }
        let tint = if node.failed {
            theme::muted()
        } else {
            tint(node.kind)
        };
        let hot = response.hovered() || selected == Some(index);
        plot.rect(
            rect,
            6.0 * zoom,
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
            body.clone(),
            theme::text(),
        );
        if response.clicked() {
            clicked = Some(index);
        }
        response.on_hover_text(tooltip(file, node));
    }
    // The gutter over the nodes: a solid ground, then one name per lane,
    // cut to the room with its whole text on hover. The names follow the
    // lanes up and down.
    painter.rect_filled(gutter, 0.0, ui.visuals().panel_fill);
    painter.vline(
        gutter.right(),
        gutter.y_range(),
        Stroke::new(1.0_f32, theme::line_soft()),
    );
    let names = painter.with_clip_rect(gutter);
    let font = egui::TextStyle::Small.resolve(ui.style());
    for (lane, process) in layout.lanes.iter().enumerate() {
        let top = origin.y + lane as f32 * LANE_HEIGHT * zoom;
        let full = activity.process_label(*process);
        let shown = fit(&names, &full, &font, GUTTER - 2.0 * NAME_PAD);
        let spot = pos2(gutter.left() + NAME_PAD, top + LANE_HEIGHT * zoom / 2.0);
        let rect = names.text(
            spot,
            Align2::LEFT_CENTER,
            &shown,
            font.clone(),
            theme::muted(),
        );
        if shown != full {
            let id = ui.id().with(("file-activity-lane", lane));
            ui.interact(
                rect.expand2(vec2(NAME_PAD, 4.0)).intersect(gutter),
                id,
                Sense::hover(),
            )
            .on_hover_text(full);
        }
    }
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

/// The graph as Mermaid text: each node is one stretch of calls of one
/// process (its name above the operation), each pointing at the next in time
/// order, as the picture draws them. `process_label` names a process index.
pub(super) fn mermaid(layout: &Layout, process_label: impl Fn(u32) -> String) -> String {
    let mut chart = crate::mermaid::Flowchart::new("LR");
    let key = |index: usize| format!("call-{index}");
    for (index, node) in layout.nodes.iter().enumerate() {
        chart.node(
            &key(index),
            &format!("{}\n{}", process_label(node.process), label(node)),
        );
    }
    for index in 1..layout.nodes.len() {
        chart.edge(&key(index - 1), &key(index), None);
    }
    chart.render()
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

#[cfg(test)]
mod mermaid_tests {
    use super::*;

    #[test]
    fn the_nodes_follow_each_other_with_the_process_named() {
        let node = |kind, process, count: usize, failed| Node {
            kind,
            process,
            events: 0..count,
            failed,
            lane: 0,
            rest: false,
        };
        let layout = Layout {
            lanes: vec![1, 2],
            nodes: vec![
                node(Kind::Open, 1, 1, false),
                node(Kind::Write, 2, 3, false),
                node(Kind::Delete, 1, 1, true),
            ],
        };
        let text = mermaid(&layout, |process| format!("proc <{process}>"));
        assert!(text.starts_with("flowchart LR\n"));
        assert!(text.contains("proc #lt;2#gt;<br/>"), "{text}");
        assert_eq!(text.matches(" --> ").count(), 2, "{text}");
        assert_eq!(text.matches("[\"").count(), 3, "{text}");
    }
}
