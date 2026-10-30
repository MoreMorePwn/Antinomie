// SPDX-License-Identifier: GPL-3.0-only
//! The lineage graph's viewport: a layered layout (parents left, the sample in
//! the middle, children right), pan by dragging, zoom with the wheel about the
//! pointer, a zoom bar, a minimap and keyboard control. It draws nodes and
//! labelled edges and says what was clicked; it keeps no data of its own.
use super::{parts, *};
use antinomie_monitor_core::samples::{EdgeKind, LineageEdge, LineageGraph, LineageNode, NodeKind};
use eframe::egui::{Color32, Pos2, Rect, Shape, Stroke, Vec2};
use std::collections::BTreeMap;

use super::labels;

pub(super) const HEIGHT: f32 = 380.0;
const COLUMN: f32 = 310.0;
const ROW: f32 = 64.0;
const NODE_W: f32 = 170.0;
const NODE_H: f32 = 32.0;
const MIN_ZOOM: f32 = 0.2;
const MAX_ZOOM: f32 = 3.0;
const MINIMAP: Vec2 = egui::vec2(150.0, 96.0);

fn stroke(width: f32, color: Color32) -> Stroke {
    Stroke::new(width, color)
}

/// The positions of the nodes in graph space.
pub(super) struct Layout {
    pub(super) at: BTreeMap<String, Rect>,
    /// Each edge's route in graph space, by its index in the graph's edges
    /// (none when an end is not drawn).
    pub(super) routes: Vec<Option<[Pos2; 4]>>,
    pub(super) bounds: Rect,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            at: BTreeMap::new(),
            routes: Vec::new(),
            bounds: Rect::from_min_size(Pos2::ZERO, Vec2::splat(1.0)),
        }
    }
}

impl Layout {
    pub(super) fn of(graph: &LineageGraph) -> Self {
        let mut columns: BTreeMap<i32, usize> = BTreeMap::new();
        let first = graph.nodes.iter().map(|node| node.level).min().unwrap_or(0);
        let mut at = BTreeMap::new();
        let mut bounds: Option<Rect> = None;
        for node in &graph.nodes {
            let row = columns.entry(node.level).or_default();
            let min = Pos2::new((node.level - first) as f32 * COLUMN, *row as f32 * ROW);
            *row += 1;
            let rect = Rect::from_min_size(min, egui::vec2(NODE_W, NODE_H));
            bounds = Some(bounds.map_or(rect, |bounds| bounds.union(rect)));
            at.insert(node.id.clone(), rect);
        }
        let routes: Vec<Option<[Pos2; 4]>> = graph
            .edges
            .iter()
            .map(|edge| {
                let (from, to) = (at.get(&edge.from)?, at.get(&edge.to)?);
                Some(labels::route(*from, *to, edge.from == edge.to))
            })
            .collect();
        // Loops and bulges are part of the picture the view must fit.
        for point in routes.iter().flatten().flatten() {
            bounds = bounds.map(|bounds| bounds.union(Rect::from_min_max(*point, *point)));
        }
        Self {
            at,
            routes,
            bounds: bounds
                .unwrap_or_else(|| Rect::from_min_size(Pos2::ZERO, Vec2::splat(1.0)))
                .expand(40.0),
        }
    }
}

/// Pan and zoom: `offset` is where graph-space (0, 0) sits in the viewport.
#[derive(Clone, Copy)]
pub(super) struct View {
    pub(super) offset: Vec2,
    pub(super) zoom: f32,
    pub(super) fitted: bool,
}

impl Default for View {
    fn default() -> Self {
        Self {
            offset: Vec2::ZERO,
            zoom: 1.0,
            fitted: false,
        }
    }
}

impl View {
    fn screen_point(&self, origin: Pos2, point: Pos2) -> Pos2 {
        origin + self.offset + point.to_vec2() * self.zoom
    }

    fn rect_to_screen(&self, origin: Pos2, rect: Rect) -> Rect {
        Rect::from_min_max(
            self.screen_point(origin, rect.min),
            self.screen_point(origin, rect.max),
        )
    }

    /// The whole graph in the viewport.
    pub(super) fn fit(&mut self, viewport: Vec2, bounds: Rect) {
        let zoom = (viewport.x / bounds.width().max(1.0))
            .min(viewport.y / bounds.height().max(1.0))
            .clamp(MIN_ZOOM, 1.0);
        self.zoom = zoom;
        self.offset = (viewport - bounds.size() * zoom) / 2.0 - bounds.min.to_vec2() * zoom;
        self.fitted = true;
    }

    /// Actual size, centred on `centre` (graph space).
    fn actual(&mut self, viewport: Vec2, centre: Pos2) {
        self.zoom = 1.0;
        self.offset = viewport / 2.0 - centre.to_vec2();
    }

    /// Zoom by `factor` keeping the graph point under `pivot` (viewport space).
    fn zoom_about(&mut self, pivot: Vec2, factor: f32) {
        let zoom = (self.zoom * factor).clamp(MIN_ZOOM, MAX_ZOOM);
        let factor = zoom / self.zoom;
        self.offset = pivot - (pivot - self.offset) * factor;
        self.zoom = zoom;
    }
}

/// What the viewport reports.
#[derive(Default)]
pub(super) struct Hit {
    pub(super) node: Option<String>,
    /// The `+N` / `−` badge of a node was clicked.
    pub(super) badge: Option<String>,
    pub(super) edge: Option<(String, String)>,
    /// The empty background was clicked.
    pub(super) background: bool,
    pub(super) open: Option<String>,
}

pub(super) fn kind_color(kind: EdgeKind) -> Color32 {
    match kind {
        EdgeKind::Dropped => theme::palette().string,
        EdgeKind::Downloaded => theme::palette().info,
        EdgeKind::Executed => theme::palette().good,
        EdgeKind::Loaded => theme::palette().pointer,
    }
}

/// The kind's shape: square dropped, downward triangle downloaded, right
/// triangle executed, circle loaded.
pub(super) fn kind_shape(painter: &egui::Painter, kind: EdgeKind, centre: Pos2, size: f32) {
    let color = kind_color(kind);
    let r = size / 2.0;
    match kind {
        EdgeKind::Dropped => {
            painter.rect_filled(
                Rect::from_center_size(centre, Vec2::splat(size * 0.9)),
                1.0,
                color,
            );
        }
        EdgeKind::Downloaded => {
            painter.add(Shape::convex_polygon(
                vec![
                    centre + egui::vec2(-r, -r * 0.8),
                    centre + egui::vec2(r, -r * 0.8),
                    centre + egui::vec2(0.0, r),
                ],
                color,
                Stroke::NONE,
            ));
        }
        EdgeKind::Executed => {
            painter.add(Shape::convex_polygon(
                vec![
                    centre + egui::vec2(-r * 0.8, -r),
                    centre + egui::vec2(-r * 0.8, r),
                    centre + egui::vec2(r, 0.0),
                ],
                color,
                Stroke::NONE,
            ));
        }
        EdgeKind::Loaded => {
            painter.circle_filled(centre, r * 0.85, color);
        }
    }
}

fn border(node: &LineageNode) -> (Color32, Color32) {
    let palette = theme::palette();
    match &node.kind {
        NodeKind::Sample => (palette.accent, palette.accent.gamma_multiply(0.22)),
        NodeKind::Library { verdict, .. } => {
            (crate::sample_tags::verdict_color(verdict), palette.panel)
        }
        NodeKind::Captured => (palette.muted, palette.muted.gamma_multiply(0.22)),
        NodeKind::Lost => (palette.muted, palette.panel),
        NodeKind::Command => (palette.line, palette.panel),
        NodeKind::System => (palette.line_soft, palette.panel),
    }
}

fn node_title(node: &LineageNode) -> String {
    match node.kind {
        NodeKind::Lost => format!("{} · hash unknown", node.label),
        _ => node.label.clone(),
    }
}

fn dashed(painter: &egui::Painter, rect: Rect, stroke: Stroke) {
    let points = vec![
        rect.left_top(),
        rect.right_top(),
        rect.right_bottom(),
        rect.left_bottom(),
        rect.left_top(),
    ];
    painter.extend(Shape::dashed_line(&points, stroke, 4.0, 3.0));
}

/// Draw the graph in `rect`; returns what was clicked.
#[allow(clippy::too_many_arguments)]
pub(super) fn show(
    ui: &mut egui::Ui,
    rect: Rect,
    graph: &LineageGraph,
    layout: &Layout,
    view: &mut View,
    selected: Option<&str>,
    selected_edge: Option<&(String, String)>,
    expanded: &std::collections::BTreeSet<String>,
    sample: &str,
    context: &mut Option<String>,
    menu: &mut dyn FnMut(&mut egui::Ui, &LineageNode),
) -> Hit {
    let palette = theme::palette();
    let response = ui.allocate_rect(rect, egui::Sense::click_and_drag());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 4.0, palette.panel);
    painter.rect_stroke(
        rect,
        4.0,
        stroke(1.0, palette.line_soft),
        egui::StrokeKind::Inside,
    );
    let viewport = rect.size();
    if !view.fitted && viewport.x > 50.0 {
        view.fit(viewport, layout.bounds);
    }
    let origin = rect.min;
    let minimap = Rect::from_min_size(
        Pos2::new(rect.right() - MINIMAP.x - 8.0, rect.top() + 8.0),
        MINIMAP,
    );
    // A press that began in the minimap moves the view, not the graph.
    let press = ui.input(|input| input.pointer.press_origin());
    let on_minimap = press.is_some_and(|at| minimap.contains(at));
    if on_minimap {
        if let Some(pointer) = response.interact_pointer_pos().filter(|_| {
            response.dragged() || response.clicked() || response.is_pointer_button_down_on()
        }) {
            let scale = (MINIMAP.x / layout.bounds.width().max(1.0))
                .min(MINIMAP.y / layout.bounds.height().max(1.0));
            let world = layout.bounds.min + (pointer - minimap.min) / scale;
            view.offset = viewport / 2.0 - world.to_vec2() * view.zoom;
        }
    } else if response.dragged() {
        view.offset += response.drag_delta();
    }
    if response.hovered() {
        let (scroll, pinch, pointer) = ui.input(|input| {
            (
                input.raw_scroll_delta.y,
                input.zoom_delta(),
                input.pointer.hover_pos(),
            )
        });
        let pivot = pointer.map_or(viewport / 2.0, |at| at - origin);
        if scroll != 0.0 {
            view.zoom_about(pivot, (scroll * 0.0015).exp());
        }
        if pinch != 1.0 {
            view.zoom_about(pivot, pinch);
        }
    }
    if response.clicked() {
        response.request_focus();
    }
    if response.has_focus() {
        let step = 40.0;
        let (dx, dy, zoom, fit) = ui.input(|input| {
            let axis = |plus: egui::Key, minus: egui::Key| {
                f32::from(input.key_pressed(plus)) - f32::from(input.key_pressed(minus))
            };
            (
                axis(egui::Key::ArrowLeft, egui::Key::ArrowRight) * step,
                axis(egui::Key::ArrowUp, egui::Key::ArrowDown) * step,
                axis(egui::Key::Plus, egui::Key::Minus)
                    + axis(egui::Key::Equals, egui::Key::Minus) * 0.0,
                input.key_pressed(egui::Key::Num0),
            )
        });
        view.offset += egui::vec2(dx, dy);
        if zoom != 0.0 {
            view.zoom_about(viewport / 2.0, if zoom > 0.0 { 1.2 } else { 1.0 / 1.2 });
        }
        if fit {
            view.fit(viewport, layout.bounds);
        }
    }
    let to_screen = |rect: Rect| view.rect_to_screen(origin, rect);
    let scale = view.zoom;
    let mut hits = Hit::default();
    let click = response
        .clicked()
        .then(|| response.interact_pointer_pos())
        .flatten();
    let double = response
        .double_clicked()
        .then(|| response.interact_pointer_pos())
        .flatten();
    let in_minimap = |at: Pos2| minimap.contains(at);
    // Edges first, under the nodes; their labels are placed once all are
    // known (so none covers a node or another label) and drawn over the nodes.
    let font = egui::FontId::proportional((11.0 * scale).clamp(8.0, 16.0));
    struct Pending<'a> {
        edge: &'a LineageEdge,
        galley: std::sync::Arc<egui::Galley>,
        color: Color32,
        route: [Pos2; 4],
    }
    let mut pending: Vec<Pending<'_>> = Vec::new();
    for (index, edge) in graph.edges.iter().enumerate() {
        let Some(Some(world_route)) = layout.routes.get(index) else {
            continue;
        };
        let points = world_route.map(|point| view.screen_point(origin, point));
        let chosen = selected_edge.is_some_and(|(a, b)| *a == edge.from && *b == edge.to);
        let color = if chosen { palette.accent } else { palette.line };
        painter.add(Shape::CubicBezier(
            egui::epaint::CubicBezierShape::from_points_stroke(
                points,
                false,
                Color32::TRANSPARENT,
                stroke(if chosen { 2.0 } else { 1.3 }, color),
            ),
        ));
        // The arrow head at the child's end.
        let end = points[3];
        let back = (points[3] - points[2]).normalized();
        let side = egui::vec2(-back.y, back.x);
        let tip = 7.0 * scale.clamp(0.6, 1.4);
        painter.add(Shape::convex_polygon(
            vec![
                end,
                end - back * tip + side * tip * 0.45,
                end - back * tip - side * tip * 0.45,
            ],
            color,
            Stroke::NONE,
        ));
        let text = antinomie_monitor_core::samples::runs_label(&edge.runs);
        pending.push(Pending {
            edge,
            galley: painter.layout_no_wrap(text, font.clone(), palette.text),
            color,
            route: points,
        });
    }
    let mut node_rects: Vec<(Rect, &LineageNode)> = Vec::new();
    for node in &graph.nodes {
        let Some(world) = layout.at.get(&node.id) else {
            continue;
        };
        let box_ = to_screen(*world);
        if !box_.intersects(rect) {
            continue;
        }
        let (stroke_color, fill) = border(node);
        let chosen = selected == Some(node.id.as_str());
        let node_stroke = stroke(
            if chosen || node.id == sample {
                2.0
            } else {
                1.2
            },
            stroke_color,
        );
        painter.rect_filled(box_, 6.0 * scale, fill);
        if matches!(node.kind, NodeKind::Lost) {
            dashed(&painter, box_, node_stroke);
        } else {
            painter.rect_stroke(box_, 6.0 * scale, node_stroke, egui::StrokeKind::Inside);
        }
        if chosen {
            painter.rect_stroke(
                box_.expand(3.0),
                8.0 * scale,
                stroke(1.0, palette.accent),
                egui::StrokeKind::Outside,
            );
        }
        let text_color = match node.kind {
            NodeKind::System => palette.muted,
            _ => palette.text,
        };
        let family = if matches!(node.kind, NodeKind::Command) {
            egui::FontFamily::Monospace
        } else {
            egui::FontFamily::Proportional
        };
        // One line; the full text is the node's hover text.
        let mut job = egui::text::LayoutJob::simple(
            node_title(node),
            egui::FontId::new((12.0 * scale).clamp(8.0, 18.0), family),
            text_color,
            box_.width() - 12.0 * scale,
        );
        job.wrap.max_rows = 1;
        job.wrap.break_anywhere = true;
        let galley = painter.layout_job(job);
        painter.galley(
            Pos2::new(
                box_.left() + 8.0 * scale,
                box_.center().y - galley.size().y.min(box_.height()) / 2.0,
            ),
            galley,
            text_color,
        );
        // +N badges for the neighbours left out, "−" when expanded.
        let badge =
            |side_x: f32, count: usize, hit: &mut Option<String>, painter: &egui::Painter| {
                let is_open = expanded.contains(&node.id);
                if count == 0 && !is_open {
                    return;
                }
                let label = if count > 0 {
                    format!("+{count}")
                } else {
                    "−".into()
                };
                let size = egui::vec2(26.0, 16.0) * scale.clamp(0.7, 1.2);
                let pill = Rect::from_center_size(Pos2::new(side_x, box_.center().y), size);
                painter.rect_filled(pill, size.y / 2.0, palette.panel);
                painter.rect_stroke(
                    pill,
                    size.y / 2.0,
                    stroke(1.0, palette.accent),
                    egui::StrokeKind::Inside,
                );
                painter.text(
                    pill.center(),
                    egui::Align2::CENTER_CENTER,
                    label,
                    egui::FontId::proportional(10.0 * scale.clamp(0.7, 1.2)),
                    palette.accent,
                );
                if click.is_some_and(|at| pill.contains(at) && !in_minimap(at)) {
                    *hit = Some(node.id.clone());
                }
            };
        badge(
            box_.left() - 4.0,
            node.hidden_parents,
            &mut hits.badge,
            &painter,
        );
        badge(
            box_.right() + 4.0,
            node.hidden_children,
            &mut hits.badge,
            &painter,
        );
        if response.hovered()
            && ui
                .input(|input| input.pointer.hover_pos())
                .is_some_and(|at| box_.contains(at) && !minimap.contains(at))
        {
            egui::show_tooltip_at_pointer(
                ui.ctx(),
                ui.layer_id(),
                egui::Id::new(("lineage_node", &node.id)),
                |ui| {
                    ui.label(node_title(node));
                    if !node.path.is_empty() {
                        ui.label(RichText::new(&node.path).monospace().small());
                    }
                },
            );
        }
        node_rects.push((box_, node));
    }
    // The labels: kind shapes then the runs, on the edge where nothing is in
    // the way. Placement works on screen rectangles (the label's size follows
    // the zoom), against the nodes drawn.
    let obstacles: Vec<Rect> = node_rects.iter().map(|(box_, _)| *box_).collect();
    let sized: Vec<([Pos2; 4], Vec2)> = pending
        .iter()
        .map(|item| {
            let shapes = item.edge.kinds.len() as f32 * (font.size + 2.0);
            let size = egui::vec2(
                item.galley.size().x + shapes + 12.0,
                item.galley.size().y + 4.0,
            );
            (item.route, size)
        })
        .collect();
    let spots = labels::place(&sized, &obstacles);
    let mut labels: Vec<(Rect, &LineageEdge)> = Vec::new();
    for (item, pill) in pending.into_iter().zip(spots) {
        let size = pill.size();
        painter.rect_filled(pill, size.y / 2.0, palette.panel);
        painter.rect_stroke(
            pill,
            size.y / 2.0,
            stroke(1.0, item.color),
            egui::StrokeKind::Inside,
        );
        let mut x = pill.left() + 6.0 + font.size / 2.0;
        for kind in item.edge.kinds.keys() {
            kind_shape(
                &painter,
                *kind,
                Pos2::new(x, pill.center().y),
                font.size * 0.7,
            );
            x += font.size + 2.0;
        }
        painter.galley(
            Pos2::new(
                x - font.size / 2.0,
                pill.center().y - item.galley.size().y / 2.0,
            ),
            item.galley,
            palette.text,
        );
        labels.push((pill, item.edge));
    }
    // What an edge label stands for, as a tooltip: the counts per kind.
    if response.hovered() {
        if let Some(at) = ui
            .input(|input| input.pointer.hover_pos())
            .filter(|at| !in_minimap(*at))
        {
            if let Some((_, edge)) = labels.iter().rev().find(|(pill, _)| pill.contains(at)) {
                egui::show_tooltip_at_pointer(
                    ui.ctx(),
                    ui.layer_id(),
                    egui::Id::new(("lineage_edge", &edge.from, &edge.to)),
                    |ui| {
                        ui.label(super::edge_summary(edge));
                    },
                );
            }
        }
    }
    // Right-click: the node under the pointer gets its menu.
    if response.secondary_clicked() {
        *context = response
            .interact_pointer_pos()
            .filter(|at| !in_minimap(*at))
            .and_then(|at| {
                node_rects
                    .iter()
                    .rev()
                    .find(|(box_, _)| box_.contains(at))
                    .map(|(_, node)| node.id.clone())
            });
    }
    response.context_menu(|ui| {
        match context
            .as_ref()
            .and_then(|id| graph.nodes.iter().find(|node| node.id == *id))
        {
            Some(node) => menu(ui, node),
            None => ui.close_menu(),
        }
    });
    // Clicks: a badge wins, then a label, then a node.
    if hits.badge.is_none() {
        if let Some(at) = click.filter(|at| !in_minimap(*at)) {
            if let Some((_, edge)) = labels.iter().rev().find(|(pill, _)| pill.contains(at)) {
                hits.edge = Some((edge.from.clone(), edge.to.clone()));
            } else if let Some((_, node)) =
                node_rects.iter().rev().find(|(box_, _)| box_.contains(at))
            {
                hits.node = Some(node.id.clone());
                // Another library sample opens with one click.
                if matches!(node.kind, NodeKind::Library { .. }) && node.id != sample {
                    hits.open = Some(node.id.clone());
                }
            } else {
                hits.background = true;
            }
        }
        if let Some(at) = double.filter(|at| !in_minimap(*at)) {
            if let Some((_, node)) = node_rects.iter().rev().find(|(box_, _)| box_.contains(at)) {
                hits.open = Some(node.id.clone());
            }
        }
    }
    minimap_draw(&painter, minimap, graph, layout, view, viewport, sample);
    zoom_bar(ui, rect, view, viewport, layout, sample);
    hits
}

fn minimap_draw(
    painter: &egui::Painter,
    minimap: Rect,
    graph: &LineageGraph,
    layout: &Layout,
    view: &View,
    viewport: Vec2,
    sample: &str,
) {
    let palette = theme::palette();
    painter.rect_filled(minimap, 3.0, palette.panel);
    painter.rect_stroke(
        minimap,
        3.0,
        stroke(1.0, palette.line_soft),
        egui::StrokeKind::Inside,
    );
    let scale = (MINIMAP.x / layout.bounds.width().max(1.0))
        .min(MINIMAP.y / layout.bounds.height().max(1.0));
    let map = |point: Pos2| minimap.min + (point - layout.bounds.min) * scale;
    for node in &graph.nodes {
        if let Some(world) = layout.at.get(&node.id) {
            let color = if node.id == sample {
                palette.accent
            } else {
                border(node).0
            };
            painter.rect_filled(
                Rect::from_min_max(map(world.min), map(world.max)),
                1.0,
                color,
            );
        }
    }
    // The viewport rectangle in graph space.
    let min = ((Vec2::ZERO - view.offset) / view.zoom).to_pos2();
    let max = ((viewport - view.offset) / view.zoom).to_pos2();
    let shown = Rect::from_min_max(map(min), map(max)).intersect(minimap);
    painter.rect_stroke(
        shown,
        1.0,
        stroke(1.2, palette.accent),
        egui::StrokeKind::Inside,
    );
}

fn zoom_bar(
    ui: &mut egui::Ui,
    rect: Rect,
    view: &mut View,
    viewport: Vec2,
    layout: &Layout,
    sample: &str,
) {
    let bar = Rect::from_min_size(
        Pos2::new(rect.right() - 236.0, rect.bottom() - 30.0),
        egui::vec2(228.0, 24.0),
    );
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(bar)
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
    );
    if child
        .small_button("1:1")
        .on_hover_text("Actual size, centred on the sample")
        .clicked()
    {
        let centre = layout
            .at
            .get(sample)
            .map_or(layout.bounds.center(), Rect::center);
        view.actual(viewport, centre);
    }
    if child
        .small_button("Fit")
        .on_hover_text("The whole graph")
        .clicked()
    {
        view.fit(viewport, layout.bounds);
    }
    if child.small_button("+").clicked() {
        view.zoom_about(viewport / 2.0, 1.2);
    }
    child.label(
        RichText::new(format!("{:.0}%", view.zoom * 100.0))
            .color(theme::muted())
            .small(),
    );
    if child.small_button("−").clicked() {
        view.zoom_about(viewport / 2.0, 1.0 / 1.2);
    }
}

/// A small legend entry: the shape and its word.
pub(super) fn legend(ui: &mut egui::Ui) {
    for kind in EdgeKind::ALL {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 14.0), egui::Sense::hover());
        kind_shape(ui.painter(), kind, rect.center(), 9.0);
        ui.label(RichText::new(kind.label()).small().color(theme::muted()));
    }
    let _ = parts::run_name;
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::samples::{LineageNode, NodeKind};

    fn node(id: &str, level: i32) -> LineageNode {
        LineageNode {
            id: id.into(),
            kind: NodeKind::Captured,
            label: id.into(),
            path: String::new(),
            sha256: String::new(),
            level,
            hidden_parents: 0,
            hidden_children: 0,
        }
    }

    #[test]
    fn levels_are_columns_left_to_right_and_rows_stack() {
        let graph = LineageGraph {
            nodes: vec![node("p", -1), node("s", 0), node("a", 1), node("b", 1)],
            ..LineageGraph::default()
        };
        let layout = Layout::of(&graph);
        assert!(layout.at["p"].min.x < layout.at["s"].min.x);
        assert!(layout.at["s"].min.x < layout.at["a"].min.x);
        assert_eq!(layout.at["a"].min.x, layout.at["b"].min.x);
        assert!(layout.at["a"].min.y < layout.at["b"].min.y);
        assert!(layout.bounds.contains_rect(layout.at["b"]));
    }

    #[test]
    fn fit_shows_the_whole_graph_and_never_enlarges() {
        let bounds = Rect::from_min_size(Pos2::ZERO, egui::vec2(2000.0, 500.0));
        let mut view = View::default();
        view.fit(egui::vec2(1000.0, 380.0), bounds);
        assert!((view.zoom - 0.5).abs() < 1e-3);
        let screen = view.rect_to_screen(Pos2::ZERO, bounds);
        assert!(screen.min.x >= -0.5 && screen.max.x <= 1000.5);
        let small = Rect::from_min_size(Pos2::ZERO, egui::vec2(200.0, 100.0));
        view.fit(egui::vec2(1000.0, 380.0), small);
        assert_eq!(view.zoom, 1.0);
    }

    #[test]
    fn zoom_keeps_the_point_under_the_pointer_and_stays_in_range() {
        let mut view = View::default();
        let pivot = egui::vec2(300.0, 200.0);
        let before = (pivot - view.offset) / view.zoom;
        view.zoom_about(pivot, 1.5);
        let after = (pivot - view.offset) / view.zoom;
        assert!((before - after).length() < 1e-3);
        view.zoom_about(pivot, 1000.0);
        assert_eq!(view.zoom, MAX_ZOOM);
        view.zoom_about(pivot, 0.0001);
        assert_eq!(view.zoom, MIN_ZOOM);
    }
}
