// SPDX-License-Identifier: GPL-3.0-only
//! The Relationships graph's viewport: pan by dragging the background, zoom
//! with the buttons, ctrl and the wheel or a pinch, and a click on a node.
//! Where the nodes sit is `layout`'s. It draws the graph and says what was
//! clicked; it keeps no data of its own.
use super::fold::Fold;
use super::layout::Layout;
use super::model::{EdgeKind, Graph, GroupInfo, NodeKind};
use crate::theme;
use eframe::egui::{self, Color32, Pos2, Rect, RichText, Sense, Shape, Stroke, Vec2};

/// Low enough for Fit all to show about a thousand boxes in one column.
const MIN_ZOOM: f32 = 0.005;
const MAX_ZOOM: f32 = 3.0;
/// The smallest size a graph opens at.
const READABLE: f32 = 0.6;
/// Below this zoom the names on nodes are not drawn.
const TEXT_FROM: f32 = 0.4;
/// Below this zoom edge labels and arrowheads are not drawn.
const LABELS_FROM: f32 = 0.55;
/// Below this zoom edges are straight lines.
const CURVES_FROM: f32 = 0.3;
/// An open group with more members than this is joined to them by a comb: a
/// trunk beside each column of members with a short stub to each, not one
/// curve per member.
const COMB_MIN: u32 = 20;
/// Where the zoom bar sits: its size and its margin from the box's edge.
const BAR_HEIGHT: f32 = 26.0;
/// The bar's padding, the same on every side.
const BAR_PAD: f32 = 4.0;
/// Between the bar's buttons.
const BAR_GAP: f32 = 4.0;
const BAR_MARGIN: f32 = 8.0;

/// Pan and zoom: `offset` is where graph-space (0, 0) sits in the viewport.
#[derive(Clone, Copy, Debug)]
pub(in crate::triage) struct View {
    pub offset: Vec2,
    pub zoom: f32,
    /// The graph has been fitted to the viewport once.
    pub fitted: bool,
    /// A box that was opened or closed, to keep where it was on screen when
    /// the graph is laid out again.
    pin: Option<Pin>,
}

/// Where a node was on the screen (from the viewport's corner) when it was
/// clicked, and which layout it was in.
#[derive(Clone, Copy, Debug)]
struct Pin {
    node: u64,
    generation: u64,
    at: Vec2,
    time: f64,
}

/// A pin older than this is dropped (seconds).
const PIN_LIFE: f64 = 5.0;

fn hash_of(id: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    id.hash(&mut hasher);
    hasher.finish()
}

impl Default for View {
    fn default() -> Self {
        Self {
            offset: Vec2::ZERO,
            zoom: 1.0,
            fitted: false,
            pin: None,
        }
    }
}

impl View {
    /// Fit: the whole graph in the viewport (never enlarged past 1) when it
    /// can be read there; else its width and its top, at a size the names
    /// can be read at (the root is near the top left). A tall column runs
    /// off below, reached by scrolling or panning; "Fit all" shows all of it.
    pub(in crate::triage) fn fit(&mut self, viewport: Vec2, bounds: Rect) {
        // The zoom bar sits at the top right: the graph is fitted below it.
        let top = BAR_HEIGHT + 2.0 * BAR_MARGIN;
        let room = egui::vec2(viewport.x, (viewport.y - top).max(1.0));
        let across = (room.x / bounds.width().max(1.0)).clamp(MIN_ZOOM, 1.0);
        let down = room.y / bounds.height().max(1.0);
        if across.min(down) >= READABLE || down >= across {
            self.fit_all(viewport, bounds);
            return;
        }
        let zoom = across.max(READABLE);
        self.zoom = zoom;
        self.offset = egui::vec2(-bounds.min.x, top - bounds.min.y) * zoom;
        self.fitted = true;
    }

    /// Every box in the viewport, however small that makes them.
    pub(in crate::triage) fn fit_all(&mut self, viewport: Vec2, bounds: Rect) {
        let top = BAR_HEIGHT + 2.0 * BAR_MARGIN;
        let room = egui::vec2(viewport.x, (viewport.y - top).max(1.0));
        let zoom = (room.x / bounds.width().max(1.0))
            .min(room.y / bounds.height().max(1.0))
            .clamp(MIN_ZOOM, 1.0);
        self.zoom = zoom;
        self.offset = (room - bounds.size() * zoom) / 2.0 + egui::vec2(0.0, top)
            - bounds.min.to_vec2() * zoom;
        self.fitted = true;
    }

    /// Zoom by `factor` keeping the graph point under `pivot` (a viewport
    /// point) where it is.
    pub(in crate::triage) fn zoom_about(&mut self, pivot: Vec2, factor: f32) {
        let zoom = (self.zoom * factor).clamp(MIN_ZOOM, MAX_ZOOM);
        let factor = zoom / self.zoom;
        self.offset = pivot - (pivot - self.offset) * factor;
        self.zoom = zoom;
    }

    fn point_on_screen(&self, origin: Pos2, point: Pos2) -> Pos2 {
        origin + self.offset + point.to_vec2() * self.zoom
    }

    fn rect_to_screen(&self, origin: Pos2, rect: Rect) -> Rect {
        Rect::from_min_max(
            self.point_on_screen(origin, rect.min),
            self.point_on_screen(origin, rect.max),
        )
    }
}

fn kind_color(kind: EdgeKind) -> Color32 {
    match kind {
        EdgeKind::Injected => theme::error(),
        EdgeKind::Signalled => theme::warn(),
        EdgeKind::Connected => theme::good(),
        EdgeKind::Wrote | EdgeKind::Ran => theme::blue(),
        EdgeKind::Forked | EdgeKind::Execed | EdgeKind::Member => theme::muted(),
    }
}

fn tier_color(tier: crate::triage::rules::Tier) -> Color32 {
    theme::tone(tier.tone())
}

fn glyph(kind: &NodeKind) -> &'static str {
    match kind {
        NodeKind::Process(_) => egui_phosphor::regular::CPU,
        NodeKind::File(_) => egui_phosphor::regular::FILE,
        NodeKind::Endpoint(_) => egui_phosphor::regular::GLOBE,
        NodeKind::Victim(_) => egui_phosphor::regular::CROSSHAIR,
        NodeKind::Group(GroupInfo { open: true, .. }) => egui_phosphor::regular::CARET_DOWN,
        NodeKind::Group(_) => egui_phosphor::regular::STACK,
    }
}

/// What a frame of the canvas did.
#[derive(Default)]
pub(in crate::triage) struct Outcome {
    pub clicked: Option<usize>,
    /// The arrow of a box was clicked: open or close what is under it.
    pub folded: Option<usize>,
}

/// The arrow's width on a box, at zoom `scale`.
fn arrow_width(scale: f32) -> f32 {
    22.0 * scale.clamp(0.7, 1.2)
}

/// Draw the graph in a viewport `height` tall. Ctrl and the wheel, or a
/// pinch, zoom; the plain wheel is left to the page that holds the graph.
pub(in crate::triage) fn show(
    ui: &mut egui::Ui,
    id: egui::Id,
    graph: &Graph,
    layout: &Layout,
    view: &mut View,
    height: f32,
    folds: &[Fold],
) -> Outcome {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), Sense::hover());
    // What shows is the box, and of the box what the page shows of it.
    let visible = rect.intersect(ui.clip_rect());
    let response = ui.interact(visible, id, Sense::click_and_drag());
    let viewport = rect.size();
    if !view.fitted && viewport.x > 1.0 {
        view.fit(viewport, layout.bounds);
    }
    if let Some(pin) = view.pin {
        let now = ui.input(|i| i.time);
        if now - pin.time > PIN_LIFE {
            view.pin = None;
        } else if layout.generation != pin.generation {
            // The box that was clicked stays where it was.
            let node = layout
                .shown
                .iter()
                .find(|&&at| hash_of(&graph.nodes[at].kind.id()) == pin.node);
            if let Some(at) = node.and_then(|&at| layout.get(at)) {
                view.offset = pin.at - at.min.to_vec2() * view.zoom;
            }
            view.pin = None;
        }
    }
    if response.dragged() {
        view.offset += response.drag_delta();
        view.pin = None;
    }
    if let Some(pointer) = response.hover_pos() {
        let (scroll, pinch, ctrl) =
            ui.input(|i| (i.smooth_scroll_delta.y, i.zoom_delta(), i.modifiers.command));
        let pivot = pointer - rect.min;
        if pinch != 1.0 {
            view.zoom_about(pivot, pinch);
        } else if scroll != 0.0 && ctrl {
            view.zoom_about(pivot, (scroll * 0.0015).exp());
        }
    }
    let painter = ui.painter().with_clip_rect(rect);
    painter.rect_filled(rect, 4.0, theme::panel());
    painter.rect_stroke(
        rect,
        4.0,
        Stroke::new(1.0, theme::line()),
        egui::StrokeKind::Inside,
    );
    let origin = rect.min;
    let scale = view.zoom;
    let font = egui::FontId::proportional((12.0 * scale.clamp(0.7, 1.3)).max(8.0));
    let reach = rect.expand(24.0);
    let comb = |node: usize| matches!(&graph.nodes[node].kind, NodeKind::Group(info) if info.open && info.members > COMB_MIN);
    // The zoom bar's place: no node text is drawn under it.
    // The bar hugs its buttons: Fit, +, a percentage as wide as "300%", and
    // the minus, with the same padding left and right.
    let button_font = egui::TextStyle::Button.resolve(ui.style());
    let small_font = egui::TextStyle::Small.resolve(ui.style());
    let text_width = |text: &str, font: &egui::FontId| {
        ui.painter()
            .layout_no_wrap(text.to_owned(), font.clone(), Color32::WHITE)
            .size()
            .x
    };
    let button_pad = ui.spacing().button_padding.x * 2.0;
    let gap = BAR_GAP;
    let percent_width = text_width("300%", &small_font);
    let inner = ["Fit all", "Fit", "+", "\u{2212}"]
        .iter()
        .map(|text| text_width(text, &button_font) + button_pad)
        .sum::<f32>()
        + percent_width
        + 4.0 * gap;
    let bar_size = egui::vec2(
        (inner + 2.0 * BAR_PAD).min(rect.width() - 2.0 * BAR_MARGIN),
        BAR_HEIGHT,
    );
    let bar_rect = Rect::from_min_size(
        rect.right_top() + egui::vec2(-BAR_MARGIN - bar_size.x, BAR_MARGIN),
        bar_size,
    );
    for edge in &graph.edges {
        // What a comb draws below; a member with a finding is drawn as any.
        if edge.kind == EdgeKind::Member && comb(edge.from) && graph.nodes[edge.to].tier.is_none() {
            continue;
        }
        let (Some(from), Some(to)) = (layout.get(edge.from), layout.get(edge.to)) else {
            continue;
        };
        let (from, to) = (
            view.rect_to_screen(origin, from),
            view.rect_to_screen(origin, to),
        );
        // Out of the box, however long the edge: nothing to draw.
        if !from.union(to).intersects(reach) {
            continue;
        }
        // Right of the root: along the row; left of it: back along the row;
        // below: down the column.
        let (a, b, away) = if to.left() >= from.right() {
            (from.right_center(), to.left_center(), egui::vec2(1.0, 0.0))
        } else if to.right() <= from.left() {
            (from.left_center(), to.right_center(), egui::vec2(-1.0, 0.0))
        } else if to.top() >= from.bottom() {
            (from.center_bottom(), to.center_top(), egui::vec2(0.0, 1.0))
        } else {
            (from.center_top(), to.center_bottom(), egui::vec2(0.0, -1.0))
        };
        let color = kind_color(edge.kind);
        let member = edge.kind == EdgeKind::Member;
        let stroke = Stroke::new(if member { 1.0 } else { 1.3 }, color);
        if scale < CURVES_FROM {
            painter.line_segment([a, b], stroke);
            continue;
        }
        let span = if away.x != 0.0 {
            (b.x - a.x).abs()
        } else {
            (b.y - a.y).abs()
        };
        let bend = away * (span * 0.5).max(20.0 * scale);
        painter.add(Shape::CubicBezier(
            egui::epaint::CubicBezierShape::from_points_stroke(
                [a, a + bend, b - bend, b],
                false,
                Color32::TRANSPARENT,
                stroke,
            ),
        ));
        if member {
            continue;
        }
        let back = -away;
        let side = egui::vec2(-back.y, back.x);
        let tip = 7.0 * scale.clamp(0.6, 1.3);
        painter.add(Shape::convex_polygon(
            vec![
                b,
                b + back * tip + side * tip * 0.45,
                b + back * tip - side * tip * 0.45,
            ],
            color,
            Stroke::NONE,
        ));
        // The label sits at the middle of the edge: left out when that is
        // out of the box, however long the edge.
        if scale >= LABELS_FROM && reach.contains(a + (b - a) * 0.5) {
            let text = if edge.count > 1 {
                format!("{} \u{d7}{}", edge.kind.label(), edge.count)
            } else {
                edge.kind.label().to_owned()
            };
            let mid = a + (b - a) * 0.5;
            let galley = painter.layout_no_wrap(text, font.clone(), color);
            let pill = Rect::from_center_size(mid, galley.size() + egui::vec2(8.0, 2.0));
            painter.rect_filled(pill, pill.height() / 2.0, theme::panel());
            painter.galley(pill.center() - galley.size() / 2.0, galley, color);
        }
    }
    for &node in &layout.shown {
        if comb(node) {
            draw_comb(&painter, graph, layout, view, rect, node);
        }
    }
    let mut clicked = None;
    let pointer = response
        .interact_pointer_pos()
        .or_else(|| response.hover_pos());
    let mut hovered = None;
    let mut on_arrow = false;
    for &node in &layout.shown {
        let Some(world) = layout.get(node) else {
            continue;
        };
        let screen = view.rect_to_screen(origin, world);
        if !screen.intersects(rect) {
            continue;
        }
        let item = &graph.nodes[node];
        let over = pointer.is_some_and(|at| screen.contains(at) && !bar_rect.contains(at))
            && response.hovered();
        if over {
            hovered = Some(node);
        }
        let fold = folds.get(node).filter(|fold| fold.has_kids);
        let arrow = Rect::from_min_max(
            Pos2::new(screen.right() - arrow_width(scale), screen.top()),
            screen.right_bottom(),
        );
        if over && fold.is_some() && scale >= TEXT_FROM {
            on_arrow = pointer.is_some_and(|at| arrow.contains(at));
        }
        let line = item.tier.map_or_else(theme::line, tier_color);
        let fill = if over { theme::bg() } else { theme::panel() };
        if let NodeKind::Group(info) = &item.kind {
            // A stack: the outline of a second box behind the first.
            if !info.open {
                let behind = screen.translate(egui::vec2(4.0, 4.0) * scale.clamp(0.4, 1.0));
                painter.rect_stroke(
                    behind,
                    5.0,
                    Stroke::new(1.0, line),
                    egui::StrokeKind::Inside,
                );
            }
        }
        painter.rect_filled(screen, 5.0, fill);
        painter.rect_stroke(
            screen,
            5.0,
            Stroke::new(if item.tier.is_some() { 1.8 } else { 1.0 }, line),
            egui::StrokeKind::Inside,
        );
        if scale < TEXT_FROM || screen.intersects(bar_rect.expand(2.0)) {
            continue;
        }
        let mut text_box = screen.shrink(1.0);
        if let Some(fold) = fold {
            let small = egui::FontId::proportional((10.0 * scale.clamp(0.7, 1.3)).max(8.0));
            let mut right = screen.right() - arrow_width(scale);
            if fold.hidden > 0 {
                let badge = painter.layout_no_wrap(
                    format!("+{}", crate::values::thousands(u64::from(fold.hidden))),
                    small,
                    theme::muted(),
                );
                right -= badge.size().x + 4.0;
                painter.galley(
                    Pos2::new(right + 2.0, screen.center().y - badge.size().y / 2.0),
                    badge,
                    theme::muted(),
                );
            }
            let glyph = if fold.open {
                egui_phosphor::regular::CARET_DOWN
            } else {
                egui_phosphor::regular::CARET_RIGHT
            };
            let colour = if over && on_arrow {
                theme::text()
            } else {
                theme::muted()
            };
            let galley = painter.layout_no_wrap(glyph.to_owned(), font.clone(), colour);
            painter.galley(arrow.center() - galley.size() / 2.0, galley, colour);
            text_box.max.x = right;
        }
        let inner = painter.with_clip_rect(text_box.intersect(rect));
        let mut x = screen.left() + 8.0 * scale.clamp(0.7, 1.2);
        if let Some(tier) = item.tier {
            inner.circle_filled(
                Pos2::new(x + 3.0, screen.center().y),
                4.0 * scale.clamp(0.7, 1.2),
                tier_color(tier),
            );
            x += 12.0 * scale.clamp(0.7, 1.2);
        }
        let text = format!("{} {}", glyph(&item.kind), item.label);
        let galley = inner.layout_no_wrap(text, font.clone(), theme::text());
        inner.galley(
            Pos2::new(x, screen.center().y - galley.size().y / 2.0),
            galley,
            theme::text(),
        );
    }
    let mut folded = None;
    if response.clicked() {
        if on_arrow {
            folded = hovered;
        } else {
            clicked = hovered;
        }
        // A box that opens or closes something stays where it is.
        if let Some(node) = hovered.filter(|&node| {
            folded.is_some() || matches!(graph.nodes[node].kind, NodeKind::Group(_))
        }) {
            if let Some(at) = layout.get(node) {
                view.pin = Some(Pin {
                    node: hash_of(&graph.nodes[node].kind.id()),
                    generation: layout.generation,
                    at: view.rect_to_screen(origin, at).min - origin,
                    time: ui.input(|i| i.time),
                });
            }
        }
    }
    if let Some(node) = hovered {
        response.clone().on_hover_ui_at_pointer(|ui| {
            if on_arrow {
                let fold = folds.get(node).copied().unwrap_or_default();
                ui.label(RichText::new(&graph.nodes[node].label).strong());
                ui.weak(if fold.open {
                    "Click to close what is under it".to_owned()
                } else if fold.hidden > 0 {
                    format!(
                        "Click to open the next level; {} nodes are under it",
                        crate::values::thousands(u64::from(fold.hidden))
                    )
                } else {
                    "Click to open the next level".to_owned()
                });
                return;
            }
            ui.label(RichText::new(&graph.nodes[node].label).strong());
            if let Some(tier) = graph.nodes[node].tier {
                ui.label(format!("Highest tier: {}", tier.tag().to_uppercase()));
            }
            if let NodeKind::Group(info) = &graph.nodes[node].kind {
                for name in &info.sample {
                    ui.label(name);
                }
                if info.members as usize > info.sample.len() {
                    ui.weak(format!(
                        "and {} more",
                        crate::values::thousands(
                            u64::from(info.members) - info.sample.len() as u64
                        )
                    ));
                }
                ui.weak(if info.open {
                    "Click to close the group"
                } else {
                    "Click to open the group"
                });
            } else {
                ui.weak("Click to open its details");
            }
        });
    }
    // The zoom bar: on a background of its own, a margin in from the corner,
    // clipped to the box and to the page's own view, so a page scrolled past
    // the box does not carry it along.
    painter.rect_filled(bar_rect, 6.0, theme::panel());
    painter.rect_stroke(
        bar_rect,
        6.0,
        Stroke::new(1.0, theme::line()),
        egui::StrokeKind::Inside,
    );
    let bar = bar_rect.shrink2(egui::vec2(BAR_PAD, 0.0));
    let mut zoom_ui = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(bar)
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
    );
    zoom_ui.set_clip_rect(visible);
    zoom_ui.spacing_mut().item_spacing.x = BAR_GAP;
    if zoom_ui
        .small_button("Fit all")
        .on_hover_text("Show every box, however small")
        .clicked()
    {
        view.fit_all(viewport, layout.bounds);
    }
    if zoom_ui
        .small_button("Fit")
        .on_hover_text("Show the top of the graph, as wide as the box")
        .clicked()
    {
        view.fit(viewport, layout.bounds);
    }
    if zoom_ui.small_button("+").on_hover_text("Zoom in").clicked() {
        view.zoom_about(viewport / 2.0, 1.2);
    }
    zoom_ui.add_sized(
        [percent_width, BAR_HEIGHT],
        egui::Label::new(
            RichText::new(format!("{:.0}%", view.zoom * 100.0))
                .small()
                .color(theme::muted()),
        ),
    );
    if zoom_ui
        .small_button("\u{2212}")
        .on_hover_text("Zoom out")
        .clicked()
    {
        view.zoom_about(viewport / 2.0, 1.0 / 1.2);
    }
    Outcome { clicked, folded }
}

/// The comb of an open group: per column of members one connector from the
/// group, one trunk beside the column and a stub to each member in view.
fn draw_comb(
    painter: &egui::Painter,
    graph: &Graph,
    layout: &Layout,
    view: &View,
    rect: Rect,
    group: usize,
) {
    let Some(parent) = layout.get(group) else {
        return;
    };
    let from = view.rect_to_screen(rect.min, parent).right_center();
    let stroke = Stroke::new(1.0, kind_color(EdgeKind::Member));
    let scale = view.zoom;
    let mut columns: std::collections::BTreeMap<i32, Vec<Rect>> = std::collections::BTreeMap::new();
    for edge in graph.edges_out(group) {
        if edge.kind != EdgeKind::Member || graph.nodes[edge.to].tier.is_some() {
            continue;
        }
        if let Some(at) = layout.get(edge.to) {
            columns.entry(at.left() as i32).or_default().push(at);
        }
    }
    let reach = rect.expand(24.0);
    for members in columns.values_mut() {
        members.sort_by(|a, b| a.top().total_cmp(&b.top()));
        let screen: Vec<Rect> = members
            .iter()
            .map(|at| view.rect_to_screen(rect.min, *at))
            .collect();
        let trunk = screen[0].left() - 14.0 * scale.clamp(0.3, 1.0);
        let (top, bottom) = (screen[0].center().y, screen[screen.len() - 1].center().y);
        let wide = Rect::from_two_pos(from, egui::pos2(trunk, top));
        if wide.intersects(reach) {
            let bend = ((trunk - from.x) * 0.5).max(10.0 * scale);
            painter.add(Shape::CubicBezier(
                egui::epaint::CubicBezierShape::from_points_stroke(
                    [
                        from,
                        from + egui::vec2(bend, 0.0),
                        egui::pos2(trunk - bend, top),
                        egui::pos2(trunk, top),
                    ],
                    false,
                    Color32::TRANSPARENT,
                    stroke,
                ),
            ));
        }
        if trunk < reach.left() || trunk > reach.right() {
            continue;
        }
        painter.line_segment(
            [
                egui::pos2(trunk, top.max(reach.top())),
                egui::pos2(trunk, bottom.min(reach.bottom())),
            ],
            stroke,
        );
        // Only the members in view get a stub.
        let first = screen.partition_point(|at| at.bottom() < reach.top());
        for at in screen[first..]
            .iter()
            .take_while(|at| at.top() <= reach.bottom())
        {
            let y = at.center().y;
            painter.line_segment([egui::pos2(trunk, y), egui::pos2(at.left(), y)], stroke);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{tests::fixture, Graph};
    use super::*;

    #[test]
    fn zoom_keeps_the_point_under_the_pointer_and_fit_never_enlarges() {
        let mut view = View::default();
        let pivot = egui::vec2(200.0, 100.0);
        let before = (pivot - view.offset) / view.zoom;
        view.zoom_about(pivot, 1.5);
        let after = (pivot - view.offset) / view.zoom;
        assert!((before - after).length() < 1e-3);
        view.zoom_about(pivot, 10_000.0);
        assert_eq!(view.zoom, MAX_ZOOM);
        view.zoom_about(pivot, 0.00001);
        assert_eq!(view.zoom, MIN_ZOOM);
        let mut view = View::default();
        view.fit(
            egui::vec2(1000.0, 400.0),
            Rect::from_min_size(Pos2::ZERO, egui::vec2(100.0, 50.0)),
        );
        assert_eq!(view.zoom, 1.0);
        view.fit(
            egui::vec2(500.0, 400.0),
            Rect::from_min_size(Pos2::ZERO, egui::vec2(1000.0, 100.0)),
        );
        assert!((view.zoom - 0.5).abs() < 1e-3);
    }

    fn frame(
        ctx: &egui::Context,
        graph: &Graph,
        layout: &Layout,
        view: &mut View,
        events: Vec<egui::Event>,
        time: f64,
    ) -> Outcome {
        let mut out = Outcome::default();
        let _ = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(800.0, 500.0))),
                events,
                time: Some(time),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE)
                    .show(root, |ui| {
                        out = show(ui, egui::Id::new("c"), graph, layout, view, 300.0, &[]);
                    });
            },
        );
        out
    }

    fn button(pos: Pos2, pressed: bool) -> egui::Event {
        egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        }
    }

    #[test]
    fn dragging_the_background_pans_and_a_click_on_a_node_names_it() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let graph = Graph::build(&fixture());
        let all: Vec<usize> = (0..graph.nodes.len()).collect();
        let layout = Layout::of(&graph, &all);
        let mut view = View::default();
        frame(&ctx, &graph, &layout, &mut view, vec![], 0.0);
        assert!(view.fitted);
        // A spot in the viewport no node covers.
        let nodes: Vec<Rect> = layout
            .shown
            .iter()
            .filter_map(|&n| layout.get(n))
            .map(|r| view.rect_to_screen(Pos2::ZERO, r))
            .collect();
        let spot = (0..30)
            .flat_map(|y| {
                (0..40).map(move |x| Pos2::new(20.0 + x as f32 * 19.0, 40.0 + y as f32 * 8.0))
            })
            .find(|p| {
                p.y < 280.0 && nodes.iter().all(|r| !r.expand(30.0).contains(*p)) && p.x < 690.0
            })
            .expect("a free spot");
        let before = view.offset;
        frame(
            &ctx,
            &graph,
            &layout,
            &mut view,
            vec![egui::Event::PointerMoved(spot)],
            0.1,
        );
        frame(
            &ctx,
            &graph,
            &layout,
            &mut view,
            vec![button(spot, true)],
            0.2,
        );
        let to = spot + egui::vec2(40.0, 25.0);
        frame(
            &ctx,
            &graph,
            &layout,
            &mut view,
            vec![egui::Event::PointerMoved(to)],
            0.3,
        );
        frame(
            &ctx,
            &graph,
            &layout,
            &mut view,
            vec![egui::Event::PointerMoved(to + egui::vec2(1.0, 1.0))],
            0.4,
        );
        frame(
            &ctx,
            &graph,
            &layout,
            &mut view,
            vec![button(to, false)],
            0.5,
        );
        assert!(
            (view.offset - before).length() > 20.0,
            "panned from {before:?} to {:?}",
            view.offset
        );
        // A click on the root node.
        let centre = view
            .rect_to_screen(Pos2::ZERO, layout.get(0).unwrap())
            .center();
        frame(
            &ctx,
            &graph,
            &layout,
            &mut view,
            vec![egui::Event::PointerMoved(centre)],
            1.0,
        );
        frame(
            &ctx,
            &graph,
            &layout,
            &mut view,
            vec![button(centre, true)],
            1.1,
        );
        let out = frame(
            &ctx,
            &graph,
            &layout,
            &mut view,
            vec![button(centre, false)],
            1.2,
        );
        assert_eq!(out.clicked, Some(0));
    }

    #[test]
    fn a_big_graph_opens_on_its_root_and_at_a_readable_size() {
        use super::super::group::Rendered;
        use super::super::model::tests::synthetic;
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let raw = Graph::build(&synthetic(300, 0));
        let rendered = Rendered::full(&raw, &raw.expanded(super::super::group::FULL_CAP));
        let root = rendered.layout.root.expect("a root");
        assert_eq!(rendered.graph.nodes[root].kind, NodeKind::Process((1, 1)));
        let mut view = View::default();
        frame(
            &ctx,
            &rendered.graph,
            &rendered.layout,
            &mut view,
            vec![],
            0.0,
        );
        assert!(view.fitted);
        assert!(view.zoom >= READABLE - 1e-3, "{}", view.zoom);
        let at = view.rect_to_screen(Pos2::ZERO, rendered.layout.get(root).unwrap());
        let viewport = Rect::from_min_size(Pos2::ZERO, egui::vec2(800.0, 300.0));
        assert!(
            viewport.contains_rect(at),
            "the root {at:?} is in the box {viewport:?}"
        );
    }

    #[test]
    fn a_big_open_group_is_joined_to_its_members_by_a_comb_not_a_curve_each() {
        use super::super::group::Rendered;
        use super::super::model::Proc;
        let mut facts = fixture();
        for n in 0..40u32 {
            facts.procs.push(Proc {
                pid: 1000 + n,
                cookie: 100 + u64::from(n),
                parent: Some((401, 1)),
                name: "ls".into(),
                ..Default::default()
            });
        }
        let raw = Graph::build(&facts);
        let rendered = Rendered::full(&raw, &raw.expanded(super::super::group::FULL_CAP));
        let members = rendered
            .graph
            .nodes
            .iter()
            .filter(|n| n.label.starts_with("ls ("))
            .count();
        assert_eq!(members, 40);
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut view = View {
            fitted: true,
            zoom: 0.4,
            offset: egui::vec2(10.0, 10.0),
            ..View::default()
        };
        let out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1200.0, 700.0))),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE)
                    .show(root, |ui| {
                        show(
                            ui,
                            egui::Id::new("c"),
                            &rendered.graph,
                            &rendered.layout,
                            &mut view,
                            600.0,
                            &[],
                        );
                    });
            },
        );
        fn curves(shape: &egui::Shape) -> usize {
            match shape {
                egui::Shape::CubicBezier(_) => 1,
                egui::Shape::Vec(all) => all.iter().map(curves).sum(),
                _ => 0,
            }
        }
        let drawn: usize = out.shapes.iter().map(|s| curves(&s.shape)).sum();
        assert!(drawn < 25, "{drawn} curves for 40 members");
    }

    fn walk(shape: &egui::Shape, bars: &mut Vec<Rect>, texts: &mut Vec<(String, Rect)>) {
        match shape {
            egui::Shape::Rect(rect) if (rect.rect.height() - BAR_HEIGHT).abs() < 0.5 => {
                bars.push(rect.rect);
            }
            egui::Shape::Text(text) => {
                let rect = text.galley.rect.translate(text.pos.to_vec2());
                texts.push((text.galley.text().to_owned(), rect));
            }
            egui::Shape::Vec(all) => all.iter().for_each(|s| walk(s, bars, texts)),
            _ => {}
        }
    }

    #[test]
    fn the_zoom_bar_hugs_its_buttons_with_equal_padding_left_and_right() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let graph = Graph::build(&fixture());
        let all: Vec<usize> = (0..graph.nodes.len()).collect();
        let layout = Layout::of(&graph, &all);
        let mut view = View::default();
        let out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(800.0, 500.0))),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE)
                    .show(root, |ui| {
                        show(
                            ui,
                            egui::Id::new("c"),
                            &graph,
                            &layout,
                            &mut view,
                            300.0,
                            &[],
                        );
                    });
            },
        );
        let (mut bars, mut texts) = (Vec::new(), Vec::new());
        for shape in &out.shapes {
            walk(&shape.shape, &mut bars, &mut texts);
        }
        let bar = bars.first().copied().expect("the bar's background");
        assert!(bar.width() < 300.0, "hugs its buttons: {bar:?}");
        let text = |wanted: &str| {
            texts
                .iter()
                .find(|(t, r)| t == wanted && bar.contains_rect(r.shrink(0.5)))
                .map(|(_, r)| *r)
                .unwrap_or_else(|| panic!("{wanted:?} in the bar"))
        };
        let (first, last) = (text("\u{2212}"), text("Fit all"));
        let (left, right) = (first.left() - bar.left(), bar.right() - last.right());
        assert!((left - right).abs() < 2.0, "left {left}, right {right}");
    }

    /// A parent with `kids` children, each its own box in one column.
    fn parent_with(kids: u32) -> (Graph, Layout) {
        use super::super::model::Proc;
        let mut facts = fixture();
        for n in 0..kids {
            facts.procs.push(Proc {
                pid: 1000 + n,
                cookie: 100 + u64::from(n),
                parent: Some((401, 1)),
                name: format!("kid{n}"),
                ..Default::default()
            });
        }
        let graph = Graph::build(&facts);
        let all: Vec<usize> = (0..graph.nodes.len()).collect();
        let layout = Layout::of(&graph, &all);
        (graph, layout)
    }

    fn draw(
        ctx: &egui::Context,
        graph: &Graph,
        layout: &Layout,
        view: &mut View,
    ) -> Vec<(String, Rect)> {
        let out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1280.0, 800.0))),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE)
                    .show(root, |ui| {
                        show(ui, egui::Id::new("c"), graph, layout, view, 700.0, &[]);
                    });
            },
        );
        let (mut bars, mut texts) = (Vec::new(), Vec::new());
        for shape in &out.shapes {
            walk(&shape.shape, &mut bars, &mut texts);
        }
        texts
    }

    #[test]
    fn a_parent_with_150_children_is_one_column_fit_reads_the_root_and_fit_all_shows_every_box() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let (graph, layout) = parent_with(150);
        let kids: Vec<Rect> = (0..graph.nodes.len())
            .filter(|&n| graph.nodes[n].label.starts_with("kid"))
            .map(|n| layout.get(n).unwrap())
            .collect();
        assert_eq!(kids.len(), 150);
        assert!(
            kids.iter().all(|r| r.left() == kids[0].left()),
            "one column"
        );
        let mut view = View::default();
        let first = draw(&ctx, &graph, &layout, &mut view);
        // Fit: the root and the first levels are readable.
        assert!(view.zoom >= READABLE - 1e-3, "{}", view.zoom);
        let root = layout.root.expect("a root");
        let name = &graph.nodes[root].label;
        assert!(
            first.iter().any(|(text, _)| text.contains(name.as_str())),
            "the root's label is drawn: {first:?}"
        );
        // Culling: only the boxes in view are drawn.
        assert!(first.len() < 60, "{} texts drawn", first.len());
        // Fit all: every box inside the view.
        let viewport = egui::vec2(1280.0, 700.0);
        view.fit_all(viewport, layout.bounds);
        let box_rect = Rect::from_min_size(Pos2::ZERO, viewport);
        for &node in &layout.shown {
            let at = view.rect_to_screen(Pos2::ZERO, layout.get(node).unwrap());
            assert!(box_rect.contains_rect(at), "{at:?} outside {box_rect:?}");
        }
        let all = draw(&ctx, &graph, &layout, &mut view);
        assert!(all.len() < 60, "{} texts drawn at Fit all", all.len());
    }

    #[test]
    fn fit_all_reaches_a_thousand_boxes_in_one_column() {
        let (_, layout) = parent_with(1000);
        let mut view = View::default();
        let viewport = egui::vec2(1280.0, 700.0);
        view.fit_all(viewport, layout.bounds);
        assert!(view.zoom > MIN_ZOOM, "{}", view.zoom);
        let box_rect = Rect::from_min_size(Pos2::ZERO, viewport);
        let last = layout
            .shown
            .iter()
            .filter_map(|&n| layout.get(n))
            .map(|r| view.rect_to_screen(Pos2::ZERO, r))
            .fold(Rect::NOTHING, |a, b| a.union(b));
        assert!(box_rect.contains_rect(last), "{last:?}");
    }

    #[test]
    fn after_fit_no_node_is_under_the_zoom_bar() {
        use super::super::group::Rendered;
        use super::super::model::tests::synthetic;
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let raw = Graph::build(&synthetic(12, 0));
        let rendered = Rendered::full(&raw, &raw.expanded(super::super::group::FULL_CAP));
        let mut view = View::default();
        let run = |view: &mut View| {
            ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(800.0, 500.0))),
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default()
                        .frame(egui::Frame::NONE)
                        .show(root, |ui| {
                            show(
                                ui,
                                egui::Id::new("c"),
                                &rendered.graph,
                                &rendered.layout,
                                view,
                                300.0,
                                &[],
                            );
                        });
                },
            )
        };
        // Fitted as the box opens, and again by "Fit".
        for fit_again in [false, true] {
            if fit_again {
                view.fit(egui::vec2(800.0, 300.0), rendered.layout.bounds);
            }
            let out = run(&mut view);
            let (mut bars, mut texts) = (Vec::new(), Vec::new());
            for shape in &out.shapes {
                walk(&shape.shape, &mut bars, &mut texts);
            }
            let bar = bars.first().copied().expect("the bar");
            for &node in &rendered.layout.shown {
                let at = view.rect_to_screen(Pos2::ZERO, rendered.layout.get(node).unwrap());
                assert!(!at.intersects(bar), "{at:?} under the bar {bar:?}");
            }
        }
    }

    /// A parent with `ANTINOMIE_QA_KIDS` (150) children in the graph box, for
    /// screenshots under Xvfb. `ANTINOMIE_QA_FITALL=1` presses Fit all.
    #[test]
    #[ignore = "requires owned isolated X11; Relationships graph screenshot fixture"]
    fn native_one_column_graph_fixture() {
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct Fixture {
            graph: Graph,
            layout: Layout,
            view: View,
            fit_all: bool,
            frame: u32,
            deadline: std::time::Instant,
        }
        impl eframe::App for Fixture {
            fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
                let ctx = root.ctx().clone();
                self.frame += 1;
                if self.fit_all && self.frame == 5 {
                    let room = egui::vec2(ctx.content_rect().width() - 16.0, 700.0);
                    self.view.fit_all(room, self.layout.bounds);
                }
                egui::CentralPanel::default().show(root, |ui| {
                    show(
                        ui,
                        egui::Id::new("c"),
                        &self.graph,
                        &self.layout,
                        &mut self.view,
                        700.0,
                        &[],
                    );
                });
                if std::time::Instant::now() > self.deadline {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ctx.request_repaint_after(std::time::Duration::from_millis(100));
            }
        }
        let kids = std::env::var("ANTINOMIE_QA_KIDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(150);
        let (graph, layout) = parent_with(kids);
        let fit_all = std::env::var("ANTINOMIE_QA_FITALL").is_ok_and(|value| value == "1");
        eframe::run_native(
            "Antinomie graph QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size([1280.0, 800.0])
                    .with_position([0.0, 0.0]),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11();
                    builder.with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                theme::install(&cc.egui_ctx);
                Ok(Box::new(Fixture {
                    graph,
                    layout,
                    view: View::default(),
                    fit_all,
                    frame: 0,
                    deadline: std::time::Instant::now() + std::time::Duration::from_secs(40),
                }))
            }),
        )
        .expect("native graph fixture");
    }
}
