// SPDX-License-Identifier: GPL-3.0-only
//! The Relationships graph's viewport: pan by dragging the background, zoom
//! with the buttons, ctrl and the wheel or a pinch, and a click on a node.
//! Where the nodes sit is `layout`'s. It draws the graph and says what was
//! clicked; it keeps no data of its own.
use super::layout::Layout;
use super::model::{EdgeKind, Graph, GroupInfo, NodeKind};
use crate::theme;
use eframe::egui::{self, Color32, Pos2, Rect, RichText, Sense, Shape, Stroke, Vec2};

const MIN_ZOOM: f32 = 0.05;
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
const BAR: Vec2 = egui::vec2(196.0, 26.0);
const BAR_MARGIN: f32 = 8.0;

/// Pan and zoom: `offset` is where graph-space (0, 0) sits in the viewport.
#[derive(Clone, Copy, Debug)]
pub(in crate::triage) struct View {
    pub offset: Vec2,
    pub zoom: f32,
    /// The graph has been fitted to the viewport once.
    pub fitted: bool,
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
    /// The whole graph in the viewport, never enlarged past 1.
    pub(in crate::triage) fn fit(&mut self, viewport: Vec2, bounds: Rect) {
        let zoom = (viewport.x / bounds.width().max(1.0))
            .min(viewport.y / bounds.height().max(1.0))
            .clamp(MIN_ZOOM, 1.0);
        self.zoom = zoom;
        self.offset = (viewport - bounds.size() * zoom) / 2.0 - bounds.min.to_vec2() * zoom;
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
    tier.color()
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
) -> Outcome {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), Sense::hover());
    // What shows is the box, and of the box what the page shows of it.
    let visible = rect.intersect(ui.clip_rect());
    let response = ui.interact(visible, id, Sense::click_and_drag());
    let viewport = rect.size();
    if !view.fitted && viewport.x > 1.0 {
        view.fit(viewport, layout.bounds);
        // A graph too big for the box opens at a size the names can be read
        // at, on the root; "Fit" shows all of it.
        if view.zoom < READABLE {
            view.zoom = READABLE;
            let root = layout
                .root
                .and_then(|node| layout.get(node))
                .map_or(Pos2::ZERO, |at| at.center());
            view.offset =
                egui::vec2(viewport.x * 0.22, viewport.y * 0.3) - root.to_vec2() * READABLE;
        }
    }
    if response.dragged() {
        view.offset += response.drag_delta();
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
    let bar_size = egui::vec2(BAR.x.min(rect.width() - 2.0 * BAR_MARGIN), BAR.y);
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
        if scale >= LABELS_FROM {
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
        let inner = painter.with_clip_rect(screen.shrink(1.0).intersect(rect));
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
    if response.clicked() {
        clicked = hovered;
    }
    if let Some(node) = hovered {
        response.clone().on_hover_ui_at_pointer(|ui| {
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
    let bar = bar_rect.shrink2(egui::vec2(4.0, 0.0));
    let mut zoom_ui = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(bar)
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
    );
    zoom_ui.set_clip_rect(visible);
    if zoom_ui
        .small_button("Fit")
        .on_hover_text("Show the whole graph")
        .clicked()
    {
        view.fit(viewport, layout.bounds);
    }
    if zoom_ui.small_button("+").on_hover_text("Zoom in").clicked() {
        view.zoom_about(viewport / 2.0, 1.2);
    }
    zoom_ui.label(
        RichText::new(format!("{:.0}%", view.zoom * 100.0))
            .small()
            .color(theme::muted()),
    );
    if zoom_ui
        .small_button("\u{2212}")
        .on_hover_text("Zoom out")
        .clicked()
    {
        view.zoom_about(viewport / 2.0, 1.0 / 1.2);
    }
    Outcome { clicked }
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
                        out = show(ui, egui::Id::new("c"), graph, layout, view, 300.0);
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
        let rendered = Rendered::full(&raw, &std::collections::BTreeSet::new());
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
        let rendered = Rendered::full(&raw, &std::collections::BTreeSet::new());
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
}
