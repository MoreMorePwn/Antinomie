// SPDX-License-Identifier: GPL-3.0-only
//! The Relationships graph's viewport: a left-to-right layout (the root at the
//! left, what it started, wrote, contacted and acted on to its right), pan by
//! dragging the background, zoom with the buttons, ctrl and the wheel or a
//! pinch, and a click on a node. It draws the graph and says what was
//! clicked; it keeps no data of its own.
use super::model::{EdgeKind, Graph, NodeKind};
use crate::theme;
use eframe::egui::{self, Color32, Pos2, Rect, RichText, Sense, Shape, Stroke, Vec2};
use std::collections::BTreeMap;

const NODE: Vec2 = egui::vec2(188.0, 30.0);
const ROW: f32 = 46.0;
const COLUMN: f32 = 250.0;
/// A level with more nodes than this wraps into more columns.
const WRAP: usize = 10;
const WRAP_GAP: f32 = 24.0;
const MIN_ZOOM: f32 = 0.15;
const MAX_ZOOM: f32 = 3.0;

/// Where each shown node sits, in graph space.
pub(in crate::triage) struct Layout {
    pub at: BTreeMap<usize, Rect>,
    pub bounds: Rect,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            at: BTreeMap::new(),
            bounds: Rect::from_min_size(Pos2::ZERO, Vec2::splat(1.0)),
        }
    }
}

impl Layout {
    pub(in crate::triage) fn of(graph: &Graph, shown: &[usize]) -> Self {
        let level = graph.levels(shown);
        let mut by_level: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for &node in shown {
            by_level
                .entry(level.get(&node).copied().unwrap_or(0))
                .or_default()
                .push(node);
        }
        let mut at = BTreeMap::new();
        let mut x = 0.0;
        let mut bounds: Option<Rect> = None;
        let mut row_of: BTreeMap<usize, f32> = BTreeMap::new();
        for nodes in by_level.values_mut() {
            // Under the anchor, so an edge runs short: order by where the
            // node that leads to it sits.
            nodes.sort_by(|a, b| {
                let key = |n: &usize| {
                    graph
                        .edges
                        .iter()
                        .find(|edge| edge.to == *n)
                        .and_then(|edge| row_of.get(&edge.from))
                        .copied()
                        .unwrap_or(0.0)
                };
                key(a).total_cmp(&key(b)).then(a.cmp(b))
            });
            let rows = nodes.len().min(WRAP);
            let columns = nodes.len().div_ceil(WRAP.max(1));
            let height = (rows.max(1) - 1) as f32 * ROW;
            for (i, &node) in nodes.iter().enumerate() {
                let (column, row) = (i / WRAP, i % WRAP);
                let min = Pos2::new(
                    x + column as f32 * (NODE.x + WRAP_GAP),
                    -height / 2.0 + row as f32 * ROW - NODE.y / 2.0,
                );
                let rect = Rect::from_min_size(min, NODE);
                bounds = Some(bounds.map_or(rect, |b| b.union(rect)));
                row_of.insert(node, rect.center().y);
                at.insert(node, rect);
            }
            x += (columns.max(1) - 1) as f32 * (NODE.x + WRAP_GAP) + COLUMN;
        }
        Self {
            at,
            bounds: bounds
                .unwrap_or_else(|| Rect::from_min_size(Pos2::ZERO, Vec2::splat(1.0)))
                .expand(24.0),
        }
    }
}

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
        EdgeKind::Forked | EdgeKind::Execed => theme::muted(),
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
    }
}

/// What a frame of the canvas did.
#[derive(Default)]
pub(in crate::triage) struct Outcome {
    pub clicked: Option<usize>,
}

/// Draw the graph in a viewport `height` tall. `wheel` zooms with the plain
/// wheel (a window); otherwise ctrl and the wheel, or a pinch, do.
pub(in crate::triage) fn show(
    ui: &mut egui::Ui,
    id: egui::Id,
    graph: &Graph,
    layout: &Layout,
    view: &mut View,
    height: f32,
    wheel: bool,
) -> Outcome {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), Sense::hover());
    let response = ui.interact(rect, id, Sense::click_and_drag());
    let viewport = rect.size();
    if !view.fitted && viewport.x > 1.0 {
        view.fit(viewport, layout.bounds);
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
        } else if scroll != 0.0 && (wheel || ctrl) {
            view.zoom_about(pivot, (scroll * 0.0015).exp());
        }
    }
    let painter = ui.painter_at(rect);
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
    for edge in &graph.edges {
        let (Some(from), Some(to)) = (layout.at.get(&edge.from), layout.at.get(&edge.to)) else {
            continue;
        };
        let (from, to) = (
            view.rect_to_screen(origin, *from),
            view.rect_to_screen(origin, *to),
        );
        let (a, b) = if to.left() >= from.right() {
            (from.right_center(), to.left_center())
        } else {
            (from.center_bottom(), to.center_top())
        };
        let bend = ((b.x - a.x).abs() * 0.5).max(20.0 * scale);
        let color = kind_color(edge.kind);
        painter.add(Shape::CubicBezier(
            egui::epaint::CubicBezierShape::from_points_stroke(
                [a, a + egui::vec2(bend, 0.0), b - egui::vec2(bend, 0.0), b],
                false,
                Color32::TRANSPARENT,
                Stroke::new(1.3, color),
            ),
        ));
        let back = (b - (b - egui::vec2(bend, 0.0))).normalized();
        let side = egui::vec2(-back.y, back.x);
        let tip = 7.0 * scale.clamp(0.6, 1.3);
        painter.add(Shape::convex_polygon(
            vec![
                b,
                b - back * tip + side * tip * 0.45,
                b - back * tip - side * tip * 0.45,
            ],
            color,
            Stroke::NONE,
        ));
        if scale >= 0.55 {
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
    let mut clicked = None;
    let pointer = response
        .interact_pointer_pos()
        .or_else(|| response.hover_pos());
    let mut hovered = None;
    for (&node, world) in &layout.at {
        let screen = view.rect_to_screen(origin, *world);
        if !screen.intersects(rect) {
            continue;
        }
        let item = &graph.nodes[node];
        let over = pointer.is_some_and(|at| screen.contains(at)) && response.hovered();
        if over {
            hovered = Some(node);
        }
        let line = item.tier.map_or_else(theme::line, tier_color);
        painter.rect_filled(screen, 5.0, if over { theme::bg() } else { theme::panel() });
        painter.rect_stroke(
            screen,
            5.0,
            Stroke::new(if item.tier.is_some() { 1.8 } else { 1.0 }, line),
            egui::StrokeKind::Inside,
        );
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
        let mut text = format!("{} {}", glyph(&item.kind), item.label);
        if item.warn {
            text.push_str(" \u{26a0}");
        }
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
            if graph.nodes[node].warn {
                ui.label("argv[0] does not match the image the kernel loaded");
            }
            ui.weak("Click to open its details");
        });
    }
    // The zoom bar.
    let bar = Rect::from_min_size(
        rect.right_top() + egui::vec2(-108.0, 6.0),
        egui::vec2(102.0, 24.0),
    );
    let mut zoom_ui = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(bar)
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
    );
    if zoom_ui
        .small_button("\u{2212}")
        .on_hover_text("Zoom out")
        .clicked()
    {
        view.zoom_about(viewport / 2.0, 1.0 / 1.2);
    }
    zoom_ui.label(
        RichText::new(format!("{:.0}%", view.zoom * 100.0))
            .small()
            .color(theme::muted()),
    );
    if zoom_ui.small_button("+").on_hover_text("Zoom in").clicked() {
        view.zoom_about(viewport / 2.0, 1.2);
    }
    if zoom_ui
        .small_button("Fit")
        .on_hover_text("Show the whole graph")
        .clicked()
    {
        view.fit(viewport, layout.bounds);
    }
    Outcome { clicked }
}

#[cfg(test)]
mod tests {
    use super::super::model::{tests::fixture, Graph};
    use super::*;

    #[test]
    fn layout_puts_levels_in_columns_left_to_right_without_overlap() {
        let graph = Graph::build(&fixture());
        let all: Vec<usize> = (0..graph.nodes.len()).collect();
        let layout = Layout::of(&graph, &all);
        assert_eq!(layout.at.len(), all.len());
        let rects: Vec<Rect> = layout.at.values().copied().collect();
        for (i, a) in rects.iter().enumerate() {
            for b in &rects[i + 1..] {
                assert!(!a.intersects(*b), "{a:?} overlaps {b:?}");
            }
        }
        let root = layout.at[&0];
        assert!(layout.at.values().all(|r| r.left() >= root.left()));
        assert!(layout.bounds.contains_rect(root));
    }

    #[test]
    fn a_wide_level_wraps_into_columns() {
        let mut facts = fixture();
        for n in 0..40u32 {
            facts.procs.push(super::super::model::Proc {
                pid: 1000 + n,
                cookie: 100 + u64::from(n),
                parent: Some((401, 1)),
                name: "ls".into(),
                ..Default::default()
            });
        }
        let graph = Graph::build(&facts);
        let all: Vec<usize> = (0..graph.nodes.len()).collect();
        let layout = Layout::of(&graph, &all);
        let height = layout.bounds.height();
        assert!(height < (WRAP as f32 + 3.0) * ROW, "{height}");
    }

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
                        out = show(ui, egui::Id::new("c"), graph, layout, view, 300.0, false);
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
            .at
            .values()
            .map(|r| view.rect_to_screen(Pos2::ZERO, *r))
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
        let centre = view.rect_to_screen(Pos2::ZERO, layout.at[&0]).center();
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
}
