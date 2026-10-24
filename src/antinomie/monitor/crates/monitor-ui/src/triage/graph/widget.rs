// SPDX-License-Identifier: GPL-3.0-only
//! The graph widget: allocates its area, reads the mouse and keyboard, and
//! paints. It never touches the Triage view; it returns what it wants done.
use super::axis::{Axis, Spacing};
use super::index::GraphIndex;
use super::input::{self, Action, Hit, Layout};
use super::lanes::Lane;
use super::paint::{self, Colors};
use super::ruler;
use super::view::{self, Drag, Frame, State, INDIVIDUAL_BELOW};
use super::*;
use crate::triage::rules::{Category, Tier};
use eframe::egui::{
    Align2, Color32, EventFilter, Key, Painter, Pos2, Rect, Sense, Shape, Stroke, Vec2,
};

/// Indent of each depth in the lane-name column.
const DEPTH_PX: f32 = 10.0;
/// Individual markers get a label with their count when fewer than this are in view.
const LABELLED_BELOW: usize = 300;
/// Icons need room: with more findings than this in view the markers are plain tier dots.
const ICONS_BELOW: usize = 600;

pub(in crate::triage) struct Config<'a> {
    pub index: &'a GraphIndex,
    pub colors: Colors,
    pub clock: Option<antinomie_monitor_core::HostClockAnchor>,
    /// The height to take; the widget never asks for less than a usable area.
    pub height: f32,
    /// How the findings are spaced along the time axis.
    pub spacing: Spacing,
}

/// Draw the graph and say what to do about what the user did.
pub(in crate::triage) fn show(ui: &mut egui::Ui, state: &mut State, cfg: &Config) -> Vec<Action> {
    let size = Vec2::new(ui.available_width(), cfg.height.max(240.0));
    let (rect, response) = ui.allocate_exact_size(size, Sense::click_and_drag());
    // A window kept in the other spacing's units is moved to this one's.
    if state.units != cfg.spacing {
        let axis = Axis::new(cfg.spacing, &cfg.index.slots);
        state.window = state
            .window
            .map(|window| axis.convert_from(state.units, window));
        state.units = cfg.spacing;
        state.ruler = None;
    }
    let mut actions = Vec::new();
    handle(ui, &response, rect, state, cfg, &mut actions);
    let layout = Layout::new(rect, state, cfg.index);
    state.scroll = layout.scroll;
    // The ruler's marks cover the whole run; they are made again only when
    // the findings, the width or the spacing change.
    let columns = layout.frame.ruler.width().round().max(1.0) as usize;
    if !state
        .ruler
        .as_ref()
        .is_some_and(|marks| marks.is_for(cfg.index, &layout.frame.map, columns))
    {
        state.ruler = Some(ruler::Marks::build(
            cfg.index,
            &layout.frame.map,
            layout.range,
            columns,
        ));
    }
    let painter = ui.painter_at(rect);
    draw(&painter, &layout, state, cfg);
    if let Some(Hit::Marker { record, near }) = response
        .hover_pos()
        .and_then(|pos| input::hit_test(&layout, cfg.index, DEPTH_PX, pos))
    {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        let lines = input::tooltip(cfg.index, record, near, cfg.clock);
        response.on_hover_ui_at_pointer(|ui| {
            for (at, line) in lines.iter().enumerate() {
                if at == 0 {
                    ui.strong(line);
                } else {
                    ui.label(line);
                }
            }
        });
    }
    actions
}

/// The window on the axis now, in its units.
fn window_of(state: &State, index: &GraphIndex) -> (f64, f64) {
    state
        .window
        .unwrap_or_else(|| Axis::new(state.units, &index.slots).all(index.extent()))
}

/// Mouse and keyboard.
fn handle(
    ui: &mut egui::Ui,
    response: &egui::Response,
    rect: Rect,
    state: &mut State,
    cfg: &Config,
    actions: &mut Vec<Action>,
) {
    let index = cfg.index;
    let layout = Layout::new(rect, state, index);
    let bounds = layout.range;
    let frame = layout.frame.clone();
    let min_span = frame.map.min_span();
    // Wheel, pinch and Ctrl+wheel.
    if response.hovered() {
        let (scroll, zoom) = ui.input(|i| (i.smooth_scroll_delta, i.zoom_delta()));
        let anchor = response
            .hover_pos()
            .map_or((frame.t0 + frame.t1) / 2.0, |pos| frame.u_at(pos.x));
        if zoom != 1.0 {
            state.window = Some(view::zoomed_min(
                window_of(state, index),
                anchor,
                f64::from(zoom),
                bounds,
                min_span,
            ));
        }
        if scroll.x != 0.0 {
            let delta = -f64::from(scroll.x) * frame.u_per_px();
            state.window = Some(view::panned(window_of(state, index), delta, bounds));
        }
        if scroll.y != 0.0 {
            state.scroll = layout.scroll - scroll.y;
        }
        if scroll != Vec2::ZERO {
            ui.input_mut(|i| i.smooth_scroll_delta = Vec2::ZERO);
        }
    }
    if response.drag_started() || response.clicked() {
        response.request_focus();
    }
    drag(ui, response, state, index, &layout, bounds, actions);
    if let Some(pos) = response.interact_pointer_pos() {
        let hit = input::hit_test(&layout, index, DEPTH_PX, pos);
        if response.double_clicked() {
            double_click(state, index, hit, pos, &layout, actions);
        } else if response.clicked() {
            let shift = ui.input(|i| i.modifiers.shift);
            click(state, index, hit, shift, &layout, actions);
        }
    }
    if response.has_focus() {
        ui.memory_mut(|memory| {
            memory.set_focus_lock_filter(
                response.id,
                EventFilter {
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    escape: true,
                    tab: false,
                },
            );
        });
        keys(ui, state, index, rect, cfg.spacing, actions);
    }
}

fn click(
    state: &mut State,
    index: &GraphIndex,
    hit: Option<Hit>,
    shift: bool,
    layout: &Layout,
    actions: &mut Vec<Action>,
) {
    match hit {
        Some(Hit::Marker { record, .. }) => {
            state.selected = Some(record);
            actions.push(Action::Select {
                record,
                focus: true,
            });
        }
        Some(Hit::Chevron { row }) => toggle(state, index, layout, row),
        Some(Hit::LaneName { row }) => {
            let lane = layout.rows.lanes[row];
            let cookies = if shift {
                index.lanes.subtree_cookies(lane)
            } else {
                vec![index.lanes.list[lane as usize].cookie]
            };
            if cookies.iter().any(|cookie| *cookie != 0) {
                actions.push(Action::Lane { cookies });
            }
        }
        Some(Hit::Phase { span }) => {
            if let (Some(geometry), Some(span)) = (index.geometry, index.phases.get(span)) {
                actions.push(Action::Brush(
                    geometry.start(0, span.first as usize) as u64,
                    geometry.start(0, span.last as usize + 1) as u64,
                ));
            }
        }
        Some(Hit::Fit) => state.fit(),
        Some(Hit::Run) => state.window = Some(layout.range),
        Some(Hit::Spacing(spacing)) => actions.push(Action::Spacing(spacing)),
        Some(Hit::Axis) | Some(Hit::Ruler) | None => {}
    }
}

fn double_click(
    state: &mut State,
    index: &GraphIndex,
    hit: Option<Hit>,
    pos: Pos2,
    layout: &Layout,
    actions: &mut Vec<Action>,
) {
    match hit {
        Some(Hit::Marker { record, .. }) => {
            state.selected = Some(record);
            actions.push(Action::Open(record));
        }
        Some(Hit::Axis) => {
            let window = window_of(state, index);
            state.window = Some(view::zoomed_min(
                window,
                layout.frame.u_at(pos.x),
                2.0,
                layout.range,
                layout.frame.map.min_span(),
            ));
        }
        // The whole run again.
        Some(Hit::Ruler) => state.window = Some(layout.range),
        _ => {}
    }
}

fn toggle(state: &mut State, index: &GraphIndex, layout: &Layout, row: usize) {
    let lane = &index.lanes.list[layout.rows.lanes[row] as usize];
    if lane.subtree_end as usize > layout.rows.lanes[row] as usize + 1 {
        let key = (lane.cookie, lane.pid);
        if !state.collapsed.remove(&key) {
            state.collapsed.insert(key);
        }
    }
}

/// Dragging the plot pans; dragging the axis brushes a time range.
fn drag(
    ui: &egui::Ui,
    response: &egui::Response,
    state: &mut State,
    index: &GraphIndex,
    layout: &Layout,
    bounds: (f64, f64),
    actions: &mut Vec<Action>,
) {
    let frame = &layout.frame;
    if response.drag_started() {
        let origin = ui.input(|i| i.pointer.press_origin());
        let window = window_of(state, index);
        state.drag = origin.and_then(|pos| {
            if frame.ruler.contains(pos) {
                Some(Drag::Ruler(ruler::begin(
                    frame.ruler,
                    layout.range,
                    window,
                    pos.x,
                )))
            } else if frame.axis.contains(pos)
                && !layout.fit.contains(pos)
                && !layout.run.contains(pos)
                && !layout.spacing.iter().any(|chip| chip.contains(pos))
            {
                Some(Drag::Brush {
                    start: frame.ns(pos.x),
                    now: frame.ns(pos.x),
                })
            } else if frame.plot.contains(pos) {
                Some(Drag::Pan)
            } else {
                None
            }
        });
    }
    match state.drag {
        Some(Drag::Pan) if response.dragged() => {
            let delta = response.drag_delta();
            let window = window_of(state, index);
            state.window = Some(view::panned(
                window,
                -f64::from(delta.x) * frame.u_per_px(),
                bounds,
            ));
            state.scroll = layout.scroll - delta.y;
        }
        Some(Drag::Ruler(_)) if response.dragged() => {
            if let Some(pos) = response.interact_pointer_pos() {
                let window = window_of(state, index);
                if let Some(moved) = ruler::drag(
                    state,
                    frame.ruler,
                    layout.range,
                    window,
                    pos.x,
                    frame.map.min_span(),
                ) {
                    state.window = Some(moved);
                }
            }
        }
        Some(Drag::Brush { start, .. }) if response.dragged() => {
            if let Some(pos) = response.interact_pointer_pos() {
                state.drag = Some(Drag::Brush {
                    start,
                    now: frame.ns(pos.x),
                });
            }
        }
        _ => {}
    }
    if response.drag_stopped() {
        if let Some(Drag::Ruler(view::Ruler::Select { start, now })) = state.drag {
            let window = window_of(state, index);
            state.window = Some(ruler::selected(
                frame.ruler,
                layout.range,
                window,
                (start, now),
                frame.map.min_span(),
            ));
        }
        if let Some(Drag::Brush { start, now }) = state.drag {
            if (frame.x(now) - frame.x(start)).abs() >= 3.0 {
                let (from, to) = (
                    start.min(now).max(0.0) as u64,
                    start.max(now).max(0.0) as u64,
                );
                state.brush = Some((from, to));
                actions.push(Action::Brush(from, to));
            }
        }
        state.drag = None;
    }
}

/// ←/→ previous and next finding in time, ↑/↓ lane, Enter opens, F fits,
/// +/- zoom at the selection, Space folds a lane, H M L I toggle tiers,
/// 1…9 and 0 the first ten category chips, Escape clears the brush.
fn keys(
    ui: &mut egui::Ui,
    state: &mut State,
    index: &GraphIndex,
    rect: Rect,
    spacing: Spacing,
    actions: &mut Vec<Action>,
) {
    const WATCHED: [Key; 30] = [
        Key::ArrowLeft,
        Key::ArrowRight,
        Key::ArrowUp,
        Key::ArrowDown,
        Key::Enter,
        Key::Space,
        Key::Escape,
        Key::F,
        Key::R,
        Key::T,
        Key::H,
        Key::M,
        Key::L,
        Key::I,
        Key::Plus,
        Key::Equals,
        Key::Minus,
        Key::Num0,
        Key::Num1,
        Key::Num2,
        Key::Num3,
        Key::Num4,
        Key::Num5,
        Key::Num6,
        Key::Num7,
        Key::Num8,
        Key::Num9,
        Key::Home,
        Key::End,
        Key::Tab,
    ];
    let pressed: Vec<Key> = ui.input(|input| {
        if input.modifiers.ctrl || input.modifiers.alt || input.modifiers.command {
            return Vec::new();
        }
        WATCHED
            .into_iter()
            .filter(|key| input.key_pressed(*key))
            .collect()
    });
    for key in pressed {
        let layout = Layout::new(rect, state, index);
        let (window, bounds) = (window_of(state, index), layout.range);
        let axis = &layout.frame.map;
        let ns_window = (axis.to_ns(window.0), axis.to_ns(window.1));
        let selected = state.selected.filter(|at| *at < index.records.len());
        let mut pick = |record: Option<usize>, state: &mut State| {
            if let Some(record) = record {
                select(state, index, &layout, record);
                actions.push(Action::Select {
                    record,
                    focus: false,
                });
            }
        };
        match key {
            Key::ArrowLeft => pick(input::step_time(index, selected, -1, ns_window), state),
            Key::ArrowRight => pick(input::step_time(index, selected, 1, ns_window), state),
            Key::Home => pick((!index.records.is_empty()).then_some(0), state),
            Key::End => pick(index.records.len().checked_sub(1), state),
            Key::ArrowUp | Key::ArrowDown => {
                let direction = if key == Key::ArrowUp { -1 } else { 1 };
                let next = match selected {
                    Some(from) => input::step_lane(index, &layout, from, direction),
                    None => input::step_time(index, None, 1, ns_window),
                };
                pick(next, state);
            }
            Key::Enter => {
                if let Some(record) = selected {
                    actions.push(Action::Open(record));
                }
            }
            Key::F => state.fit(),
            Key::R => state.window = Some(layout.range),
            Key::T => actions.push(Action::Spacing(spacing.other())),
            Key::Plus | Key::Equals | Key::Minus => {
                let factor = if key == Key::Minus { 0.5 } else { 2.0 };
                let anchor = selected
                    .map(|at| axis.to_u(index.records[at].first_ns as f64))
                    .unwrap_or((window.0 + window.1) / 2.0);
                state.window = Some(view::zoomed_min(
                    window,
                    anchor,
                    factor,
                    bounds,
                    axis.min_span(),
                ));
            }
            Key::Space => {
                if let Some(row) = selected.and_then(|at| layout.row_of(index.records[at].lane)) {
                    toggle(state, index, &layout, row);
                }
            }
            Key::H => actions.push(Action::Tier(Tier::High)),
            Key::M => actions.push(Action::Tier(Tier::Medium)),
            Key::L => actions.push(Action::Tier(Tier::Low)),
            Key::I => actions.push(Action::Tier(Tier::Info)),
            Key::Escape => {
                state.drag = None;
                if state.brush.take().is_some() {
                    actions.push(Action::ClearBrush);
                }
            }
            other => {
                let number = match other {
                    Key::Num0 => Some(9),
                    Key::Num1 => Some(0),
                    Key::Num2 => Some(1),
                    Key::Num3 => Some(2),
                    Key::Num4 => Some(3),
                    Key::Num5 => Some(4),
                    Key::Num6 => Some(5),
                    Key::Num7 => Some(6),
                    Key::Num8 => Some(7),
                    Key::Num9 => Some(8),
                    _ => None,
                };
                if let Some(category) = number.and_then(|at| Category::ALL.get(at)) {
                    actions.push(Action::Category(*category));
                }
            }
        }
    }
}

/// Select a record from the keyboard and bring it into view.
fn select(state: &mut State, index: &GraphIndex, layout: &Layout, record: usize) {
    state.selected = Some(record);
    let found = &index.records[record];
    let window = window_of(state, index);
    let at = layout.frame.map.to_u(found.first_ns as f64);
    state.window = Some(input::including(window, at, layout.range));
    if let Some(row) = layout.row_of(found.lane) {
        state.scroll = input::scroll_to(
            row,
            layout.scroll,
            layout.frame.lanes.height(),
            layout.frame.m.lane_h,
        );
    }
}

fn draw(painter: &Painter, layout: &Layout, state: &State, cfg: &Config) {
    let (frame, colors, index) = (&layout.frame, &cfg.colors, cfg.index);
    painter.rect_filled(frame.whole, 0.0, colors.panel);
    paint::phase_band(painter, frame, index, colors);
    let visible = frame.visible_rows(layout.scroll, layout.rows.lanes.len());
    let pass = paint::event_pass(layout, index, visible);
    let tallest = paint::severity_curve(painter, frame, index, colors, pass.as_ref());
    paint::heat_strip(
        painter,
        frame,
        index,
        colors,
        &layout.categories,
        pass.as_ref(),
    );
    side_labels(painter, layout, colors, tallest);
    lanes(painter, layout, state, cfg, pass.as_ref());
    if let Some((from, to)) = state.brush {
        overlay(painter, frame, from as f64, to as f64, colors);
    }
    if let Some(Drag::Brush { start, now }) = state.drag {
        overlay(painter, frame, start.min(now), start.max(now), colors);
    }
    // Ticks stop before the spacing label.
    let right = layout.spacing[0].left() - 58.0;
    paint::axis(
        painter,
        frame,
        index.run_extent().0,
        cfg.clock,
        colors,
        right,
    );
    paint::breaks(painter, frame, colors, right);
    footer(painter, layout, cfg);
    let axis = &frame.map;
    let selecting = match state.drag {
        Some(Drag::Ruler(view::Ruler::Select { start, now })) => Some((start, now)),
        _ => None,
    };
    ruler::paint(
        painter,
        ruler::Drawing {
            rect: frame.ruler,
            range: layout.range,
            window: (frame.t0, frame.t1),
            marks: state.ruler.as_ref(),
            brush: state
                .brush
                .map(|(from, to)| (axis.to_u(from as f64), axis.to_u(to as f64))),
            selecting,
        },
        colors,
    );
}

/// The band between two times, over the whole plot.
fn overlay(painter: &Painter, frame: &Frame, from: f64, to: f64, colors: &Colors) {
    let rect = Rect::from_min_max(
        Pos2::new(frame.x(from).max(frame.plot.left()), frame.phases.top()),
        Pos2::new(frame.x(to).min(frame.plot.right()), frame.axis.bottom()),
    );
    if rect.width() <= 0.0 {
        return;
    }
    painter.rect_filled(rect, 0.0, colors.accent.gamma_multiply(0.14));
    for x in [rect.left(), rect.right()] {
        painter.line_segment(
            [Pos2::new(x, rect.top()), Pos2::new(x, rect.bottom())],
            Stroke::new(1.0_f32, colors.accent),
        );
    }
}

fn side_labels(painter: &Painter, layout: &Layout, colors: &Colors, tallest: u32) {
    let frame = &layout.frame;
    let left = frame.labels.left() + 4.0;
    paint::label(
        painter,
        Pos2::new(left, frame.phases.center().y),
        Align2::LEFT_CENTER,
        "phases",
        12.0,
        colors.muted,
    );
    paint::label(
        painter,
        Pos2::new(left, frame.curve.top() + 8.0),
        Align2::LEFT_CENTER,
        "severity",
        12.0,
        colors.muted,
    );
    if tallest > 0 {
        paint::label(
            painter,
            Pos2::new(left, frame.curve.top() + 22.0),
            Align2::LEFT_CENTER,
            &format!("max {tallest}"),
            11.0,
            colors.muted,
        );
    }
    for (row, category) in layout.categories.iter().enumerate() {
        paint::label(
            painter,
            Pos2::new(
                left,
                frame.heat.top() + row as f32 * frame.m.heat_h + frame.m.heat_h / 2.0,
            ),
            Align2::LEFT_CENTER,
            &format!(
                "{} {}",
                paint::icon(*category as u8),
                Category::ALL[*category].chip()
            ),
            (frame.m.heat_h - 2.0).min(10.5),
            colors.muted,
        );
    }
}

/// Lane names, lifelines, spawn and injection edges, and the markers: icons when
/// the window holds few findings, plain tier dots when it holds many.
fn lanes(
    painter: &Painter,
    layout: &Layout,
    state: &State,
    cfg: &Config,
    pass: Option<&paint::EventPass>,
) {
    let (frame, colors, index) = (&layout.frame, &cfg.colors, cfg.index);
    let area = frame.lanes;
    let rows = layout.rows.lanes.len();
    let clip = painter.with_clip_rect(area.union(Rect::from_min_max(
        Pos2::new(frame.labels.left(), area.top()),
        Pos2::new(frame.labels.right(), area.bottom()),
    )));
    if index.is_empty() && rows == 0 {
        return;
    }
    let visible = frame.visible_rows(layout.scroll, rows);
    for row in visible.clone() {
        let top = frame.row_top(row, layout.scroll);
        let band = Rect::from_min_max(
            Pos2::new(frame.labels.left(), top),
            Pos2::new(frame.whole.right(), top + frame.m.lane_h),
        );
        clip.rect_filled(band, 0.0, colors.lane(row));
        lifeline_and_name(&clip, layout, index, colors, row, top);
    }
    spawn_edges(&clip, layout, index, colors, visible.clone());
    markers(&clip, layout, state, cfg, visible, pass);
    injection_edges(&clip, layout, cfg);
    if let Some(row) = state
        .selected
        .and_then(|at| index.records.get(at))
        .and_then(|record| layout.row_of(record.lane))
    {
        if layout.row_in_view(row) {
            let top = frame.row_top(row, layout.scroll);
            clip.rect_stroke(
                Rect::from_min_max(
                    Pos2::new(frame.labels.left(), top),
                    Pos2::new(frame.whole.right(), top + frame.m.lane_h),
                ),
                0.0,
                Stroke::new(1.0_f32, colors.selection),
                eframe::egui::StrokeKind::Inside,
            );
        }
    }
}

fn lifeline_and_name(
    painter: &Painter,
    layout: &Layout,
    index: &GraphIndex,
    colors: &Colors,
    row: usize,
    top: f32,
) {
    let frame = &layout.frame;
    let lane_index = layout.rows.lanes[row];
    let lane: &Lane = &index.lanes.list[lane_index as usize];
    let center = top + frame.m.lane_h / 2.0;
    if lane.last_ns > 0 {
        let (from, to) = (frame.x(lane.first_ns as f64), frame.x(lane.last_ns as f64));
        let stroke = Stroke::new(2.0_f32, colors.line);
        painter.line_segment(
            [
                Pos2::new(from.max(frame.plot.left()), center),
                Pos2::new(to.min(frame.plot.right()), center),
            ],
            stroke,
        );
        if lane.exited && to <= frame.plot.right() {
            painter.line_segment(
                [Pos2::new(to, center - 4.0), Pos2::new(to, center + 4.0)],
                stroke,
            );
        }
    }
    let indent = f32::from(lane.depth.saturating_sub(1)) * DEPTH_PX;
    let x = frame.labels.left() + 4.0 + indent;
    let has_children = lane.subtree_end > lane_index + 1;
    if has_children {
        let collapsed = layout.rows.is_collapsed(&index.lanes, row);
        chevron(painter, Pos2::new(x + 5.0, center), collapsed, colors.muted);
    }
    let name = lane.label();
    painter
        .with_clip_rect(Rect::from_min_max(
            Pos2::new(x, top),
            Pos2::new(frame.labels.right() - 2.0, top + frame.m.lane_h),
        ))
        .text(
            Pos2::new(x + 14.0, center),
            Align2::LEFT_CENTER,
            name,
            eframe::egui::FontId::proportional(if frame.m.lane_h >= 30.0 { 13.0 } else { 12.0 }),
            if lane_index == 0 {
                colors.muted
            } else {
                colors.text
            },
        );
}

fn chevron(painter: &Painter, center: Pos2, collapsed: bool, color: Color32) {
    let points = if collapsed {
        vec![
            center + Vec2::new(-2.0, -4.0),
            center + Vec2::new(3.0, 0.0),
            center + Vec2::new(-2.0, 4.0),
        ]
    } else {
        vec![
            center + Vec2::new(-4.0, -2.0),
            center + Vec2::new(4.0, -2.0),
            center + Vec2::new(0.0, 3.0),
        ]
    };
    painter.add(Shape::convex_polygon(points, color, Stroke::NONE));
}

/// A thin vertical connector from a parent's lane to a child's, at the child's first sight.
fn spawn_edges(
    painter: &Painter,
    layout: &Layout,
    index: &GraphIndex,
    colors: &Colors,
    rows: std::ops::Range<usize>,
) {
    let frame = &layout.frame;
    let stroke = Stroke::new(1.0_f32, colors.muted.gamma_multiply(0.6));
    for row in rows {
        let lane = &index.lanes.list[layout.rows.lanes[row] as usize];
        let Some(parent_row) = lane.parent.and_then(|parent| layout.row_of(parent)) else {
            continue;
        };
        if parent_row >= row || lane.first_ns == 0 {
            continue;
        }
        // Both ends in the lane area.
        if !layout.row_in_view(parent_row) {
            continue;
        }
        let x = frame.x(lane.first_ns as f64);
        if x < frame.plot.left() || x > frame.plot.right() {
            continue;
        }
        painter.line_segment(
            [
                Pos2::new(x, layout.row_center(parent_row)),
                Pos2::new(x, layout.row_center(row)),
            ],
            stroke,
        );
        painter.circle_filled(Pos2::new(x, layout.row_center(row)), 1.8, colors.muted);
    }
}

fn markers(
    painter: &Painter,
    layout: &Layout,
    state: &State,
    cfg: &Config,
    rows: std::ops::Range<usize>,
    pass: Option<&paint::EventPass>,
) {
    let (frame, colors, index) = (&layout.frame, &cfg.colors, cfg.index);
    if index.is_empty() {
        return;
    }
    let (ns0, ns1) = frame.ns_range();
    let in_window = index.window(ns0, ns1);
    let mut shapes: Vec<Shape> = Vec::new();
    if in_window.len() < INDIVIDUAL_BELOW {
        let labelled = in_window.len() < LABELLED_BELOW;
        let icons = in_window.len() < ICONS_BELOW;
        for at in in_window {
            let record = &index.records[at];
            let Some(row) = layout.row_of(record.lane).filter(|row| rows.contains(row)) else {
                continue;
            };
            let y = layout.row_center(row);
            let color = colors.tier[usize::from(record.tier).min(3)];
            let x = frame.x_rec(record);
            if record.last_ns > record.first_ns {
                let end = frame
                    .x(record.last_ns as f64)
                    .min(frame.plot.right() + 20.0);
                if end - x > 4.0 {
                    shapes.push(Shape::line_segment(
                        [Pos2::new(x, y), Pos2::new(end, y)],
                        Stroke::new(1.5_f32, color.gamma_multiply(0.45)),
                    ));
                }
            }
            let hollow = record.flags & index::HOLLOW != 0;
            if icons {
                paint::marker(
                    painter,
                    &mut shapes,
                    record.category,
                    Pos2::new(x, y),
                    frame.m.glyph(),
                    color,
                    hollow,
                );
            } else if hollow {
                shapes.push(Shape::circle_stroke(
                    Pos2::new(x, y),
                    frame.m.glyph() * 0.62,
                    Stroke::new(1.3_f32, color),
                ));
            } else {
                paint::dot(&mut shapes, Pos2::new(x, y), frame.m.glyph() * 0.62, color);
            }
            if record.count > 1 && labelled {
                painter.text(
                    Pos2::new(x + 7.0, y),
                    Align2::LEFT_CENTER,
                    format!("×{}", record.count),
                    eframe::egui::FontId::proportional(11.0),
                    colors.text,
                );
            }
            if state.selected == Some(at) {
                shapes.push(Shape::circle_stroke(
                    Pos2::new(x, y),
                    frame.m.glyph() + 3.5,
                    Stroke::new(2.0_f32, colors.text),
                ));
            }
        }
    } else if let Some(pass) = pass {
        // Equal slots: the findings were put into columns of a few pixels,
        // row by row, in one pass over the window.
        let step = frame.plot.width() / pass.columns as f32;
        for (place, cell) in pass.cells.iter().enumerate() {
            let Some(cell) = cell else { continue };
            let (row, column) = (pass.first_row + place / pass.columns, place % pass.columns);
            let at = Pos2::new(
                frame.plot.left() + (column as f32 + 0.5) * step,
                layout.row_center(row),
            );
            let color = colors.tier[usize::from(cell.top).min(3)];
            paint::dot(&mut shapes, at, frame.m.glyph() * 0.62, color);
            if cell.total() > 1 {
                shapes.push(Shape::circle_filled(
                    at + eframe::egui::vec2(4.0, -4.5),
                    1.7,
                    colors.text,
                ));
            }
        }
        if let Some(at) = state.selected.filter(|at| *at < index.records.len()) {
            let record = &index.records[at];
            if let Some(row) = layout
                .row_of(record.lane)
                .filter(|row| layout.row_in_view(*row))
            {
                shapes.push(Shape::circle_stroke(
                    Pos2::new(frame.x_rec(record), layout.row_center(row)),
                    frame.m.glyph() + 3.5,
                    Stroke::new(2.0_f32, colors.text),
                ));
            }
        }
    } else {
        let (wanted, ..) = paint::visible_buckets(index, frame);
        let (slot, level) = index.kept_level(wanted);
        let geometry = index.geometry();
        let width = geometry.width(level);
        let low = (((ns0 - geometry.origin as f64) / width).floor().max(0.0)) as u32;
        let high = (((ns1 - geometry.origin as f64) / width).ceil().max(0.0)) as u32;
        let mut merged: Vec<index::Cell> = Vec::new();
        for row in rows {
            let lane = layout.rows.lanes[row];
            let end = index.lanes.list[lane as usize].subtree_end.max(lane + 1);
            merged.clear();
            let collapsed = layout.rows.is_collapsed(&index.lanes, row);
            let covered = if collapsed { lane..end } else { lane..lane + 1 };
            for member in covered {
                merged.extend_from_slice(index.lane_cells(slot, member, low, high));
            }
            if collapsed {
                merged.sort_by_key(|cell| cell.bucket);
            }
            let y = layout.row_center(row);
            // Cells closer than a bucket's worth of pixels share one glyph.
            let mut pending: Option<(f32, index::Cell)> = None;
            let flush = |pending: Option<(f32, index::Cell)>, shapes: &mut Vec<Shape>| {
                if let Some((x, cell)) = pending {
                    let color = colors.tier[usize::from(cell.top).min(3)];
                    paint::dot(shapes, Pos2::new(x, y), frame.m.glyph() * 0.62, color);
                    if cell.total() > 1 {
                        shapes.push(Shape::circle_filled(
                            Pos2::new(x + 4.0, y - 4.5),
                            1.7,
                            colors.text,
                        ));
                    }
                }
            };
            for cell in &merged {
                let x = frame.x(geometry.origin as f64 + (f64::from(cell.bucket) + 0.5) * width);
                match &mut pending {
                    Some((at, run)) if x - *at < view::MIN_BUCKET_PX as f32 => run.merge(cell),
                    _ => {
                        flush(pending.take(), &mut shapes);
                        pending = Some((x, *cell));
                    }
                }
            }
            flush(pending, &mut shapes);
        }
        if let Some(at) = state.selected.filter(|at| *at < index.records.len()) {
            let record = &index.records[at];
            if let Some(row) = layout
                .row_of(record.lane)
                .filter(|row| layout.row_in_view(*row))
            {
                shapes.push(Shape::circle_stroke(
                    Pos2::new(frame.x_rec(record), layout.row_center(row)),
                    frame.m.glyph() + 3.5,
                    Stroke::new(2.0_f32, colors.text),
                ));
            }
        }
    }
    painter.extend(shapes);
}

/// A curved arrow from an injector's marker to the target's lane.
fn injection_edges(painter: &Painter, layout: &Layout, cfg: &Config) {
    let (frame, index, colors) = (&layout.frame, cfg.index, &cfg.colors);
    for edge in &index.injections {
        let record = &index.records[edge.record as usize];
        let (from_row, to_row) = (layout.row_of(record.lane), layout.row_of(edge.target));
        let (Some(from_row), Some(to_row)) = (from_row, to_row) else {
            continue;
        };
        let x = frame.x_rec(record);
        if x < frame.plot.left()
            || x > frame.plot.right()
            || !layout.row_in_view(from_row)
            || !layout.row_in_view(to_row)
        {
            continue;
        }
        let start = Pos2::new(x, layout.row_center(from_row));
        let end = Pos2::new(x + 24.0, layout.row_center(to_row));
        let control = Pos2::new(x + 24.0, start.y);
        painter.add(Shape::QuadraticBezier(
            eframe::egui::epaint::QuadraticBezierShape::from_points_stroke(
                [start, control, end],
                false,
                Color32::TRANSPARENT,
                Stroke::new(1.5_f32, colors.injection),
            ),
        ));
        let direction = if to_row > from_row { 1.0 } else { -1.0 };
        painter.add(Shape::convex_polygon(
            vec![
                end,
                end + Vec2::new(-3.5, -5.0 * direction),
                end + Vec2::new(3.5, -5.0 * direction),
            ],
            colors.injection,
            Stroke::NONE,
        ));
    }
}

/// The curve's scale, the host zone and the Fit button.
fn footer(painter: &Painter, layout: &Layout, cfg: &Config) {
    let (frame, colors) = (&layout.frame, &cfg.colors);
    let caption = match (cfg.spacing, cfg.clock.is_some()) {
        (Spacing::Events, true) => format!(
            "Equal spacing · host time ({})",
            crate::time_format::zone_label()
        ),
        (Spacing::Events, false) => "Equal spacing · guest time".to_owned(),
        (Spacing::Time, true) => format!("Host time ({})", crate::time_format::zone_label()),
        (Spacing::Time, false) => "Guest time, from the start".to_owned(),
    };
    paint::label(
        &painter.with_clip_rect(frame.labels),
        Pos2::new(frame.labels.left() + 4.0, frame.axis.center().y),
        Align2::LEFT_CENTER,
        &caption,
        10.5,
        colors.muted,
    );
    // The spacing choice, the chosen one filled.
    paint::label(
        painter,
        Pos2::new(layout.spacing[0].left() - 6.0, layout.spacing[0].center().y),
        Align2::RIGHT_CENTER,
        "Spacing",
        10.5,
        colors.muted,
    );
    for (chip, mode, text) in [
        (layout.spacing[0], Spacing::Events, "Events"),
        (layout.spacing[1], Spacing::Time, "Time"),
    ] {
        let on = cfg.spacing == mode;
        if on {
            painter.rect_filled(chip, 3.0, colors.accent.gamma_multiply(0.28));
        }
        painter.rect_stroke(
            chip,
            3.0,
            Stroke::new(1.0_f32, if on { colors.accent } else { colors.line }),
            eframe::egui::StrokeKind::Inside,
        );
        paint::label(
            painter,
            chip.center(),
            Align2::CENTER_CENTER,
            text,
            11.0,
            colors.text,
        );
    }
    for (rect, text) in [(layout.fit, "Fit"), (layout.run, "Run")] {
        painter.rect_stroke(
            rect,
            3.0,
            Stroke::new(1.0_f32, colors.line),
            eframe::egui::StrokeKind::Inside,
        );
        paint::label(
            painter,
            rect.center(),
            Align2::CENTER_CENTER,
            text,
            11.0,
            colors.text,
        );
    }
}
