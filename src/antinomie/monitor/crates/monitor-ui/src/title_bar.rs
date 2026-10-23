// SPDX-License-Identifier: GPL-3.0-only
//! Shared application chrome for the main and detached workspace viewports.
//! All operations use native viewport commands, including the normal close
//! event path; this module never owns a VM, terminal or shutdown operation.
use crate::theme;
use eframe::egui::{self, Color32, Pos2, Rect, Sense, Stroke, Vec2, ViewportCommand};

const BUTTON_WIDTH: f32 = 44.0;
const EDGE: f32 = 5.0;
const CORNER: f32 = 12.0;

#[derive(Clone, Copy)]
enum Control {
    Minimize,
    Maximize,
    Close,
}

impl Control {
    const ALL: [Self; 3] = [Self::Minimize, Self::Maximize, Self::Close];
    fn name(self, maximized: bool) -> &'static str {
        match self {
            Self::Minimize => "Minimize",
            Self::Maximize if maximized => "Restore",
            Self::Maximize => "Maximize",
            Self::Close => "Close",
        }
    }
    fn command(self, maximized: bool) -> ViewportCommand {
        match self {
            Self::Minimize => ViewportCommand::Minimized(true),
            Self::Maximize => ViewportCommand::Maximized(!maximized),
            Self::Close => ViewportCommand::Close,
        }
    }
}

pub(crate) fn builder(builder: egui::ViewportBuilder) -> egui::ViewportBuilder {
    builder.with_decorations(false)
}

/// Draw the native viewport's title bar. Embedded egui windows already own a
/// title bar and must not call this. Fullscreen deliberately hides the chrome.
pub(crate) fn show(ctx: &egui::Context, title: &str) {
    let (maximized, fullscreen) = ctx.input(|i| {
        (
            i.viewport().maximized.unwrap_or(false),
            i.viewport().fullscreen.unwrap_or(false),
        )
    });
    let height = (egui::TextStyle::Body.resolve(&ctx.style()).size + 14.0).max(34.0);
    let key = egui::Id::new(("native-caption-height", ctx.viewport_id()));
    ctx.data_mut(|data| data.insert_temp(key, if fullscreen { 0.0_f32 } else { height }));
    if fullscreen {
        return;
    }
    egui::TopBottomPanel::top(egui::Id::new(("native-title-bar", ctx.viewport_id())))
        .exact_height(height)
        .frame(egui::Frame::NONE.fill(theme::panel()))
        .show(ctx, |ui| {
            let bar = ui.max_rect();
            let button_width = BUTTON_WIDTH.min(bar.width() / 4.0);
            let title_rect = Rect::from_min_max(
                bar.min + egui::vec2(12.0, 0.0),
                egui::pos2(
                    (bar.right() - 3.0 * button_width - 8.0).max(bar.left() + 12.0),
                    bar.bottom(),
                ),
            );
            let drag = ui.interact(
                Rect::from_min_max(
                    title_rect.min + egui::vec2(0.0, if maximized { 0.0 } else { EDGE }),
                    title_rect.max,
                ),
                ui.id().with("drag"),
                Sense::click_and_drag() - Sense::FOCUSABLE,
            );
            let mut preserve_focus = drag.is_pointer_button_down_on() || drag.clicked();
            let mut job = egui::text::LayoutJob::simple_singleline(
                title.to_owned(),
                egui::TextStyle::Body.resolve(ui.style()),
                theme::text(),
            );
            job.wrap.max_width = title_rect.width();
            job.wrap.max_rows = 1;
            job.wrap.break_anywhere = true;
            let galley = ui.fonts(|fonts| fonts.layout_job(job));
            let position = egui::pos2(
                title_rect.left(),
                title_rect.center().y - galley.size().y / 2.0,
            );
            ui.painter_at(title_rect)
                .galley(position, galley, theme::text());
            if drag.double_clicked() {
                ctx.send_viewport_cmd(ViewportCommand::Maximized(!maximized));
            } else if drag.drag_started_by(egui::PointerButton::Primary) {
                ctx.send_viewport_cmd(ViewportCommand::StartDrag);
            }
            drag.on_hover_text(title);
            for (index, control) in Control::ALL.into_iter().enumerate() {
                let rect = Rect::from_min_size(
                    egui::pos2(bar.right() - (3 - index) as f32 * button_width, bar.top()),
                    egui::vec2(button_width, height),
                );
                let response = control_button(ui, rect, control, maximized);
                preserve_focus |= response.is_pointer_button_down_on() || response.clicked();
                if response.clicked() {
                    ctx.send_viewport_cmd(control.command(maximized));
                }
            }
            let focus_key = focus_key(ctx);
            if preserve_focus
                && let Some(focus) = ctx
                    .data(|d| d.get_temp::<Option<egui::Id>>(focus_key))
                    .flatten()
            {
                ctx.data_mut(|data| data.insert_temp(focus_key.with("restore"), focus));
            }
            ui.painter().hline(
                bar.x_range(),
                bar.bottom() - 0.5,
                Stroke::new(1.0_f32, theme::line()),
            );
        });
}

/// Floating panes stay below the caption, just as with an OS-owned title bar.
/// Auxiliary viewports that do not use this chrome keep their whole client area.
pub(crate) fn content_rect(ctx: &egui::Context) -> Rect {
    let key = egui::Id::new(("native-caption-height", ctx.viewport_id()));
    let height = ctx.data(|data| data.get_temp::<f32>(key)).unwrap_or(0.0);
    let mut rect = ctx.screen_rect();
    rect.min.y += height;
    rect
}

fn control_button(
    ui: &mut egui::Ui,
    rect: Rect,
    control: Control,
    maximized: bool,
) -> egui::Response {
    let label = control.name(maximized);
    let hit = Rect::from_min_max(
        rect.min + egui::vec2(0.0, if maximized { 0.0 } else { EDGE }),
        rect.max,
    );
    let response = ui.interact(hit, ui.id().with(label), Sense::click() - Sense::FOCUSABLE);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, label));
    let hot = response.hovered() || response.is_pointer_button_down_on();
    let color = if hot && matches!(control, Control::Close) {
        ui.painter().rect_filled(rect, 0.0, theme::error());
        // The dark palettes use a light red, and Light uses a dark red.
        // The background-color glyph stays legible against both.
        theme::bg()
    } else {
        if hot {
            ui.painter().rect_filled(rect, 0.0, theme::palette().hover);
        }
        theme::text()
    };
    icon(ui.painter(), rect.center(), control, maximized, color);
    response.on_hover_text(label)
}

/// Pixel-independent vector controls: no font-dependent square/cross glyphs.
fn icon(painter: &egui::Painter, center: Pos2, control: Control, maximized: bool, color: Color32) {
    let stroke = Stroke::new(1.3_f32, color);
    let bounds = Rect::from_center_size(center, egui::vec2(10.0, 10.0));
    match control {
        Control::Minimize => {
            painter.line_segment(
                [
                    egui::pos2(bounds.left(), center.y + 3.0),
                    egui::pos2(bounds.right(), center.y + 3.0),
                ],
                stroke,
            );
        }
        Control::Maximize if maximized => {
            let back = bounds.translate(egui::vec2(2.0, -2.0));
            painter.line_segment([back.left_top(), back.right_top()], stroke);
            painter.line_segment([back.right_top(), back.right_bottom()], stroke);
            painter.rect_stroke(bounds, 0.0, stroke, egui::StrokeKind::Inside);
        }
        Control::Maximize => {
            painter.rect_stroke(bounds, 0.0, stroke, egui::StrokeKind::Inside);
        }
        Control::Close => {
            painter.line_segment([bounds.left_top(), bounds.right_bottom()], stroke);
            painter.line_segment([bounds.right_top(), bounds.left_bottom()], stroke);
        }
    }
}

fn focus_key(ctx: &egui::Context) -> egui::Id {
    egui::Id::new(("native-caption-focus", ctx.viewport_id()))
}

/// Native resizing replaces the resize border lost with OS decorations.
/// Hit-test only the native frame edge; no foreground areas cover the client.
pub(crate) fn resize(ctx: &egui::Context) {
    let key = focus_key(ctx);
    let restore = ctx.data(|data| data.get_temp::<egui::Id>(key.with("restore")));
    if let Some(focus) = restore {
        ctx.memory_mut(|memory| memory.request_focus(focus));
        ctx.data_mut(|data| data.remove::<egui::Id>(key.with("restore")));
    }
    let focus = ctx.memory(|memory| memory.focused());
    ctx.data_mut(|data| data.insert_temp(key, focus));
    if ctx.input(|i| {
        i.viewport().maximized.unwrap_or(false) || i.viewport().fullscreen.unwrap_or(false)
    }) {
        return;
    }
    let rect = ctx.screen_rect();
    let painter = ctx.layer_painter(egui::LayerId::new(
        egui::Order::Foreground,
        egui::Id::new(("native-window-outline", ctx.viewport_id())),
    ));
    painter.rect_stroke(
        rect.shrink(0.5),
        0.0,
        Stroke::new(1.0_f32, theme::line()),
        egui::StrokeKind::Inside,
    );
    let (pointer, pressed) = ctx.input(|i| {
        (
            i.pointer.hover_pos(),
            i.pointer.button_pressed(egui::PointerButton::Primary),
        )
    });
    if let Some((_, direction, cursor)) = resize_regions(rect)
        .into_iter()
        .find(|(rect, _, _)| pointer.is_some_and(|pos| rect.contains(pos)))
    {
        ctx.set_cursor_icon(cursor);
        if pressed {
            ctx.send_viewport_cmd(ViewportCommand::BeginResize(direction));
        }
    }
}

fn resize_regions(rect: Rect) -> [(Rect, egui::ResizeDirection, egui::CursorIcon); 8] {
    use egui::{CursorIcon as C, ResizeDirection as D};
    let (left, right, top, bottom) = (rect.left(), rect.right(), rect.top(), rect.bottom());
    [
        (
            Rect::from_min_size(rect.left_top(), Vec2::splat(CORNER)),
            D::NorthWest,
            C::ResizeNwSe,
        ),
        (
            Rect::from_min_size(egui::pos2(right - CORNER, top), Vec2::splat(CORNER)),
            D::NorthEast,
            C::ResizeNeSw,
        ),
        (
            Rect::from_min_size(egui::pos2(left, bottom - CORNER), Vec2::splat(CORNER)),
            D::SouthWest,
            C::ResizeNeSw,
        ),
        (
            Rect::from_min_size(
                egui::pos2(right - CORNER, bottom - CORNER),
                Vec2::splat(CORNER),
            ),
            D::SouthEast,
            C::ResizeNwSe,
        ),
        (
            Rect::from_min_max(
                egui::pos2(left + CORNER, top),
                egui::pos2(right - CORNER, top + EDGE),
            ),
            D::North,
            C::ResizeVertical,
        ),
        (
            Rect::from_min_max(
                egui::pos2(left + CORNER, bottom - EDGE),
                egui::pos2(right - CORNER, bottom),
            ),
            D::South,
            C::ResizeVertical,
        ),
        (
            Rect::from_min_max(
                egui::pos2(left, top + CORNER),
                egui::pos2(left + EDGE, bottom - CORNER),
            ),
            D::West,
            C::ResizeHorizontal,
        ),
        (
            Rect::from_min_max(
                egui::pos2(right - EDGE, top + CORNER),
                egui::pos2(right, bottom - CORNER),
            ),
            D::East,
            C::ResizeHorizontal,
        ),
    ]
}

#[cfg(test)]
mod tests;
