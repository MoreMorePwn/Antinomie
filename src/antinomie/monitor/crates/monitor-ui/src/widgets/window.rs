// SPDX-License-Identifier: GPL-3.0-only
//! Window and dialog chrome in the mockup's style.
use crate::theme;
use eframe::egui;

/// A spawned window in the mockup's style, built like `egui::Window` (the
/// same chain: `.id`, `.open`, `.default_width`, `.default_size`,
/// `.default_pos`, `.min_size`, `.max_size`, `.fixed_size`, `.anchor`, ...).
///
/// The frame (raised fill, 1 px line, 8 px corners, soft shadow) comes from
/// the theme's visuals. The title bar is the mockup's: the title left in
/// bold, a close button at the right and a soft rule below. There is no
/// dim behind the window and its position stays free (drag it by any empty
/// part). With `.open(&mut flag)` the close button clears `flag`.
pub fn window<'open>(title: impl Into<String>) -> Dialog<'open> {
    let title = title.into();
    Dialog {
        window: egui::Window::new(&title).title_bar(false).resizable(true),
        title,
        id: None,
        open: None,
        positioned: false,
        fixed: false,
        max_width: None,
        max_height: None,
    }
}

/// The window builder returned by [`window`].
pub struct Dialog<'open> {
    window: egui::Window<'open>,
    title: String,
    /// The window's id, when the caller gave one (else egui's: the title).
    id: Option<egui::Id>,
    open: Option<&'open mut bool>,
    /// The caller placed the window; otherwise it opens centred.
    positioned: bool,
    /// The caller fixed the size.
    fixed: bool,
    max_width: Option<f32>,
    max_height: Option<f32>,
}

macro_rules! forward {
    ($($(#[$doc:meta])* $name:ident($($arg:ident: $ty:ty),*);)*) => {
        $($(#[$doc])* pub fn $name(mut self, $($arg: $ty),*) -> Self {
            self.window = self.window.$name($($arg),*);
            self
        })*
    };
}

impl<'open> Dialog<'open> {
    /// The close button clears `open`.
    pub fn open(mut self, open: &'open mut bool) -> Self {
        self.open = Some(open);
        self
    }

    pub fn id(mut self, id: egui::Id) -> Self {
        self.id = Some(id);
        self.window = self.window.id(id);
        self
    }

    forward! {
        resizable(resizable: impl Into<egui::Vec2b>);
        /// Kept for call-site compatibility: the mockup's windows never collapse.
        collapsible(collapsible: bool);
        movable(movable: bool);
        default_width(width: f32);
        default_height(height: f32);
        default_size(size: impl Into<egui::Vec2>);
        min_size(size: impl Into<egui::Vec2>);
        min_width(width: f32);
    }

    /// A window of exactly this size (never capped to the window area).
    pub fn fixed_size(mut self, size: impl Into<egui::Vec2>) -> Self {
        self.fixed = true;
        self.window = self.window.fixed_size(size);
        self
    }

    /// Where the window opens (it stays movable).
    pub fn default_pos(mut self, pos: impl Into<egui::Pos2>) -> Self {
        self.positioned = true;
        self.window = self.window.default_pos(pos);
        self
    }

    pub fn default_rect(mut self, rect: egui::Rect) -> Self {
        self.positioned = true;
        self.window = self.window.default_rect(rect);
        self
    }

    pub fn current_pos(mut self, pos: impl Into<egui::Pos2>) -> Self {
        self.positioned = true;
        self.window = self.window.current_pos(pos);
        self
    }

    pub fn anchor(mut self, align: egui::Align2, offset: impl Into<egui::Vec2>) -> Self {
        self.positioned = true;
        self.window = self.window.anchor(align, offset);
        self
    }

    pub fn pivot(mut self, pivot: egui::Align2) -> Self {
        self.positioned = true;
        self.window = self.window.pivot(pivot);
        self
    }

    /// The most the window may grow to; it is also capped to the window
    /// area so a dialog never reaches past the screen edge.
    pub fn max_size(mut self, size: impl Into<egui::Vec2>) -> Self {
        let size = size.into();
        self.max_width = Some(size.x);
        self.max_height = Some(size.y);
        self
    }

    pub fn max_width(mut self, width: f32) -> Self {
        self.max_width = Some(width);
        self
    }

    pub fn max_height(mut self, height: f32) -> Self {
        self.max_height = Some(height);
        self
    }

    /// Show the window: title row, then `add_contents`.
    pub fn show<R>(
        self,
        ctx: &egui::Context,
        add_contents: impl FnOnce(&mut egui::Ui) -> R,
    ) -> Option<egui::InnerResponse<Option<R>>> {
        let Dialog {
            window,
            title,
            id,
            open,
            positioned,
            fixed,
            max_width,
            max_height,
        } = self;
        let closable = open.is_some();
        let mut close = false;
        let area = crate::title_bar::content_rect(ctx);
        let mut window = if fixed {
            window
        } else {
            window.max_size(egui::vec2(
                max_width.unwrap_or(f32::INFINITY).min(area.width() - 24.0),
                max_height
                    .unwrap_or(f32::INFINITY)
                    .min(area.height() - 24.0),
            ))
        };
        // A window that opens centred stays centred while the app window
        // grows to its final size (the first frames of a start run in a
        // smaller one) until the person moves it.
        let id = id.unwrap_or_else(|| egui::Id::new(&title));
        let centre_key = id.with("dialog-centred-in");
        if !positioned {
            window = window
                .pivot(egui::Align2::CENTER_CENTER)
                .default_pos(area.center());
            let last: Option<(egui::Rect, egui::Pos2)> = ctx.data(|data| data.get_temp(centre_key));
            let now = ctx
                .memory(|memory| memory.area_rect(id))
                .map(|rect| rect.center());
            let moved =
                ctx.data(|data| data.get_temp::<bool>(id.with("dialog-moved"))) == Some(true);
            if let (Some((last_area, last_centre)), Some(now), false) = (last, now, moved) {
                if last_area != area && now.distance(last_centre) < 2.0 {
                    window = window.current_pos(area.center());
                }
            }
        }
        let shown = window.constrain_to(area).show(ctx, |ui| {
            let rule = ui.painter().add(egui::Shape::Noop);
            let header = ui
                .horizontal(|ui| {
                    // Not selectable: dragging the title moves the window.
                    ui.add(
                        egui::Label::new(theme::bold(ui, &title).color(theme::text()))
                            .selectable(false),
                    );
                    // Room for the close button, which is placed at the
                    // window's right edge once the width is known.
                    if closable {
                        ui.add_space(CLOSE_SIZE + 12.0);
                    }
                })
                .response
                .rect;
            ui.add_space(6.0);
            let rule_y = ui.cursor().top();
            ui.add_space(8.0);
            // In a child ui: contents that call `set_max_height` (egui then
            // resets the cursor to the top of the ui) must not reach back
            // over the title row.
            let inner = ui.scope(add_contents).inner;
            let width = ui.min_rect().x_range();
            ui.painter().set(
                rule,
                egui::Shape::hline(
                    width,
                    rule_y,
                    egui::Stroke::new(1.0_f32, theme::line_soft()),
                ),
            );
            if !closable {
                return inner;
            }
            let button = egui::Rect::from_min_size(
                egui::pos2(width.max - CLOSE_SIZE, header.center().y - CLOSE_SIZE / 2.0),
                egui::vec2(CLOSE_SIZE, CLOSE_SIZE),
            );
            // Painted and sensed without taking layout space, so the window
            // does not grow by the button every frame.
            let response = ui
                .interact(button, ui.id().with("close"), egui::Sense::click())
                .on_hover_text("Close");
            let color = if response.hovered() {
                theme::palette().text
            } else {
                theme::palette().muted
            };
            if response.hovered() {
                ui.painter()
                    .rect_filled(button, 4.0, theme::palette().hover);
            }
            ui.painter().text(
                button.center(),
                egui::Align2::CENTER_CENTER,
                egui_phosphor::regular::X,
                egui::TextStyle::Body.resolve(ui.style()),
                color,
            );
            close = response.clicked();
            inner
        });
        if close {
            if let Some(open) = open {
                *open = false;
            }
        }
        if !positioned {
            let moved_key = id.with("dialog-moved");
            match shown.as_ref() {
                Some(shown) => {
                    if shown.response.dragged() {
                        // Moved by hand: it keeps its place from now on.
                        ctx.data_mut(|data| data.insert_temp(moved_key, true));
                    }
                    let centre = shown.response.rect.center();
                    ctx.data_mut(|data| data.insert_temp(centre_key, (area, centre)));
                }
                None => ctx.data_mut(|data| {
                    data.remove::<(egui::Rect, egui::Pos2)>(centre_key);
                    data.remove::<bool>(moved_key);
                }),
            }
        }
        shown
    }
}

const CLOSE_SIZE: f32 = 22.0;

/// A soft rule and a row of `buttons` (main action first, left to right).
pub fn footer(ui: &mut egui::Ui, buttons: impl FnOnce(&mut egui::Ui)) {
    rule(ui);
    ui.horizontal(buttons);
}

/// A soft rule, then `left` (status, secondary actions) at the left and
/// `right` at the right. `right` runs in a right-to-left layout: add the
/// primary button first and it lands rightmost, with Cancel to its left.
pub fn footer_split(
    ui: &mut egui::Ui,
    left: impl FnOnce(&mut egui::Ui),
    right: impl FnOnce(&mut egui::Ui),
) {
    rule(ui);
    ui.horizontal(|ui| {
        left(ui);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), right);
    });
}

fn rule(ui: &mut egui::Ui) {
    ui.add_space(4.0);
    let y = ui.cursor().top();
    let x = ui.max_rect().x_range();
    ui.painter()
        .hline(x, y, egui::Stroke::new(1.0_f32, theme::line_soft()));
    ui.add_space(8.0);
}

/// `ui.columns(count, ..)` for the body of a resizable window. egui's own
/// columns report the widest column times `count` as their width, so a
/// column whose content overshoots by a rounding step (a text box that fills
/// its column at a fractional width) widens the window by that much on every
/// frame. These columns are whole points wide and never report more than the
/// width they were given.
pub fn columns<R>(
    ui: &mut egui::Ui,
    count: usize,
    add_contents: impl FnOnce(&mut [egui::Ui]) -> R,
) -> R {
    let spacing = ui.spacing().item_spacing.x;
    let total = ui.available_width();
    let width = ((total - spacing * (count as f32 - 1.0)) / count as f32)
        .floor()
        .max(0.0);
    let top_left = ui.cursor().min;
    let bottom = ui.max_rect().bottom();
    let mut columns: Vec<egui::Ui> = (0..count)
        .map(|index| {
            let left = top_left.x + index as f32 * (width + spacing);
            let rect = egui::Rect::from_min_max(
                egui::pos2(left, top_left.y),
                egui::pos2(left + width, bottom),
            );
            let mut column = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(rect)
                    .layout(egui::Layout::top_down_justified(egui::Align::LEFT)),
            );
            column.set_width(width);
            column
        })
        .collect();
    let result = add_contents(&mut columns);
    let height = columns
        .iter()
        .map(|column| column.min_size().y)
        .fold(0.0, f32::max);
    ui.advance_cursor_after_rect(egui::Rect::from_min_size(
        top_left,
        egui::vec2(total, height),
    ));
    result
}

/// The body of a resizable window, laid out in exactly the width it has. A
/// widget that fills its row (a text box, a right-aligned footer) can come
/// out a rounding step wider than the row at a fractional text size; reported
/// back, that step widens the window, and again on the next frame. The body
/// keeps its own height but never reports more than the width it was given.
pub fn fixed_width_body<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let rect = ui.available_rect_before_wrap();
    let width = rect.width().floor().max(0.0);
    let mut body = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(egui::Rect::from_min_size(
                rect.min,
                egui::vec2(width, rect.height()),
            ))
            .layout(*ui.layout()),
    );
    let result = add_contents(&mut body);
    let height = body.min_rect().height();
    ui.advance_cursor_after_rect(egui::Rect::from_min_size(
        rect.min,
        egui::vec2(width, height),
    ));
    result
}
