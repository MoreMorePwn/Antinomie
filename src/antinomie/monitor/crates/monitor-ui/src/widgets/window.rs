// SPDX-License-Identifier: GPL-3.0-only
//! Window and dialog chrome in the mockup's style.
use crate::theme;
use eframe::egui::{self, RichText};

/// A spawned window in the mockup's style, built like `egui::Window` (the
/// same chain: `.id`, `.open`, `.default_width`, `.default_size`,
/// `.default_pos`, `.min_size`, `.max_size`, `.fixed_size`, `.anchor`, ...).
///
/// The frame (raised fill, 1 px line, 8 px corners, soft shadow) comes from
/// the theme's visuals. The title bar is the mockup's: the title left in
/// semibold, a close button at the right and a soft rule below. There is no
/// dim behind the window and its position stays free (drag it by any empty
/// part). With `.open(&mut flag)` the close button clears `flag`.
pub fn window<'open>(title: impl Into<String>) -> Dialog<'open> {
    let title = title.into();
    Dialog {
        window: egui::Window::new(&title).title_bar(false).resizable(true),
        title,
        open: None,
    }
}

/// The window builder returned by [`window`].
pub struct Dialog<'open> {
    window: egui::Window<'open>,
    title: String,
    open: Option<&'open mut bool>,
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

    forward! {
        id(id: egui::Id);
        resizable(resizable: impl Into<egui::Vec2b>);
        /// Kept for call-site compatibility: the mockup's windows never collapse.
        collapsible(collapsible: bool);
        movable(movable: bool);
        default_width(width: f32);
        default_height(height: f32);
        default_size(size: impl Into<egui::Vec2>);
        default_pos(pos: impl Into<egui::Pos2>);
        default_rect(rect: egui::Rect);
        current_pos(pos: impl Into<egui::Pos2>);
        fixed_size(size: impl Into<egui::Vec2>);
        min_size(size: impl Into<egui::Vec2>);
        max_size(size: impl Into<egui::Vec2>);
        min_width(width: f32);
        max_width(width: f32);
        max_height(height: f32);
        anchor(align: egui::Align2, offset: impl Into<egui::Vec2>);
        pivot(pivot: egui::Align2);
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
            open,
        } = self;
        let closable = open.is_some();
        let mut close = false;
        let shown = window
            .constrain_to(crate::title_bar::content_rect(ctx))
            .show(ctx, |ui| {
                let rule = ui.painter().add(egui::Shape::Noop);
                let header = ui
                    .horizontal(|ui| {
                        // Not selectable: dragging the title moves the window.
                        ui.add(
                            egui::Label::new(
                                RichText::new(&title)
                                    .strong()
                                    // Strong text is the primary button's
                                    // white in the light theme: color it.
                                    .color(theme::text())
                                    .text_style(egui::TextStyle::Body),
                            )
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
