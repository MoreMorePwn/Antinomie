// SPDX-License-Identifier: MIT
//! Notification toasts (design section 6.12): a bottom-right stack with an
//! icon, a title, a one-line detail, an optional action link and a close
//! button. Info toasts leave after 6 s, warnings after 12 s and errors stay
//! until dismissed; hovering a toast pauses its timer. A burst of the same
//! toast becomes one toast with a count. Every toast is also an Activity row.
//!
//! The stack lives in the egui context, so any code with a `Context` or a
//! `Ui` can raise one, with or without an Activity pane open:
//! [`push`] (title, detail, action) or [`notify`] (one message).
use crate::{activity::Level, theme, workspace::Panel};
use eframe::egui::{self, RichText};
use std::time::Duration;

/// Seconds an info toast stays; warnings stay twice as long.
pub(crate) const INFO_SECS: f64 = 6.0;
pub(crate) const WARN_SECS: f64 = 12.0;
/// Toasts shown at once; the rest wait, with their timers stopped.
pub(crate) const VISIBLE: usize = 5;
/// Toasts kept in all; the oldest non-error one goes first.
const STORED: usize = 40;
const WIDTH: f32 = 380.0;
const MARGIN: f32 = 16.0;
/// Height at the bottom of a window kept clear for its footer buttons.
const FOOTER: f32 = 64.0;
const HUB: &str = "toast-stack";
const STACK: &str = "toast-stack-area";

/// An action link: its text and the panel it brings forward, through the
/// app's ordinary panel focus.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Action {
    pub label: String,
    pub panel: Panel,
}
impl Action {
    pub(crate) fn open_activity() -> Self {
        Self {
            label: "Open Activity".into(),
            panel: Panel::Activity,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Toast {
    pub id: u64,
    pub level: Level,
    pub title: String,
    pub detail: String,
    pub action: Option<Action>,
    /// How many times this toast was raised while it was on screen.
    pub count: u32,
    /// Seconds left; `None` stays until dismissed.
    pub left: Option<f64>,
    pub hovered: bool,
}

/// The stack and its hand-offs to the rest of the app.
#[derive(Clone, Default)]
pub(crate) struct Toasts {
    items: Vec<Toast>,
    next_id: u64,
    /// Activity rows of toasts raised here, not yet taken by the journal.
    rows: Vec<(Level, String)>,
    /// Y of the status bar's top edge; the stack sits above it.
    floor: Option<f32>,
}

fn lifetime(level: Level) -> Option<f64> {
    match level {
        Level::Info => Some(INFO_SECS),
        Level::Warn => Some(WARN_SECS),
        Level::Error => None,
    }
}

impl Toasts {
    /// Raise a toast, or count a repeat of one already in the stack. A repeat
    /// restarts the timer so it is seen again. `row` also writes the Activity
    /// row (false when the caller already logged the event).
    pub(crate) fn add(
        &mut self,
        level: Level,
        title: &str,
        detail: &str,
        action: Option<Action>,
        row: bool,
    ) {
        if row {
            self.rows.push((level, row_text(title, detail)));
            self.rows.truncate(crate::activity::INBOX_LIMIT);
        }
        if let Some(same) = self
            .items
            .iter_mut()
            .find(|toast| toast.level == level && toast.title == title && toast.detail == detail)
        {
            same.count = same.count.saturating_add(1);
            same.left = lifetime(level);
            return;
        }
        self.next_id += 1;
        self.items.push(Toast {
            id: self.next_id,
            level,
            title: title.into(),
            detail: detail.into(),
            action,
            count: 1,
            left: lifetime(level),
            hovered: false,
        });
        if self.items.len() > STORED {
            let drop = self
                .items
                .iter()
                .position(|toast| toast.level != Level::Error)
                .unwrap_or(0);
            self.items.remove(drop);
        }
    }

    /// Advance the timers of the shown toasts by `dt` seconds. A hovered
    /// toast keeps its time; so does one still waiting behind the shown ones.
    pub(crate) fn tick(&mut self, dt: f64) {
        let first = self.items.len().saturating_sub(VISIBLE);
        let mut index = 0;
        self.items.retain_mut(|toast| {
            let shown = index >= first;
            index += 1;
            if let (true, false, Some(left)) = (shown, toast.hovered, toast.left.as_mut()) {
                *left -= dt;
                return *left > 0.0;
            }
            true
        });
    }

    pub(crate) fn dismiss(&mut self, id: u64) {
        self.items.retain(|toast| toast.id != id);
    }

    #[cfg(test)]
    pub(crate) fn items(&self) -> &[Toast] {
        &self.items
    }

    pub(crate) fn take_rows(&mut self) -> Vec<(Level, String)> {
        std::mem::take(&mut self.rows)
    }
}

fn row_text(title: &str, detail: &str) -> String {
    if detail.is_empty() {
        title.into()
    } else {
        format!("{title}: {detail}")
    }
}

fn with<R>(ctx: &egui::Context, f: impl FnOnce(&mut Toasts) -> R) -> R {
    ctx.data_mut(|data| f(data.get_temp_mut_or_default::<Toasts>(egui::Id::new(HUB))))
}

/// Raise a toast and write its Activity row.
pub(crate) fn push(
    ctx: &egui::Context,
    level: Level,
    title: &str,
    detail: &str,
    action: Option<Action>,
) {
    with(ctx, |toasts| toasts.add(level, title, detail, action, true));
    ctx.request_repaint();
}

/// Raise a toast from one message (split into a title and a detail) and
/// write its Activity row.
pub(crate) fn notify(ctx: &egui::Context, level: Level, message: impl std::fmt::Display) {
    let (title, detail) = split(level, &message.to_string());
    push(ctx, level, &title, &detail, Some(Action::open_activity()));
}

/// Raise the toast of an event the journal already has a row for.
pub(crate) fn push_logged(ctx: &egui::Context, level: Level, message: &str) {
    let (title, detail) = split(level, message);
    with(ctx, |toasts| {
        toasts.add(level, &title, &detail, Some(Action::open_activity()), false)
    });
    ctx.request_repaint();
}

/// A view's `(message, failed)` status after an action: a failure becomes a
/// toast and leaves the status; a success stays for the view to draw.
pub(crate) fn take_failure(ctx: &egui::Context, status: &mut Option<(String, bool)>) {
    if matches!(status, Some((_, true))) {
        if let Some((message, _)) = status.take() {
            notify(ctx, Level::Error, message);
        }
    }
}

pub(crate) fn take_rows(ctx: &egui::Context) -> Vec<(Level, String)> {
    with(ctx, Toasts::take_rows)
}

/// Screenshot fixtures: give every toast its full time again.
#[cfg(test)]
pub(crate) fn keep_alive(ctx: &egui::Context) {
    with(ctx, |toasts| {
        for toast in &mut toasts.items {
            toast.left = lifetime(toast.level);
        }
    });
}

#[cfg(test)]
pub(crate) fn snapshot(ctx: &egui::Context) -> Vec<(Level, String, String)> {
    with(ctx, |toasts| {
        toasts
            .items()
            .iter()
            .map(|toast| (toast.level, toast.title.clone(), toast.detail.clone()))
            .collect()
    })
}

/// Where the stack must stay above (the status bar's top edge).
pub(crate) fn set_floor(ctx: &egui::Context, y: f32) {
    with(ctx, |toasts| toasts.floor = Some(y));
}

/// A title and a one-line detail for a plain message: the text before the
/// first `": "` when it is short, else a generic title.
pub(crate) fn split(level: Level, message: &str) -> (String, String) {
    let message = message.trim();
    if let Some((head, tail)) = message.split_once(": ") {
        let head = head.trim();
        if (1..=40).contains(&head.chars().count())
            && !tail.trim().is_empty()
            && !head.contains(['.', '(', '\n'])
        {
            let title = if head == "Failed" {
                "Action failed"
            } else {
                head
            };
            return (title.into(), tail.trim().into());
        }
    }
    let title = match level {
        Level::Info => "Notice",
        Level::Warn => "Warning",
        Level::Error => "Error",
    };
    (title.into(), message.into())
}

fn visuals(level: Level) -> (&'static str, egui::Color32) {
    let palette = theme::palette();
    match level {
        Level::Info => (egui_phosphor::regular::INFO, palette.info),
        Level::Warn => (egui_phosphor::regular::WARNING, palette.warn),
        Level::Error => (egui_phosphor::regular::WARNING_CIRCLE, palette.error),
    }
}

#[derive(Default)]
struct Outcome {
    hovered: bool,
    close: bool,
    follow: bool,
}

fn draw(ui: &mut egui::Ui, toast: &Toast, width: f32) -> Outcome {
    let palette = theme::palette();
    let (icon, color) = visuals(toast.level);
    let stroke = if toast.level == Level::Error {
        palette.error
    } else {
        palette.line
    };
    let mut outcome = Outcome::default();
    let frame = egui::Frame::new()
        .fill(palette.raised)
        .stroke(egui::Stroke::new(1.0_f32, stroke))
        .corner_radius(8)
        .inner_margin(egui::Margin::symmetric(10, 8))
        .shadow(egui::Shadow {
            offset: [0, 4],
            blur: 14,
            spread: 0,
            color: palette.shadow,
        })
        .show(ui, |ui| {
            ui.set_width(width - 22.0);
            ui.horizontal_top(|ui| {
                ui.label(RichText::new(icon).color(color));
                let text_width = (ui.available_width()
                    - ui.spacing().interact_size.y
                    - ui.spacing().item_spacing.x)
                    .max(0.0);
                ui.allocate_ui_with_layout(
                    egui::vec2(text_width, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&toast.title).strong().color(palette.text),
                                )
                                .truncate(),
                            );
                            if toast.count > 1 {
                                crate::widgets::chip(
                                    ui,
                                    format!("×{}", toast.count),
                                    match toast.level {
                                        Level::Info => crate::widgets::Tone::Info,
                                        Level::Warn => crate::widgets::Tone::Warn,
                                        Level::Error => crate::widgets::Tone::Error,
                                    },
                                );
                            }
                        });
                        if !toast.detail.is_empty() {
                            let one_line = toast.detail.replace('\n', " ");
                            ui.add(
                                egui::Label::new(
                                    RichText::new(one_line).small().color(palette.muted),
                                )
                                .truncate(),
                            )
                            .on_hover_text(&toast.detail);
                        }
                        if let Some(action) = &toast.action {
                            let link = ui
                                .add(
                                    egui::Label::new(
                                        RichText::new(&action.label).small().color(palette.accent),
                                    )
                                    .selectable(false)
                                    .sense(egui::Sense::click()),
                                )
                                .on_hover_cursor(egui::CursorIcon::PointingHand);
                            outcome.follow = link.clicked();
                        }
                    },
                );
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new(egui_phosphor::regular::X).color(palette.muted),
                        )
                        .frame(false),
                    )
                    .on_hover_text("Dismiss")
                    .clicked()
                {
                    outcome.close = true;
                }
            });
        });
    outcome.hovered = frame.response.contains_pointer();
    outcome
}

/// Footer bands of the windows and dialogs on screen (not panels, the backdrop
/// of a modal or the stack itself), for keeping the stack off their buttons.
fn obstacles(ctx: &egui::Context, screen: egui::Rect, mine: egui::Id) -> Vec<egui::Rect> {
    ctx.memory(|memory| {
        memory
            .layer_ids()
            .filter(|layer| {
                layer.id != mine
                    && matches!(layer.order, egui::Order::Middle | egui::Order::Foreground)
                    && memory.areas().is_visible(layer)
            })
            .filter_map(|layer| memory.area_rect(layer.id))
            .filter(|rect| rect.area() < screen.area() * 0.8)
            // Only the footer band: the stack may sit over a dialog's body but
            // never over its buttons.
            .map(|rect| {
                egui::Rect::from_min_max(egui::pos2(rect.left(), rect.bottom() - FOOTER), rect.max)
            })
            .collect()
    })
}

/// The stack's right and bottom edges: bottom-right above the status bar,
/// moved left of, or above, a window it would cover.
fn placement(
    screen: egui::Rect,
    floor: f32,
    size: egui::Vec2,
    blockers: &[egui::Rect],
) -> (f32, f32) {
    let (mut right, mut bottom) = (screen.right() - MARGIN, floor - 8.0);
    for _ in 0..3 {
        let stack = egui::Rect::from_min_max(
            egui::pos2(right - size.x, bottom - size.y),
            egui::pos2(right, bottom),
        );
        let Some(hit) = blockers.iter().find(|rect| rect.intersects(stack)) else {
            break;
        };
        if hit.left() - 8.0 - size.x >= screen.left() + 8.0 {
            right = hit.left() - 8.0;
        } else if hit.top() - 8.0 - size.y >= screen.top() + 8.0 {
            bottom = hit.top() - 8.0;
        } else {
            break;
        }
    }
    (right, bottom)
}

/// Draw the stack and run the timers. Returns the panels of clicked action
/// links, for the app to bring forward.
pub(crate) fn show(ctx: &egui::Context) -> Vec<Panel> {
    let dt = f64::from(ctx.input(|input| input.stable_dt)).min(0.5);
    let (items, floor, hidden) = with(ctx, |toasts| {
        toasts.tick(dt);
        let hidden = toasts.items.len().saturating_sub(VISIBLE);
        (toasts.items[hidden..].to_vec(), toasts.floor, hidden)
    });
    if items.is_empty() {
        return Vec::new();
    }
    let screen = ctx.screen_rect();
    let id = egui::Id::new(STACK);
    let width = WIDTH.min(screen.width() - 2.0 * MARGIN).max(200.0);
    let size = ctx
        .memory(|memory| memory.area_rect(id))
        .map_or(egui::vec2(width, 0.0), |rect| rect.size());
    let blockers = obstacles(ctx, screen, id);
    let (right, bottom) = placement(
        screen,
        floor.unwrap_or(screen.bottom()).min(screen.bottom()),
        size,
        &blockers,
    );
    let mut outcomes = Vec::new();
    egui::Area::new(id)
        .order(egui::Order::Foreground)
        .anchor(
            egui::Align2::RIGHT_BOTTOM,
            egui::vec2(right - screen.right(), bottom - screen.bottom()),
        )
        .show(ctx, |ui| {
            ui.set_width(width);
            // Min: a cross-axis Max would make the rows inside run right to left.
            ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                ui.spacing_mut().item_spacing.y = 8.0;
                if hidden > 0 {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                        ui.label(
                            RichText::new(format!("{hidden} more in Activity"))
                                .small()
                                .color(theme::muted()),
                        );
                    });
                }
                for toast in &items {
                    outcomes.push((toast.id, toast.action.clone(), draw(ui, toast, width)));
                }
            });
        });
    let mut follow = Vec::new();
    with(ctx, |toasts| {
        for (id, action, outcome) in outcomes {
            if outcome.close || outcome.follow {
                toasts.dismiss(id);
            }
            if let (true, Some(action)) = (outcome.follow, action) {
                follow.push(action.panel);
            }
            if let Some(toast) = toasts.items.iter_mut().find(|toast| toast.id == id) {
                toast.hovered = outcome.hovered;
            }
        }
    });
    if with(ctx, |toasts| {
        toasts.items.iter().any(|toast| toast.left.is_some())
    }) {
        ctx.request_repaint_after(Duration::from_millis(100));
    }
    follow
}

#[cfg(test)]
mod tests;
