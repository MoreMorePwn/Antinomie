// SPDX-License-Identifier: GPL-3.0-only
//! Bounded, persisted application log and the shared dismissible notice surface.
use crate::theme;
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

const ENTRY_LIMIT: usize = 2048;
const MESSAGE_SIZE: usize = 4096;
const JOURNAL_SIZE: usize = 2 * 1024 * 1024;
const NOTICE_LIMIT: usize = 4096;
pub(crate) const INBOX_LIMIT: usize = ENTRY_LIMIT;
const HUB: &str = "activity-notices";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Level {
    Info,
    Warn,
    Error,
}
impl Level {
    fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
    fn color(self) -> egui::Color32 {
        match self {
            Self::Info => theme::muted(),
            Self::Warn => theme::warn(),
            Self::Error => theme::error(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    unix_ms: i64,
    level: Level,
    message: String,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Journal {
    entries: VecDeque<Entry>,
    info: bool,
    warn: bool,
    error: bool,
    /// Warnings and errors logged since the last frame; each becomes a toast.
    #[serde(skip)]
    toast_out: Vec<(Level, String)>,
}
impl Default for Journal {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
            toast_out: Vec::new(),
            info: true,
            warn: true,
            error: true,
        }
    }
}

fn bounded(mut message: String) -> String {
    if message.len() > MESSAGE_SIZE {
        let mut end = MESSAGE_SIZE - "…".len();
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
        message.push('…');
    }
    message
}

impl Journal {
    pub(crate) fn restore(storage: Option<&dyn eframe::Storage>) -> Self {
        let mut journal: Self = storage
            .and_then(|storage| eframe::get_value(storage, "activity"))
            .unwrap_or_default();
        for entry in &mut journal.entries {
            entry.message = bounded(std::mem::take(&mut entry.message));
        }
        journal.trim();
        journal
    }
    pub(crate) fn save(&self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "activity", self);
    }
    fn trim(&mut self) {
        let mut size: usize = self.entries.iter().map(|entry| entry.message.len()).sum();
        while self.entries.len() > ENTRY_LIMIT || size > JOURNAL_SIZE {
            if let Some(entry) = self.entries.pop_front() {
                size -= entry.message.len();
            } else {
                break;
            }
        }
    }
    /// Log an event; a warning or an error also becomes a toast.
    pub(crate) fn log(&mut self, level: &str, message: String) {
        self.record(level, message, true);
    }
    /// Log without a toast: the row of a toast, or a state label.
    pub(crate) fn log_quiet(&mut self, level: &str, message: String) {
        self.record(level, message, false);
    }
    fn record(&mut self, level: &str, message: String, toast: bool) {
        let level = match level {
            "ERROR" => Level::Error,
            "WARN" => Level::Warn,
            _ => Level::Info,
        };
        let message = bounded(message);
        // A command failure can also be exposed in the next status snapshot.
        // Keep one adjacent identical error rather than two copies of that event.
        let unix_ms = chrono::Utc::now().timestamp_millis();
        if self.entries.back().is_some_and(|entry| {
            entry.level == level
                && entry.message.trim_start_matches("Failed: ")
                    == message.trim_start_matches("Failed: ")
                && unix_ms.saturating_sub(entry.unix_ms) < 1000
        }) {
            return;
        }
        if toast && level != Level::Info && self.toast_out.len() < INBOX_LIMIT {
            self.toast_out.push((level, message.clone()));
        }
        self.entries.push_back(Entry {
            unix_ms,
            level,
            message,
        });
        self.trim();
    }
    pub(crate) fn ingest(&mut self, ctx: &egui::Context) {
        let (pending, omitted) = ctx.data_mut(|data| {
            let hub = data.get_temp_mut_or_default::<NoticeHub>(egui::Id::new(HUB));
            (
                std::mem::take(&mut hub.pending),
                std::mem::take(&mut hub.omitted),
            )
        });
        for (level, message, toast) in pending {
            self.record(level.label(), message, toast);
        }
        for (level, row) in crate::toasts::take_rows(ctx) {
            self.log_quiet(level.label(), row);
        }
        if omitted != 0 {
            self.log(
                "WARN",
                format!("Activity notice queue overflow: {omitted} additional notices omitted"),
            );
        }
        for (level, message) in std::mem::take(&mut self.toast_out) {
            crate::toasts::push_logged(ctx, level, &message);
        }
    }
    #[cfg(test)]
    pub(crate) fn messages(&self) -> Vec<&str> {
        self.entries
            .iter()
            .map(|entry| entry.message.as_str())
            .collect()
    }
    pub(crate) fn counts(&self) -> (usize, usize) {
        (
            self.entries
                .iter()
                .filter(|entry| entry.level == Level::Warn)
                .count(),
            self.entries
                .iter()
                .filter(|entry| entry.level == Level::Error)
                .count(),
        )
    }
    /// The dock tab: "Activity" and, when there are any, a small chip each
    /// for the warnings and the errors.
    pub(crate) fn title(&self, font_size: f32) -> egui::WidgetText {
        let mut job = egui::text::LayoutJob::default();
        let format = |color, background, size| egui::TextFormat {
            font_id: egui::FontId::proportional(size),
            color,
            background,
            valign: egui::Align::Center,
            ..Default::default()
        };
        let none = egui::Color32::TRANSPARENT;
        job.append("Activity", 0.0, format(theme::text(), none, font_size));
        let palette = theme::palette();
        let (warn, error) = self.counts();
        for (count, color, background) in [
            (warn, palette.warn, palette.warn_bg),
            (error, palette.error, palette.error_bg),
        ] {
            if count != 0 {
                job.append(" ", 0.0, format(theme::text(), none, font_size));
                let size = (font_size - 3.0).max(11.0);
                job.append(&format!(" {count} "), 0.0, format(color, background, size));
            }
        }
        job.into()
    }
    fn visible(&self, level: Level) -> bool {
        match level {
            Level::Info => self.info,
            Level::Warn => self.warn,
            Level::Error => self.error,
        }
    }
    pub(crate) fn show(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.with_layout(
                egui::Layout::right_to_left(egui::Align::Center).with_main_wrap(true),
                |ui| {
                    if ui
                        .button("Clear")
                        .on_hover_text("Clear the saved Activity log, including filtered entries")
                        .clicked()
                    {
                        self.entries.clear();
                    }
                    ui.checkbox(&mut self.error, "Error");
                    ui.checkbox(&mut self.warn, "Warn");
                    ui.checkbox(&mut self.info, "Info");
                },
            );
        });
        ui.separator();
        let unsorted: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| self.visible(entry.level))
            .collect();
        let visible: Vec<_> =
            crate::table_sort::order(ui.ctx(), "activity", unsorted.len(), |column, a, b| {
                let (a, b) = (unsorted[a], unsorted[b]);
                match column {
                    0 => a.unix_ms.cmp(&b.unix_ms),
                    1 => (a.level as u8).cmp(&(b.level as u8)),
                    _ => a.message.to_lowercase().cmp(&b.message.to_lowercase()),
                }
            })
            .into_iter()
            .map(|index| unsorted[index])
            .collect();
        if visible.is_empty() {
            ui.label(if self.entries.is_empty() {
                "No activity"
            } else {
                "No activity at the selected levels"
            });
            return;
        }
        crate::widgets::table::begin(ui);
        TableBuilder::new(ui)
            .column(Column::exact(84.0))
            .column(Column::exact(60.0))
            .column(Column::remainder())
            .min_scrolled_height(0.0)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .header(26.0, |mut header| {
                for (column, label) in ["Time", "Level", "Message"].into_iter().enumerate() {
                    header.col(|ui| crate::table_sort::header(ui, "activity", column, label));
                }
            })
            .body(|body| {
                body.rows(26.0, visible.len(), |mut row| {
                    let entry = visible[row.index()];
                    let time = chrono::DateTime::from_timestamp_millis(entry.unix_ms);
                    row.col(|ui| {
                        ui.monospace(time.map_or_else(
                            || "—".into(),
                            |time| time.format("%H:%M:%S").to_string(),
                        ))
                        .on_hover_text(time.map_or_else(
                            || "UTC".into(),
                            |time| time.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                        ));
                    });
                    row.col(|ui| {
                        ui.colored_label(entry.level.color(), entry.level.label());
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(&entry.message).truncate())
                            .on_hover_text(&entry.message);
                    });
                });
            });
    }
}

/// Renderer state is separate from the journal: dismissing a banner or clearing
/// saved entries must neither change backend state nor recreate a banner each frame.
#[derive(Clone, Default)]
struct NoticeHub {
    known: HashSet<egui::Id>,
    order: VecDeque<egui::Id>,
    dismissed: HashSet<egui::Id>,
    pending: VecDeque<(Level, String, bool)>,
    omitted: usize,
    /// Toast reports of this and of the previous pass: one that was reported
    /// last pass is the same occurrence still on screen, not a new one.
    pass: u64,
    seen: HashSet<egui::Id>,
    seen_before: HashSet<egui::Id>,
}

/// Report an occurrence: an Activity row and a toast, nothing inline. Drawn
/// again every frame while it stands, it counts once; reported again after a
/// frame without it (a retry that fails again) it is a new occurrence: a
/// repeat of a toast still shown counts ×N, one that was dismissed or has
/// expired is a new toast.
pub(crate) fn report(ctx: &egui::Context, level: Level, message: impl std::fmt::Display) {
    register_with(ctx, level, bounded(message.to_string()), true);
}
/// Report a diagnostic of one object (a run, a core) once, in Activity only.
/// The object's own view shows it inline.
pub(crate) fn report_quiet(ctx: &egui::Context, level: Level, message: impl std::fmt::Display) {
    register_with(ctx, level, bounded(message.to_string()), false);
}
fn register(ctx: &egui::Context, level: Level, message: String) -> (egui::Id, bool) {
    register_with(ctx, level, message, false)
}
fn register_with(
    ctx: &egui::Context,
    level: Level,
    message: String,
    toast: bool,
) -> (egui::Id, bool) {
    let id = egui::Id::new(("activity-notice", level.label(), &message));
    let pass = ctx.cumulative_pass_nr();
    ctx.data_mut(|data| {
        let hub = data.get_temp_mut_or_default::<NoticeHub>(egui::Id::new(HUB));
        if toast {
            if hub.pass != pass {
                hub.seen_before = if hub.pass + 1 == pass {
                    std::mem::take(&mut hub.seen)
                } else {
                    hub.seen.clear();
                    HashSet::new()
                };
                hub.pass = pass;
            }
            let fresh = !hub.seen.contains(&id) && !hub.seen_before.contains(&id);
            hub.seen.insert(id);
            if fresh {
                if hub.pending.len() < INBOX_LIMIT {
                    hub.pending.push_back((level, message, true));
                } else {
                    hub.omitted = hub.omitted.saturating_add(1);
                }
            }
            return (id, false);
        }
        if hub.known.insert(id) {
            hub.order.push_back(id);
            if hub.order.len() > NOTICE_LIMIT {
                if let Some(old) = hub.order.pop_front() {
                    hub.known.remove(&old);
                    hub.dismissed.remove(&old);
                }
            }
            if hub.pending.len() < INBOX_LIMIT {
                hub.pending.push_back((level, message, toast));
            } else {
                hub.omitted = hub.omitted.saturating_add(1);
            }
        }
        (id, hub.dismissed.contains(&id))
    })
}

/// The result of an action that failed: a toast and an Activity row, nothing
/// inline (see [`report`] for how repeats count). Use [`error`] for a label that states a
/// condition or a validation.
pub(crate) fn error_toast(ui: &egui::Ui, message: impl std::fmt::Display) {
    report(ui.ctx(), Level::Error, message);
}
pub(crate) fn warning(ui: &mut egui::Ui, message: impl std::fmt::Display) -> egui::Response {
    notice(ui, Level::Warn, message)
}
pub(crate) fn error(ui: &mut egui::Ui, message: impl std::fmt::Display) -> egui::Response {
    notice(ui, Level::Error, message)
}
pub(crate) fn notice(
    ui: &mut egui::Ui,
    level: Level,
    message: impl std::fmt::Display,
) -> egui::Response {
    notice_impl(ui, level, message, false, None)
}

pub(crate) fn compact(
    ui: &mut egui::Ui,
    level: Level,
    message: impl std::fmt::Display,
) -> egui::Response {
    notice_impl(ui, level, message, true, None)
}

pub(crate) fn warning_details(
    ui: &mut egui::Ui,
    summary: String,
    details: String,
) -> egui::Response {
    notice_impl(ui, Level::Warn, summary, true, Some(details))
}

fn notice_impl(
    ui: &mut egui::Ui,
    level: Level,
    message: impl std::fmt::Display,
    compact: bool,
    details: Option<String>,
) -> egui::Response {
    let message = bounded(message.to_string());
    let details = details.map(bounded).unwrap_or_else(|| message.clone());
    let (id, dismissed) = register(ui.ctx(), level, details.clone());
    if dismissed {
        return ui.allocate_response(egui::Vec2::ZERO, egui::Sense::hover());
    }
    let output = ui.push_id(ui.next_auto_id().with(id), |ui| {
        ui.horizontal_top(|ui| {
            let natural_width = ui.fonts(|fonts| {
                fonts
                    .layout_no_wrap(
                        message.clone(),
                        egui::TextStyle::Body.resolve(ui.style()),
                        level.color(),
                    )
                    .size()
                    .x
            });
            let width =
                (ui.available_width() - ui.spacing().interact_size.y - ui.spacing().item_spacing.x)
                    .max(0.0)
                    .min(natural_width);
            let response = ui
                .allocate_ui_with_layout(
                    egui::vec2(width, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        let label = egui::Label::new(RichText::new(&message).color(level.color()));
                        ui.add(if compact {
                            label.truncate()
                        } else {
                            label.wrap()
                        })
                        .on_hover_text(&details)
                    },
                )
                .inner;
            if dismiss_button(ui)
                .on_hover_text("Dismiss this notice; details remain in Activity")
                .clicked()
            {
                ui.ctx().data_mut(|data| {
                    data.get_temp_mut_or_default::<NoticeHub>(egui::Id::new(HUB))
                        .dismissed
                        .insert(id)
                });
            }
            response
        })
        .inner
    });
    output.inner
}

fn dismiss_button(ui: &mut egui::Ui) -> egui::Response {
    if ui.is_enabled() || !ui.is_visible() {
        return ui.small_button("×");
    }
    // A disabled VM form still allows dismissal of its diagnostic. Keep this
    // one control enabled without enabling any of the form's actions.
    let (id, rect) = ui.allocate_space(egui::Vec2::splat(ui.spacing().interact_size.y));
    let mut control = egui::Ui::new(
        ui.ctx().clone(),
        id,
        egui::UiBuilder::new()
            .layer_id(ui.layer_id())
            .max_rect(rect)
            .style(ui.style().clone()),
    );
    control.set_clip_rect(ui.clip_rect());
    control.add_sized(rect.size(), egui::Button::new("×").small())
}

#[cfg(test)]
mod tests;
