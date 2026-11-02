// SPDX-License-Identifier: GPL-3.0-only
//! The command palette (Ctrl+K): one search box over the menu actions, the
//! open tabs, the machines, the recent runs and the library samples.
//!
//! Enter runs the highlighted entry through `MonitorApp::run_action`, the same
//! path as the menus and the shortcuts. An entry that cannot run now stays in
//! the list, greyed, with the reason; Enter on it shows the reason and keeps
//! the palette open. Escape (or Ctrl+K again) closes it.
use super::*;

/// How many recent runs and library samples the palette lists.
const RECENT_LIMIT: usize = 30;
/// The widest the palette gets, in points.
const WIDTH: f32 = 640.0;

/// What an entry does when it runs.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Target {
    Action(Action),
    Tab(Panel),
    Machine(String),
    Run(String),
    Sample(String),
}

/// One line of the palette.
#[derive(Clone, Debug)]
pub(super) struct Item {
    pub(super) target: Target,
    pub(super) label: String,
    /// "Tab", "Machine", "Run", "Sample" or the menu of an action.
    pub(super) kind: String,
    /// The shortcut, or what else tells entries of one kind apart.
    pub(super) detail: String,
    /// Why it cannot run now.
    pub(super) unavailable: Option<String>,
    /// Everything a query can match.
    haystack: String,
}

/// The palette's state between frames.
#[derive(Default)]
pub(super) struct Palette {
    pub(super) open: bool,
    pub(super) query: String,
    /// The highlighted entry, as a position in the shown list.
    pub(super) cursor: usize,
    /// The reason the last Enter did nothing.
    pub(super) notice: Option<String>,
    /// The highlighted entry moved: scroll it into view.
    scroll_to_cursor: bool,
}

/// How well `query` matches `text`: every character of the query must appear
/// in order (case ignored). Runs of characters, word starts and an exact
/// substring score higher; gaps cost a little. `None` when it does not match.
pub(super) fn fuzzy_score(query: &str, text: &str) -> Option<i32> {
    let text: Vec<char> = text.to_lowercase().chars().collect();
    let query: Vec<char> = query
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut next = 0;
    let mut previous: Option<usize> = None;
    let mut score = 0;
    for wanted in &query {
        let found = (next..text.len()).find(|at| text[*at] == *wanted)?;
        score += 1;
        if found == 0 || !text[found - 1].is_alphanumeric() {
            score += 8;
        }
        match previous {
            Some(before) if before + 1 == found => score += 6,
            Some(before) => score -= ((found - before - 1).min(10) / 2) as i32,
            None => score -= (found.min(10) / 2) as i32,
        }
        previous = Some(found);
        next = found + 1;
    }
    let whole: String = text.iter().collect();
    let needle: String = query.iter().collect();
    if !needle.is_empty() && whole.contains(&needle) {
        score += 30;
    }
    Some(score)
}

/// The score of a whole query (words separated by spaces) against an item: each
/// word must match; a match in the label counts double.
fn item_score(query: &str, item: &Item) -> Option<i32> {
    let mut total = 0;
    for word in query.split_whitespace() {
        let in_label = fuzzy_score(word, &item.label).map(|score| score * 2);
        let anywhere = fuzzy_score(word, &item.haystack);
        total += in_label.into_iter().chain(anywhere).max()?;
    }
    Some(total)
}

impl MonitorApp {
    /// Every entry the palette can offer now, in the order shown for an empty
    /// query: tabs, machines, recent runs, actions, samples.
    pub(super) fn palette_items(&self, ctx: &egui::Context) -> Vec<Item> {
        let mut items = Vec::new();
        for panel in self.layout.all_tabs() {
            let title = self.panel_title(&panel);
            let detail = self
                .shortcut_text(ctx, &Action::Go(panel.clone()))
                .unwrap_or_default();
            items.push(Item {
                haystack: format!("{title} tab view"),
                label: title,
                kind: "Tab".into(),
                detail,
                unavailable: None,
                target: Target::Tab(panel),
            });
        }
        for vm in &self.snapshot.vms {
            let state = if self.snapshot.active_vm.as_ref() == Some(&vm.id) {
                "running"
            } else {
                "stopped"
            };
            let selected = if self.selected.as_ref() == Some(&vm.id) {
                " · selected"
            } else {
                ""
            };
            items.push(Item {
                target: Target::Machine(vm.id.clone()),
                label: vm.name.clone(),
                kind: "Machine".into(),
                detail: format!("{state}{selected}"),
                unavailable: None,
                haystack: format!("{} machine vm {}", vm.name, vm.id),
            });
        }
        let mut runs: Vec<&RunSummary> = Vec::new();
        for run in self.snapshot.runs.iter().chain(&self.history) {
            if !runs.iter().any(|seen| seen.id == run.id) {
                runs.push(run);
            }
        }
        runs.sort_by(|a, b| b.started_ms.cmp(&a.started_ms));
        for run in runs.into_iter().take(RECENT_LIMIT) {
            let program = std::path::Path::new(&run.request.path)
                .file_name()
                .map_or_else(|| run.request.path.clone(), |n| n.to_string_lossy().into());
            let machine = self
                .snapshot
                .vms
                .iter()
                .find(|vm| vm.id == run.vm_id)
                .map_or("", |vm| vm.name.as_str());
            items.push(Item {
                target: Target::Run(run.id.clone()),
                label: format!(
                    "{program}  [{}]",
                    run.id.chars().take(8).collect::<String>()
                ),
                kind: "Run".into(),
                detail: format!(
                    "{} · {machine}",
                    crate::time_format::unix_ms(run.started_ms)
                ),
                unavailable: None,
                haystack: format!("{} run {machine} {}", run.request.path, run.id),
            });
        }
        for action in Action::PALETTE {
            let label = action.label(self);
            let kind = action.group().to_owned();
            items.push(Item {
                detail: self.shortcut_text(ctx, &action).unwrap_or_default(),
                unavailable: self.action_unavailable(&action),
                haystack: format!("{kind} {label}"),
                label,
                kind,
                target: Target::Action(action),
            });
        }
        if self.samples_page.is_loaded() {
            for row in self.samples_page.rows().iter().take(RECENT_LIMIT) {
                let record = &row.record;
                let name = if record.name.is_empty() {
                    record.sha256.chars().take(12).collect()
                } else {
                    record.name.clone()
                };
                items.push(Item {
                    target: Target::Sample(record.sha256.clone()),
                    haystack: format!("{name} sample {} {}", record.sha256, record.family),
                    label: name,
                    kind: "Sample".into(),
                    detail: record.sha256.chars().take(12).collect(),
                    unavailable: None,
                });
            }
        }
        items
    }

    /// The entries `query` keeps, best first (the given order for an empty
    /// query; an available entry before an unavailable one of the same score).
    pub(super) fn palette_results(&self, ctx: &egui::Context, query: &str) -> Vec<Item> {
        let items = self.palette_items(ctx);
        if query.trim().is_empty() {
            return items;
        }
        let mut scored: Vec<(i32, Item)> = items
            .into_iter()
            .filter_map(|item| item_score(query, &item).map(|score| (score, item)))
            .collect();
        scored.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then(a.1.unavailable.is_some().cmp(&b.1.unavailable.is_some()))
        });
        scored.into_iter().map(|(_, item)| item).collect()
    }

    /// Select a machine as the sidebar does.
    pub(super) fn select_vm(&mut self, vm_id: String) {
        if self.selected.as_ref() != Some(&vm_id) {
            self.selected = Some(vm_id);
            self.clear_history();
            self.select_run(None);
            self.refresh_history();
        }
    }

    /// Run an entry. `false` when it could not run, with the reason in the
    /// palette's notice.
    pub(super) fn palette_run(&mut self, ctx: &egui::Context, item: &Item) -> bool {
        if let Some(reason) = &item.unavailable {
            self.shortcut_ui.palette.notice = Some(format!("{}: {reason}", item.label));
            return false;
        }
        match &item.target {
            Target::Action(action) => self.run_action(ctx, action.clone()),
            Target::Tab(panel) => self.focus_panel = Some(panel.clone()),
            Target::Machine(id) => self.select_vm(id.clone()),
            Target::Run(id) => {
                if let Some(run) = self.run(id).cloned() {
                    self.open_sample_run(&run, Panel::Summary, None);
                }
            }
            Target::Sample(sha256) => {
                self.open_library(LibraryPage::Samples);
                self.samples_page.open_detail(sha256);
            }
        }
        true
    }

    /// The palette: its keys first (before anything else can take Escape, the
    /// arrows or Enter), then the window.
    pub(super) fn palette(&mut self, ctx: &egui::Context) {
        if !self.shortcut_ui.palette.open {
            return;
        }
        let (close, down, up, page_down, page_up, enter) = ctx.input_mut(|input| {
            let none = egui::Modifiers::NONE;
            (
                input.consume_key(none, egui::Key::Escape)
                    || input.consume_shortcut(&keys::PALETTE),
                input.consume_key(none, egui::Key::ArrowDown),
                input.consume_key(none, egui::Key::ArrowUp),
                input.consume_key(none, egui::Key::PageDown),
                input.consume_key(none, egui::Key::PageUp),
                input.consume_key(none, egui::Key::Enter),
            )
        });
        if close {
            self.shortcut_ui.palette.open = false;
            return;
        }
        let query = self.shortcut_ui.palette.query.clone();
        let results = self.palette_results(ctx, &query);
        let last = results.len().saturating_sub(1);
        let state = &mut self.shortcut_ui.palette;
        let before = state.cursor;
        if down {
            state.cursor += 1;
        }
        if up {
            state.cursor = state.cursor.saturating_sub(1);
        }
        if page_down {
            state.cursor += 8;
        }
        if page_up {
            state.cursor = state.cursor.saturating_sub(8);
        }
        state.cursor = state.cursor.min(last);
        if state.cursor != before {
            state.scroll_to_cursor = true;
            state.notice = None;
        }
        if enter {
            if let Some(item) = results.get(state.cursor).cloned() {
                if self.palette_run(ctx, &item) {
                    self.shortcut_ui.palette.open = false;
                    return;
                }
            }
        }
        let clicked = self.palette_window(ctx, &results);
        if let Some(item) = clicked {
            if self.palette_run(ctx, &item) {
                self.shortcut_ui.palette.open = false;
            }
        }
    }

    /// Draw the window; returns the entry that was clicked.
    fn palette_window(&mut self, ctx: &egui::Context, results: &[Item]) -> Option<Item> {
        let screen = ctx.screen_rect();
        let width = WIDTH.min((screen.width() - 24.0).max(280.0));
        let list_height = (screen.height() * 0.5).clamp(120.0, 420.0);
        let font = self.settings.font_size;
        let mut clicked = None;
        let state = &mut self.shortcut_ui.palette;
        let window = egui::Window::new("Command palette")
            .id(egui::Id::new("command_palette"))
            .title_bar(false)
            .collapsible(false)
            .resizable(false)
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 64.0))
            .min_width(width)
            .max_width(width)
            .show(ctx, |ui| {
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut state.query)
                        .id(egui::Id::new("command_palette_query"))
                        .hint_text(theme::hint_text(
                            "Type a command, tab, machine, run or sample",
                        ))
                        .margin(theme::TEXT_EDIT_MARGIN)
                        .desired_width(f32::INFINITY),
                );
                // The query is the only thing here that takes typing.
                edit.request_focus();
                if edit.changed() {
                    state.cursor = 0;
                    state.notice = None;
                    state.scroll_to_cursor = true;
                }
                ui.add_space(4.0);
                if results.is_empty() {
                    theme::empty_state(ui, "Nothing matches.");
                }
                let row_height = font + 12.0;
                egui::ScrollArea::vertical()
                    .id_salt("command_palette_list")
                    .max_height(list_height)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for (position, item) in results.iter().enumerate() {
                            let selected = position == state.cursor;
                            let (rect, response) = ui.allocate_exact_size(
                                egui::vec2(ui.available_width(), row_height),
                                egui::Sense::click(),
                            );
                            if ui.is_rect_visible(rect) {
                                paint_row(ui, rect, item, selected, response.hovered(), font);
                            }
                            if selected && state.scroll_to_cursor {
                                ui.scroll_to_rect(rect, None);
                            }
                            if response.clicked() {
                                clicked = Some(item.clone());
                            }
                        }
                    });
                state.scroll_to_cursor = false;
                ui.add_space(4.0);
                match &state.notice {
                    Some(notice) => {
                        ui.colored_label(theme::warn(), notice);
                    }
                    None => {
                        let reason = results
                            .get(state.cursor)
                            .and_then(|item| item.unavailable.as_deref());
                        match reason {
                            Some(reason) => ui.colored_label(theme::warn(), reason),
                            None => ui.weak("↑ ↓ choose · Enter run · Esc close"),
                        };
                    }
                }
            });
        // A click outside closes it.
        if let Some(window) = window {
            let outside = ctx.input(|input| {
                input.pointer.any_pressed()
                    && input
                        .pointer
                        .interact_pos()
                        .is_some_and(|at| !window.response.rect.contains(at))
            });
            if outside {
                self.shortcut_ui.palette.open = false;
            }
        }
        clicked
    }
}

/// One row: the label on the left, the shortcut or the reason and the kind on
/// the right.
fn paint_row(
    ui: &egui::Ui,
    rect: egui::Rect,
    item: &Item,
    selected: bool,
    hovered: bool,
    font: f32,
) {
    let painter = ui.painter();
    if selected {
        painter.rect_filled(rect, 3.0, ui.visuals().selection.bg_fill);
    } else if hovered {
        painter.rect_filled(rect, 3.0, theme::raised());
    }
    let id = egui::FontId::proportional(font);
    let color = if item.unavailable.is_some() {
        theme::muted()
    } else {
        theme::text()
    };
    let truncated = |text: &str, color: egui::Color32, width: f32| {
        let mut job = egui::text::LayoutJob::simple_singleline(text.to_owned(), id.clone(), color);
        job.wrap = egui::text::TextWrapping::truncate_at_width(width.max(24.0));
        painter.layout_job(job)
    };
    let centre = rect.center().y;
    let kind = painter.layout_no_wrap(item.kind.clone(), id.clone(), theme::muted());
    let kind_left = rect.right() - 8.0 - kind.size().x;
    painter.galley(
        egui::pos2(kind_left, centre - kind.size().y / 2.0),
        kind,
        theme::muted(),
    );
    // The reason an entry cannot run replaces its shortcut or detail.
    let (side_text, side_color) = match &item.unavailable {
        Some(reason) => (reason.as_str(), theme::warn()),
        None => (item.detail.as_str(), theme::muted()),
    };
    let side = truncated(side_text, side_color, rect.width() * 0.45 - 40.0);
    let side_left = kind_left - 14.0 - side.size().x;
    painter.galley(
        egui::pos2(side_left, centre - side.size().y / 2.0),
        side,
        side_color,
    );
    let label = truncated(&item.label, color, side_left - rect.left() - 24.0);
    painter.galley(
        egui::pos2(rect.left() + 8.0, centre - label.size().y / 2.0),
        label,
        color,
    );
}
