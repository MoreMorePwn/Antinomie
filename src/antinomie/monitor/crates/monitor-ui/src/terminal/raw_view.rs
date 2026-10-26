// SPDX-License-Identifier: GPL-3.0-only
//! Drawing, searching and copying the Raw view.
use super::raw::{Mark, RawLine};
use super::*;

/// Matches kept for one search, so a very common word stays cheap.
const MATCH_LIMIT: usize = 5000;
const COPY_MAX_SIZE: usize = 8 * 1024 * 1024;

#[cfg(test)]
mod tests;

/// A place in the raw text. `line` counts from the first line ever kept, so
/// it stays right when old lines are dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Place {
    pub line: usize,
    pub col: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RawSelection {
    pub anchor: Place,
    pub head: Place,
}

impl RawSelection {
    fn range(self) -> (Place, Place) {
        (self.anchor.min(self.head), self.anchor.max(self.head))
    }

    fn columns(self, line: usize, chars: usize) -> std::ops::Range<usize> {
        let (start, end) = self.range();
        if line < start.line || line > end.line {
            return 0..0;
        }
        let first = if line == start.line { start.col } else { 0 };
        let last = if line == end.line { end.col } else { chars };
        first.min(chars)..last.min(chars)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Found {
    line: usize,
    start: usize,
    end: usize,
}

#[derive(Default)]
pub(super) struct RawView {
    pub find: String,
    matches: Vec<Found>,
    /// What `matches` was computed from.
    scanned: Option<(u64, String)>,
    current: usize,
    /// Scroll to the current match on the next frame.
    jump: bool,
    selection: Option<RawSelection>,
    /// Visual rows of the last frame, to keep the view in place as output arrives.
    rows: usize,
}

/// Visual rows a line takes when wrapped to `cols`.
fn rows_of(line: &RawLine, cols: usize) -> usize {
    line.chars.max(1).div_ceil(cols)
}

fn style_color(mark: Option<Mark>) -> Color32 {
    match mark {
        None => theme::terminal_text(),
        Some(Mark::Plain) => theme::muted(),
        Some(Mark::Conceal | Mark::Clipboard) => theme::error(),
        Some(_) => theme::warn(),
    }
}

fn style_fill(mark: Mark) -> Option<Color32> {
    match mark {
        Mark::Plain => None,
        Mark::Conceal | Mark::Clipboard => Some(theme::palette().error_bg),
        _ => Some(theme::palette().warn_bg),
    }
}

/// The mark covering each of the `a..b` characters of `line`.
fn styles(line: &RawLine, a: usize, b: usize) -> Vec<Option<Mark>> {
    let mut styles = vec![None; b - a];
    for span in &line.spans {
        for index in span.start.max(a)..span.end.min(b) {
            // A hazard stays visible when a plain span overlaps it.
            let slot = &mut styles[index - a];
            if slot.is_none_or(|old: Mark| !old.hides() || span.mark.hides()) {
                *slot = Some(span.mark);
            }
        }
    }
    styles
}

impl Terminal {
    /// The Formatted / Raw switch and, in Raw, the search field.
    pub(crate) fn view_controls(&mut self, ui: &mut egui::Ui) {
        let mut view = self.view;
        for (value, label, hint) in [
            (
                View::Formatted,
                "Formatted",
                "Draw the output as a terminal does",
            ),
            (
                View::Raw,
                "Raw",
                "Show escape codes as text (\\e is ESC, \\xNN a control byte, \\\\ a backslash). \
                 Highlighted codes can hide output.",
            ),
        ] {
            if ui
                .selectable_label(view == value, label)
                .on_hover_text(hint)
                .clicked()
            {
                view = value;
            }
        }
        self.set_view(view);
        if self.view != View::Raw {
            return;
        }
        let state = &mut self.raw_view;
        let field = ui.add(
            egui::TextEdit::singleline(&mut state.find)
                .hint_text(theme::hint_text("Find"))
                .desired_width(140.0),
        );
        self.refresh_matches();
        let state = &mut self.raw_view;
        let count = state.matches.len();
        if !state.find.is_empty() {
            let text = if count == 0 {
                "No matches".to_string()
            } else {
                format!(
                    "{} of {count}{}",
                    state.current + 1,
                    if count >= MATCH_LIMIT { "+" } else { "" }
                )
            };
            ui.label(egui::RichText::new(text).small().color(theme::muted()));
        }
        let enter = field.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
        let back = ui
            .add_enabled(
                count > 0,
                egui::Button::new(egui_phosphor::regular::CARET_UP),
            )
            .on_hover_text("Previous match")
            .clicked();
        let forward = ui
            .add_enabled(
                count > 0,
                egui::Button::new(egui_phosphor::regular::CARET_DOWN),
            )
            .on_hover_text("Next match")
            .clicked()
            || enter;
        if count > 0 && (back || forward) {
            state.current = if back {
                (state.current + count - 1) % count
            } else {
                (state.current + 1) % count
            };
            state.jump = true;
        }
    }

    /// Finds `find` in the raw text, again only when it or the text changed.
    fn refresh_matches(&mut self) {
        let state = &mut self.raw_view;
        let key = (self.raw.generation(), state.find.clone());
        if state.scanned.as_ref() == Some(&key) {
            return;
        }
        let new_query = state.scanned.as_ref().is_none_or(|(_, old)| *old != key.1);
        state.scanned = Some(key);
        state.matches.clear();
        if new_query {
            state.current = 0;
            if !state.find.is_empty() {
                state.jump = true;
            }
        }
        if state.find.is_empty() {
            return;
        }
        let needle = state.find.to_ascii_lowercase();
        let evicted = self.raw.evicted();
        'lines: for (index, line) in self.raw.lines().iter().enumerate() {
            let hay = line.text.to_ascii_lowercase();
            for (at, _) in hay.match_indices(&needle) {
                let start = hay[..at].chars().count();
                state.matches.push(Found {
                    line: evicted + index,
                    start,
                    end: start + needle.chars().count(),
                });
                if state.matches.len() >= MATCH_LIMIT {
                    break 'lines;
                }
            }
        }
        state.current = state.current.min(state.matches.len().saturating_sub(1));
    }

    /// The rows in view, as (line index, wrapped row of that line), top first.
    fn raw_rows(&self, cols: usize, shown: usize, offset: usize) -> Vec<(usize, usize)> {
        let mut skip = offset;
        let mut rows = Vec::with_capacity(shown);
        'lines: for (index, line) in self.raw.lines().iter().enumerate().rev() {
            for sub in (0..rows_of(line, cols)).rev() {
                if skip > 0 {
                    skip -= 1;
                } else if rows.len() < shown {
                    rows.push((index, sub));
                } else {
                    break 'lines;
                }
            }
        }
        rows.reverse();
        rows
    }

    /// Visual rows between the end of the text and the top of `line`'s row `sub`.
    fn rows_below(&self, cols: usize, index: usize, sub: usize) -> usize {
        let lines = self.raw.lines();
        let after: usize = lines
            .iter()
            .skip(index + 1)
            .map(|line| rows_of(line, cols))
            .sum();
        after + rows_of(&lines[index], cols) - 1 - sub
    }

    fn raw_text(&self, selection: RawSelection) -> Result<String, &'static str> {
        let (start, end) = selection.range();
        let evicted = self.raw.evicted();
        let lines = self.raw.lines();
        let mut text = String::new();
        for number in start.line.max(evicted)..=end.line {
            let Some(line) = lines.get(number - evicted) else {
                break;
            };
            let range = selection.columns(number, line.chars);
            if number != start.line.max(evicted) {
                text.push('\n');
            }
            text.extend(line.text.chars().skip(range.start).take(range.len()));
            if text.len() > COPY_MAX_SIZE {
                return Err("Selection exceeds 8 MiB; select a smaller range");
            }
        }
        Ok(text)
    }

    fn copy_raw(&self, ui: &egui::Ui) -> bool {
        let Some(selection) = self.raw_view.selection else {
            return false;
        };
        match self.raw_text(selection) {
            Ok(text) if !text.is_empty() => {
                ui.ctx().copy_text(text);
                true
            }
            Ok(_) => false,
            Err(message) => {
                crate::activity::report(ui.ctx(), crate::activity::Level::Warn, message);
                true
            }
        }
    }

    fn raw_copy_actions(&mut self, ui: &mut egui::Ui, response: &egui::Response) -> bool {
        let selected = self.raw_view.selection.is_some_and(|s| s.anchor != s.head);
        let mut copied = self.copy_requested(ui, response, selected) && self.copy_raw(ui);
        response.context_menu(|ui| {
            if ui
                .add_enabled(
                    selected,
                    egui::Button::new("Copy selection    Ctrl+Shift+C"),
                )
                .clicked()
            {
                copied |= self.copy_raw(ui);
                ui.close_menu();
            }
            if ui.button("Select all output").clicked() {
                let evicted = self.raw.evicted();
                let last = self.raw.lines().len() - 1;
                self.raw_view.selection = Some(RawSelection {
                    anchor: Place {
                        line: evicted,
                        col: 0,
                    },
                    head: Place {
                        line: evicted + last,
                        col: self.raw.lines()[last].chars,
                    },
                });
                response.request_focus();
                ui.close_menu();
            }
            if ui
                .add_enabled(
                    self.raw_view.selection.is_some(),
                    egui::Button::new("Clear selection"),
                )
                .clicked()
            {
                self.raw_view.selection = None;
                ui.close_menu();
            }
        });
        copied
    }

    #[allow(clippy::too_many_arguments)]
    /// Selection by mouse, in text positions. Returns the mark under the
    /// pointer, for its hover text.
    fn raw_select(
        &mut self,
        ui: &egui::Ui,
        response: &egui::Response,
        grid: egui::Rect,
        cell: egui::Vec2,
        cols: usize,
        rows: &[(usize, usize)],
        max_offset: usize,
    ) -> Option<Mark> {
        if rows.is_empty() {
            return None;
        }
        let evicted = self.raw.evicted();
        let widths: Vec<usize> = rows
            .iter()
            .map(|&(index, _)| self.raw.lines()[index].chars)
            .collect();
        let place = |pos: egui::Pos2| {
            let row =
                (((pos.y - grid.top()) / cell.y).floor().max(0.0) as usize).min(rows.len() - 1);
            let (index, sub) = rows[row];
            let chars = widths[row];
            let col = (sub * cols + ((pos.x - grid.left()) / cell.x).round().max(0.0) as usize)
                .min(chars)
                .min((sub + 1) * cols);
            Place {
                line: evicted + index,
                col,
            }
        };
        let pointer = ui.input(|i| i.pointer.hover_pos());
        let mut hovered = None;
        if let Some(pos) = pointer.filter(|pos| response.hovered() && grid.contains(*pos)) {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Text);
            let row =
                (((pos.y - grid.top()) / cell.y).floor().max(0.0) as usize).min(rows.len() - 1);
            let (index, sub) = rows[row];
            let line = &self.raw.lines()[index];
            let index = sub * cols + ((pos.x - grid.left()) / cell.x).floor().max(0.0) as usize;
            hovered = line
                .spans
                .iter()
                .rev()
                .find(|span| span.mark.hides() && (span.start..span.end).contains(&index))
                .map(|span| span.mark);
        }
        let press = ui.input(|i| {
            i.events.iter().find_map(|event| match event {
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    ..
                } if grid.contains(*pos) && response.contains_pointer() => Some(*pos),
                _ => None,
            })
        });
        if let Some(pos) = press {
            let at = place(pos);
            self.raw_view.selection = Some(RawSelection {
                anchor: at,
                head: at,
            });
            response.request_focus();
        }
        if response.dragged_by(egui::PointerButton::Primary)
            && let Some(pos) = response.interact_pointer_pos()
        {
            let at = place(pos);
            if let Some(selection) = &mut self.raw_view.selection {
                selection.head = at;
            }
            if pos.y < grid.top() || pos.y > grid.bottom() {
                self.scroll(if pos.y < grid.top() { 1 } else { -1 }, max_offset);
                ui.ctx().request_repaint_after(Duration::from_millis(30));
            }
        }
        if response.double_clicked()
            && let Some(pos) = response.interact_pointer_pos()
        {
            let at = place(pos);
            let line = &self.raw.lines()[at.line - evicted];
            let chars: Vec<char> = line.text.chars().collect();
            let word = |col: usize| chars.get(col).is_some_and(|c| !c.is_whitespace());
            let mut start = at.col.min(chars.len());
            let mut end = start;
            while start > 0 && word(start - 1) {
                start -= 1;
            }
            while word(end) {
                end += 1;
            }
            self.raw_view.selection = Some(RawSelection {
                anchor: Place { col: start, ..at },
                head: Place { col: end, ..at },
            });
        }
        hovered
    }

    /// The Raw view: the same pane and scrollback as the Formatted one, with
    /// the PTY still sized to it and keys still going to a live program.
    pub(super) fn show_raw(
        &mut self,
        ui: &mut egui::Ui,
        enabled: bool,
        resize_parser: bool,
    ) -> (Vec<u8>, Option<(u16, u16)>) {
        let Some(Prepared {
            font,
            cell,
            available,
            fit,
            resize,
        }) = self.prepare(ui, resize_parser)
        else {
            return (Vec::new(), None);
        };
        let cols = usize::from(fit.1).max(1);
        let shown = usize::from(fit.0).max(1);
        let (rect, response) = ui.allocate_exact_size(available, Sense::click_and_drag());
        let grid = egui::Rect::from_min_size(
            rect.min,
            egui::vec2(cols as f32 * cell.x, shown as f32 * cell.y),
        );
        ui.painter().rect_filled(rect, 0.0, theme::terminal());
        if response.clicked() || response.drag_started() {
            response.request_focus();
        }
        let total: usize = self
            .raw
            .lines()
            .iter()
            .map(|line| rows_of(line, cols))
            .sum();
        // New output below a scrolled-back view leaves it where it was.
        if self.offset > 0 && total > self.raw_view.rows {
            self.offset += total - self.raw_view.rows;
        }
        self.raw_view.rows = total;
        let max_offset = total.saturating_sub(shown);
        let page = shown.saturating_sub(1).max(1) as isize;
        self.scroll_input(ui, rect, cell, &response, max_offset, page, 0);
        if self.raw_view.jump {
            self.raw_view.jump = false;
            if let Some(found) = self.raw_view.matches.get(self.raw_view.current).copied() {
                let index = found.line.saturating_sub(self.raw.evicted());
                if index < self.raw.lines().len() {
                    let below = self.rows_below(cols, index, found.start / cols);
                    self.offset = below.saturating_sub(shown / 2);
                }
            }
        }
        self.offset = self.offset.min(max_offset);
        let track = egui::Rect::from_min_max(
            egui::pos2(rect.right() - BAR, grid.top()),
            egui::pos2(rect.right(), grid.bottom()),
        );
        let first = max_offset - self.offset;
        if let Some(first) = scrollbar(
            ui,
            track,
            response.id.with("scrollbar"),
            true,
            total,
            shown,
            first,
        ) {
            self.offset = max_offset - first.min(max_offset);
        }
        let rows = self.raw_rows(cols, shown, self.offset);
        let hovered = self.raw_select(ui, &response, grid, cell, cols, &rows, max_offset);
        if let Some(mark) = hovered {
            response.clone().on_hover_text(mark.hint());
        }
        self.paint_raw(ui.painter_at(grid), &font, cell, grid, cols, &rows);
        ui.painter().rect_stroke(
            focus_edge(rect),
            0.0,
            egui::Stroke::new(
                1.0_f32,
                if response.has_focus() {
                    theme::palette().accent
                } else {
                    theme::line()
                },
            ),
            egui::StrokeKind::Inside,
        );
        self.jump_button(ui, grid, &response);
        let mut copied = self.raw_copy_actions(ui, &response);
        let input = self.read_input(ui, &response, enabled, &mut copied);
        if !input.is_empty() {
            self.raw_view.selection = None;
        }
        (input, resize)
    }

    fn paint_raw(
        &self,
        painter: egui::Painter,
        font: &egui::FontId,
        cell: egui::Vec2,
        grid: egui::Rect,
        cols: usize,
        rows: &[(usize, usize)],
    ) {
        let evicted = self.raw.evicted();
        let view = &self.raw_view;
        let x_of = |col: usize| grid.left() + col as f32 * cell.x;
        for (position, &(index, sub)) in rows.iter().enumerate() {
            let line = &self.raw.lines()[index];
            let (a, b) = (sub * cols, ((sub + 1) * cols).min(line.chars));
            let y = grid.top() + position as f32 * cell.y;
            let band = |start: usize, end: usize, fill: Color32| {
                let (start, end) = (start.max(a), end.min(b));
                if start < end {
                    painter.rect_filled(
                        egui::Rect::from_min_max(
                            egui::pos2(x_of(start - a), y),
                            egui::pos2(x_of(end - a), y + cell.y),
                        ),
                        0.0,
                        fill,
                    );
                }
            };
            if a >= b {
                continue;
            }
            let marks = styles(line, a, b);
            for (offset, mark) in marks.iter().enumerate() {
                if let Some(fill) = mark.and_then(style_fill) {
                    band(a + offset, a + offset + 1, fill);
                }
            }
            let number = evicted + index;
            let at = view.matches.partition_point(|found| found.line < number);
            for (n, found) in view.matches.iter().enumerate().skip(at) {
                if found.line != number {
                    break;
                }
                let current = n == view.current;
                band(
                    found.start,
                    found.end,
                    if current {
                        theme::palette().selection
                    } else {
                        theme::palette().selection_soft
                    },
                );
            }
            if let Some(selection) = view.selection {
                let range = selection.columns(number, line.chars);
                band(range.start, range.end, theme::palette().selection);
            }
            let chars: Vec<char> = line.text.chars().skip(a).take(b - a).collect();
            let mut start = 0;
            while start < chars.len() {
                let mark = marks[start];
                let mut end = start + 1;
                while end < chars.len() && marks[end] == mark {
                    end += 1;
                }
                let color = if line.note {
                    theme::muted()
                } else {
                    style_color(mark)
                };
                painter.text(
                    egui::pos2(x_of(start), y),
                    egui::Align2::LEFT_TOP,
                    chars[start..end].iter().collect::<String>(),
                    font.clone(),
                    color,
                );
                start = end;
            }
        }
    }
}
