// SPDX-License-Identifier: GPL-3.0-only
//! Selection in terminal cells, including retained scrollback, never ANSI bytes.
use super::*;

const COPY_MAX_SIZE: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Point {
    pub row: usize,
    pub col: u16,
}

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug)]
pub(super) struct Selection {
    pub anchor: Point,
    pub head: Point,
}

impl Selection {
    fn range(self) -> (Point, Point) {
        (self.anchor.min(self.head), self.anchor.max(self.head))
    }

    fn columns(self, row: usize, cols: u16) -> std::ops::Range<u16> {
        let (start, end) = self.range();
        if row < start.row || row > end.row {
            return 0..0;
        }
        let first = if row == start.row { start.col } else { 0 };
        let last = if row == end.row { end.col } else { cols };
        first.min(cols)..last.min(cols)
    }

    fn shifted(self, removed: usize) -> Option<Self> {
        Some(Self {
            anchor: Point {
                row: self.anchor.row.checked_sub(removed)?,
                ..self.anchor
            },
            head: Point {
                row: self.head.row.checked_sub(removed)?,
                ..self.head
            },
        })
    }
}

impl Terminal {
    /// A single pinned scrollback row counts newly scrolled lines, including
    /// at a full history buffer. Clear selections whose original cells change
    /// or are evicted, instead of copying different bytes under an old highlight.
    pub(super) fn process_selected(&mut self, bytes: &[u8]) {
        let history = self.history();
        let selection = self.selection.expect("selection checked by process");
        let (start, end) = selection.range();
        let live = (end.row >= history).then_some(Selection {
            anchor: start.max(Point {
                row: history,
                col: 0,
            }),
            head: end,
        });
        let before = live.and_then(|range| self.selection_text(range, history).ok());
        let alternate = self.parser.screen().alternate_screen();
        self.parser
            .screen_mut()
            .set_scrollback(usize::from(history > 0));
        self.parser.process(bytes);
        let marker = self.parser.screen().scrollback();
        let after_history = self.history();
        let scrolled = if history == 0 {
            after_history
        } else {
            marker.saturating_sub(1)
        };
        if self.offset > 0 {
            self.offset = self.offset.saturating_add(scrolled).min(after_history);
        }
        let removed = history
            .saturating_add(scrolled)
            .saturating_sub(after_history);
        self.selection = selection.shifted(removed);
        if alternate != self.parser.screen().alternate_screen()
            || marker == SCROLLBACK
            || (history == 0 && after_history == SCROLLBACK)
        {
            self.selection = None;
        } else if let Some(live) = live {
            let after = live
                .shifted(removed)
                .and_then(|range| self.selection_text(range, after_history).ok());
            if before != after || before.is_none() {
                self.selection = None;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn select(
        &mut self,
        ui: &mut egui::Ui,
        response: &egui::Response,
        grid: egui::Rect,
        cell: egui::Vec2,
        first: usize,
        count: usize,
        cols: u16,
        history: usize,
    ) {
        if count == 0 {
            return;
        }
        if response.hovered()
            && grid.contains(ui.input(|i| i.pointer.hover_pos().unwrap_or(egui::Pos2::ZERO)))
        {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Text);
        }
        let column = self.column;
        let point = |pos: egui::Pos2| Point {
            row: first + (((pos.y - grid.top()) / cell.y).floor().max(0.0) as usize).min(count - 1),
            col: (f32::from(column) + ((pos.x - grid.left()) / cell.x).round())
                .clamp(0.0, f32::from(cols)) as u16,
        };
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
            let at = point(pos);
            self.selection = Some(Selection {
                anchor: at,
                head: at,
            });
            response.request_focus();
        }
        if response.dragged_by(egui::PointerButton::Primary)
            && let Some(pos) = response.interact_pointer_pos()
        {
            let at = point(pos);
            if let Some(selection) = &mut self.selection {
                selection.head = at;
            }
            if pos.y < grid.top() || pos.y > grid.bottom() {
                self.scroll(if pos.y < grid.top() { 1 } else { -1 }, history);
                ui.ctx().request_repaint_after(Duration::from_millis(30));
            }
        }
        if response.double_clicked()
            && let Some(pos) = response.interact_pointer_pos()
        {
            let at = point(pos);
            self.parser
                .screen_mut()
                .set_scrollback(history.saturating_sub(at.row));
            let row = at.row.saturating_sub(history) as u16;
            let word = |col| {
                self.parser.screen().cell(row, col).is_some_and(|c| {
                    c.is_wide_continuation() || c.contents().chars().any(|c| !c.is_whitespace())
                })
            };
            let mut start = at.col.min(cols - 1);
            let mut end = start + 1;
            while start > 0 && word(start - 1) {
                start -= 1;
            }
            while end < cols && word(end) {
                end += 1;
            }
            self.parser.screen_mut().set_scrollback(0);
            self.selection = Some(Selection {
                anchor: Point { col: start, ..at },
                head: Point { col: end, ..at },
            });
        }
    }

    /// Bounded plain text, with soft wraps joined and wide-cell continuations
    /// skipped. Always restores vt100's live-screen view, even on a size error.
    fn selection_text(
        &mut self,
        selection: Selection,
        history: usize,
    ) -> Result<String, &'static str> {
        let (start, end) = selection.range();
        let (rows, cols) = self.parser.screen().size();
        if end.row >= history + usize::from(rows) {
            return Err("Selection is no longer available");
        }
        let mut text = String::new();
        let mut wrapped = false;
        let result = (|| {
            for line in start.row..=end.row {
                self.parser
                    .screen_mut()
                    .set_scrollback(history.saturating_sub(line));
                let row = line.saturating_sub(history) as u16;
                let screen = self.parser.screen();
                let range = selection.columns(line, cols);
                if range.is_empty() && line == end.row {
                    if line != start.row && !wrapped {
                        text.push('\n');
                    }
                    break;
                }
                if line != start.row && !wrapped {
                    text.push('\n');
                }
                let line_start = text.len();
                for col in range.clone() {
                    let Some(cell) = screen.cell(row, col) else {
                        continue;
                    };
                    if cell.is_wide_continuation() {
                        if col == range.start
                            && col > 0
                            && let Some(previous) = screen.cell(row, col - 1)
                        {
                            text.push_str(previous.contents());
                        }
                    } else if cell.contents().is_empty() {
                        text.push(' ');
                    } else {
                        text.push_str(cell.contents());
                    }
                    if text.len() > COPY_MAX_SIZE {
                        return Err("Selection exceeds 8 MiB; select a smaller range");
                    }
                }
                wrapped = range.end == cols && screen.row_wrapped(row);
                if range.end == cols && !wrapped {
                    let trimmed = text[line_start..].trim_end_matches(' ').len();
                    text.truncate(line_start + trimmed);
                }
            }
            Ok(text)
        })();
        self.parser.screen_mut().set_scrollback(0);
        result
    }

    fn copy_selection(&mut self, ui: &egui::Ui, history: usize) -> bool {
        let Some(selection) = self.selection else {
            return false;
        };
        match self.selection_text(selection, history) {
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

    pub(super) fn copy_actions(
        &mut self,
        ui: &mut egui::Ui,
        response: &egui::Response,
        history: usize,
        rows: u16,
        cols: u16,
    ) -> bool {
        let copy = response.has_focus()
            && ui.input(|i| {
                i.events.iter().any(|event| match event {
                    egui::Event::Copy => true,
                    egui::Event::Key {
                        key: Key::C,
                        pressed: true,
                        modifiers,
                        ..
                    } => {
                        modifiers.ctrl
                            && (modifiers.shift
                                || self.selection.is_some_and(|s| s.anchor != s.head))
                    }
                    egui::Event::Key {
                        key: Key::Insert,
                        pressed: true,
                        modifiers,
                        ..
                    } => modifiers.ctrl,
                    _ => false,
                })
            });
        let mut copied = copy && self.copy_selection(ui, history);
        response.context_menu(|ui| {
            if ui
                .add_enabled(
                    self.selection.is_some_and(|s| s.anchor != s.head),
                    egui::Button::new("Copy selection    Ctrl+Shift+C"),
                )
                .clicked()
            {
                copied |= self.copy_selection(ui, history);
                ui.close_menu();
            }
            if ui.button("Select all output").clicked() {
                self.selection = Some(Selection {
                    anchor: Point { row: 0, col: 0 },
                    head: Point {
                        row: history + usize::from(rows) - 1,
                        col: cols,
                    },
                });
                response.request_focus();
                ui.close_menu();
            }
            if ui
                .add_enabled(
                    self.selection.is_some(),
                    egui::Button::new("Clear selection"),
                )
                .clicked()
            {
                self.selection = None;
                ui.close_menu();
            }
        });
        copied
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn paint_selection(
        &self,
        painter: &egui::Painter,
        font: &egui::FontId,
        cell: egui::Vec2,
        grid: egui::Rect,
        line: usize,
        first: usize,
        top: usize,
        span: usize,
        view_cols: u16,
    ) {
        let Some(selection) = self.selection else {
            return;
        };
        let screen = self.parser.screen();
        for offset in 0..span {
            let row = line + offset;
            let mut range = selection.columns(row, screen.size().1);
            if range.is_empty() {
                continue;
            }
            let screen_row = (top + offset) as u16;
            if range.start > 0
                && screen
                    .cell(screen_row, range.start)
                    .is_some_and(vt100::Cell::is_wide_continuation)
            {
                range.start -= 1;
            }
            if screen
                .cell(screen_row, range.end - 1)
                .is_some_and(vt100::Cell::is_wide)
            {
                range.end = (range.end + 1).min(screen.size().1);
            }
            let visible = range.start.max(self.column)..range.end.min(self.column + view_cols);
            let position = |col| {
                grid.min
                    + egui::vec2(
                        f32::from(col - self.column) * cell.x,
                        (row - first) as f32 * cell.y,
                    )
            };
            for col in visible.clone() {
                painter.rect_filled(
                    egui::Rect::from_min_size(position(col), cell),
                    0.0,
                    theme::palette().selection,
                );
            }
            for col in visible {
                if let Some(content) = screen.cell(screen_row, col)
                    && !content.is_wide_continuation()
                {
                    painter.text(
                        position(col),
                        egui::Align2::LEFT_TOP,
                        content.contents(),
                        font.clone(),
                        theme::terminal_text(),
                    );
                }
            }
        }
    }
}
