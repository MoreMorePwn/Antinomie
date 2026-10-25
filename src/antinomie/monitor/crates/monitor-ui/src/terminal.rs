use crate::theme;
use eframe::egui::{self, Color32, Key, Sense, TextStyle};
use std::time::{Duration, Instant};

mod selection;
use selection::Selection;

/// Output lines kept above the screen for scrolling back.
const SCROLLBACK: usize = 10_000;
/// The backend accepts PTY sizes of 1..=256 rows and columns.
const MAX_ROWS: u16 = 256;
const MAX_COLS: u16 = 256;
/// Room beside the grid for its scrollbar. It is always reserved, so the
/// guest's PTY does not change size when history first appears.
const BAR: f32 = 10.0;
const MIN_THUMB: f32 = 16.0;

pub struct Terminal {
    parser: vt100::Parser,
    size: (u16, u16),
    /// Lines between the newest output and the bottom of the view; 0 follows
    /// new output.
    offset: usize,
    /// Wheel movement short of a whole cell, carried to the next event.
    wheel: egui::Vec2,
    /// First column shown when a recorded screen is wider than its pane.
    column: u16,
    /// Last time the grid was drawn. A gap means the tab was hidden.
    last_show: Option<Instant>,
    selection: Option<Selection>,
}

impl Default for Terminal {
    fn default() -> Self {
        Self {
            parser: vt100::Parser::new(24, 80, SCROLLBACK),
            size: (0, 0),
            offset: 0,
            wheel: egui::Vec2::ZERO,
            column: 0,
            last_show: None,
            selection: None,
        }
    }
}

/// Where the focus edge is drawn in a pane of `rect`: one point inside it, so
/// all four sides show. A line on the pane's own border is clipped by the
/// panel or window around it on the sides that meet it, which left only the
/// right and bottom edges to be seen.
fn focus_edge(rect: egui::Rect) -> egui::Rect {
    rect.shrink(1.0)
}

impl Terminal {
    #[cfg(test)]
    pub(crate) fn contents(&self) -> String {
        self.parser.screen().contents()
    }

    #[cfg(test)]
    pub(crate) fn size(&self) -> (u16, u16) {
        self.parser.screen().size()
    }

    pub fn process(&mut self, bytes: &[u8]) {
        if self.selection.is_some() && !bytes.is_empty() {
            self.process_selected(bytes);
            return;
        }
        // While the view is scrolled back, vt100 moves its own offset along
        // with each line entering the history; follow it so the lines being
        // read stay in place.
        let anchored = self.offset > 0;
        if anchored {
            self.parser.screen_mut().set_scrollback(self.offset);
        }
        let before = self.parser.screen().scrollback();
        self.parser.process(bytes);
        if anchored {
            self.offset += self.parser.screen().scrollback().saturating_sub(before);
            self.parser.screen_mut().set_scrollback(0);
        }
    }

    pub(crate) fn invalidate_resize(&mut self) {
        self.size = (0, 0);
    }

    pub(crate) fn replay_resize(&mut self, rows: u16, cols: u16) {
        self.selection = None;
        self.parser
            .screen_mut()
            .set_size(rows.clamp(1, MAX_ROWS), cols.clamp(1, MAX_COLS));
        self.size = (0, 0);
    }

    pub(crate) fn replace_screen(&mut self, rows: u16, cols: u16, data: &[u8]) {
        self.selection = None;
        let size = (rows.clamp(1, MAX_ROWS), cols.clamp(1, MAX_COLS));
        // Redraw the screen in place instead of starting a new parser, so the
        // history above it survives PTY resizes and resyncs. Leave the
        // alternate screen, scroll region, origin mode, attributes and
        // screen contents behind first, as a new parser would.
        self.parser.screen_mut().set_size(size.0, size.1);
        self.parser
            .process(b"\x1b[?1049l\x1b[r\x1b[?6l\x1b[m\x1b[H\x1b[2J");
        self.parser.process(data);
        self.size = size;
    }

    /// Lines kept above the screen.
    fn history(&mut self) -> usize {
        let screen = self.parser.screen_mut();
        screen.set_scrollback(usize::MAX);
        let history = screen.scrollback();
        screen.set_scrollback(0);
        history
    }

    fn scroll(&mut self, lines: isize, max: usize) {
        self.offset = self.offset.saturating_add_signed(lines).min(max);
    }

    pub fn show(&mut self, ui: &mut egui::Ui, enabled: bool) -> (Vec<u8>, Option<(u16, u16)>) {
        self.show_grid(ui, enabled, true)
    }

    /// Draws the terminal into the space left in `ui`. A live terminal
    /// (`resize_parser`) fits its grid to that space and reports the new PTY
    /// size; a recorded one keeps its grid and shows as many lines of it and
    /// its history as fit.
    pub(crate) fn show_grid(
        &mut self,
        ui: &mut egui::Ui,
        enabled: bool,
        resize_parser: bool,
    ) -> (Vec<u8>, Option<(u16, u16)>) {
        let font = TextStyle::Monospace.resolve(ui.style());
        let cell =
            ui.fonts(|fonts| egui::vec2(fonts.glyph_width(&font, 'M'), fonts.row_height(&font)));
        let available = ui.available_size();
        let Some(fit) = fit_grid(available, cell) else {
            return (Vec::new(), None);
        };
        // Coming back to a hidden terminal paints the bytes already drained
        // into the parser. A PTY resize on that same frame would reflow or
        // clear the screen before those bytes are visible, so the size change
        // waits until the following shown frame.
        let returning = self
            .last_show
            .is_some_and(|shown| shown.elapsed() > Duration::from_millis(100));
        self.last_show = Some(Instant::now());
        let resize = if resize_parser && self.size != fit && !returning {
            self.selection = None;
            self.size = fit;
            self.parser.screen_mut().set_size(fit.0, fit.1);
            Some(fit)
        } else {
            None
        };
        let (rows, cols) = self.parser.screen().size();
        let (mut view_rows, view_cols) = if resize_parser {
            (rows, cols)
        } else {
            (fit.0, cols.min(fit.1))
        };
        let wide = cols > view_cols;
        if wide {
            view_rows = fit_grid(available - egui::vec2(0.0, BAR), cell)
                .map_or(1, |(rows, _)| rows)
                .max(1);
        }
        let grid = egui::vec2(f32::from(view_cols) * cell.x, f32::from(view_rows) * cell.y);
        let (rect, response) = ui.allocate_exact_size(available, Sense::click_and_drag());
        let grid = egui::Rect::from_min_size(rect.min, grid);
        ui.painter().rect_filled(rect, 0.0, theme::terminal());
        if response.clicked() || response.drag_started() {
            response.request_focus();
        }

        let history = self.history();
        let lines = history + usize::from(rows);
        let shown = usize::from(view_rows);
        let max_offset = lines.saturating_sub(shown);
        let page = shown.saturating_sub(1).max(1) as isize;
        let max_column = cols - view_cols;
        if ui.rect_contains_pointer(rect) {
            let delta = ui.input(|state| state.raw_scroll_delta);
            if delta != egui::Vec2::ZERO {
                self.wheel += egui::vec2(delta.x / cell.x, delta.y / cell.y);
                let lines = self.wheel.y.trunc();
                let columns = self.wheel.x.trunc();
                self.wheel -= egui::vec2(columns, lines);
                self.scroll(lines as isize, max_offset);
                self.column =
                    (f32::from(self.column) - columns).clamp(0.0, f32::from(max_column)) as u16;
            }
        }
        if response.has_focus() {
            ui.input(|state| {
                for event in &state.events {
                    if let egui::Event::Key {
                        key,
                        pressed: true,
                        modifiers,
                        ..
                    } = event
                    {
                        if modifiers.shift {
                            match key {
                                Key::PageUp => self.scroll(page, max_offset),
                                Key::PageDown => self.scroll(-page, max_offset),
                                Key::Home => self.offset = max_offset,
                                Key::End => self.offset = 0,
                                _ => {}
                            }
                        }
                    }
                }
            });
        }
        self.offset = self.offset.min(max_offset);
        self.column = self.column.min(max_column);
        let scrollbar_id = response.id.with("scrollbar");
        let track = egui::Rect::from_min_max(
            egui::pos2(rect.right() - BAR, grid.top()),
            egui::pos2(rect.right(), grid.bottom()),
        );
        let first = max_offset - self.offset;
        if let Some(first) = scrollbar(ui, track, scrollbar_id, true, lines, shown, first) {
            self.offset = max_offset - first.min(max_offset);
        }
        if wide {
            let track = egui::Rect::from_min_max(
                egui::pos2(grid.left(), grid.bottom()),
                egui::pos2(grid.right(), rect.bottom()),
            );
            let id = response.id.with("columns");
            let (cols, view, column) = (
                usize::from(cols),
                usize::from(view_cols),
                usize::from(self.column),
            );
            if let Some(column) = scrollbar(ui, track, id, false, cols, view, column) {
                self.column = column.min(usize::from(max_column)) as u16;
            }
        }

        let (first, count) = view_lines(lines, shown, self.offset);
        self.select(ui, &response, grid, cell, first, count, cols, history);
        let painter = ui.painter_at(grid);
        // The terminal occupies the entire pane, including fractional cells.
        // Keep an unobtrusive inset focus edge rather than a second card frame.
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
        let mut line = first;
        while line < first + count {
            // vt100 shows `rows` lines starting `scrollback` lines above the
            // screen; read the view through as many such windows as it needs.
            let (scrollback, top) = if line < history {
                (history - line, 0)
            } else {
                (0, line - history)
            };
            let span = (usize::from(rows) - top).min(first + count - line);
            self.parser.screen_mut().set_scrollback(scrollback);
            paint_rows(
                &painter,
                self.parser.screen(),
                &font,
                cell,
                grid.min + egui::vec2(0.0, (line - first) as f32 * cell.y),
                top as u16..(top + span) as u16,
                self.column..self.column + view_cols,
            );
            self.paint_selection(
                &painter, &font, cell, grid, line, first, top, span, view_cols,
            );
            line += span;
        }
        self.parser.screen_mut().set_scrollback(0);
        let screen = self.parser.screen();
        if enabled && response.has_focus() && !screen.hide_cursor() {
            let (row, col) = screen.cursor_position();
            let line = history + usize::from(row);
            if (first..first + count).contains(&line)
                && (self.column..self.column + view_cols).contains(&col)
            {
                let pos = grid.min
                    + egui::vec2(
                        f32::from(col - self.column) * cell.x,
                        (line - first) as f32 * cell.y,
                    );
                painter.rect_filled(egui::Rect::from_min_size(pos, cell), 0.0, cursor_color());
                if let Some(content) = screen.cell(row, col) {
                    painter.text(
                        pos,
                        egui::Align2::LEFT_TOP,
                        content.contents(),
                        font.clone(),
                        theme::terminal(),
                    );
                }
            }
        }
        if self.offset > 0 {
            let below = self.offset;
            let jump = ui
                .scope_builder(
                    egui::UiBuilder::new()
                        .max_rect(grid.shrink(6.0))
                        .layout(egui::Layout::right_to_left(egui::Align::Max)),
                    |ui| {
                        ui.add(
                            egui::Button::new(format!(
                                "{} {below} newer line{}",
                                egui_phosphor::regular::ARROW_LINE_DOWN,
                                if below == 1 { "" } else { "s" }
                            ))
                            .fill(theme::raised()),
                        )
                        .on_hover_text("Jump to the newest output (Shift+End)")
                    },
                )
                .inner;
            if jump.clicked() {
                self.offset = 0;
                response.request_focus();
            }
        }

        let mut input = Vec::new();
        let closing = ui.input(|state| state.viewport().close_requested());
        let queued_focus = closing && ui.memory(|memory| memory.has_focus(response.id));
        let mut copied = self.copy_actions(ui, &response, history, rows, cols);
        let screen = self.parser.screen();
        if enabled && (response.has_focus() || queued_focus) {
            ui.input(|state| {
                for event in &state.events {
                    // Viewport Close is untimestamped; focus-loss events delimit ordered input.
                    if closing && matches!(event, egui::Event::WindowFocused(false)) {
                        break;
                    }
                    match event {
                        egui::Event::Copy if !copied && !state.modifiers.shift => {
                            // egui-winit converts ordinary Ctrl+C into Copy.
                            // Without a selection it must still interrupt the PTY.
                            input.push(3);
                            copied = true;
                        }
                        egui::Event::Text(text) | egui::Event::Paste(text) => {
                            input.extend_from_slice(text.as_bytes())
                        }
                        egui::Event::Key {
                            key,
                            pressed: true,
                            modifiers,
                            ..
                        } => {
                            if modifiers.ctrl && modifiers.shift && matches!(key, Key::C | Key::V) {
                                // Clipboard commands are handled locally; never send ETX/SYN.
                            } else if copied && modifiers.ctrl && *key == Key::C {
                                // Do not also interrupt after copying a selection.
                            } else if modifiers.ctrl && *key >= Key::A && *key <= Key::Z {
                                input.push(*key as u8 - Key::A as u8 + 1);
                            } else if modifiers.shift
                                && matches!(key, Key::PageUp | Key::PageDown | Key::Home | Key::End)
                            {
                                // Scrolls the history above instead.
                            } else {
                                input.extend_from_slice(match key {
                                    Key::Enter => b"\r",
                                    Key::Backspace => b"\x7f",
                                    Key::Tab => b"\t",
                                    Key::Escape => b"\x1b",
                                    Key::ArrowUp => {
                                        if screen.application_cursor() {
                                            b"\x1bOA"
                                        } else {
                                            b"\x1b[A"
                                        }
                                    }
                                    Key::ArrowDown => {
                                        if screen.application_cursor() {
                                            b"\x1bOB"
                                        } else {
                                            b"\x1b[B"
                                        }
                                    }
                                    Key::ArrowRight => {
                                        if screen.application_cursor() {
                                            b"\x1bOC"
                                        } else {
                                            b"\x1b[C"
                                        }
                                    }
                                    Key::ArrowLeft => {
                                        if screen.application_cursor() {
                                            b"\x1bOD"
                                        } else {
                                            b"\x1b[D"
                                        }
                                    }
                                    Key::Home => b"\x1b[H",
                                    Key::End => b"\x1b[F",
                                    Key::Delete => b"\x1b[3~",
                                    Key::PageUp => b"\x1b[5~",
                                    Key::PageDown => b"\x1b[6~",
                                    _ => b"",
                                });
                            }
                        }
                        _ => {}
                    }
                }
            });
        }
        if !input.is_empty() {
            self.offset = 0;
            self.selection = None;
        }
        (input, resize)
    }
}

/// Rows and columns of whole cells that fit in `available` beside the
/// scrollbar, within the PTY limits.
fn fit_grid(available: egui::Vec2, cell: egui::Vec2) -> Option<(u16, u16)> {
    let width = available.x - BAR;
    if cell.x <= 0.0 || cell.y <= 0.0 || width < cell.x || available.y < cell.y {
        return None;
    }
    Some((
        (available.y / cell.y).floor().min(f32::from(MAX_ROWS)) as u16,
        (width / cell.x).floor().min(f32::from(MAX_COLS)) as u16,
    ))
}

/// The lines in view, as the first one (counted from the oldest kept line)
/// and how many follow: `shown` lines ending `offset` lines above the newest.
/// A buffer shorter than the view is shown from its top.
fn view_lines(lines: usize, shown: usize, offset: usize) -> (usize, usize) {
    let bottom = lines - offset.min(lines.saturating_sub(shown));
    let first = bottom.saturating_sub(shown);
    (first, shown.min(lines - first))
}

/// Paints screen `rows` and `cols` (as vt100 currently shows them) from `origin`.
fn paint_rows(
    painter: &egui::Painter,
    screen: &vt100::Screen,
    font: &egui::FontId,
    cell: egui::Vec2,
    origin: egui::Pos2,
    rows: std::ops::Range<u16>,
    cols: std::ops::Range<u16>,
) {
    let at = |row: u16, col: u16| {
        origin
            + egui::vec2(
                f32::from(col - cols.start) * cell.x,
                f32::from(row - rows.start) * cell.y,
            )
    };
    for row in rows.clone() {
        for col in cols.clone() {
            let Some(content) = screen.cell(row, col) else {
                continue;
            };
            let bg = if content.inverse() {
                color(content.fgcolor(), theme::terminal_text())
            } else {
                color(content.bgcolor(), theme::terminal())
            };
            painter.rect_filled(egui::Rect::from_min_size(at(row, col), cell), 0.0, bg);
        }
    }
    // Paint every background first so wide glyphs survive their continuation cell.
    for row in rows.clone() {
        for col in cols.clone() {
            let Some(content) = screen.cell(row, col) else {
                continue;
            };
            let pos = at(row, col);
            let fg = if content.inverse() {
                color(content.bgcolor(), theme::terminal())
            } else {
                color(content.fgcolor(), theme::terminal_text())
            };
            if !content.is_wide_continuation() {
                painter.text(
                    pos,
                    egui::Align2::LEFT_TOP,
                    content.contents(),
                    font.clone(),
                    fg,
                );
            }
            if content.underline() {
                painter.line_segment(
                    [
                        pos + egui::vec2(0.0, cell.y - 1.0),
                        pos + egui::vec2(cell.x, cell.y - 1.0),
                    ],
                    egui::Stroke::new(1.0_f32, fg),
                );
            }
        }
    }
}

/// A scrollbar on `track` over `total` units of which `shown` are in view
/// from `start`. Returns the start that pressing or dragging it asks for.
fn scrollbar(
    ui: &egui::Ui,
    track: egui::Rect,
    id: egui::Id,
    vertical: bool,
    total: usize,
    shown: usize,
    start: usize,
) -> Option<usize> {
    let span = total.saturating_sub(shown);
    if span == 0 {
        return None;
    }
    let response = ui.interact(track, id, Sense::click_and_drag());
    let along = |pos: egui::Pos2| if vertical { pos.y } else { pos.x };
    let length = if vertical {
        track.height()
    } else {
        track.width()
    };
    let thumb = (length * shown as f32 / total as f32).clamp(MIN_THUMB.min(length), length);
    let travel = length - thumb;
    let at = travel * start.min(span) as f32 / span as f32;
    let origin = along(track.min);
    let mut requested = None;
    let grab_id = id.with("grab");
    if response.is_pointer_button_down_on() {
        if let Some(pointer) = response.interact_pointer_pos() {
            let pointer = along(pointer) - origin;
            // Where the thumb was taken stays under the pointer while dragging.
            let grab = ui.data_mut(|data| {
                *data.get_temp_mut_or_insert_with(grab_id, || {
                    if (at..=at + thumb).contains(&pointer) {
                        pointer - at
                    } else {
                        thumb / 2.0
                    }
                })
            });
            if travel > 0.0 {
                let fraction = ((pointer - grab) / travel).clamp(0.0, 1.0);
                requested = Some((fraction * span as f32).round() as usize);
            }
        }
    } else {
        ui.data_mut(|data| data.remove::<f32>(grab_id));
    }
    let start = requested.map_or(at, |start| travel * start as f32 / span as f32);
    let thumb = if vertical {
        egui::Rect::from_min_size(
            egui::pos2(track.left() + 2.0, origin + start),
            egui::vec2(track.width() - 4.0, thumb),
        )
    } else {
        egui::Rect::from_min_size(
            egui::pos2(origin + start, track.top() + 2.0),
            egui::vec2(thumb, track.height() - 4.0),
        )
    };
    let fill = if response.hovered() || response.is_pointer_button_down_on() {
        theme::muted()
    } else {
        theme::line()
    };
    ui.painter().rect_filled(thumb, 3.0, fill);
    requested
}

fn color(value: vt100::Color, default: Color32) -> Color32 {
    match value {
        vt100::Color::Default => default,
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
        vt100::Color::Idx(index) => {
            const ANSI: [[u8; 3]; 16] = [
                [0, 0, 0],
                [205, 49, 49],
                [13, 188, 121],
                [229, 229, 16],
                [36, 114, 200],
                [188, 63, 188],
                [17, 168, 205],
                [229, 229, 229],
                [102, 102, 102],
                [241, 76, 76],
                [35, 209, 139],
                [245, 245, 67],
                [59, 142, 234],
                [214, 112, 214],
                [41, 184, 219],
                [255, 255, 255],
            ];
            let rgb = if index < 16 {
                ANSI[usize::from(index)]
            } else if index < 232 {
                let n = index - 16;
                let level = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
                [level(n / 36), level((n / 6) % 6), level(n % 6)]
            } else {
                let v = 8 + (index - 232) * 10;
                [v, v, v]
            };
            Color32::from_rgb(rgb[0], rgb[1], rgb[2])
        }
    }
}

/// The cursor's outline: the terminal's own text color, so it reads on the
/// dark terminal and on the Light theme's near-white one.
fn cursor_color() -> Color32 {
    theme::terminal_text()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cursor_reads_on_the_terminal_in_every_theme() {
        let luminance = |color: Color32| {
            let linear = |channel: u8| {
                let c = f32::from(channel) / 255.0;
                if c <= 0.03928 {
                    c / 12.92
                } else {
                    ((c + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * linear(color.r()) + 0.7152 * linear(color.g()) + 0.0722 * linear(color.b())
        };
        for theme in theme::Theme::ALL {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::apply_theme(&ctx, theme);
            let (a, b) = (luminance(cursor_color()), luminance(theme::terminal()));
            let ratio = (a.max(b) + 0.05) / (a.min(b) + 0.05);
            assert!(ratio >= 7.0, "{theme:?}: cursor contrast {ratio}");
        }
    }

    #[test]
    fn historical_grid_survives_small_viewports_and_large_fonts() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        theme::text_size(&ctx, 24.0);
        let mut terminal = Terminal::default();
        terminal.replay_resize(4, 12);
        terminal.process(b"123456789012X");
        let original = terminal.contents();
        for pane in [egui::vec2(160.0, 80.0), egui::vec2(800.0, 600.0)] {
            let mut resize = None;
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, pane)),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        resize = terminal.show_grid(ui, false, false).1;
                    });
                },
            );
            assert!(resize.is_none());
            assert_eq!(terminal.parser.screen().size(), (4, 12));
            assert_eq!(terminal.contents(), original);
        }
        terminal.process(b"Y");
        assert!(terminal.contents().contains("XY"));
    }

    #[test]
    fn return_frame_paints_output_accumulated_while_hidden() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut terminal = Terminal::default();
        let pane = egui::vec2(800.0, 600.0);
        let (_, _, resize) = frame(&ctx, &mut terminal, pane, Vec::new(), true);
        assert!(resize.is_some());
        let size = terminal.parser.screen().size();
        terminal.process(b"while-hidden");
        terminal.last_show = Some(Instant::now() - Duration::from_secs(2));
        let mut result = (Vec::new(), None);
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 700.0),
                )),
                events: vec![egui::Event::Text("typed-unfocused".into())],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE)
                    .show(ctx, |ui| {
                        result = terminal.show_grid(ui, false, true);
                    });
            },
        );
        let (input, resize) = result;
        assert!(resize.is_none(), "return must not resize before painting");
        assert_eq!(terminal.parser.screen().size(), size);
        assert!(input.is_empty(), "hidden return does not take input");
        assert!(
            rendered(&output)
                .iter()
                .any(|row| row.contains("while-hidden")),
            "{:?}",
            rendered(&output)
        );
        let (_, input, resize) = frame(
            &ctx,
            &mut terminal,
            egui::vec2(900.0, 700.0),
            vec![egui::Event::Text("k".into())],
            true,
        );
        assert!(resize.is_some(), "the following frame applies the new pane");
        assert_eq!(input, b"k");
    }

    #[test]
    fn vt100_parser_keeps_terminal_state_and_ansi_colors() {
        let mut terminal = Terminal::default();
        terminal.process(b"hello\r\n\x1b[31mred\x1b[0m");
        assert!(terminal.parser.screen().contents().contains("hello\nred"));
        assert_eq!(
            terminal.parser.screen().cell(1, 0).unwrap().fgcolor(),
            vt100::Color::Idx(1)
        );
        terminal.invalidate_resize();
        assert_eq!(terminal.size, (0, 0));
        assert!(terminal.parser.screen().contents().contains("red"));
    }

    #[test]
    fn terminal_defaults_use_native_theme_without_overriding_explicit_color() {
        assert_eq!(color(vt100::Color::Default, theme::text()), theme::text());
        assert_eq!(
            color(vt100::Color::Rgb(1, 2, 3), theme::text()),
            Color32::from_rgb(1, 2, 3)
        );
        assert_eq!(
            color(vt100::Color::Idx(255), theme::text()),
            Color32::from_rgb(238, 238, 238)
        );
    }

    #[test]
    fn terminal_grid_fits_its_pane_and_tracks_the_shared_font() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut terminal = Terminal::default();
        terminal.process(b"\x1b[4mAB\x1b[0m\r\nCD");
        let mut previous_size: Option<(u16, u16)> = None;
        for (font_size, pane) in [
            (16.0, egui::vec2(540.0, 150.0)),
            (20.0, egui::vec2(540.0, 150.0)),
            (16.0, egui::vec2(540.0, 64.0)),
        ] {
            ctx.style_mut(|style| {
                style
                    .text_styles
                    .insert(TextStyle::Monospace, egui::FontId::monospace(font_size));
            });
            let mut resize = None;
            let mut cell = egui::Vec2::ZERO;
            let mut allocation = egui::Rect::NOTHING;
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, pane)),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default()
                        .frame(egui::Frame::NONE)
                        .show(ctx, |ui| {
                            let font = TextStyle::Monospace.resolve(ui.style());
                            cell = ui.fonts(|fonts| {
                                egui::vec2(fonts.glyph_width(&font, 'M'), fonts.row_height(&font))
                            });
                            let focus = ui.next_auto_id();
                            ui.memory_mut(|memory| memory.request_focus(focus));
                            resize = terminal.show(ui, true).1;
                            allocation = ui.min_rect();
                        });
                },
            );
            let size = resize.expect("changing font or pane must resize the terminal");
            assert_eq!(terminal.parser.screen().size(), size);
            assert_eq!(size.0, (pane.y / cell.y).floor() as u16);
            assert_eq!(size.1, ((pane.x - BAR) / cell.x).floor() as u16);
            assert!(allocation.right() <= pane.x && allocation.bottom() <= pane.y);
            if font_size == 20.0 {
                let previous = previous_size.unwrap();
                assert!(size.0 < previous.0 && size.1 < previous.1);
            }
            previous_size = Some(size);
            let glyphs: Vec<_> = output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::Shape::Text(text)
                        if ["A", "B", "C", "D"].contains(&text.galley.text()) =>
                    {
                        Some(text)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(glyphs.len(), 4);
            assert!(
                glyphs[0].visual_bounding_rect().right() <= glyphs[1].visual_bounding_rect().left()
            );
            assert!(
                glyphs[0].visual_bounding_rect().bottom() <= glyphs[2].visual_bounding_rect().top()
            );
            assert!(glyphs
                .iter()
                .all(|text| text.galley.job.sections[0].format.font_id.size == font_size));
            let underline = output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::Shape::LineSegment { points, .. } => Some(points),
                    _ => None,
                })
                .expect("underlined terminal content must render an underline");
            assert!((underline[1].x - underline[0].x - cell.x).abs() < 0.01);
            assert!((underline[0].y - glyphs[0].pos.y - cell.y + 1.0).abs() < 0.01);
            let cursor = output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::Shape::Rect(rect) if rect.fill == cursor_color() => Some(rect.rect),
                    _ => None,
                })
                .expect("focused terminal must render its cursor");
            assert!((cursor.width() - cell.x).abs() < 0.01);
            assert!((cursor.height() - cell.y).abs() < 0.01);
            assert!((cursor.left() - 2.0 * cell.x).abs() < 0.01);
            assert!((cursor.top() - cell.y).abs() < 0.01);
        }
    }

    #[test]
    fn the_focus_edge_is_drawn_inside_the_pane_so_all_four_sides_show() {
        let pane = egui::vec2(480.0, 300.0);
        let accent = crate::theme::palette().accent;
        let edge_of = |live: bool, color: egui::Color32| {
            // A context of its own each time: focus is kept in it.
            let ctx = egui::Context::default();
            crate::theme::install(&ctx);
            let mut terminal = Terminal::default();
            terminal.process(b"prompt$ ");
            let (output, ..) = frame(&ctx, &mut terminal, pane, Vec::new(), live);
            output.shapes.iter().find_map(|shape| match &shape.shape {
                egui::Shape::Rect(rect)
                    if rect.stroke.color == color && rect.stroke.width > 0.0 =>
                {
                    Some(rect.rect)
                }
                _ => None,
            })
        };
        let whole = egui::Rect::from_min_size(egui::Pos2::ZERO, pane);
        let focused = edge_of(true, accent).expect("a focused terminal draws its edge");
        // A point in from every side of the pane: a line on the pane's own
        // border is hidden by what surrounds it, on the left and top as well
        // as on the right and bottom.
        assert!(
            focused.left() >= whole.left() + 1.0
                && focused.top() >= whole.top() + 1.0
                && focused.right() <= whole.right() - 1.0
                && focused.bottom() <= whole.bottom() - 1.0,
            "{focused:?} in {whole:?}"
        );
        assert_eq!(focused, super::focus_edge(whole));
        // An unfocused one keeps the same place, in the line colour.
        let quiet = edge_of(false, crate::theme::line()).expect("the quiet edge");
        assert_eq!(quiet, focused);
    }

    /// Runs one frame of a terminal filling `pane`, live or recorded.
    fn frame(
        ctx: &egui::Context,
        terminal: &mut Terminal,
        pane: egui::Vec2,
        events: Vec<egui::Event>,
        live: bool,
    ) -> (egui::FullOutput, Vec<u8>, Option<(u16, u16)>) {
        let mut result = (Vec::new(), None);
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, pane)),
                events,
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE)
                    .show(ctx, |ui| {
                        if live {
                            let focus = ui.next_auto_id();
                            ui.memory_mut(|memory| memory.request_focus(focus));
                        }
                        result = terminal.show_grid(ui, live, live);
                    });
            },
        );
        (output, result.0, result.1)
    }

    /// The painted terminal cells, one string per row from the top.
    fn rendered(output: &egui::FullOutput) -> Vec<String> {
        let mut glyphs: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text)
                    if text.galley.text().chars().count() == 1
                        && !text.galley.text().trim().is_empty() =>
                {
                    Some((text.pos.y, text.pos.x, text.galley.text().to_owned()))
                }
                _ => None,
            })
            .collect();
        glyphs.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.total_cmp(&b.1)));
        let mut rows: Vec<(f32, String)> = Vec::new();
        for (y, _, text) in glyphs {
            match rows.last_mut() {
                Some((row, line)) if (*row - y).abs() < 0.5 => line.push_str(&text),
                _ => rows.push((y, text)),
            }
        }
        rows.into_iter().map(|(_, line)| line).collect()
    }

    fn wheel(lines: f32, at: egui::Pos2) -> Vec<egui::Event> {
        vec![
            egui::Event::PointerMoved(at),
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, lines),
                modifiers: egui::Modifiers::NONE,
            },
        ]
    }

    fn key(key: Key, modifiers: egui::Modifiers) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers,
        }
    }

    #[test]
    fn grid_follows_the_window_up_to_the_pty_limit() {
        let cell = egui::vec2(8.0, 16.0);
        assert_eq!(
            fit_grid(egui::vec2(640.0 + BAR, 384.0), cell),
            Some((24, 80))
        );
        // A maximized window gets a larger PTY instead of a pinned 80x24.
        assert_eq!(
            fit_grid(egui::vec2(1916.0 + BAR, 1046.0), cell),
            Some((65, 239))
        );
        assert_eq!(
            fit_grid(egui::vec2(4000.0, 8000.0), cell),
            Some((MAX_ROWS, MAX_COLS))
        );
        assert_eq!(fit_grid(egui::vec2(BAR + 7.0, 400.0), cell), None);
        assert_eq!(fit_grid(egui::vec2(400.0, 15.0), cell), None);
    }

    #[test]
    fn view_lines_follow_output_and_stop_at_the_oldest_line() {
        // 100 history lines above a 24-row screen.
        assert_eq!(view_lines(124, 24, 0), (100, 24));
        assert_eq!(view_lines(124, 24, 30), (70, 24));
        assert_eq!(view_lines(124, 24, 100), (0, 24));
        assert_eq!(view_lines(124, 24, 5000), (0, 24));
        // A recorded screen in a taller pane shows its history above it.
        assert_eq!(view_lines(124, 60, 0), (64, 60));
        // Fewer lines than the view are shown from the top.
        assert_eq!(view_lines(10, 24, 3), (0, 10));
    }

    #[test]
    fn wheel_scrolls_history_and_new_output_keeps_the_view() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let pane = egui::vec2(600.0, 240.0);
        let mut terminal = Terminal::default();
        let (_, _, size) = frame(&ctx, &mut terminal, pane, Vec::new(), true);
        let (rows, _) = size.expect("first frame sizes the PTY");
        for line in 0..200 {
            terminal.process(format!("line {line}\r\n").as_bytes());
        }
        assert_eq!(terminal.history(), 201 - usize::from(rows));
        let (output, _, _) = frame(&ctx, &mut terminal, pane, Vec::new(), true);
        assert_eq!(rendered(&output).last().unwrap(), "line199");

        let (output, _, _) = frame(
            &ctx,
            &mut terminal,
            pane,
            wheel(400.0, (pane / 2.0).to_pos2()),
            true,
        );
        let scrolled = terminal.offset;
        assert!(scrolled > 0);
        let view = rendered(&output);
        assert_eq!(view.len(), usize::from(rows));
        assert_eq!(view.last().unwrap(), &format!("line{}", 200 - scrolled));
        // A scrollbar thumb and a way back to the newest output appear.
        assert!(output.shapes.iter().any(|shape| matches!(
            &shape.shape,
            egui::Shape::Rect(rect) if rect.fill == theme::line() || rect.fill == theme::muted()
        )));
        assert!(output.shapes.iter().any(|shape| matches!(
            &shape.shape,
            egui::Shape::Text(text) if text.galley.text().ends_with(&format!("{scrolled} newer lines"))
        )));

        // New output while scrolled back leaves the same lines in view.
        let top = view[0].clone();
        terminal.process(b"line 200\r\nline 201\r\n");
        let (output, _, _) = frame(&ctx, &mut terminal, pane, Vec::new(), true);
        assert_eq!(terminal.offset, scrolled + 2);
        assert_eq!(rendered(&output)[0], top);

        // The wheel cannot go past the oldest line.
        let (output, _, _) = frame(
            &ctx,
            &mut terminal,
            pane,
            wheel(1e6, (pane / 2.0).to_pos2()),
            true,
        );
        assert_eq!(rendered(&output)[0], "line0");
        let history = terminal.history();
        assert_eq!(terminal.offset, history);

        // Shift+End returns to the newest output without reaching the guest.
        let (_, input, _) = frame(
            &ctx,
            &mut terminal,
            pane,
            vec![key(Key::End, egui::Modifiers::SHIFT)],
            true,
        );
        assert!(input.is_empty());
        assert_eq!(terminal.offset, 0);
        let (_, input, _) = frame(
            &ctx,
            &mut terminal,
            pane,
            vec![key(Key::PageUp, egui::Modifiers::SHIFT)],
            true,
        );
        assert!(input.is_empty());
        assert_eq!(terminal.offset, usize::from(rows) - 1);

        // Typing still reaches the guest and follows the output again.
        let (output, input, _) = frame(
            &ctx,
            &mut terminal,
            pane,
            vec![
                egui::Event::Text("ls".into()),
                key(Key::Enter, egui::Modifiers::NONE),
                key(Key::PageUp, egui::Modifiers::NONE),
            ],
            true,
        );
        assert_eq!(input, b"ls\r\x1b[5~");
        assert_eq!(terminal.offset, 0);
        assert_eq!(terminal.contents().lines().last().unwrap(), "line 201");
        drop(output);
    }

    #[test]
    fn resizing_the_pty_keeps_history() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut terminal = Terminal::default();
        for line in 0..100 {
            terminal.process(format!("old {line}\r\n").as_bytes());
        }
        let history = terminal.history();
        assert_eq!(history, 101 - 24);
        // The backend answers a resize with its own screen state.
        let mut backend = vt100::Parser::new(40, 120, 0);
        backend.process(b"\x1b[?1049h\x1b[2;3r\x1b[?6hredrawn prompt $ ");
        let mut redrawn = vt100::Parser::new(40, 120, 0);
        redrawn.process(b"redrawn prompt $ ");
        terminal.replace_screen(40, 120, &redrawn.screen().state_formatted());
        assert_eq!(terminal.parser.screen().size(), (40, 120));
        assert_eq!(terminal.history(), history);
        assert_eq!(terminal.contents(), "redrawn prompt $ ");
        assert_eq!(terminal.parser.screen().cursor_position(), (0, 17));
        terminal.process(b"x\r\n");
        assert_eq!(terminal.contents(), "redrawn prompt $ x");
        // A resync while the old parser was in the alternate screen still
        // lands on the normal screen with its history.
        terminal.process(b"\x1b[?1049h\x1b[5;10r\x1b[?6h");
        terminal.replace_screen(40, 120, &backend.screen().state_formatted());
        assert!(!terminal.parser.screen().alternate_screen());
        assert_eq!(terminal.history(), history);
        assert_eq!(terminal.contents(), backend.screen().contents());
        assert_eq!(
            terminal.parser.screen().cursor_position(),
            backend.screen().cursor_position()
        );
        // Oversized PTYs are limited to what the backend accepts.
        terminal.replace_screen(900, 900, b"");
        assert_eq!(terminal.parser.screen().size(), (MAX_ROWS, MAX_COLS));
    }

    #[test]
    fn scrollbar_reaches_bounded_history_and_returns_to_latest_output() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut terminal = Terminal::default();
        let pane = egui::vec2(600.0, 240.0);
        frame(&ctx, &mut terminal, pane, Vec::new(), true);
        for line in 0..12_000 {
            terminal.process(format!("line {line}\r\n").as_bytes());
        }
        assert_eq!(terminal.history(), SCROLLBACK);
        // Establish the new scrollbar's hit area before pressing it.
        frame(&ctx, &mut terminal, pane, Vec::new(), true);
        let font = TextStyle::Monospace.resolve(&ctx.style());
        let cell =
            ctx.fonts(|fonts| egui::vec2(fonts.glyph_width(&font, 'M'), fonts.row_height(&font)));
        let (rows, cols) = terminal.size();
        let track_x = f32::from(cols) * cell.x + BAR / 2.0;
        let top = egui::pos2(track_x, 1.0);
        let bottom = egui::pos2(track_x, f32::from(rows) * cell.y - 1.0);
        let press = |at| {
            vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ]
        };
        let (output, _, _) = frame(&ctx, &mut terminal, pane, press(top), true);
        assert_eq!(terminal.offset, SCROLLBACK);
        let oldest = rendered(&output)[0].clone();
        assert_ne!(oldest, "line0");
        // Eviction while reading the oldest retained line advances the view
        // rather than allocating an unbounded history.
        terminal.process(b"line 12000\r\n");
        let (output, _, _) = frame(&ctx, &mut terminal, pane, Vec::new(), true);
        assert_eq!(terminal.history(), SCROLLBACK);
        assert_ne!(rendered(&output)[0], oldest);
        // Dragging the same scrollbar back down follows new output again.
        frame(
            &ctx,
            &mut terminal,
            pane,
            vec![egui::Event::PointerMoved(bottom)],
            true,
        );
        assert_eq!(terminal.offset, 0);
        terminal.process(b"latest output");
        let (output, _, _) = frame(&ctx, &mut terminal, pane, Vec::new(), true);
        assert_eq!(rendered(&output).last().unwrap(), "latestoutput");
    }

    #[test]
    fn recorded_terminal_fills_a_maximized_window_with_its_history() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut terminal = Terminal::default();
        terminal.replay_resize(4, 30);
        for line in 0..20 {
            terminal.process(format!("out {line}\r\n").as_bytes());
        }
        terminal.process(b"done");
        let small = frame(
            &ctx,
            &mut terminal,
            egui::vec2(400.0, 80.0),
            Vec::new(),
            false,
        );
        let tall = frame(
            &ctx,
            &mut terminal,
            egui::vec2(400.0, 800.0),
            Vec::new(),
            false,
        );
        assert!(small.2.is_none() && tall.2.is_none());
        assert_eq!(terminal.parser.screen().size(), (4, 30));
        let small = rendered(&small.0);
        let tall = rendered(&tall.0);
        assert_eq!(small.last().unwrap(), "done");
        assert_eq!(tall.last().unwrap(), "done");
        assert!(tall.len() > small.len());
        assert_eq!(tall[0], "out0");
        assert_eq!(tall.len(), 21);

        // A recorded screen wider than its pane pans sideways.
        let mut wide = Terminal::default();
        wide.replay_resize(3, 200);
        wide.process(format!("{}END", "-".repeat(197)).as_bytes());
        let pane = egui::vec2(300.0, 200.0);
        let (output, _, _) = frame(&ctx, &mut wide, pane, Vec::new(), false);
        assert!(!rendered(&output).concat().contains("END"));
        let (output, _, _) = frame(
            &ctx,
            &mut wide,
            pane,
            vec![
                egui::Event::PointerMoved(pane.to_pos2() / 2.0),
                egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    delta: egui::vec2(-1e5, 0.0),
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            false,
        );
        assert!(wide.column > 0);
        assert!(rendered(&output).concat().ends_with("END"));
    }
}
