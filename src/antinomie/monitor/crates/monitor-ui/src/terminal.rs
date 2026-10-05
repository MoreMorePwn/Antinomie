use crate::theme;
use eframe::egui::{self, Color32, Key, Sense, TextStyle};

pub struct Terminal {
    parser: vt100::Parser,
    size: (u16, u16),
}

impl Default for Terminal {
    fn default() -> Self {
        Self {
            parser: vt100::Parser::new(24, 80, 2000),
            size: (0, 0),
        }
    }
}

impl Terminal {
    #[cfg(test)]
    pub(crate) fn contents(&self) -> String {
        self.parser.screen().contents()
    }

    pub fn process(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    pub(crate) fn invalidate_resize(&mut self) {
        self.size = (0, 0);
    }

    pub(crate) fn replay_resize(&mut self, rows: u16, cols: u16) {
        self.parser.set_size(rows.clamp(1, 80), cols.clamp(1, 240));
        self.size = (0, 0);
    }

    pub(crate) fn replace_screen(&mut self, rows: u16, cols: u16, data: &[u8]) {
        let size = (rows.clamp(1, 80), cols.clamp(1, 240));
        self.parser = vt100::Parser::new(size.0, size.1, 2000);
        self.parser.process(data);
        self.size = size;
    }

    pub fn show(&mut self, ui: &mut egui::Ui, enabled: bool) -> (Vec<u8>, Option<(u16, u16)>) {
        self.show_grid(ui, enabled, true)
    }

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
        if available.x < cell.x || available.y < cell.y {
            return (Vec::new(), None);
        }
        let mut cols = (available.x / cell.x).floor().clamp(1.0, 240.0) as u16;
        let mut rows = (available.y / cell.y).floor().clamp(1.0, 80.0) as u16;
        if !resize_parser {
            let size = self.parser.screen().size();
            rows = size.0;
            cols = size.1;
        }
        let resize = if resize_parser && self.size != (rows, cols) {
            self.size = (rows, cols);
            self.parser.set_size(rows, cols);
            Some(self.size)
        } else {
            None
        };
        let (rect, response) = ui.allocate_exact_size(
            egui::vec2(f32::from(cols) * cell.x, f32::from(rows) * cell.y),
            Sense::click(),
        );
        if response.clicked() {
            response.request_focus();
        }
        if resize_parser && response.hovered() {
            let scroll = ui.input(|state| state.raw_scroll_delta.y);
            if scroll != 0.0 {
                let old = self.parser.screen().scrollback();
                let lines = (scroll.abs() / cell.y).ceil() as usize;
                self.parser.set_scrollback(if scroll > 0.0 {
                    old.saturating_add(lines)
                } else {
                    old.saturating_sub(lines)
                });
            }
        }
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, theme::TERMINAL);
        let screen = self.parser.screen();
        for row in 0..rows {
            for col in 0..cols {
                let Some(content) = screen.cell(row, col) else {
                    continue;
                };
                let pos = rect.min + egui::vec2(f32::from(col) * cell.x, f32::from(row) * cell.y);
                let bg = if content.inverse() {
                    color(content.fgcolor(), theme::TEXT)
                } else {
                    color(content.bgcolor(), theme::TERMINAL)
                };
                painter.rect_filled(egui::Rect::from_min_size(pos, cell), 0.0, bg);
            }
        }
        // Paint every background first so wide glyphs survive their continuation cell.
        for row in 0..rows {
            for col in 0..cols {
                let Some(content) = screen.cell(row, col) else {
                    continue;
                };
                let pos = rect.min + egui::vec2(f32::from(col) * cell.x, f32::from(row) * cell.y);
                let fg = if content.inverse() {
                    color(content.bgcolor(), theme::TERMINAL)
                } else {
                    color(content.fgcolor(), theme::TEXT)
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
        if enabled && response.has_focus() && !screen.hide_cursor() {
            let (row, col) = screen.cursor_position();
            let pos = rect.min + egui::vec2(f32::from(col) * cell.x, f32::from(row) * cell.y);
            painter.rect_stroke(
                egui::Rect::from_min_size(pos, cell),
                0.0,
                egui::Stroke::new(1.0_f32, Color32::WHITE),
                egui::StrokeKind::Inside,
            );
        }
        let mut input = Vec::new();
        let closing = ui.input(|state| state.viewport().close_requested());
        let queued_focus = closing && ui.memory(|memory| memory.has_focus(response.id));
        if enabled && (response.has_focus() || queued_focus) {
            ui.input(|state| {
                for event in &state.events {
                    // Viewport Close is untimestamped; focus-loss events delimit ordered input.
                    if closing && matches!(event, egui::Event::WindowFocused(false)) {
                        break;
                    }
                    match event {
                        egui::Event::Text(text) | egui::Event::Paste(text) => {
                            input.extend_from_slice(text.as_bytes())
                        }
                        egui::Event::Key {
                            key,
                            pressed: true,
                            modifiers,
                            ..
                        } => {
                            if modifiers.ctrl && *key >= Key::A && *key <= Key::Z {
                                input.push(*key as u8 - Key::A as u8 + 1);
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
            self.parser.set_scrollback(0);
        }
        (input, resize)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
                        egui::ScrollArea::both().show(ui, |ui| {
                            resize = terminal.show_grid(ui, false, false).1;
                        });
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
        assert_eq!(color(vt100::Color::Default, theme::TEXT), theme::TEXT);
        assert_eq!(
            color(vt100::Color::Rgb(1, 2, 3), theme::TEXT),
            Color32::from_rgb(1, 2, 3)
        );
        assert_eq!(
            color(vt100::Color::Idx(255), theme::TEXT),
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
            assert_eq!(size.1, (pane.x / cell.x).floor() as u16);
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
                    egui::Shape::Rect(rect) if rect.stroke.color == Color32::WHITE => {
                        Some(rect.rect)
                    }
                    _ => None,
                })
                .expect("focused terminal must render its cursor");
            assert!((cursor.width() - cell.x).abs() < 0.01);
            assert!((cursor.height() - cell.y).abs() < 0.01);
            assert!((cursor.left() - 2.0 * cell.x).abs() < 0.01);
            assert!((cursor.top() - cell.y).abs() < 0.01);
        }
    }
}
