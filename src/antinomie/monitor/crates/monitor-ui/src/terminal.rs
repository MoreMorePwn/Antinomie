use crate::theme;
use eframe::egui::{self, Color32, FontId, Key, Sense};

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
    pub fn process(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    pub(crate) fn invalidate_resize(&mut self) {
        self.size = (0, 0);
    }

    pub fn show(&mut self, ui: &mut egui::Ui, enabled: bool) -> (Vec<u8>, Option<(u16, u16)>) {
        let cell = egui::vec2(8.0, 17.0);
        let available = ui.available_size();
        let cols = (available.x / cell.x).floor().clamp(20.0, 240.0) as u16;
        let rows = (available.y / cell.y).floor().clamp(4.0, 80.0) as u16;
        let resize = if self.size != (rows, cols) {
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
        if response.hovered() {
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
                let mut fg = color(content.fgcolor(), theme::TEXT);
                let mut bg = color(content.bgcolor(), theme::TERMINAL);
                if content.inverse() {
                    std::mem::swap(&mut fg, &mut bg);
                }
                painter.rect_filled(egui::Rect::from_min_size(pos, cell), 0.0, bg);
                if !content.is_wide_continuation() {
                    painter.text(
                        pos,
                        egui::Align2::LEFT_TOP,
                        content.contents(),
                        FontId::monospace(13.0),
                        fg,
                    );
                }
                if content.underline() {
                    painter.line_segment(
                        [pos + egui::vec2(0.0, 15.0), pos + egui::vec2(8.0, 15.0)],
                        egui::Stroke::new(1.0_f32, fg),
                    );
                }
            }
        }
        if response.has_focus() && !screen.hide_cursor() {
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
        if enabled && response.has_focus() {
            ui.input(|state| {
                for event in &state.events {
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
}
