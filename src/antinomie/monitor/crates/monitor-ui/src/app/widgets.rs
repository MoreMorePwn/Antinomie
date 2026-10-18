// SPDX-License-Identifier: MIT
//! Small shared widgets and formatting helpers.
use super::*;

/// Compact byte size for catalog rows and download progress.
pub(super) fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub(super) fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// "just now", "5 min ago", "3 h ago", "2 d ago".
pub(super) fn relative_time(seconds: u64) -> String {
    match seconds {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", seconds / 60),
        3600..86400 => format!("{} h ago", seconds / 3600),
        _ => format!("{} d ago", seconds / 86400),
    }
}

/// The file name of a program path.
pub(super) fn program_name(path: &str) -> &str {
    path.rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(path)
}

pub(super) fn open_directory(directory: &std::path::Path) {
    crate::folders::show_detached(directory.to_owned());
}

/// One line of colored text pieces, cut with "…" at `width`.
fn line_galley(
    ui: &egui::Ui,
    pieces: &[(String, egui::Color32)],
    font: &egui::FontId,
    width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = egui::text::LayoutJob::default();
    for (text, color) in pieces {
        job.append(text, 0.0, egui::TextFormat::simple(font.clone(), *color));
    }
    job.wrap = egui::text::TextWrapping::truncate_at_width(width.max(1.0));
    ui.fonts(|fonts| fonts.layout_job(job))
}

pub(super) fn sidebar_row(ui: &mut egui::Ui, row: SidebarRow<'_>) -> egui::Response {
    let body = egui::TextStyle::Body.resolve(ui.style());
    let small = egui::TextStyle::Small.resolve(ui.style());
    let (body_height, small_height) =
        ui.fonts(|fonts| (fonts.row_height(&body), fonts.row_height(&small)));
    let padding = egui::vec2(8.0, 5.0);
    let gap = 2.0;
    let height = padding.y * 2.0 + body_height + row.details.len() as f32 * (small_height + gap);
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::click(),
    );
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let palette = theme::palette();
    if row.selected {
        ui.painter().rect_filled(rect, 4.0, palette.selection);
        ui.painter().rect_filled(
            egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height())),
            2.0,
            palette.accent,
        );
    } else if response.hovered() {
        ui.painter().rect_filled(rect, 4.0, palette.hover);
    }
    let left = rect.left() + padding.x;
    let right = rect.right() - padding.x;
    let top = rect.top() + padding.y;
    let mark = line_galley(
        ui,
        &[(row.mark.0.to_owned(), row.mark.1)],
        &body,
        f32::INFINITY,
    );
    let text_left = left + mark.size().x.max(body.size) + 6.0;
    ui.painter().galley(egui::pos2(left, top), mark, row.mark.1);
    let mut name_right = right;
    if let Some((word, color)) = row.state {
        let state = line_galley(ui, &[(word.to_owned(), color)], &small, f32::INFINITY);
        let position = egui::pos2(
            right - state.size().x,
            top + (body_height - small_height) * 0.5,
        );
        name_right = position.x - 8.0;
        ui.painter().galley(position, state, color);
    }
    let name = line_galley(
        ui,
        &[(row.name.to_owned(), theme::text())],
        &body,
        name_right - text_left,
    );
    ui.painter()
        .galley(egui::pos2(text_left, top), name, theme::text());
    let mut y = top + body_height + gap;
    for line in &row.details {
        let galley = line_galley(ui, line, &small, right - text_left);
        ui.painter()
            .galley(egui::pos2(text_left, y), galley, theme::muted());
        y += small_height + gap;
    }
    response
}

/// A sidebar section title: a fold arrow and the title in the heading color
/// (click to fold), a muted count, and a "+" action on the right; a
/// separator below. The "+" lights up while hovered, or while its menu is
/// `open`. Returns the "+" response.
pub(super) fn section_header(
    ui: &mut egui::Ui,
    header: SectionHeader<'_>,
    collapsed: &mut bool,
) -> egui::Response {
    let size = ui.spacing().interact_size.y;
    let response = ui
        .horizontal(|ui| {
            let title_width = (ui.available_width() - size - ui.spacing().item_spacing.x).max(0.0);
            let (rect, title) =
                ui.allocate_exact_size(egui::vec2(title_width, size), egui::Sense::click());
            if title.clicked() {
                *collapsed = !*collapsed;
            }
            if ui.is_rect_visible(rect) {
                let body = egui::TextStyle::Body.resolve(ui.style());
                let small = egui::TextStyle::Small.resolve(ui.style());
                let color = if title.hovered() {
                    theme::blue()
                } else {
                    theme::heading()
                };
                let caret = line_galley(
                    ui,
                    &[(
                        if *collapsed {
                            egui_phosphor::regular::CARET_RIGHT
                        } else {
                            egui_phosphor::regular::CARET_DOWN
                        }
                        .to_owned(),
                        color,
                    )],
                    &small,
                    f32::INFINITY,
                );
                let caret_width = small.size + 4.0;
                ui.painter().galley(
                    egui::pos2(rect.left(), rect.center().y - caret.size().y * 0.5),
                    caret,
                    color,
                );
                let count = line_galley(
                    ui,
                    &[(header.count.to_string(), theme::muted())],
                    &small,
                    f32::INFINITY,
                );
                let name = line_galley(
                    ui,
                    &[(header.title.to_owned(), color)],
                    &body,
                    rect.width() - caret_width - count.size().x - 8.0,
                );
                let name_left = rect.left() + caret_width;
                let name_right = name_left + name.size().x;
                ui.painter().galley(
                    egui::pos2(name_left, rect.center().y - name.size().y * 0.5),
                    name,
                    color,
                );
                ui.painter().galley(
                    egui::pos2(name_right + 8.0, rect.center().y - count.size().y * 0.5),
                    count,
                    theme::muted(),
                );
            }
            title.on_hover_text(header.tooltip);
            let sense = if header.enabled {
                egui::Sense::click()
            } else {
                egui::Sense::hover()
            };
            let (rect, response) = ui.allocate_exact_size(egui::vec2(size, size), sense);
            let lit = header.enabled && (response.hovered() || header.open);
            if ui.is_rect_visible(rect) {
                if lit {
                    ui.painter().rect_filled(rect, 4.0, theme::primary());
                }
                let color = match (header.enabled, lit) {
                    (false, _) => theme::muted().gamma_multiply(0.5),
                    (true, true) => theme::palette().primary_text,
                    (true, false) => theme::text(),
                };
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    egui_phosphor::regular::PLUS,
                    egui::FontId::proportional(ui.text_style_height(&egui::TextStyle::Body)),
                    color,
                );
            }
            if header.enabled {
                response.on_hover_text(header.action)
            } else {
                response.on_hover_text(format!("{} (stop the running VM first)", header.action))
            }
        })
        .inner;
    ui.separator();
    response
}

pub(super) fn tool_button(ui: &mut egui::Ui, button: ToolButton<'_>) -> bool {
    let font = egui::TextStyle::Button.resolve(ui.style());
    let (icon, label) = if button.enabled {
        (
            button.tone,
            if button.active || button.strong {
                button.tone
            } else {
                theme::text()
            },
        )
    } else {
        (theme::muted(), theme::muted())
    };
    let mut job = egui::text::LayoutJob::default();
    job.append(
        button.icon,
        0.0,
        egui::TextFormat::simple(font.clone(), icon),
    );
    job.append(button.label, 6.0, egui::TextFormat::simple(font, label));
    let mut widget = egui::Button::new(job).min_size(egui::vec2(0.0, ui.spacing().interact_size.y));
    if button.active {
        widget = widget
            .fill(button.tone.gamma_multiply(0.18))
            .stroke(egui::Stroke::new(1.0_f32, button.tone));
    }
    ui.add_enabled(button.enabled, widget)
        .on_hover_text(button.tooltip)
        .on_disabled_hover_text(button.tooltip)
        .clicked()
}

/// The main action of a dialog, in the primary color.
pub(super) fn primary_button<'a>(text: &str) -> egui::Button<'a> {
    egui::Button::new(RichText::new(text).color(theme::palette().primary_text))
        .fill(theme::primary())
}

/// A destructive confirmation, in the error color.
pub(super) fn danger_button<'a>(text: &str) -> egui::Button<'a> {
    egui::Button::new(RichText::new(text).color(theme::palette().primary_text)).fill(theme::error())
}

/// A secondary destructive action: error-colored text on a plain button.
pub(super) fn danger_text_button<'a>(text: &str) -> egui::Button<'a> {
    egui::Button::new(RichText::new(text).color(theme::error()))
}

/// A single-line text field with room around the text.
pub(super) fn text_field(text: &mut String) -> egui::TextEdit<'_> {
    egui::TextEdit::singleline(text).margin(theme::TEXT_EDIT_MARGIN)
}

/// A status bar figure inside a right-to-left row. The value is added first so
/// it sits to the right of its name: `TRL 0`.
pub(super) fn status_value_rtl(
    ui: &mut egui::Ui,
    name: &str,
    value: &str,
    color: egui::Color32,
) -> egui::Response {
    let value = ui.label(RichText::new(value).monospace().color(color));
    let name = ui.label(RichText::new(name).color(theme::muted()));
    value | name
}

/// A status bar message line: an icon and the text in `color`, cut to fit.
pub(super) fn status_line(ui: &mut egui::Ui, icon: &str, text: &str, color: egui::Color32) {
    if color == theme::error() {
        crate::activity::compact(ui, crate::activity::Level::Error, text);
        return;
    }
    if color == theme::warn() {
        crate::activity::compact(ui, crate::activity::Level::Warn, text);
        return;
    }
    ui.horizontal(|ui| {
        ui.colored_label(color, icon);
        ui.add(egui::Label::new(RichText::new(text).color(color)).truncate());
    })
    .response
    .on_hover_text(text);
}

pub(super) fn icon(ui: &mut egui::Ui, icon: &str, tooltip: &str, enabled: bool) -> bool {
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(icon).size(ui.text_style_height(&egui::TextStyle::Body)))
            .frame(false)
            .min_size(egui::vec2(
                ui.spacing().interact_size.y,
                ui.spacing().interact_size.y,
            )),
    )
    .on_hover_text(tooltip)
    .clicked()
}
