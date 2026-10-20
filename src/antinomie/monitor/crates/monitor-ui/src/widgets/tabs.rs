// SPDX-License-Identifier: MIT
//! In-page tab strips (thin-bordered) and the segmented control. Dock tabs
//! (egui_dock) are separate and keep their own look.
use super::Tone;
use crate::theme;
use eframe::egui::{
    self, vec2, Response, RichText, Sense, Stroke, TextStyle, WidgetInfo, WidgetType,
};

/// What one tab shows besides being selectable.
#[derive(Clone, Debug)]
pub struct TabItem {
    pub label: String,
    /// A glyph before the label (a phosphor icon), drawn in the tone's color.
    pub icon: Option<(String, Tone)>,
    /// A count or word in a small pill after the label.
    pub badge: Option<(String, Tone)>,
    /// Shown on hover; for a disabled tab, why it is disabled.
    pub tooltip: Option<String>,
    /// A disabled tab is drawn in the hint color and takes no clicks.
    pub enabled: bool,
    /// A dimmed tab is drawn in the hint color but still opens: its view
    /// explains why it is empty.
    pub dim: bool,
}

impl TabItem {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            icon: None,
            badge: None,
            tooltip: None,
            enabled: true,
            dim: false,
        }
    }
    pub fn icon(mut self, glyph: impl Into<String>, tone: Tone) -> Self {
        self.icon = Some((glyph.into(), tone));
        self
    }
    pub fn badge(mut self, text: impl Into<String>, tone: Tone) -> Self {
        self.badge = Some((text.into(), tone));
        self
    }
    pub fn tooltip(mut self, text: impl Into<String>) -> Self {
        self.tooltip = Some(text.into());
        self
    }
    /// Dim the tab (still clickable); `why` is its tooltip.
    pub fn dimmed(mut self, why: impl Into<String>) -> Self {
        self.dim = true;
        self.tooltip = Some(why.into());
        self
    }
    /// Disable the tab; `why` is its tooltip.
    pub fn disabled(mut self, why: impl Into<String>) -> Self {
        self.enabled = false;
        self.tooltip = Some(why.into());
        self
    }
}

impl From<&str> for TabItem {
    fn from(label: &str) -> Self {
        TabItem::new(label)
    }
}

/// A strip of tabs: `items` are (value, tab); clicking one sets `selected`.
/// Returns whether the selection changed.
pub fn tabs<T: Copy + PartialEq>(
    ui: &mut egui::Ui,
    items: impl IntoIterator<Item = (T, TabItem)>,
    selected: &mut T,
) -> bool {
    let mut changed = false;
    tab_row(ui, |ui| {
        for (value, item) in items {
            if tab(ui, *selected == value, &item).clicked() && *selected != value {
                *selected = value;
                changed = true;
            }
        }
    });
    changed
}

/// The strip around `tab` calls: wraps when narrow and draws one thin line
/// under the last row (the selected tab's accent underline sits on it).
pub fn tab_row(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    let width = ui.available_width();
    let rule = ui.painter().add(egui::Shape::Noop);
    let out = ui.scope(|ui| {
        ui.spacing_mut().item_spacing = vec2(3.0, 3.0);
        ui.horizontal_wrapped(add);
    });
    let rect = out.response.rect;
    let y = rect.bottom() - 0.5;
    ui.painter().set(
        rule,
        egui::Shape::hline(
            rect.left()..=rect.left() + width,
            y,
            Stroke::new(1.0_f32, theme::line_soft()),
        ),
    );
    ui.add_space(6.0);
}

/// One thin-bordered tab: a 1 px outline, the selected one on the deepest
/// surface with the line color and a 2 px accent underline.
pub fn tab(ui: &mut egui::Ui, selected: bool, item: &TabItem) -> Response {
    let palette = theme::palette();
    let font = TextStyle::Button.resolve(ui.style());
    let small = TextStyle::Small.resolve(ui.style());
    let color = if !item.enabled {
        palette.hint
    } else if selected {
        palette.text
    } else if item.dim {
        palette.hint
    } else {
        palette.muted
    };
    let icon = item.icon.as_ref().map(|(glyph, tone)| {
        let color = if item.enabled {
            tone.fg()
        } else {
            palette.hint
        };
        ui.painter()
            .layout_no_wrap(glyph.clone(), font.clone(), color)
    });
    let badge = item.badge.as_ref().map(|(text, tone)| {
        let galley = ui
            .painter()
            .layout_no_wrap(text.clone(), small.clone(), tone.fg());
        (galley, tone.bg())
    });
    let pad = 10.0;
    let gap = 6.0;
    let badge_pad = 5.0;
    let mut extra = pad * 2.0;
    if let Some(galley) = &icon {
        extra += galley.size().x + 5.0;
    }
    if let Some((galley, _)) = &badge {
        extra += gap + galley.size().x + badge_pad * 2.0;
    }
    // A tab never grows past the row: the label is cut with an ellipsis.
    let room = (ui.max_rect().width() - extra).max(24.0);
    let label = {
        let mut job = egui::text::LayoutJob::simple_singleline(item.label.clone(), font, color);
        job.wrap = egui::text::TextWrapping {
            max_width: room,
            max_rows: 1,
            break_anywhere: true,
            overflow_character: Some('…'),
        };
        ui.fonts(|fonts| fonts.layout_job(job))
    };
    let width = extra + label.size().x;
    let height = ui.spacing().interact_size.y.max(26.0) + 2.0;
    let sense = if item.enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, mut response) = ui.allocate_exact_size(vec2(width, height), sense);
    response.widget_info(|| {
        WidgetInfo::selected(
            WidgetType::SelectableLabel,
            item.enabled,
            selected,
            &item.label,
        )
    });
    if let Some(text) = &item.tooltip {
        response = response.on_hover_text(text);
    }
    if ui.is_rect_visible(rect) {
        let hovered = response.hovered() && item.enabled;
        let painter = ui.painter();
        let radius = egui::CornerRadius {
            nw: 4,
            ne: 4,
            sw: 0,
            se: 0,
        };
        let fill = if selected {
            palette.bg
        } else if hovered {
            palette.hover
        } else {
            egui::Color32::TRANSPARENT
        };
        let line = if selected {
            palette.line
        } else {
            palette.line_soft
        };
        painter.rect(
            rect,
            radius,
            fill,
            Stroke::new(1.0_f32, line),
            egui::StrokeKind::Inside,
        );
        if selected {
            let bar = egui::Rect::from_min_max(
                egui::pos2(rect.left() + 1.0, rect.bottom() - 2.0),
                egui::pos2(rect.right() - 1.0, rect.bottom()),
            );
            painter.rect_filled(bar, 0.0, palette.accent);
        }
        let mut left = rect.left() + pad;
        if let Some(galley) = icon {
            let pos = egui::pos2(left, rect.center().y - galley.size().y / 2.0);
            left += galley.size().x + 5.0;
            painter.galley(pos, galley, egui::Color32::PLACEHOLDER);
        }
        let text_pos = egui::pos2(left, rect.center().y - label.size().y / 2.0);
        painter.galley(text_pos, label, color);
        if let Some((galley, badge_bg)) = badge {
            let size = galley.size() + vec2(badge_pad * 2.0, 2.0);
            let left = rect.right() - pad - size.x + 0.0;
            let pill =
                egui::Rect::from_min_size(egui::pos2(left, rect.center().y - size.y / 2.0), size);
            painter.rect_filled(pill, 8.0, badge_bg);
            painter.galley(
                egui::pos2(
                    pill.left() + badge_pad,
                    pill.center().y - galley.size().y / 2.0,
                ),
                galley,
                egui::Color32::PLACEHOLDER,
            );
        }
    }
    response
}

/// Mutually exclusive choices in one bordered group (Graph / Tree,
/// Table / Text); a choice's badge is a count after its label. Returns
/// whether the selection changed.
pub fn segmented<T: Copy + PartialEq>(
    ui: &mut egui::Ui,
    items: impl IntoIterator<Item = (T, TabItem)>,
    selected: &mut T,
) -> bool {
    let palette = theme::palette();
    let mut changed = false;
    egui::Frame::new()
        .fill(palette.bg)
        .stroke(Stroke::new(1.0_f32, palette.line))
        .corner_radius(4)
        .inner_margin(2)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            ui.horizontal(|ui| {
                for (value, item) in items {
                    let active = *selected == value;
                    let color = if active { palette.text } else { palette.muted };
                    // A badge is a count after the label, in its tone's color.
                    let mut text = egui::text::LayoutJob::default();
                    let font = TextStyle::Button.resolve(ui.style());
                    text.append(
                        &item.label,
                        0.0,
                        egui::TextFormat::simple(font.clone(), color),
                    );
                    if let Some((badge, tone)) = &item.badge {
                        text.append(
                            badge,
                            8.0,
                            egui::TextFormat::simple(
                                TextStyle::Small.resolve(ui.style()),
                                tone.fg(),
                            ),
                        );
                    }
                    let mut button = egui::Button::new(text).corner_radius(3);
                    button = if active {
                        button
                            .fill(palette.raised)
                            .stroke(Stroke::new(1.0_f32, palette.line))
                    } else {
                        button.fill(egui::Color32::TRANSPARENT).stroke(Stroke::NONE)
                    };
                    let mut response = ui.add_enabled(item.enabled, button);
                    if let Some(tip) = &item.tooltip {
                        response = response.on_hover_text(tip);
                    }
                    if response.clicked() && !active {
                        *selected = value;
                        changed = true;
                    }
                }
            });
        });
    changed
}
