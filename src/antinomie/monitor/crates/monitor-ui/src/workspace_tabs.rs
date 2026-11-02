// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Dock tab bars that keep every tab reachable at narrow widths.
//!
//! `egui_dock` clips the tabs that do not fit and offers only a thin scroll
//! bar, so at 1100 points the last tabs ("Core dumps", "Static analysis")
//! could not be found. Before a leaf is drawn this module measures its tabs
//! against the width the leaf had on the previous frame:
//!
//! 1. the tabs fit: nothing changes;
//! 2. they do not: the leaf uses short names ("Trace" for "Syscall Trace")
//!    and tighter padding; the full name stays in the hover text;
//! 3. they still do not: the tab bar scrolls so the active tab is in view
//!    whenever the active tab or the width changes, and a tab list button
//!    (a caret at the right end of the bar) opens every tab of the leaf.
//!
//! Both decisions are pure functions of the widths, so they do not flicker.
use super::*;
use egui::{Id, TextStyle, WidgetText};

/// Width `egui_dock` keeps free at the right end of a bar when it has an add
/// button; the tab list button sits there.
pub(super) const BUTTON_SLOT: f32 = 24.0;
/// Width `egui_dock` adds to a tab for its text margins.
const TAB_MARGIN: f32 = 16.0;
/// Width of a tab's close button.
const CLOSE_SLOT: f32 = 24.0;

/// A shorter name for a main tab; the hover text keeps the full one.
pub(super) fn short_name(full: &str) -> &str {
    match full {
        "Syscall Trace" => "Trace",
        "Run History" => "History",
        "Static analysis" => "Static",
        "Core dumps" => "Cores",
        "Detection rules" => "Rules",
        "Base images" => "Bases",
        "Analysis tools" => "Tools",
        other => other,
    }
}

/// A tab's name at the tight size: short name, one space of padding.
pub(super) fn tight_title(full: &str) -> String {
    format!(" {} ", short_name(full))
}

/// What the tab bar of one leaf needs this frame.
pub(super) struct LeafFit {
    pub(super) node: NodeIndex,
    /// Even the tight titles do not fit: show the tab list button.
    pub(super) overflows: bool,
}

/// The tab widths of a leaf, as `egui_dock` lays them out.
fn widths(ui: &egui::Ui, viewer: &mut Viewer<'_>, tabs: &mut [Panel], tight: bool) -> Vec<f32> {
    tabs.iter_mut()
        .map(|tab| {
            let title: WidgetText = viewer.title_for(tab, tight);
            let text = title.into_galley(ui, None, f32::INFINITY, TextStyle::Button);
            let close = if viewer.closeable(tab) {
                CLOSE_SLOT
            } else {
                0.0
            };
            text.size().x + TAB_MARGIN + close
        })
        .collect()
}

/// Decide the tab bars of every leaf of `local` (a dock holding one
/// surface), set the tight titles on `viewer` and scroll the active tab into
/// view where the bar overflows.
pub(super) fn fit(
    ui: &egui::Ui,
    viewer: &mut Viewer<'_>,
    local: &mut DockState<Panel>,
    surface: SurfaceIndex,
) -> Vec<LeafFit> {
    let leaves: Vec<(usize, f32, Vec<Panel>, usize)> = local
        .main_surface()
        .iter()
        .enumerate()
        .filter_map(|(index, node)| match node {
            egui_dock::Node::Leaf {
                rect, tabs, active, ..
            } if rect.width() > 1.0 && tabs.len() > 1 => {
                Some((index, rect.width(), tabs.clone(), active.0))
            }
            _ => None,
        })
        .collect();
    let mut fits = Vec::new();
    for (index, width, mut tabs, active) in leaves {
        let room = width - BUTTON_SLOT;
        let full: f32 = widths(ui, viewer, &mut tabs, false).iter().sum();
        let tight = full > room;
        if tight {
            viewer.tight.extend(tabs.iter().cloned());
        }
        let sizes = widths(ui, viewer, &mut tabs, tight);
        let used: f32 = sizes.iter().sum();
        let overflows = used > room;
        if overflows {
            // Keep the active tab in view when it or the width changed, so
            // the person can still scroll away from it with the wheel.
            let key = (surface.0, index, active, room as i32, tight);
            let id = Id::new(("tab-bar-view", key.0, key.1));
            let seen = ui.data_mut(|data| data.get_temp::<(usize, i32, bool)>(id));
            if seen != Some((key.2, key.3, key.4)) {
                ui.data_mut(|data| data.insert_temp(id, (key.2, key.3, key.4)));
                let start: f32 = sizes.iter().take(active).sum();
                let end = start + sizes.get(active).copied().unwrap_or(0.0);
                if let Some(egui_dock::Node::Leaf { scroll, .. }) =
                    local.main_surface_mut().iter_mut().nth(index)
                {
                    if start < -*scroll {
                        *scroll = -start;
                    } else if end > -*scroll + room {
                        *scroll = -(end - room);
                    }
                }
            }
        }
        fits.push(LeafFit {
            node: NodeIndex(index),
            overflows,
        });
    }
    fits
}

/// The tab list button of an overflowing leaf, over the slot `egui_dock`
/// keeps free at the right end of its bar. Returns the tab picked, if any.
pub(super) fn list_button(
    ui: &mut egui::Ui,
    viewer: &mut Viewer<'_>,
    local: &mut DockState<Panel>,
    surface: SurfaceIndex,
    node: NodeIndex,
    bar_fill: egui::Color32,
) -> Option<usize> {
    let (rect, viewport, titles, active) = match &local.main_surface()[node] {
        egui_dock::Node::Leaf {
            rect,
            viewport,
            tabs,
            active,
            ..
        } => (*rect, *viewport, tabs.clone(), active.0),
        _ => return None,
    };
    let slot = Rect::from_min_max(
        egui::pos2(rect.max.x - BUTTON_SLOT, rect.min.y),
        egui::pos2(rect.max.x, viewport.min.y - 2.0),
    );
    if !slot.is_positive() {
        return None;
    }
    let id = Id::new(("tab-list", surface.0, node.0));
    let response = ui
        .interact(slot, id, egui::Sense::click())
        .on_hover_text("All tabs")
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    ui.painter().rect_filled(slot, 0.0, bar_fill);
    if response.hovered() {
        ui.painter()
            .rect_filled(slot, 0.0, ui.visuals().widgets.hovered.weak_bg_fill);
    }
    ui.painter().text(
        slot.center(),
        egui::Align2::CENTER_CENTER,
        egui_phosphor::regular::CARET_DOWN,
        egui::FontId::proportional(14.0),
        ui.visuals().text_color(),
    );
    let popup = id.with("popup");
    if response.clicked() {
        ui.memory_mut(|memory| memory.toggle_popup(popup));
    }
    let mut picked = None;
    egui::popup_below_widget(
        ui,
        popup,
        &response,
        egui::PopupCloseBehavior::CloseOnClick,
        |ui| {
            ui.set_min_width(160.0);
            for (index, tab) in titles.iter().enumerate() {
                let name = viewer.app.panel_title(tab);
                if ui.selectable_label(index == active, name).clicked() {
                    picked = Some(index);
                }
            }
        },
    );
    picked
}
