// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! One destination calculation for both the docking preview and the actual drop.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DropAction {
    Stay,
    Empty,
    Append,
    Insert(usize),
    Split(egui_dock::Split),
}

pub(super) struct DropTarget {
    pub(super) surface: SurfaceIndex,
    pub(super) node: NodeIndex,
    pub(super) action: DropAction,
    pub(super) highlight: Rect,
}

impl WorkspaceLayout {
    pub(super) fn drop_target(&self, panel: &Panel, position: egui::Pos2) -> Option<DropTarget> {
        let location = self.dock.find_tab(panel)?;
        let (surface, node, rect) = self
            .targets
            .iter()
            .rev()
            .find(|(_, _, rect)| rect.contains(position))
            .copied()?;
        if self.dock[surface].is_empty() {
            return Some(DropTarget {
                surface,
                node,
                action: DropAction::Empty,
                highlight: rect,
            });
        }
        let own = location.0 == surface && location.1 == node;
        let header = self
            .target_headers
            .iter()
            .find(|(s, n, _)| *s == surface && *n == node)
            .map(|(_, _, rect)| *rect);
        if let Some(header) = header.filter(|header| header.contains(position)) {
            let mut slot = None;
            // The rectangles reflect visible tabs, including horizontal scrolling.
            for (tab, tab_surface, tab_rect) in &self.tab_targets {
                if *tab_surface != surface {
                    continue;
                }
                let Some((_, tab_node, index)) = self.dock.find_tab(tab) else {
                    continue;
                };
                if tab_node != node {
                    continue;
                }
                if position.x < tab_rect.center().x {
                    slot = Some((index.0, tab_rect.left()));
                    break;
                }
                slot = Some((index.0 + 1, tab_rect.right()));
            }
            if let Some((before, x)) = slot {
                // The docking library removes the source before inserting.
                let index = before.saturating_sub(usize::from(own && location.2 .0 < before));
                let action = if own && index == location.2 .0 {
                    DropAction::Stay
                } else {
                    DropAction::Insert(index)
                };
                let x = x.clamp(
                    header.left() + 2.0,
                    (header.right() - 2.0).max(header.left() + 2.0),
                );
                let highlight = Rect::from_min_max(
                    egui::pos2(x - 2.0, header.top()),
                    egui::pos2(x + 2.0, header.bottom()),
                );
                return Some(DropTarget {
                    surface,
                    node,
                    action,
                    highlight,
                });
            }
            return Some(DropTarget {
                surface,
                node,
                action: if own {
                    DropAction::Stay
                } else {
                    DropAction::Append
                },
                highlight: header,
            });
        }
        if own && self.dock[surface][node].tabs_count() == 1 {
            return Some(DropTarget {
                surface,
                node,
                action: DropAction::Stay,
                highlight: rect,
            });
        }
        let rel = (position - rect.min) / rect.size();
        let body = Rect::from_min_max(
            egui::pos2(
                rect.left(),
                header.map_or(rect.top(), |header| header.bottom()),
            ),
            rect.max,
        );
        let (action, highlight) = if rel.x < 0.2 {
            (
                DropAction::Split(egui_dock::Split::Left),
                Rect::from_min_max(body.min, egui::pos2(body.center().x, body.bottom())),
            )
        } else if rel.x > 0.8 {
            (
                DropAction::Split(egui_dock::Split::Right),
                Rect::from_min_max(egui::pos2(body.center().x, body.top()), body.max),
            )
        } else if rel.y < 0.2 {
            (
                DropAction::Split(egui_dock::Split::Above),
                Rect::from_min_max(body.min, egui::pos2(body.right(), body.center().y)),
            )
        } else if rel.y > 0.8 {
            (
                DropAction::Split(egui_dock::Split::Below),
                Rect::from_min_max(egui::pos2(body.left(), body.center().y), body.max),
            )
        } else {
            (DropAction::Append, body)
        };
        Some(DropTarget {
            surface,
            node,
            action,
            highlight,
        })
    }

    pub(super) fn show_drag_preview(
        &mut self,
        ui: &egui::Ui,
        surface: SurfaceIndex,
        origin: egui::Pos2,
        app: &MonitorApp,
    ) {
        if self.drag.is_none() {
            return;
        }
        if ui.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.drag = None;
            self.released = None;
            ui.ctx().stop_dragging();
            ui.ctx().request_repaint();
            return;
        }
        let Some((panel, _)) = self.drag.as_ref() else {
            return;
        };
        let Some(pointer) = ui.input(|input| input.pointer.hover_pos()) else {
            return;
        };
        if self.cancel_drag || self.released.is_some() {
            return;
        }
        ui.ctx().set_cursor_icon(egui::CursorIcon::Grabbing);
        ui.ctx().request_repaint();
        let target = self.drop_target(panel, pointer + origin.to_vec2());
        let layer = egui::LayerId::new(
            egui::Order::Tooltip,
            egui::Id::new(("workspace-drag-preview", ui.ctx().viewport_id())),
        );
        // Embedded floating surfaces share a viewport. The final surface has
        // all target geometry: replace our earlier preview, never stack ghosts.
        ui.ctx()
            .graphics_mut(|graphics| *graphics.entry(layer) = Default::default());
        let painter = ui.ctx().layer_painter(layer);
        let caption = match target.as_ref().map(|target| target.action) {
            Some(DropAction::Stay) => "Keep position",
            Some(DropAction::Empty | DropAction::Append) => "Join tabs",
            Some(DropAction::Insert(_)) => {
                if self.dock.find_tab(panel).is_some_and(|(s, n, _)| {
                    target
                        .as_ref()
                        .is_some_and(|t| t.surface == s && t.node == n)
                }) {
                    "Reorder tabs"
                } else {
                    "Join tabs"
                }
            }
            Some(DropAction::Split(egui_dock::Split::Left)) => "Dock left",
            Some(DropAction::Split(egui_dock::Split::Right)) => "Dock right",
            Some(DropAction::Split(egui_dock::Split::Above)) => "Dock above",
            Some(DropAction::Split(egui_dock::Split::Below)) => "Dock below",
            None => "Detach window",
        };
        if let Some(target) =
            target.filter(|target| target.surface == surface || ui.ctx().embed_viewports())
        {
            let highlight = target.highlight.translate(-origin.to_vec2());
            painter.rect_filled(highlight, 3.0, theme::blue().gamma_multiply(0.22));
            painter.rect_stroke(
                highlight,
                3.0,
                egui::Stroke::new(2.0_f32, theme::blue()),
                egui::StrokeKind::Inside,
            );
        }
        let bounds = ui.ctx().screen_rect().shrink(6.0);
        let width = (bounds.width() - 20.0).clamp(40.0, 220.0);
        let font = ui.style().text_styles[&egui::TextStyle::Button].clone();
        let title: String = app
            .panel_title(panel)
            .chars()
            .take(120)
            .map(|ch| if ch.is_control() { ' ' } else { ch })
            .collect();
        let mut job = egui::text::LayoutJob::simple(title, font.clone(), theme::text(), width);
        job.wrap.max_rows = 2;
        let title = painter.layout_job(job);
        let hint = painter.layout(
            format!("{caption} · Esc cancels"),
            font,
            theme::blue(),
            width,
        );
        let size = egui::vec2(
            title.size().x.max(hint.size().x) + 20.0,
            title.size().y + hint.size().y + 20.0,
        );
        let min = pointer + egui::vec2(18.0, 20.0);
        let min = egui::pos2(
            min.x
                .clamp(bounds.left(), (bounds.right() - size.x).max(bounds.left())),
            min.y
                .clamp(bounds.top(), (bounds.bottom() - size.y).max(bounds.top())),
        );
        let ghost = Rect::from_min_size(min, size);
        let shadow = egui::epaint::Shadow {
            offset: [3, 4],
            blur: 12,
            spread: 1,
            color: egui::Color32::from_black_alpha(110),
        };
        painter.add(shadow.as_shape(ghost, 5.0));
        painter.rect_filled(ghost, 5.0, theme::raised());
        painter.rect_stroke(
            ghost,
            5.0,
            egui::Stroke::new(1.5_f32, theme::blue()),
            egui::StrokeKind::Inside,
        );
        painter.galley(min + egui::vec2(10.0, 8.0), title.clone(), theme::text());
        painter.galley(
            min + egui::vec2(10.0, title.size().y + 12.0),
            hint,
            theme::blue(),
        );
    }
}
