// SPDX-License-Identifier: GPL-3.0-only
//! The sidebar folded to a narrow rail of icons: Virtual machines (with the
//! state dot of the running or selected VM), Base images, Detection rules,
//! Analysis tools, Samples and Explorer. Ctrl+B, View > Sidebar, the palette
//! and the chevron at the top of either form switch between them.
use super::*;
use crate::workspace::LibraryPage;

/// One rail button: an icon in a square, an optional state dot at its
/// bottom-right corner and a tooltip.
fn rail_button(
    ui: &mut egui::Ui,
    icon: &str,
    tooltip: &str,
    dot: Option<egui::Color32>,
) -> egui::Response {
    let size = ui.spacing().interact_size.y + 10.0;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let hovered = response.hovered() || response.has_focus();
        if hovered {
            ui.painter().rect_filled(rect, 4.0, theme::palette().hover);
        }
        let body = ui.text_style_height(&egui::TextStyle::Body);
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            icon,
            egui::FontId::proportional(body * 1.25),
            if hovered {
                theme::blue()
            } else {
                theme::text()
            },
        );
        if let Some(color) = dot {
            let centre = rect.right_bottom() - egui::vec2(8.0, 8.0);
            ui.painter().circle(
                centre,
                4.5,
                color,
                egui::Stroke::new(1.5_f32, theme::panel()),
            );
        }
    }
    response.on_hover_text(tooltip)
}

impl MonitorApp {
    /// Fold the sidebar to the rail, or open it again.
    pub(super) fn toggle_sidebar(&mut self) {
        self.settings.sidebar_rail = !self.settings.sidebar_rail;
    }

    /// The chevron at the right end of the first section header of the
    /// open sidebar: no row of its own, so a short window keeps Explorer.
    pub(super) fn sidebar_fold_button(&mut self, ui: &mut egui::Ui) {
        let fold = ui
            .add(
                egui::Button::new(
                    RichText::new(egui_phosphor::regular::CARET_DOUBLE_LEFT).color(theme::muted()),
                )
                .frame(false),
            )
            .on_hover_text(format!(
                "Fold the sidebar to icons ({})",
                ui.ctx().format_shortcut(&keys::TOGGLE_SIDEBAR)
            ))
            .clicked();
        if fold {
            self.toggle_sidebar();
        }
    }

    pub(super) fn sidebar_rail(&mut self, root: &mut egui::Ui) {
        let now = unix_seconds();
        let mut selected_vm = None;
        let mut new_vm = false;
        let mut unfold = false;
        let width = root.spacing().interact_size.y + 10.0 + 12.0;
        egui::Panel::left("vms-rail")
            .exact_size(width)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(theme::panel())
                    .inner_margin(egui::Margin::same(6)),
            )
            .show(root, |ui| {
                ui.spacing_mut().item_spacing.y = 4.0;
                if rail_button(
                    ui,
                    egui_phosphor::regular::CARET_DOUBLE_RIGHT,
                    &format!(
                        "Show the sidebar ({})",
                        ui.ctx().format_shortcut(&keys::TOGGLE_SIDEBAR)
                    ),
                    None,
                )
                .clicked()
                {
                    unfold = true;
                }
                ui.separator();
                let active = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|vm| Some(&vm.id) == self.snapshot.active_vm.as_ref());
                let selected = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|vm| Some(&vm.id) == self.selected.as_ref());
                let (dot, state) = match (active, selected) {
                    (Some(vm), _) => {
                        let (word, color) = vm_state_word(&self.snapshot.state);
                        (Some(color), format!("{}: {word}", vm.name))
                    }
                    (None, Some(vm)) => (Some(theme::muted()), format!("{}: Stopped", vm.name)),
                    (None, None) => (None, "no VM selected".to_owned()),
                };
                let vms = self.snapshot.vms.len();
                let button = rail_button(
                    ui,
                    egui_phosphor::regular::DESKTOP_TOWER,
                    &format!("Virtual machines: {vms} ({state}). Click to choose one or add a VM"),
                    dot,
                );
                egui::Popup::menu(&button)
                    .align(egui::RectAlign::RIGHT_START)
                    .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
                    .show(|ui| {
                        ui.set_min_width(260.0);
                        ui.set_max_height(ui.ctx().content_rect().height() * 0.6);
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            if vms == 0 && self.pending_vm_rows().is_empty() {
                                ui.label(RichText::new("No saved VMs").color(theme::muted()));
                            }
                            for work in self.pending_vm_rows() {
                                Self::pending_vm_row(ui, work);
                            }
                            for vm in &self.snapshot.vms {
                                let response = self.vm_row(ui, vm, now);
                                if response.clicked() {
                                    selected_vm = Some(vm.id.clone());
                                    ui.close();
                                }
                            }
                        });
                        ui.separator();
                        if ui
                            .add_enabled(
                                self.snapshot.active_vm.is_none(),
                                egui::Button::new(format!(
                                    "{} New VM",
                                    egui_phosphor::regular::PLUS
                                )),
                            )
                            .clicked()
                        {
                            new_vm = true;
                            ui.close();
                        }
                    });
                ui.separator();
                let packs = match self.rules_ui.pack_count() {
                    Some(1) => "1 pack".to_owned(),
                    Some(count) => format!("{count} packs"),
                    None => "loading".to_owned(),
                };
                let samples = self.samples_count();
                for (page, icon, text) in [
                    (
                        LibraryPage::BaseImages,
                        egui_phosphor::regular::HARD_DRIVE,
                        format!("Base images: {}", self.snapshot.bases.len()),
                    ),
                    (
                        LibraryPage::Rules,
                        egui_phosphor::regular::SHIELD_CHECK,
                        format!("Detection rules: {packs}"),
                    ),
                    (
                        LibraryPage::Tools,
                        egui_phosphor::regular::FLASK,
                        "Analysis tools".to_owned(),
                    ),
                    (
                        LibraryPage::Samples,
                        egui_phosphor::regular::BIOHAZARD,
                        format!("Samples: {samples}"),
                    ),
                    (
                        LibraryPage::Screenshots,
                        egui_phosphor::regular::IMAGES,
                        "Screenshots".to_owned(),
                    ),
                ] {
                    if rail_button(ui, icon, &text, None).clicked() {
                        self.open_library(page);
                    }
                }
                ui.separator();
                let folder = match &self.explorer_browser.root {
                    Some(root) => format!("Explorer: {}", root.display()),
                    None => "Explorer: no folder chosen".to_owned(),
                };
                if rail_button(ui, egui_phosphor::regular::FOLDER_OPEN, &folder, None).clicked() {
                    self.settings.explorer_collapsed = false;
                    unfold = true;
                }
            });
        if unfold {
            self.settings.sidebar_rail = false;
        }
        if new_vm {
            self.new_image();
        }
        if let Some(vm_id) = selected_vm {
            self.select_vm(vm_id);
        }
    }
}
