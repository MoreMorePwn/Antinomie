// SPDX-License-Identifier: GPL-3.0-only
//! The finished state of an export dialog: the files it wrote, shown against
//! their common folder, in an area of bounded height. A long host path never
//! widens the window: names are cut in the middle, the whole path is on hover.
use eframe::egui::{self, RichText};
use std::path::{Path, PathBuf};

/// The folder every path is in: the parent of one file, else the deepest folder
/// they share.
fn common_folder(paths: &[&Path]) -> PathBuf {
    let mut folder: Option<PathBuf> = None;
    for path in paths {
        let parent = path.parent().unwrap_or(Path::new("")).to_path_buf();
        folder = Some(match folder {
            None => parent,
            Some(current) => current
                .components()
                .zip(parent.components())
                .take_while(|(a, b)| a == b)
                .map(|(a, _)| a)
                .collect(),
        });
    }
    folder.unwrap_or_default()
}

/// The folder (with Copy path and Open folder) and each written file under it,
/// as (label, path). At most `rows` file rows show before the list scrolls.
pub fn written_files(ui: &mut egui::Ui, id: &str, files: &[(String, PathBuf)], rows: usize) {
    if files.is_empty() {
        return;
    }
    let paths: Vec<&Path> = files.iter().map(|(_, path)| path.as_path()).collect();
    let folder = common_folder(&paths);
    let mono = egui::TextStyle::Monospace.resolve(ui.style());
    let width = ui.available_width();
    ui.horizontal(|ui| {
        ui.label(RichText::new("Folder").weak());
        // The buttons first, from the right: the path takes what is left.
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .small_button("Open folder")
                .on_hover_text("Show the folder in the file manager")
                .clicked()
            {
                crate::folders::show_detached(folder.clone());
            }
            if ui.small_button("Copy path").clicked() {
                ui.ctx().copy_text(folder.display().to_string());
            }
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                let shown = crate::widgets::fit_middle(
                    ui,
                    &folder.display().to_string(),
                    &mono,
                    ui.available_width() - 8.0,
                );
                ui.add(egui::Label::new(RichText::new(shown).monospace()).selectable(false))
                    .on_hover_text(folder.display().to_string());
            });
        });
    });
    let label_width = files
        .iter()
        .map(|(label, _)| {
            ui.fonts(|fonts| {
                fonts
                    .layout_no_wrap(
                        format!("{label}:"),
                        egui::TextStyle::Body.resolve(ui.style()),
                        egui::Color32::PLACEHOLDER,
                    )
                    .size()
                    .x
            })
        })
        .fold(0.0_f32, f32::max);
    let row_height = ui.spacing().interact_size.y + ui.spacing().item_spacing.y;
    egui::ScrollArea::vertical()
        .id_salt(("written_files", id))
        .max_height(row_height * rows as f32 + 4.0)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.set_width(width - 12.0);
            for (label, path) in files {
                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(label_width, ui.spacing().interact_size.y),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.set_min_width(label_width);
                            ui.label(format!("{label}:"));
                        },
                    );
                    let relative = path.strip_prefix(&folder).unwrap_or(path);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .small_button(egui_phosphor::regular::COPY)
                            .on_hover_text("Copy this file's path")
                            .clicked()
                        {
                            ui.ctx().copy_text(path.display().to_string());
                        }
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            let shown = crate::widgets::fit_middle(
                                ui,
                                &relative.display().to_string(),
                                &mono,
                                ui.available_width() - 8.0,
                            );
                            ui.add(
                                egui::Label::new(RichText::new(shown).monospace())
                                    .selectable(false),
                            )
                            .on_hover_text(path.display().to_string());
                        });
                    });
                });
            }
        });
}

/// A name for a window title: a long one (a SHA-256) is cut so the title does
/// not set the window's width.
pub fn short_name(name: &str) -> String {
    if name.chars().count() > 28 {
        format!("{}…", name.chars().take(26).collect::<String>())
    } else {
        name.to_owned()
    }
}
