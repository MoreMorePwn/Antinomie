// SPDX-License-Identifier: MIT
//! Shared evidence labels and actions. Sidecars never rename recorded files.
use antinomie_monitor_core::annotations::{self, Annotation};
use eframe::egui;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    labels: BTreeMap<PathBuf, Result<Annotation, String>>,
    editor: Option<Editor>,
    error: Option<String>,
}
#[derive(Clone)]
struct Editor {
    directory: PathBuf,
    name: String,
    tags: String,
}
type Shared = Arc<Mutex<State>>;
fn state(ctx: &egui::Context) -> Shared {
    ctx.data_mut(|data| {
        data.get_temp_mut_or_default::<Shared>(egui::Id::new("evidence-labels"))
            .clone()
    })
}

pub(crate) fn title(ui: &egui::Ui, directory: &Path, fallback: &str) -> String {
    let shared = state(ui.ctx());
    let mut data = shared.lock().unwrap_or_else(|e| e.into_inner());
    // Bound cache size independently of how many archived records exist.
    if data.labels.len() >= 4096 && !data.labels.contains_key(directory) {
        data.labels.clear();
    }
    let annotation = data
        .labels
        .entry(directory.to_owned())
        .or_insert_with(|| annotations::load(directory));
    match annotation {
        Ok(value) => {
            let name = if value.name.is_empty() {
                fallback
            } else {
                &value.name
            };
            if value.tags.is_empty() {
                name.to_owned()
            } else {
                format!("{name}  [{}]", value.tags.join(", "))
            }
        }
        Err(_) => fallback.to_owned(),
    }
}

pub(crate) fn controls(ui: &mut egui::Ui, directory: &Path) {
    ui.menu_button("Evidence…", |ui| menu(ui, directory));
}
pub(crate) fn menu(ui: &mut egui::Ui, directory: &Path) {
    if ui.button("Rename / tags…").clicked() {
        let shared = state(ui.ctx());
        let mut data = shared.lock().unwrap_or_else(|e| e.into_inner());
        match annotations::load(directory) {
            Ok(value) => {
                data.editor = Some(Editor {
                    directory: directory.to_owned(),
                    name: value.name,
                    tags: value.tags.join(", "),
                })
            }
            Err(error) => data.error = Some(error),
        }
        ui.close_menu();
    }
    if ui.button("Open result directory").clicked() {
        reveal(ui.ctx(), directory);
        ui.close_menu();
    }
}
pub(crate) fn reveal(ctx: &egui::Context, directory: &Path) {
    let shared = state(ctx);
    // A PCAP's labels have their own sidecar directory, created only on save.
    let directory = if directory.exists() {
        directory
    } else {
        directory.parent().unwrap_or(directory)
    };
    match std::process::Command::new("xdg-open")
        .arg(directory)
        .spawn()
    {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let error = match child.wait() {
                    Ok(status) if status.success() => None,
                    Ok(status) => Some(format!("Open directory failed: {status}")),
                    Err(error) => Some(format!("Open directory failed: {error}")),
                };
                if let Some(error) = error {
                    shared.lock().unwrap_or_else(|e| e.into_inner()).error = Some(error);
                }
            });
        }
        Err(error) => {
            shared.lock().unwrap_or_else(|e| e.into_inner()).error =
                Some(format!("Open directory: {error}"))
        }
    }
}

pub(crate) fn dialogs(ctx: &egui::Context) {
    let shared = state(ctx);
    let (mut editor, error) = {
        let mut data = shared.lock().unwrap_or_else(|e| e.into_inner());
        (data.editor.take(), data.error.take())
    };
    if let Some(ref mut edit) = editor {
        let mut open = true;
        let mut save = false;
        egui::Window::new("Evidence name and tags")
            .id(egui::Id::new("annotation-editor"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(460.0)
            .show(ctx, |ui| {
                ui.label("Name");
                ui.add(egui::TextEdit::singleline(&mut edit.name).desired_width(f32::INFINITY));
                ui.label("Tags (comma separated)");
                ui.add(egui::TextEdit::singleline(&mut edit.tags).desired_width(f32::INFINITY));
                ui.colored_label(
                    crate::theme::muted(),
                    "The original evidence and its identity are preserved.",
                );
                save = ui.button("Save").clicked();
            });
        let mut data = shared.lock().unwrap_or_else(|e| e.into_inner());
        if save {
            let value = Annotation {
                name: edit.name.trim().to_owned(),
                tags: edit
                    .tags
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect(),
            };
            match annotations::save(&edit.directory, &value) {
                Ok(()) => {
                    data.labels.insert(edit.directory.clone(), Ok(value));
                }
                Err(error) => {
                    data.error = Some(error);
                    data.editor = editor;
                }
            }
        } else if open {
            data.editor = editor;
        }
    }
    if let Some(error) = error {
        let mut open = true;
        egui::Window::new("Evidence action failed")
            .open(&mut open)
            .show(ctx, |ui| {
                ui.colored_label(crate::theme::error(), &error);
            });
        if open {
            shared.lock().unwrap_or_else(|e| e.into_inner()).error = Some(error);
        }
    }
}
