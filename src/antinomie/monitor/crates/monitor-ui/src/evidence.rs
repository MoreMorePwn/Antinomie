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
#[derive(Clone, Copy)]
enum Field {
    Name,
    Tags,
}
#[derive(Clone)]
struct Editor {
    directory: PathBuf,
    field: Field,
    draft: String,
    stored: Annotation,
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

pub(crate) fn menu(ui: &mut egui::Ui, directory: &Path) {
    if ui.button("Rename…").clicked() {
        open_editor(ui, directory, Field::Name);
    }
    if ui.button("Edit tags…").clicked() {
        open_editor(ui, directory, Field::Tags);
    }
    if ui.button("Open result directory").clicked() {
        reveal(ui.ctx(), directory);
        ui.close_menu();
    }
}
fn open_editor(ui: &mut egui::Ui, directory: &Path, field: Field) {
    let shared = state(ui.ctx());
    let mut data = shared.lock().unwrap_or_else(|e| e.into_inner());
    match annotations::load(directory) {
        Ok(stored) => {
            let draft = match field {
                Field::Name => stored.name.clone(),
                Field::Tags => stored.tags.join(", "),
            };
            data.editor = Some(Editor {
                directory: directory.to_owned(),
                field,
                draft,
                stored,
            });
        }
        Err(error) => data.error = Some(error),
    }
    ui.close_menu();
}
fn merge_annotation(stored: &Annotation, field: Field, draft: &str) -> Annotation {
    match field {
        Field::Name => Annotation {
            name: draft.trim().to_owned(),
            tags: stored.tags.clone(),
        },
        Field::Tags => Annotation {
            name: stored.name.clone(),
            tags: draft
                .split(',')
                .map(str::trim)
                .filter(|tag| !tag.is_empty())
                .map(str::to_owned)
                .collect(),
        },
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
        let title = match edit.field {
            Field::Name => "Evidence name",
            Field::Tags => "Evidence tags",
        };
        egui::Window::new(title)
            .id(egui::Id::new("annotation-editor"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(460.0)
            .show(ctx, |ui| {
                match edit.field {
                    Field::Name => {
                        ui.label("Name");
                    }
                    Field::Tags => {
                        ui.label("Tags (comma separated)");
                    }
                }
                ui.add(egui::TextEdit::singleline(&mut edit.draft).desired_width(f32::INFINITY));
                ui.colored_label(
                    crate::theme::muted(),
                    "The original evidence and its identity are preserved.",
                );
                save = ui.button("Save").clicked();
            });
        let mut data = shared.lock().unwrap_or_else(|e| e.into_inner());
        if save {
            let value = merge_annotation(&edit.stored, edit.field, &edit.draft);
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

/// `tag == "name"` and `tag contains "part"` match stored annotation tags.
/// A `tag` expression that is not one of those forms matches nothing.
/// Anything else returns `None` so the caller can use its ordinary text search.
#[cfg(test)]
pub(crate) fn tag_query(query: &str, tags: &[String]) -> Option<bool> {
    let query = query.trim();
    let rest = query
        .strip_prefix("tag ")
        .or_else(|| query.strip_prefix("tags "))?;
    let rest = rest.trim();
    if let Some(value) = rest.strip_prefix("==") {
        let wanted = unquote(value.trim());
        return Some(tags.iter().any(|tag| tag == wanted));
    }
    if let Some(value) = rest.strip_prefix("contains") {
        let wanted = unquote(value.trim());
        return Some(!wanted.is_empty() && tags.iter().any(|tag| tag.contains(wanted)));
    }
    Some(false)
}

#[cfg(test)]
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_edit_keeps_the_field_that_was_not_opened() {
        let stored = Annotation {
            name: "  stored name  ".into(),
            tags: vec!["triage".into(), "odd, tag".into()],
        };
        let renamed = merge_annotation(&stored, Field::Name, "  renamed  ");
        assert_eq!(renamed.name, "renamed");
        assert_eq!(renamed.tags, stored.tags);
        let retagged = merge_annotation(&stored, Field::Tags, " alpha , , beta ");
        assert_eq!(retagged.name, stored.name);
        assert_eq!(retagged.tags, vec!["alpha".to_owned(), "beta".to_owned()]);
    }

    #[test]
    fn tag_query_reads_stored_tags_and_rejects_a_broken_expression() {
        let tags = vec!["review".into(), "odd, tag".into()];
        assert_eq!(tag_query(r#"tag == "review""#, &tags), Some(true));
        assert_eq!(tag_query(r#"tag == "other""#, &tags), Some(false));
        assert_eq!(tag_query(r#"tags contains "odd""#, &tags), Some(true));
        assert_eq!(tag_query("tag = review", &tags), Some(false));
        assert_eq!(tag_query("syscall.num == 1", &tags), None);
    }
}
