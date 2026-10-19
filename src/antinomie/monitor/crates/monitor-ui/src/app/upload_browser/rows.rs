// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Cached flattened tree; only the viewport's fixed-height rows create widgets.
use super::*;

pub(super) enum Row {
    Entry(Entry, usize),
    Loading(PathBuf, usize),
    Message(String, usize),
    Page {
        path: PathBuf,
        depth: usize,
        offset: usize,
        count: usize,
        more: bool,
    },
}

impl Row {
    fn depth(&self) -> usize {
        match self {
            Self::Entry(_, depth) | Self::Loading(_, depth) | Self::Message(_, depth) => *depth,
            Self::Page { depth, .. } => *depth,
        }
    }
}

fn flatten(browser: &Browser, path: &Path, depth: usize, result: &mut Vec<Row>) {
    if depth >= DEPTH_LIMIT {
        result.push(Row::Message(
            "Choose this folder as the root to browse deeper.".into(),
            depth,
        ));
        return;
    }
    let Some(listing) = browser.listings.get(path) else {
        result.push(Row::Loading(path.to_owned(), depth));
        return;
    };
    let Some(page) = &listing.result else {
        result.push(Row::Loading(path.to_owned(), depth));
        return;
    };
    match page {
        Err(error) => result.push(Row::Message(error.clone(), depth)),
        Ok(page) => {
            if page.entries.is_empty() {
                result.push(Row::Message("No entries in this folder.".into(), depth));
            }
            for entry in &page.entries {
                result.push(Row::Entry(entry.clone(), depth));
                if entry.directory && browser.expanded.contains(&entry.path) {
                    flatten(browser, &entry.path, depth + 1, result);
                }
            }
            if listing.offset > 0 || page.more {
                result.push(Row::Page {
                    path: path.to_owned(),
                    depth,
                    offset: listing.offset,
                    count: page.entries.len(),
                    more: page.more,
                });
            }
        }
    }
}

pub(super) fn show(browser: &mut Browser, ui: &mut egui::Ui, view: View) -> Option<Action> {
    browser.poll();
    let root = browser.root.as_ref()?;
    if browser.rows_dirty {
        let mut rows = Vec::new();
        flatten(browser, root, 0, &mut rows);
        // The root folder is the tree's root: its entries are the first level.
        browser.branches = crate::tree_lines::prefixes(
            &rows.iter().map(|row| row.depth() + 1).collect::<Vec<_>>(),
        );
        browser.rows = rows;
        browser.rows_dirty = false;
    }
    if let Some(path) = browser.rows.iter().find_map(|row| match row {
        Row::Loading(path, _) => Some(path.clone()),
        _ => None,
    }) {
        browser.request(&path, ui.ctx());
    }
    if let Some(error) = &browser.error {
        crate::activity::error(ui, error);
    }
    let mut selected = None;
    let mut toggle = None;
    let mut page = None;
    let row_height = ui
        .spacing()
        .interact_size
        .y
        .max(ui.text_style_height(&egui::TextStyle::Body));
    let mono = egui::TextStyle::Monospace.resolve(ui.style());
    let char_width = crate::tree_lines::char_width(ui, &mono);
    #[cfg(test)]
    let mut drawn_rows = 0;
    egui::ScrollArea::both()
        .id_salt(view.id)
        .auto_shrink([false, false])
        .max_height(view.height.max(24.0))
        .min_scrolled_height(view.height.clamp(24.0, 100.0))
        .show_rows(ui, row_height, browser.rows.len(), |ui, range| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
            #[cfg(test)]
            {
                drawn_rows += range.len();
            }
            for index in range {
                let row_id = match &browser.rows[index] {
                    Row::Entry(entry, _) => egui::Id::new((&entry.path, "entry")),
                    Row::Loading(path, _) => egui::Id::new((path, "loading")),
                    Row::Page { path, .. } => egui::Id::new((path, "page")),
                    Row::Message(..) => egui::Id::new((index, "message")),
                };
                ui.push_id((view.id, browser.generation, row_id), |ui| {
                    let branch = &browser.branches[index];
                    crate::tree_lines::row(ui, branch, char_width, |ui| {
                        match &browser.rows[index] {
                            Row::Entry(entry, _) => {
                                let name =
                                    entry.path.file_name().unwrap_or_default().to_string_lossy();
                                let available = entry.regular && entry.path.to_str().is_some();
                                let response = if entry.directory {
                                    let icon = if browser.expanded.contains(&entry.path) {
                                        "▾"
                                    } else {
                                        "▸"
                                    };
                                    let response =
                                        ui.selectable_label(false, format!("{icon} {name}"));
                                    if response.clicked() {
                                        toggle = Some(entry.path.clone());
                                    }
                                    response
                                } else {
                                    ui.add_enabled(
                                        available,
                                        egui::SelectableLabel::new(
                                            browser.selected.as_ref() == Some(&entry.path),
                                            name.as_ref(),
                                        ),
                                    )
                                };
                                if !entry.directory
                                    && (response.clicked() || response.secondary_clicked())
                                {
                                    selected = Some(Action::Select(entry.path.clone()));
                                }
                                if view.actions {
                                    if available && response.double_clicked() && view.can_send {
                                        selected = Some(Action::SendRun(entry.path.clone()));
                                    }
                                    response.context_menu(|ui| {
                                        if available
                                            && ui
                                                .add_enabled(
                                                    view.can_send,
                                                    egui::Button::new("Send and Run"),
                                                )
                                                .clicked()
                                        {
                                            selected = Some(Action::SendRun(entry.path.clone()));
                                            ui.close_menu();
                                        }
                                        if ui.button("Open Directory").clicked() {
                                            let directory = if entry.directory {
                                                Some(entry.path.as_path())
                                            } else {
                                                entry.path.parent()
                                            };
                                            if let Some(directory) = directory {
                                                selected = Some(Action::OpenDirectory(
                                                    directory.to_owned(),
                                                ));
                                            }
                                            ui.close_menu();
                                        }
                                    });
                                }
                                response.on_hover_ui(|ui| {
                                    ui.label(entry.path.display().to_string());
                                    if available && view.actions {
                                        ui.label(if view.can_send {
                                            "Double-click to Send and Run"
                                        } else {
                                            "Start the selected VM to Send and Run"
                                        });
                                    }
                                });
                            }
                            Row::Loading(..) | Row::Message(..) => {
                                if matches!(browser.rows[index], Row::Loading(..)) {
                                    theme::spinner(ui);
                                }
                                let text = match &browser.rows[index] {
                                    Row::Message(text, _) => text.as_str(),
                                    _ => "Reading folder…",
                                };
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(text).color(theme::muted()),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(text);
                            }
                            Row::Page {
                                path,
                                offset,
                                count,
                                more,
                                ..
                            } => {
                                ui.label(format!("{}–{}", offset + 1, offset + count));
                                if ui
                                    .add_enabled(*offset > 0, egui::Button::new("Previous entries"))
                                    .clicked()
                                {
                                    page = Some((path.clone(), offset.saturating_sub(PAGE_LEN)));
                                }
                                if ui
                                    .add_enabled(*more, egui::Button::new("Next entries"))
                                    .clicked()
                                {
                                    page = offset
                                        .checked_add(PAGE_LEN)
                                        .map(|offset| (path.clone(), offset));
                                }
                            }
                        }
                    });
                });
            }
        });
    #[cfg(test)]
    {
        browser.drawn_rows = drawn_rows;
    }
    if let Some(path) = toggle {
        if !browser.expanded.remove(&path) {
            browser.expanded.insert(path);
        } else {
            browser.expanded.retain(|child| !child.starts_with(&path));
            browser
                .listings
                .retain(|child, _| !child.starts_with(&path));
        }
        browser.rows_dirty = true;
        ui.ctx().request_repaint();
    }
    if let Some((path, offset)) = page {
        browser
            .listings
            .retain(|child, _| child == &path || !child.starts_with(&path));
        browser.expanded.retain(|child| !child.starts_with(&path));
        // Keep this folder open when paging inside a subtree.
        if browser.root.as_ref() != Some(&path) {
            browser.expanded.insert(path.clone());
        }
        browser.listings.insert(
            path,
            Listing {
                offset,
                result: None,
            },
        );
        browser.rows_dirty = true;
        ui.ctx().request_repaint();
    }
    if let Some(Action::Select(path) | Action::SendRun(path)) = &selected {
        browser.selected = Some(path.clone());
    }
    selected
}
