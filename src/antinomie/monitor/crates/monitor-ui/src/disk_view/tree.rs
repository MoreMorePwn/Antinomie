// SPDX-License-Identifier: MIT
//! The filesystem tree of an open disk: the host explorer's cached-flatten
//! design (lazy listings, pages of `PAGE_LEN`, a cap on expanded folders and
//! on depth, only the viewport's rows create widgets) over the reader's
//! listings. Symbolic links are shown with their target and never followed.
use super::{display_name, format_size, mode_numeric, mode_rwx};
use crate::{
    app::{DEPTH_LIMIT, DIRECTORY_LIMIT, PAGE_LEN},
    theme,
};
use antinomie_monitor_core::disks::reader::{DiskEntry, DiskEntryKind, DiskListing};
use eframe::egui;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Listing {
    pub offset: usize,
    pub result: Option<Result<DiskListing, String>>,
    pub requested: bool,
}

pub(super) enum Row {
    Entry {
        path: String,
        entry: DiskEntry,
        depth: usize,
    },
    Loading(String, usize),
    Message(String, usize),
    Page {
        path: String,
        depth: usize,
        offset: usize,
        count: usize,
        more: bool,
    },
}

impl Row {
    fn depth(&self) -> usize {
        match self {
            Self::Entry { depth, .. } | Self::Page { depth, .. } => *depth,
            Self::Loading(_, depth) | Self::Message(_, depth) => *depth,
        }
    }
}

/// What a context-menu entry of a row asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Choice {
    ExtractToView,
    SaveToHost,
    OpenWith,
    HandToAnalysis,
    CopyPath,
}

pub(super) enum Event {
    Select(String),
    Menu(String, DiskEntry, Choice),
}

pub(super) struct Options<'a> {
    pub selected: Option<&'a str>,
    pub numeric_modes: bool,
    pub height: f32,
}

#[derive(Default)]
pub(super) struct Tree {
    pub listings: BTreeMap<String, Listing>,
    pub expanded: BTreeSet<String>,
    pub rows: Vec<Row>,
    branches: Vec<crate::tree_lines::Prefix>,
    pub dirty: bool,
    /// Reveal this path: expand its parents, page to it, scroll to it.
    reveal: Option<String>,
    scroll_to: Option<usize>,
    pub hide_dotfiles: bool,
    #[cfg(test)]
    pub drawn_rows: usize,
}

pub(super) fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(index) => &path[..index],
    }
}

impl Tree {
    pub(super) fn reset(&mut self) {
        *self = Self {
            hide_dotfiles: self.hide_dotfiles,
            dirty: true,
            ..Self::default()
        };
    }

    /// The first listing the tree shows but has not asked for.
    pub(super) fn wanted(&mut self) -> Option<(String, usize)> {
        self.refresh();
        let path = self.rows.iter().find_map(|row| match row {
            Row::Loading(path, _) => Some(path.clone()),
            _ => None,
        })?;
        let listing = self.listings.get_mut(&path)?;
        if listing.requested {
            return None;
        }
        listing.requested = true;
        Some((path, listing.offset))
    }

    pub(super) fn accept(
        &mut self,
        path: &str,
        offset: usize,
        result: Result<DiskListing, String>,
    ) {
        if let Some(listing) = self.listings.get_mut(path) {
            if listing.offset == offset {
                listing.result = Some(result);
                self.dirty = true;
            }
        }
    }

    fn refresh(&mut self) {
        if !self.dirty {
            return;
        }
        let mut rows = Vec::new();
        self.flatten("/", 0, &mut rows);
        // The root folder is the tree's root: its entries are the first level.
        self.branches = crate::tree_lines::prefixes(
            &rows.iter().map(|row| row.depth() + 1).collect::<Vec<_>>(),
        );
        self.rows = rows;
        self.dirty = false;
    }

    fn flatten(&mut self, path: &str, depth: usize, rows: &mut Vec<Row>) {
        if depth >= DEPTH_LIMIT {
            rows.push(Row::Message(
                "Folders this deep are not listed; use Find to reach a file below.".into(),
                depth,
            ));
            return;
        }
        if !self.listings.contains_key(path) && self.listings.len() >= DIRECTORY_LIMIT {
            rows.push(Row::Message(
                "Collapse an expanded folder to browse more folders.".into(),
                depth,
            ));
            return;
        }
        let listing = self.listings.entry(path.to_owned()).or_insert(Listing {
            offset: 0,
            result: None,
            requested: false,
        });
        let offset = listing.offset;
        let Some(result) = listing.result.clone() else {
            rows.push(Row::Loading(path.to_owned(), depth));
            return;
        };
        match result {
            Err(error) => rows.push(Row::Message(error, depth)),
            Ok(page) => {
                let mut shown = 0;
                for entry in &page.entries {
                    if self.hide_dotfiles && entry.name.starts_with('.') {
                        continue;
                    }
                    shown += 1;
                    let child = join(path, &entry.name);
                    rows.push(Row::Entry {
                        path: child.clone(),
                        entry: entry.clone(),
                        depth,
                    });
                    if entry.kind == DiskEntryKind::Dir
                        && entry.addressable
                        && self.expanded.contains(&child)
                    {
                        self.flatten(&child, depth + 1, rows);
                    }
                }
                if shown == 0 && !page.more {
                    rows.push(Row::Message(
                        if page.entries.is_empty() {
                            "No entries in this folder."
                        } else {
                            "Only hidden entries in this folder."
                        }
                        .into(),
                        depth,
                    ));
                }
                if page.truncated {
                    rows.push(Row::Message(
                        "More entries than the reader lists in one folder.".into(),
                        depth,
                    ));
                }
                if offset > 0 || page.more {
                    rows.push(Row::Page {
                        path: path.to_owned(),
                        depth,
                        offset,
                        count: page.entries.len(),
                        more: page.more,
                    });
                }
            }
        }
    }

    pub(super) fn toggle(&mut self, path: &str) {
        if !self.expanded.remove(path) {
            self.expanded.insert(path.to_owned());
        } else {
            let prefix = format!("{path}/");
            self.expanded.retain(|child| !child.starts_with(&prefix));
            // A later expand reads the folder again.
            self.listings
                .retain(|child, _| child != path && !child.starts_with(&prefix));
        }
        self.dirty = true;
    }

    pub(super) fn page(&mut self, path: &str, offset: usize) {
        let prefix = format!("{path}/");
        self.listings
            .retain(|child, _| child == path || !child.starts_with(&prefix));
        self.expanded.retain(|child| !child.starts_with(&prefix));
        self.listings.insert(
            path.to_owned(),
            Listing {
                offset,
                result: None,
                requested: false,
            },
        );
        self.dirty = true;
    }

    /// Expand every folder above `path`, page to it and scroll to it.
    pub(super) fn reveal(&mut self, path: &str) {
        let mut parent = parent_of(path).to_owned();
        let mut chain = Vec::new();
        while parent != "/" {
            chain.push(parent.clone());
            parent = parent_of(&parent).to_owned();
        }
        self.expanded.extend(chain);
        self.reveal = Some(path.to_owned());
        self.dirty = true;
    }

    /// Move a pending reveal along; true while it is still looking.
    pub(super) fn advance_reveal(&mut self) -> bool {
        let Some(target) = self.reveal.clone() else {
            return false;
        };
        self.refresh();
        if let Some(index) = self
            .rows
            .iter()
            .position(|row| matches!(row, Row::Entry { path, .. } if *path == target))
        {
            self.scroll_to = Some(index);
            self.reveal = None;
            return false;
        }
        // The folder holding it is loaded but the entry is on another page.
        let parent = parent_of(&target).to_owned();
        let name = target.rsplit('/').next().unwrap_or("").to_owned();
        let Some(Listing {
            offset,
            result: Some(Ok(page)),
            ..
        }) = self.listings.get(&parent)
        else {
            return true;
        };
        if page.entries.iter().any(|entry| entry.name == name) {
            // Hidden by the dotfile filter: show them.
            self.hide_dotfiles = false;
            self.dirty = true;
            return true;
        }
        if page.more {
            let next = offset + PAGE_LEN;
            self.page(&parent, next);
            return true;
        }
        self.reveal = None;
        false
    }

    pub(super) fn show(&mut self, ui: &mut egui::Ui, options: &Options<'_>) -> Vec<Event> {
        self.refresh();
        let mut events = Vec::new();
        let mut toggle = None;
        let mut page = None;
        let row_height = ui
            .spacing()
            .interact_size
            .y
            .max(ui.text_style_height(&egui::TextStyle::Body));
        let mono = egui::TextStyle::Monospace.resolve(ui.style());
        let char_width = crate::tree_lines::char_width(ui, &mono);
        let mut area = egui::ScrollArea::both()
            .id_salt("disk_tree")
            .auto_shrink([false, false])
            .max_height(options.height.max(24.0));
        if let Some(index) = self.scroll_to.take() {
            let step = row_height + ui.spacing().item_spacing.y;
            area = area.vertical_scroll_offset((index as f32 * step - 2.0 * step).max(0.0));
        }
        #[cfg(test)]
        let mut drawn = 0;
        area.show_rows(ui, row_height, self.rows.len(), |ui, range| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
            #[cfg(test)]
            {
                drawn += range.len();
            }
            for index in range {
                let id = match &self.rows[index] {
                    Row::Entry { path, .. } => egui::Id::new((path, "entry")),
                    Row::Loading(path, _) => egui::Id::new((path, "loading")),
                    Row::Page { path, .. } => egui::Id::new((path, "page")),
                    Row::Message(..) => egui::Id::new((index, "message")),
                };
                ui.push_id(id, |ui| {
                    let branch = &self.branches[index];
                    crate::tree_lines::row(ui, branch, char_width, |ui| match &self.rows[index] {
                        Row::Entry { path, entry, .. } => {
                            entry_row(
                                ui,
                                path,
                                entry,
                                options,
                                &self.expanded,
                                &mut events,
                                &mut toggle,
                            );
                        }
                        Row::Loading(..) => {
                            theme::spinner(ui);
                            ui.colored_label(theme::muted(), "Reading folder…");
                        }
                        Row::Message(text, _) => {
                            ui.add(
                                egui::Label::new(egui::RichText::new(text).color(theme::muted()))
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
                                page = Some((path.clone(), offset + PAGE_LEN));
                            }
                        }
                    });
                });
            }
        });
        #[cfg(test)]
        {
            self.drawn_rows = drawn;
        }
        if let Some(path) = toggle {
            self.toggle(&path);
            ui.ctx().request_repaint();
        }
        if let Some((path, offset)) = page {
            self.page(&path, offset);
            ui.ctx().request_repaint();
        }
        events
    }
}

fn glyph(kind: DiskEntryKind, open: bool) -> &'static str {
    use egui_phosphor::regular as icon;
    match kind {
        DiskEntryKind::Dir if open => icon::FOLDER_OPEN,
        DiskEntryKind::Dir => icon::FOLDER,
        DiskEntryKind::File => icon::FILE,
        DiskEntryKind::Symlink => icon::LINK,
        DiskEntryKind::CharDev | DiskEntryKind::BlockDev => icon::HARD_DRIVE,
        DiskEntryKind::Fifo => icon::PIPE,
        DiskEntryKind::Socket => icon::PLUGS,
    }
}

fn entry_row(
    ui: &mut egui::Ui,
    path: &str,
    entry: &DiskEntry,
    options: &Options<'_>,
    expanded: &BTreeSet<String>,
    events: &mut Vec<Event>,
    toggle: &mut Option<String>,
) {
    let directory = entry.kind == DiskEntryKind::Dir;
    let open = directory && expanded.contains(path);
    let mut text = format!("{} {}", glyph(entry.kind, open), display_name(&entry.name));
    if directory {
        text.push('/');
    }
    if let Some(target) = &entry.link_target {
        text.push_str(&format!(" → {}", display_name(target)));
    }
    let selected = options.selected == Some(path);
    let enabled = entry.addressable;
    let response = ui.add_enabled(enabled, egui::SelectableLabel::new(selected, text));
    if enabled && response.clicked() {
        if directory {
            *toggle = Some(path.to_owned());
        }
        events.push(Event::Select(path.to_owned()));
    }
    let modes = if options.numeric_modes {
        mode_numeric(entry.mode)
    } else {
        mode_rwx(entry.kind, entry.mode)
    };
    let size = match entry.kind {
        DiskEntryKind::File | DiskEntryKind::Symlink => format_size(entry.size),
        DiskEntryKind::Dir => String::new(),
        _ => "—".into(),
    };
    ui.label(
        egui::RichText::new(format!("{size:>9}  {modes}  {}:{}", entry.uid, entry.gid))
            .monospace()
            .color(theme::muted()),
    );
    if !enabled {
        response.on_disabled_hover_text(
            "The name is not valid UTF-8 (or holds a separator); it cannot be addressed here",
        );
        return;
    }
    response.context_menu(|ui| {
        let mut choose = |ui: &mut egui::Ui, label: &str, enabled: bool, choice: Choice| {
            if ui.add_enabled(enabled, egui::Button::new(label)).clicked() {
                events.push(Event::Menu(path.to_owned(), entry.clone(), choice));
                ui.close_menu();
            }
        };
        let file = matches!(entry.kind, DiskEntryKind::File | DiskEntryKind::Symlink);
        if directory {
            if ui
                .button(if open { "Collapse" } else { "Expand" })
                .clicked()
            {
                *toggle = Some(path.to_owned());
                ui.close_menu();
            }
        } else {
            choose(ui, "Extract to view", file, Choice::ExtractToView);
            choose(ui, "Save to host…", file, Choice::SaveToHost);
            choose(ui, "Open with…", file, Choice::OpenWith);
            choose(
                ui,
                "Hand to Static Analysis",
                entry.kind == DiskEntryKind::File,
                Choice::HandToAnalysis,
            );
        }
        choose(ui, "Copy path", true, Choice::CopyPath);
    });
}
