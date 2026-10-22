// SPDX-License-Identifier: GPL-3.0-only
//! Find: name, path or glob search over the whole tree, run by the reader
//! (bounded in matches, entries and time) so the interface stays responsive.
use super::*;
use crate::theme;
use antinomie_monitor_core::disks::reader::{FindMode, FindQuery};

#[derive(Default)]
pub(super) struct Find {
    pub query: String,
    pub mode: Mode,
    pub running: bool,
    pub results: Option<Result<FindResults, String>>,
    pub current: usize,
    /// Reveal the first match when the answer arrives.
    reveal_first: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Mode {
    #[default]
    Name,
    Path,
    Glob,
    /// The bytes of files contain the text.
    Content,
    /// [`Self::Content`], ASCII letters in any case.
    ContentAnyCase,
}

impl Mode {
    pub(super) const ALL: [Self; 5] = [
        Self::Name,
        Self::Path,
        Self::Glob,
        Self::Content,
        Self::ContentAnyCase,
    ];

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Path => "Path",
            Self::Glob => "Glob",
            Self::Content => "Content",
            Self::ContentAnyCase => "Content (any case)",
        }
    }

    fn mode(self) -> FindMode {
        match self {
            Self::Name => FindMode::Name,
            Self::Path => FindMode::Path,
            Self::Glob => FindMode::Glob,
            Self::Content => FindMode::Content,
            Self::ContentAnyCase => FindMode::ContentAnyCase,
        }
    }

    pub(super) fn is_content(self) -> bool {
        matches!(self, Self::Content | Self::ContentAnyCase)
    }
}

/// What a content search reads, in words (the reader's limits).
fn content_limits_note() -> String {
    use antinomie_monitor_core::disks::reader::{
        CONTENT_FILE_LIMIT, CONTENT_SECONDS, CONTENT_TOTAL_LIMIT,
    };
    format!(
        "Content search reads regular files: at most the first {} of each, {} in all, for up to \
         {CONTENT_SECONDS} s. Longer files and later files are not searched.",
        format_size(CONTENT_FILE_LIMIT),
        format_size(CONTENT_TOTAL_LIMIT)
    )
}

impl Find {
    pub(super) fn finished(&mut self, results: Result<FindResults, String>) {
        self.running = false;
        self.current = 0;
        self.reveal_first = results
            .as_ref()
            .is_ok_and(|found| !found.matches.is_empty());
        self.results = Some(results);
    }
}

impl DiskView {
    pub(super) fn find_bar(&mut self, ui: &mut egui::Ui) {
        let mut start = false;
        ui.horizontal(|ui| {
            ui.label("Find:");
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.find.query)
                    .desired_width(220.0)
                    .hint_text(if self.find.mode.is_content() {
                        "text inside files (2–256 bytes)"
                    } else {
                        "name, path or *.glob"
                    }),
            );
            egui::ComboBox::from_id_salt("disk_find_mode")
                .selected_text(self.find.mode.label())
                .width(130.0)
                .show_ui(ui, |ui| {
                    for mode in Mode::ALL {
                        ui.selectable_value(&mut self.find.mode, mode, mode.label());
                    }
                });
            let enter = edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            let can = !self.find.query.trim().is_empty() && !self.find.running;
            if ui
                .add_enabled(can, egui::Button::new("Find"))
                .on_hover_text("Search the whole disk by name, path, glob or file content")
                .clicked()
                || (enter && can)
            {
                start = true;
            }
            if self.find.running {
                theme::spinner(ui);
                ui.colored_label(theme::muted(), "Searching…");
                if ui
                    .button("Cancel")
                    .on_hover_text("Stop the search; nothing is kept")
                    .clicked()
                {
                    self.cancel_find();
                }
            }
            if self.find.results.is_some()
                && ui.add(egui::Button::new("Clear").frame(false)).clicked()
            {
                self.find = find::Find::default();
            }
        });
        if start {
            let query = FindQuery {
                pattern: self.find.query.trim().to_owned(),
                mode: self.find.mode.mode(),
            };
            self.find.running = true;
            self.find.results = None;
            self.queue_search(Purpose::Find, DiskRequest::Find { query }, None);
        }
        if self.find.mode.is_content() {
            ui.add(
                egui::Label::new(egui::RichText::new(content_limits_note()).color(theme::muted()))
                    .wrap(),
            );
        }
        self.find_results(ui);
    }

    /// Stop a running search: its reader is killed and a fresh one starts
    /// with the next request. The tree and its reader are not touched.
    pub(super) fn cancel_find(&mut self) {
        self.search = None;
        self.search_queue.clear();
        self.purposes
            .retain(|_, purpose| !matches!(purpose, Purpose::Find));
        self.find.running = false;
        self.find.results = None;
        self.restart_search = true;
    }

    fn find_results(&mut self, ui: &mut egui::Ui) {
        let Some(results) = &self.find.results else {
            return;
        };
        let found = match results {
            Err(error) => {
                crate::activity::error(ui, error);
                return;
            }
            Ok(found) => found.clone(),
        };
        let count = found.matches.len();
        let mut go = None;
        ui.horizontal(|ui| {
            ui.label(format!(
                "{count} match{}",
                if count == 1 { "" } else { "es" }
            ));
            if count > 0 {
                if ui.small_button("‹").clicked() {
                    go = Some((self.find.current + count - 1) % count);
                }
                ui.label(format!("{}/{count}", self.find.current + 1));
                if ui.small_button("›").clicked() {
                    go = Some((self.find.current + 1) % count);
                }
                if let Some(hit) = found.matches.get(self.find.current) {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(display_name(&hit.path))
                                .monospace()
                                .color(theme::muted()),
                        )
                        .truncate(),
                    );
                }
            }
        });
        if let Some(hit) = found.matches.get(self.find.current) {
            if let (Some(offset), Some(snippet)) = (hit.offset, &hit.snippet) {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(format!("at byte {offset}: {snippet}"))
                            .monospace()
                            .color(theme::text()),
                    )
                    .truncate(),
                );
            }
        }
        if found.files_read > 0 {
            ui.colored_label(
                theme::muted(),
                format!(
                    "{} files read, {}{}",
                    found.files_read,
                    format_size(found.bytes_read),
                    if found.partial_files > 0 {
                        format!(
                            ", {} larger than the per-file limit searched in part",
                            found.partial_files
                        )
                    } else {
                        String::new()
                    }
                ),
            );
        }
        for (shown, note) in [
            (
                found.truncated,
                "More matches exist than the limit returned; narrow the search.",
            ),
            (
                found.timed_out,
                "The search time limit ended it; narrow the search.",
            ),
            (
                found.byte_limit_reached,
                "The limit on bytes read ended the search; files not yet read were not searched.",
            ),
        ] {
            if shown {
                crate::activity::warning(ui, note);
            }
        }
        if self.find.reveal_first {
            self.find.reveal_first = false;
            go = Some(0);
        }
        if let Some(index) = go {
            self.find.current = index;
            if let Some(hit) = found.matches.get(index) {
                self.tree.reveal(&hit.path);
                self.select(hit.path.clone());
            }
        }
    }
}
