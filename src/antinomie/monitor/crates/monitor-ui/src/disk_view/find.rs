// SPDX-License-Identifier: MIT
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
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Path => "Path",
            Self::Glob => "Glob",
        }
    }

    fn mode(self) -> FindMode {
        match self {
            Self::Name => FindMode::Name,
            Self::Path => FindMode::Path,
            Self::Glob => FindMode::Glob,
        }
    }
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
                    .hint_text("name, path or *.glob"),
            );
            egui::ComboBox::from_id_salt("disk_find_mode")
                .selected_text(self.find.mode.label())
                .width(70.0)
                .show_ui(ui, |ui| {
                    for mode in [Mode::Name, Mode::Path, Mode::Glob] {
                        ui.selectable_value(&mut self.find.mode, mode, mode.label());
                    }
                });
            let enter = edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            let can = !self.find.query.trim().is_empty() && !self.find.running;
            if ui
                .add_enabled(can, egui::Button::new("Find"))
                .on_hover_text("Search the whole disk by name, path or glob")
                .clicked()
                || (enter && can)
            {
                start = true;
            }
            if self.find.running {
                theme::spinner(ui);
                ui.colored_label(theme::muted(), "Searching…");
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
        self.find_results(ui);
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
        for (shown, note) in [
            (
                found.truncated,
                "More matches exist than the limit returned; narrow the search.",
            ),
            (
                found.timed_out,
                "The search time limit ended it; narrow the search.",
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
