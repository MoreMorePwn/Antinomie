// SPDX-License-Identifier: GPL-3.0-only
//! The lines of the Call rate graph (design 2.4): all calls, failed calls, a
//! group, or a custom filter. At most four lines. The first three kinds come
//! from the bins the main walk already made; a custom line costs one more walk
//! (`RateOnly`), started by the window.
use super::navigate::{self, FAILED};
use antinomie_monitor_core::syscall_groups::SyscallGroup;
use eframe::egui;

/// Most lines on the graph.
pub(super) const MAX_LINES: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum LineKind {
    All,
    Failed,
    /// A group by its label (`Other` included).
    Group(String),
    /// A filter in the Trace's language, added to the window's filter.
    Custom(String),
}

impl LineKind {
    /// The words on the legend chip.
    pub(super) fn label(&self) -> String {
        match self {
            Self::All => "All calls".into(),
            Self::Failed => "Failed calls".into(),
            Self::Group(label) | Self::Custom(label) => label.clone(),
        }
    }

    /// The name of the engine series this line reads.
    pub(super) fn series(&self) -> &str {
        match self {
            Self::All => "all",
            Self::Failed => "failed",
            Self::Group(label) | Self::Custom(label) => label,
        }
    }

    /// The Trace clause that selects this line's calls; empty for all calls.
    pub(super) fn clause(&self) -> String {
        match self {
            Self::All => String::new(),
            Self::Failed => FAILED.into(),
            Self::Group(label) => navigate::group_clause(label),
            Self::Custom(filter) => format!("({filter})"),
        }
    }

    /// The group a click must ask about when the Trace hides it.
    pub(super) fn group(&self) -> Option<SyscallGroup> {
        match self {
            Self::Group(label) => SyscallGroup::ALL.into_iter().find(|g| g.label() == label),
            _ => None,
        }
    }

    pub(super) fn custom(&self) -> Option<&str> {
        match self {
            Self::Custom(filter) => Some(filter),
            _ => None,
        }
    }
}

pub(super) struct Lines {
    pub(super) list: Vec<LineKind>,
    /// The custom filter being typed.
    pub(super) draft: String,
    /// Why the last add was refused.
    pub(super) message: Option<String>,
}

impl Default for Lines {
    fn default() -> Self {
        Self {
            list: vec![LineKind::All],
            draft: String::new(),
            message: None,
        }
    }
}

impl Lines {
    /// Add a line; a fifth, a repeat and a custom filter that does not compile are refused.
    pub(super) fn add(&mut self, kind: LineKind) -> Result<(), String> {
        let refused = if self.list.len() >= MAX_LINES {
            Some(format!("At most {MAX_LINES} lines. Remove one first."))
        } else if self.list.contains(&kind) {
            Some("That line is already on the graph.".to_owned())
        } else if let LineKind::Custom(filter) = &kind {
            if filter.trim().is_empty() {
                Some("Type a filter for the line.".to_owned())
            } else {
                crate::query::compile_note(filter).error
            }
        } else {
            None
        };
        match refused {
            Some(message) => {
                self.message = Some(message.clone());
                Err(message)
            }
            None => {
                self.message = None;
                self.list.push(kind);
                Ok(())
            }
        }
    }

    pub(super) fn remove(&mut self, index: usize) {
        if index < self.list.len() {
            self.list.remove(index);
            self.message = None;
        }
    }

    /// The custom filters, in line order: what the extra walk reads.
    pub(super) fn customs(&self) -> Vec<String> {
        self.list
            .iter()
            .filter_map(|line| line.custom().map(str::to_owned))
            .collect()
    }

    /// The "+ Line" menu and the legend chips' remove buttons.
    pub(super) fn edit(&mut self, ui: &mut egui::Ui, groups: &[String]) {
        let mut add = None;
        ui.menu_button("+ Line", |ui| {
            if ui.button("Failed calls").clicked() {
                add = Some(LineKind::Failed);
                ui.close();
            }
            if ui.button("All calls").clicked() {
                add = Some(LineKind::All);
                ui.close();
            }
            ui.menu_button("A group", |ui| {
                for label in groups {
                    if ui.button(label).clicked() {
                        add = Some(LineKind::Group(label.clone()));
                        ui.close();
                    }
                }
            });
            ui.separator();
            ui.label("Custom filter");
            let response = crate::query::filter_edit(
                ui,
                &mut self.draft,
                "syscall.name == connect",
                260.0,
                crate::query::FilterScope::Syscall,
            );
            let enter =
                response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            if ui.button("Add line").clicked() || enter {
                add = Some(LineKind::Custom(self.draft.trim().to_owned()));
                ui.close();
            }
        });
        if let Some(kind) = add {
            if self.add(kind.clone()).is_ok() && matches!(kind, LineKind::Custom(_)) {
                self.draft.clear();
            }
        }
    }
}
