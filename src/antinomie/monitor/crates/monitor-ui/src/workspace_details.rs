// SPDX-License-Identifier: GPL-3.0-only
//! Which main tab the Details panel follows (moved out of `workspace`).
use super::*;

/// Which main tab the bottom Details panel follows: the syscall trace, the
/// network, memory, disks, history, triage, cores or static analysis panel.
/// When only one is on screen it wins; when several are (split or detached),
/// the one clicked last.
#[derive(Default)]
pub(crate) struct DetailsFollow {
    followed: usize,
    /// Pass of the main window in which each followed panel was last drawn.
    drawn: [Option<u64>; 9],
}

/// What the Details panel shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DetailsOf {
    Syscall,
    Packet,
    MemoryRow,
    History,
    Triage,
    DiskEntry,
    Core,
    Static,
    /// A run of the open sample, selected on the sample window's Runs tab.
    Sample,
}

impl DetailsFollow {
    pub(super) const SIDES: [DetailsOf; 9] = [
        DetailsOf::Syscall,
        DetailsOf::Packet,
        DetailsOf::MemoryRow,
        DetailsOf::History,
        DetailsOf::Triage,
        DetailsOf::DiskEntry,
        DetailsOf::Core,
        DetailsOf::Static,
        DetailsOf::Sample,
    ];

    pub(super) fn side(panel: &Panel) -> Option<usize> {
        match panel {
            Panel::Trace => Some(0),
            Panel::Network => Some(1),
            Panel::Memory => Some(2),
            Panel::RunHistory => Some(3),
            Panel::Triage => Some(4),
            Panel::Disks => Some(5),
            Panel::CoreDump => Some(6),
            Panel::StaticAnalysis | Panel::AnalysisSection { .. } => Some(7),
            Panel::Library(LibraryPage::Samples) => Some(8),
            _ => None,
        }
    }

    /// `panel` was drawn into `ui` this pass.
    pub(crate) fn drawn(&mut self, ui: &egui::Ui, panel: &Panel) {
        let Some(side) = Self::side(panel) else {
            return;
        };
        let now = ui.ctx().cumulative_pass_nr_for(egui::ViewportId::ROOT);
        self.drawn[side] = Some(now);
        // Alone on screen: it stays followed after it is hidden again (by
        // Run History, say).
        let alone = (0..self.drawn.len())
            .filter(|other| *other != side)
            .all(|other| self.drawn[other].is_none_or(|pass| pass + 1 < now));
        let rect = ui.max_rect();
        if alone
            || ui.input(|input| {
                input.pointer.any_pressed()
                    && input
                        .pointer
                        .interact_pos()
                        .is_some_and(|pos| rect.contains(pos))
            })
        {
            self.followed = side;
        }
    }

    /// The user chose `panel`'s tab.
    pub(crate) fn chose(&mut self, panel: &Panel) {
        if let Some(side) = Self::side(panel) {
            self.followed = side;
        }
    }

    /// Whether the panel `of` was drawn in the last pass: its tab is on screen.
    pub(crate) fn on_screen(&self, ctx: &egui::Context, of: DetailsOf) -> bool {
        let now = ctx.cumulative_pass_nr_for(egui::ViewportId::ROOT);
        Self::SIDES
            .iter()
            .position(|side| *side == of)
            .is_some_and(|side| self.drawn[side].is_some_and(|pass| pass + 1 >= now))
    }

    /// What Details show now.
    pub(crate) fn of(&self, ctx: &egui::Context) -> DetailsOf {
        let now = ctx.cumulative_pass_nr_for(egui::ViewportId::ROOT);
        let visible: Vec<usize> = (0..self.drawn.len())
            .filter(|side| self.drawn[*side].is_some_and(|pass| pass + 1 >= now))
            .collect();
        match visible.as_slice() {
            [only] => Self::SIDES[*only],
            _ => Self::SIDES[self.followed],
        }
    }
}
