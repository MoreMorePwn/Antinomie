// SPDX-License-Identifier: GPL-3.0-only
//! The activity graph: the Suspicious activity findings on process swimlanes
//! against time, with the severity curve, the category heat strip and the
//! phases of the run.
//!
//! The scan worker builds a [`GraphIndex`] from the same rows the Suspicious
//! table filters, so the graph shows exactly the table's set. The widget in
//! [`widget`] is custom-painted and returns [`Action`]s; this module applies
//! them to the Triage view (selection, Details, the shared filter and chips).
use super::*;

mod axis;
mod filter;
mod index;
mod input;
mod lanes;
mod legend;
mod notify;
mod paint;
mod phases;
mod ruler;
mod strip;
mod tab;
mod view;
mod widget;
mod window;

/// The icon the graph draws for a finding category.
pub(super) fn category_icon(category: rules::Category) -> &'static str {
    paint::icon(category.index() as u8)
}

#[cfg(test)]
mod bench;
#[cfg(test)]
mod fill_tests;
#[cfg(test)]
mod spacing_tests;
#[cfg(test)]
mod sync_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod window_tests;

pub(crate) use axis::Spacing;
pub(super) use index::{Builder, GraphIndex};
pub(super) use lanes::Lanes;
pub(super) use notify::{HighRule, HighWatch};
pub(super) use strip::Strip;
pub(super) use view::State;
pub(super) use window::{Window, DEFAULT_SIZE};

/// What one scan hands the UI for the graph.
#[derive(Default)]
pub(super) struct GraphScan {
    /// The findings the Suspicious table is filtered to, on lanes.
    pub index: GraphIndex,
    /// The run as the default view shows it, without lanes: the Summary strip.
    pub overview: GraphIndex,
    /// HIGH rules with a visible row, for the live toast.
    pub high: Vec<HighRule>,
}

/// Feeds the rows of one scan into the index and the overview.
pub(super) struct Collector {
    index: Builder,
    overview: Builder,
    high: notify::HighRules,
    /// Which rows the overview takes: the default view with the chips' INFO choice.
    view: rules::View,
}

impl Collector {
    pub(super) fn new(nodes: &[ProcessNode], view: rules::View) -> Self {
        Self {
            index: Builder::new(Lanes::from_processes(nodes)),
            overview: Builder::overview(),
            high: notify::HighRules::default(),
            view: rules::View {
                show_info: view.show_info,
                ..rules::View::default()
            },
        }
    }

    /// One row of the engine's output. `in_table` is whether the chips and the
    /// filter keep it.
    pub(super) fn push(&mut self, finding: &Finding, in_table: bool) {
        if in_table {
            self.index.push(finding);
        }
        if rules::view_keeps(&self.view, &finding.values) {
            self.overview.push(finding);
            self.high.observe(finding);
        }
    }

    /// INFO matches counted without rows feed the phases when INFO is not
    /// filtered out by the tier chips or the category chips.
    pub(super) fn count_info(&mut self, view: &rules::View, mark: &rules::InfoMark) {
        let tier_ok = view.tiers == 0 || view.tier_on(rules::Tier::Info);
        let category_ok = view.categories == 0 || view.category_on(mark.category);
        if tier_ok && category_ok {
            self.index
                .count_info(mark.ns, mark.count, mark.rule, mark.category);
        }
        self.overview
            .count_info(mark.ns, mark.count, mark.rule, mark.category);
    }

    pub(super) fn finish(self) -> GraphScan {
        GraphScan {
            index: self.index.finish(),
            overview: self.overview.finish(),
            high: self.high.finish(),
        }
    }
}
