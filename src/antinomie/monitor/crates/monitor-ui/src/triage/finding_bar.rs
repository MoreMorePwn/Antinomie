// SPDX-License-Identifier: GPL-3.0-only
//! The chips above Suspicious activity: tiers, categories, Show INFO and Show hidden.
use super::rules::{Category, Tier, SUPPRESSION_VERSION};
use super::*;

impl TriageView {
    /// Chips that narrow the table. With none of a group selected the whole
    /// group shows; a click selects one and further clicks add to or remove from it.
    pub(super) fn finding_chips(&mut self, ui: &mut egui::Ui) {
        use crate::widgets::{toggle_chip, toggle_chip_with};
        let counts = self.scan.as_ref().map(|scan| scan.counts.finding_tiers);
        let hidden = self
            .scan
            .as_ref()
            .map_or(0, |scan| scan.counts.findings_hidden);
        let capped = self
            .scan
            .as_ref()
            .map_or(0, |scan| scan.counts.findings_capped);
        let suppressed = self
            .scan
            .as_ref()
            .map_or(0, |scan| scan.counts.findings_suppressed);
        let view = &mut self.scan_request.finding_view;
        let mut changed = false;
        for tier in [Tier::High, Tier::Medium, Tier::Low] {
            let on = view.tiers == 0 || view.tier_on(tier);
            let label = tier.tag().to_uppercase();
            if toggle_chip(ui, &label, on, counts.map(|counts| counts[tier.index()]))
                .on_hover_text("Rows of this tier. Click to show only this tier; click again to add or remove tiers.")
                .clicked()
            {
                if view.tiers == 0 {
                    view.tiers = 1 << tier.index();
                } else {
                    view.toggle_tier(tier);
                }
                changed = true;
            }
        }
        let info = counts.map(|counts| counts[Tier::Info.index()]);
        if toggle_chip(ui, "Show INFO", view.show_info, info)
            .on_hover_text("INFO matches are always counted; their rows are built only when this is on. The calls stay in the recording either way.")
            .clicked()
        {
            view.show_info = !view.show_info;
            changed = true;
        }
        ui.separator();
        for category in Category::ALL {
            let on = view.categories == 0 || view.category_on(category);
            // The category's own icon where the others have a check mark: the
            // same one its markers and heat row carry in the graph.
            let icon = super::graph::category_icon(category);
            let hover = if category == Category::Evasion {
                format!(
                    "{}\nEvasion lists the checks made through system calls and the answer each got. CPUID and RDTSC run inside the program and leave no call, so they are not visible here.",
                    category.label()
                )
            } else {
                category.label().to_owned()
            };
            if toggle_chip_with(ui, icon, category.chip(), on, None)
                .on_hover_text(hover)
                .clicked()
            {
                if view.categories == 0 {
                    view.categories = 0;
                    view.toggle_category(category);
                } else {
                    view.toggle_category(category);
                }
                changed = true;
            }
        }
        ui.separator();
        let hidden_label = if capped > 0 {
            "Show hidden / capped"
        } else {
            "Show hidden"
        };
        if toggle_chip(ui, hidden_label, view.show_hidden, Some(hidden))
            .on_hover_text(format!(
                "Rows hidden because the process is outside the run's tree. {suppressed} frames of VM housekeeping (time sync, mirrors, link-local discovery) were skipped by the built-in suppression list, version {}; they are counted, not listed. Capped rows are counted in a \"+N more\" row.",
                SUPPRESSION_VERSION
            ))
            .clicked()
        {
            view.show_hidden = !view.show_hidden;
            changed = true;
        }
        if changed {
            self.scan_request.offsets[0] = 0;
            self.request_query_refresh();
        }
    }
}
