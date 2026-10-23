// SPDX-License-Identifier: GPL-3.0-only
//! The chips above Suspicious activity: tiers, categories, Show INFO and Show hidden.
use super::rules::{Category, Tier};
use super::*;

impl TriageView {
    /// Chips that narrow the table. With none of a group selected the whole
    /// group shows; a click selects one and further clicks add to or remove from it.
    pub(super) fn finding_chips(&mut self, ui: &mut egui::Ui) {
        use crate::widgets::toggle_chip;
        let counts = self.scan.as_ref().map(|scan| scan.counts.finding_tiers);
        let hidden = self
            .scan
            .as_ref()
            .map_or(0, |scan| scan.counts.findings_hidden);
        let capped = self
            .scan
            .as_ref()
            .map_or(0, |scan| scan.counts.findings_capped);
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
            if toggle_chip(ui, category.chip(), on, None)
                .on_hover_text(category.label())
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
            .on_hover_text("Rows hidden as VM housekeeping or because the process is outside the run, which a cap or an allow-list never hides. Capped rows are counted in a \"+N more\" row.")
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
