// SPDX-License-Identifier: GPL-3.0-only
//! Triage › Process › Graph: the tab around the widget. It shares the
//! Suspicious activity filter bar and selection, and turns what the widget
//! asks for into filter text, chips and Details.
use super::filter::Parts;
use super::input::Action;
use super::widget::{self, Config};
use super::*;
use crate::triage::rules::Tier;

impl TriageView {
    pub(in crate::triage) fn graph_tab(&mut self, ui: &mut egui::Ui) {
        let (shown, unplaced) = self.scan.as_ref().map_or((0, 0), |scan| {
            (scan.graph.index.records.len(), scan.graph.index.unplaced)
        });
        let total = shown as u64 + unplaced;
        for note in self.scan.iter().flat_map(|scan| &scan.finding_notes) {
            crate::activity::warning(ui, note.clone());
        }
        self.query_bar(
            ui,
            0,
            FINDING_FIELDS,
            "finding.tier == high",
            (shown, total),
            Bar::Graph,
        );
        let Some(scan) = &self.scan else {
            theme::loading_weak(ui, "Indexing this run’s activity…");
            return;
        };
        let index = &scan.graph.index;
        ui.horizontal_wrapped(|ui| {
            let [high, medium, low, info] = index.tiers;
            ui.colored_label(
                theme::muted(),
                format!(
                    "{shown} findings ({high} high · {medium} medium · {low} low · {info} info) on {} lanes. Wheel scrolls lanes, Shift+wheel or drag pans, Ctrl+wheel zooms, drag the axis to filter by time.",
                    index.lanes.list.len().saturating_sub(1)
                ),
            );
            if unplaced > 0 {
                ui.colored_label(
                    theme::warn(),
                    format!("{unplaced} findings without a time are not on the graph."),
                );
            }
        });
        // The selection is the table's: follow it when it changed there.
        let selected_key = self.selected_call_id;
        let current = self
            .graph
            .selected
            .and_then(|record| index.rows.get(record))
            .map(|row| row.key);
        if current != selected_key {
            self.graph.selected = selected_key.and_then(|key| index.first_with_key(key));
        }
        // The brush is whatever the filter holds.
        self.graph.brush = Parts::parse(&self.filter_drafts[0]).brush;
        if index.is_empty() {
            ui.add_space(10.0);
            ui.weak("Nothing to chart: no finding in the current filter has a time.");
            return;
        }
        let config = Config {
            index,
            colors: super::paint::Colors::current(),
            clock: scan.clock_anchor.or(self.scan_request.clock_anchor),
            height: ui.available_height(),
        };
        let actions = widget::show(ui, &mut self.graph, &config);
        self.apply_graph_actions(ui.ctx(), actions);
    }

    /// Carry out what the widget asked for.
    pub(in crate::triage) fn apply_graph_actions(
        &mut self,
        ctx: &egui::Context,
        actions: Vec<Action>,
    ) {
        for action in actions {
            match action {
                Action::Select { record, focus } => self.graph_select(ctx, record, focus),
                Action::Open(record) => {
                    if let Some(row) = self
                        .scan
                        .as_ref()
                        .and_then(|scan| scan.graph.index.rows.get(record))
                    {
                        request_evidence_jump(ctx, &row.values);
                    }
                }
                Action::Brush(from, to) => {
                    let mut parts = Parts::parse(&self.filter_drafts[0]);
                    parts.brush = Some((from, to));
                    self.set_filter(ctx, &parts);
                }
                Action::ClearBrush => {
                    let mut parts = Parts::parse(&self.filter_drafts[0]);
                    parts.brush = None;
                    self.set_filter(ctx, &parts);
                }
                Action::Lane { cookies } => {
                    let mut parts = Parts::parse(&self.filter_drafts[0]);
                    // A second click on the same lane lifts the lane filter.
                    parts.cookies = if parts.cookies == cookies {
                        Vec::new()
                    } else {
                        cookies
                    };
                    self.set_filter(ctx, &parts);
                }
                Action::Tier(tier) => self.toggle_tier_chip(tier),
                Action::Category(category) => self.toggle_category_chip(category),
            }
        }
    }

    fn graph_select(&mut self, ctx: &egui::Context, record: usize, focus: bool) {
        let Some(row) = self
            .scan
            .as_ref()
            .and_then(|scan| scan.graph.index.rows.get(record))
        else {
            return;
        };
        let (key, cells) = (row.key, {
            let mut cells = row.cells.clone();
            if let Some(first) = cells.first_mut() {
                first.values.clone_from(&row.values);
            }
            cells
        });
        self.selected_call_id = Some(key);
        self.table_focus = Some(key);
        details::select(ctx, "triage-findings", rules::HEADERS, &cells);
        if focus {
            details::clicked(ctx, "triage-findings");
        }
    }

    /// Put `parts` in the filter bar; the next frame's query bar applies it.
    fn set_filter(&mut self, ctx: &egui::Context, parts: &Parts) {
        let text = parts.render();
        self.filter_drafts[0].clone_from(&text);
        ctx.data_mut(|data| data.insert_temp(egui::Id::new(("triage-filter-draft", 0usize)), text));
        ctx.request_repaint();
    }

    /// A tier chip, as a click on the chip itself does it. INFO is the Show INFO switch.
    pub(in crate::triage) fn toggle_tier_chip(&mut self, tier: Tier) {
        let view = &mut self.scan_request.finding_view;
        if tier == Tier::Info {
            view.show_info = !view.show_info;
        } else if view.tiers == 0 {
            view.tiers = 1 << tier.index();
        } else {
            view.toggle_tier(tier);
        }
        self.scan_request.offsets[0] = 0;
        self.request_query_refresh();
    }

    pub(in crate::triage) fn toggle_category_chip(&mut self, category: rules::Category) {
        self.scan_request.finding_view.toggle_category(category);
        self.scan_request.offsets[0] = 0;
        self.request_query_refresh();
    }
}
