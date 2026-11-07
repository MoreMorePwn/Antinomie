// SPDX-License-Identifier: GPL-3.0-only
//! The cells of the Suspicious activity table that are more than text: the tier
//! chip with its meaning, the process link and the technique chip. A click that
//! leaves the table is left as a request the view answers after the frame.
use super::rules::{self, Tier};
use super::*;
use crate::widgets::{chip, Tone};

/// `(pid, task cookie)` of a process a cell asks to open in Details.
pub(super) const OPEN_PROCESS: &str = "triage-finding-open-process";
/// A technique id a cell asks to filter the table by.
pub(super) const FILTER_TECHNIQUE: &str = "triage-finding-filter-technique";

/// The text a cell carries for its hover.
pub(super) fn tip(cell: &Cell) -> Option<&str> {
    cell.values.iter().find_map(|(key, value)| match value {
        RowValue::Text(text) if *key == rules::TIP => Some(text.as_str()),
        _ => None,
    })
}

fn limited(cell: &Cell) -> Option<&str> {
    cell.values.iter().find_map(|(key, value)| match value {
        RowValue::Text(text) if *key == rules::LIMITED => Some(text.as_str()),
        _ => None,
    })
}

/// Draw one cell of a finding row. `Some(true)` is not needed: the cells that
/// click leave a request in the context.
pub(super) fn draw(ui: &mut egui::Ui, column: usize, finding: &Finding, cell: &Cell) {
    match column {
        rules::COL_TIER => tier(ui, cell),
        rules::COL_PROCESS => process(ui, finding, cell),
        rules::COL_ATTACK => technique(ui, finding, cell),
        _ => plain(ui, cell),
    }
}

fn plain(ui: &mut egui::Ui, cell: &Cell) {
    let mut text = RichText::new(table::display_text(&cell.text)).color(cell.color());
    if cell.mono {
        text = text.monospace();
    }
    let label = ui.add(
        egui::Label::new(text)
            .truncate()
            .selectable(false)
            .sense(egui::Sense::hover()),
    );
    if let Some(tip) = tip(cell) {
        label.on_hover_text(tip);
    }
}

fn tier(ui: &mut egui::Ui, cell: &Cell) {
    let tier = Tier::from_tag(&cell.text).unwrap_or(Tier::Info);
    let chip = chip(ui, tier.letter(), tier.tone().into());
    if let Some(tip) = tip(cell) {
        chip.on_hover_text(tip);
    }
    if let Some(reason) = limited(cell) {
        ui.label(RichText::new(egui_phosphor::regular::FLAG).color(theme::warn()))
            .on_hover_text(format!("Limited confidence: {reason}"));
    }
}

fn process(ui: &mut egui::Ui, finding: &Finding, cell: &Cell) {
    let pid = files::number(&finding.values, "process.pid").unwrap_or(0);
    let cookie = files::number(&finding.values, "process.cookie").unwrap_or(0);
    let opens = pid != 0 && cookie != 0;
    let mut text = RichText::new(&cell.text).color(if opens {
        ui.visuals().hyperlink_color
    } else {
        cell.color()
    });
    if cell.mono {
        text = text.monospace();
    }
    let label = egui::Label::new(text)
        .truncate()
        .selectable(false)
        .sense(if opens {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        });
    let response = ui.add(label);
    let hover = match (tip(cell), opens) {
        (Some(note), true) => format!("{note}\n\nClick to open this process in Details."),
        (Some(note), false) => note.to_owned(),
        (None, true) => "Click to open this process in Details.".to_owned(),
        (None, false) => String::new(),
    };
    let response = if hover.is_empty() {
        response
    } else {
        response.on_hover_text(hover)
    };
    if opens
        && response
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
    {
        ui.ctx()
            .data_mut(|data| data.insert_temp(egui::Id::new(OPEN_PROCESS), (pid as u32, cookie)));
    }
}

/// The first technique id of a row, for the click on its chip.
fn first_technique(finding: &Finding) -> Option<String> {
    finding.values.iter().find_map(|(key, value)| match value {
        RowValue::List(ids) if *key == "finding.technique" => ids
            .iter()
            .find(|id| id.starts_with('T') && !id.starts_with("TA"))
            .cloned(),
        _ => None,
    })
}

fn technique(ui: &mut egui::Ui, finding: &Finding, cell: &Cell) {
    let Some(id) = first_technique(finding) else {
        plain(ui, cell);
        return;
    };
    let shown = chip(ui, cell.text.clone(), Tone::Accent);
    let response = ui.interact(
        shown.rect,
        shown.id.with("filter-technique"),
        egui::Sense::click(),
    );
    let names = tip(cell).unwrap_or_default();
    let response = response
        .on_hover_text(format!(
            "{names}\n\nClick to list the rows of Suspicious activity that cite {id}."
        ))
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    if response.clicked() {
        ui.ctx()
            .data_mut(|data| data.insert_temp(egui::Id::new(FILTER_TECHNIQUE), id));
    }
}

impl TriageView {
    /// The first moment of the run, the zero of the `When` column: when its
    /// first task was first seen.
    pub(super) fn run_start(&self) -> Option<u64> {
        self.scan
            .as_ref()
            .and_then(|scan| scan.process.iter().filter_map(|node| node.first_ns).min())
    }

    /// Answer what a cell of the table asked for: open a process, or list the
    /// rows of a technique.
    pub(super) fn finding_requests(&mut self, ctx: &egui::Context) {
        let process =
            ctx.data_mut(|data| data.remove_temp::<(u32, u64)>(egui::Id::new(OPEN_PROCESS)));
        if let Some((pid, cookie)) = process {
            process_details::open_process(self, ctx, pid, cookie);
        }
        let technique =
            ctx.data_mut(|data| data.remove_temp::<String>(egui::Id::new(FILTER_TECHNIQUE)));
        if let Some(id) = technique {
            self.filter_findings_by_technique(ctx, &id);
        }
    }
}
