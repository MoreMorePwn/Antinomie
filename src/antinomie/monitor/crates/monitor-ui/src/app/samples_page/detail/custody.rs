// SPDX-License-Identifier: GPL-3.0-only
//! The Custody log tab: the sample's hash chain with its verify banner, a
//! check mark per entry and the head hash to copy. The log is tamper-evident,
//! not tamper-proof; the banner says so.
use super::{parts, *};
use crate::widgets::fit_table::{Col, FitBuilder};
use crate::{app::samples_page::custody_parts, widgets::fit_table};

/// What the tab asks of the window.
pub(super) enum Outcome {
    None,
    /// Read the log again and recheck it.
    Verify,
}

/// `scroll_to`: the number of the entry to bring to the middle of the table.
pub(super) fn show(
    ui: &mut egui::Ui,
    data: &Data,
    font: f32,
    verifying: bool,
    scroll_to: Option<u64>,
) -> Outcome {
    let verify = custody_parts::banner(ui, &data.chain, verifying);
    ui.add_space(4.0);
    if data.events.is_empty() {
        theme::empty_state(ui, "No events recorded for this sample.");
        return if verify {
            Outcome::Verify
        } else {
            Outcome::None
        };
    }
    let height = ui.available_height().max(80.0);
    let mono = egui::TextStyle::Monospace.resolve(ui.style());
    let time = parts::fitted(
        ui,
        &mono,
        data.events.iter().map(|event| parts::second(event.at_ms)),
    );
    let mut builder = FitBuilder::new(ui)
        .id_salt("sample_custody")
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Col::fixed(44.0))
        .column(Col::fixed(time))
        .column(Col::fixed(130.0))
        .column(Col::fixed(80.0))
        .column(Col::rest(80.0).at_least(160.0).clip(true))
        .column(Col::fixed(120.0))
        .max_scroll_height(height)
        .min_scrolled_height(0.0);
    if let Some(at) = scroll_to.and_then(|seq| data.events.iter().position(|e| e.seq == seq)) {
        builder = builder.scroll_to_row(at, Some(egui::Align::Center));
    }
    builder
        .header(fit_table::header_height(font), |mut header| {
            for title in ["#", "Time", "Event", "By", "Detail", "Check"] {
                header.col(|ui| fit_table::head(ui, title));
            }
        })
        .body(|body| {
            body.rows(fit_table::row_height(font), data.events.len(), |mut row| {
                let index = row.index();
                let event = &data.events[index];
                let state = data.chain.state_of(event.seq);
                row.col(|ui| {
                    fit_table::cell(ui, fit_table::Cell::Number, &event.seq.to_string());
                });
                row.col(|ui| {
                    fit_table::cell(ui, fit_table::Cell::Mono, &parts::second(event.at_ms));
                });
                row.col(|ui| {
                    fit_table::cell_rich(
                        ui,
                        fit_table::Cell::Text,
                        RichText::new(event.event.label()).strong(),
                    );
                });
                row.col(|ui| {
                    fit_table::cell(ui, fit_table::Cell::Text, &event.by);
                });
                row.col(|ui| {
                    let mut detail = event.event.detail();
                    if event.before_chain {
                        detail.push_str(" (recorded before the custody log)");
                    }
                    fit_table::cell(ui, fit_table::Cell::Text, &detail).on_hover_text(&detail);
                });
                row.col(|ui| {
                    custody_parts::check_mark(ui, state, &event.prev, &event.hash);
                });
                row.response().context_menu(|ui| {
                    crate::app::samples_page::notes::menu_item(ui, || {
                        antinomie_monitor_core::samples::NoteRef::new(
                            antinomie_monitor_core::samples::RefKind::Custody,
                            event.seq.to_string(),
                            format!("Custody entry {} · {}", event.seq, event.event.label()),
                        )
                    });
                });
            });
        });
    if verify {
        Outcome::Verify
    } else {
        Outcome::None
    }
}
