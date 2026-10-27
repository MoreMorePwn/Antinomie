// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's Similar samples: library samples close to this one by TLSH
//! distance, with what they share (imports for ELF files, strings otherwise).
//! The comparison reads archives, so it runs on a worker thread once per
//! window; parents and children are left out, the lineage graph shows them.
use super::{parts, *};
use crate::widgets::table;
use antinomie_monitor_core::samples::Similar;
use std::collections::HashSet;

#[derive(Default)]
pub(super) enum State {
    /// Not asked for yet.
    #[default]
    Idle,
    Reading(Receiver<Result<Vec<Similar>, String>>),
    Done(Vec<Similar>),
    Failed(String),
}

impl State {
    /// Compare on a worker thread, once.
    pub(super) fn start(&mut self, ctx: &egui::Context, data_dir: &std::path::Path, data: &Data) {
        if !matches!(self, State::Idle) {
            return;
        }
        if data.record.tlsh.is_empty() {
            *self = State::Failed("too small or too uniform for a similarity hash".into());
            return;
        }
        let exclude: HashSet<String> = data
            .links
            .iter()
            .flat_map(|link| [link.parent.clone(), link.child.clone()])
            .collect();
        let (sender, receiver) = std::sync::mpsc::channel();
        let (data_dir, sha256, wake) = (
            data_dir.to_path_buf(),
            data.record.sha256.clone(),
            ctx.clone(),
        );
        *self = match std::thread::Builder::new()
            .name("sample-similar".into())
            .spawn(move || {
                let _ = sender.send(
                    Library::open(&data_dir)
                        .and_then(|library| library.similar_to(&sha256, &exclude)),
                );
                wake.request_repaint();
            }) {
            Ok(_) => State::Reading(receiver),
            Err(error) => State::Failed(error.to_string()),
        };
    }

    pub(super) fn poll(&mut self) {
        let State::Reading(receiver) = self else {
            return;
        };
        if let Ok(result) = receiver.try_recv() {
            *self = match result {
                Ok(found) => State::Done(found),
                Err(error) => State::Failed(error),
            };
        }
    }

    #[cfg(test)]
    pub(super) fn rows(&self) -> Option<&[Similar]> {
        match self {
            State::Done(found) => Some(found),
            _ => None,
        }
    }
}

/// Draw the section; returns the sample whose row was clicked.
pub(super) fn section(ui: &mut egui::Ui, state: &State, font: f32) -> Option<String> {
    let mut open = None;
    let count = match state {
        State::Done(found) => Some(found.len()),
        _ => None,
    };
    parts::section(ui, "Similar samples", count, |ui| match state {
        State::Idle | State::Reading(_) => {
            theme::spinner(ui);
        }
        State::Failed(why) => parts::muted_line(ui, &format!("Not compared: {why}.")),
        State::Done(found) if found.is_empty() => {
            parts::muted_line(ui, "No other sample in the library is close to this one.");
        }
        State::Done(found) => {
            parts::mini_table(ui, "sample_summary_similar")
                .column(egui_extras::Column::remainder().at_least(200.0).clip(true))
                .column(egui_extras::Column::exact(90.0))
                .column(egui_extras::Column::exact(180.0))
                .header(table::header_height(font), |mut header| {
                    for title in ["Sample", "Distance", "Shared"] {
                        header.col(|ui| table::head(ui, title));
                    }
                })
                .body(|body| {
                    body.rows(table::row_height(font) + 4.0, found.len(), |mut row| {
                        let similar = &found[row.index()];
                        row.col(|ui| {
                            if widgets::link(ui, &similar.name)
                                .on_hover_text(&similar.sha256)
                                .clicked()
                            {
                                open = Some(similar.sha256.clone());
                            }
                        });
                        row.col(|ui| {
                            ui.label(similar.distance.to_string()).on_hover_text(
                                "TLSH distance: 0 is identical, under about 100 a close variant",
                            );
                        });
                        row.col(|ui| {
                            let response = ui.label(similar.shared.label());
                            if !similar.shared.examples().is_empty() {
                                response.on_hover_text(similar.shared.examples().join("\n"));
                            }
                        });
                    });
                });
        }
    });
    open
}
