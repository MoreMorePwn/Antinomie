// SPDX-License-Identifier: GPL-3.0-only
//! The Unpacking tab: the unpack chain as phases. The file as it came, then
//! each layer an unpacker recovered from the one before, with its size and
//! hash, the packer found in it and the way to its own static analysis.
use super::*;
use crate::theme;
use crate::widgets::{chip, Tone};
use antinomie_monitor_core::UnpackLayer;

pub(super) fn show(ui: &mut egui::Ui, report: &AnalysisReport) -> Option<ReportAction> {
    let section = report
        .sections
        .iter()
        .find(|section| section.kind == AnalysisKind::Unpacking)?;
    let layers = antinomie_monitor_core::unpack_layers(report);
    let mut action = None;
    ui.add(egui::Label::new(egui::RichText::new(&section.summary).color(theme::muted())).wrap());
    if layers.is_empty() {
        return None;
    }
    ui.add_space(6.0);
    egui::ScrollArea::horizontal()
        .id_salt("unpack-phases")
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.horizontal_top(|ui| {
                for (position, layer) in layers.iter().enumerate() {
                    if position > 0 {
                        ui.label(
                            egui::RichText::new(egui_phosphor::regular::ARROW_RIGHT)
                                .size(22.0)
                                .color(theme::muted()),
                        );
                    }
                    if let Some(next) = phase(ui, layer, position) {
                        action = Some(next);
                    }
                }
            });
        });
    ui.add_space(8.0);
    ui.add(
        egui::Label::new(
            egui::RichText::new(
                "UPX decompresses the file's data; nothing here runs the program. Packers \
                 that must run the program to get past them are not unpacked by this check.",
            )
            .color(theme::muted()),
        )
        .wrap(),
    );
    action
}

fn phase(ui: &mut egui::Ui, layer: &UnpackLayer, position: usize) -> Option<ReportAction> {
    let mut action = None;
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(250.0);
        ui.label(
            egui::RichText::new(format!("Phase {}", position + 1))
                .small()
                .color(theme::muted()),
        );
        ui.label(
            egui::RichText::new(if layer.index == 0 {
                "As it came".to_owned()
            } else {
                format!("Unpacked by {}", layer.method)
            })
            .strong()
            .color(theme::heading()),
        );
        ui.label(crate::values::file_size(layer.size));
        ui.horizontal(|ui| {
            ui.monospace(format!(
                "SHA-256 {}…",
                &layer.sha256[..layer.sha256.len().min(16)]
            ))
            .on_hover_text(&layer.sha256);
            if ui
                .small_button(egui_phosphor::regular::COPY)
                .on_hover_text("Copy SHA-256")
                .clicked()
            {
                ui.ctx().copy_text(layer.sha256.clone());
            }
        });
        match &layer.packer {
            Some(packer) => chip(ui, format!("Packed with {packer}"), Tone::Warn),
            None => chip(ui, "No packer found", Tone::Neutral),
        };
        if !layer.note.is_empty() {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&layer.note)
                        .small()
                        .color(theme::muted()),
                )
                .wrap(),
            );
        }
        if layer.index > 0 {
            match &layer.report_id {
                Some(id) => {
                    if ui
                        .button("Show its analysis")
                        .on_hover_text("Open this layer's own static analysis in the Report list")
                        .clicked()
                    {
                        action = Some(ReportAction::ShowReport {
                            report_id: id.clone(),
                        });
                    }
                }
                None => {
                    ui.weak("No analysis of its own");
                }
            }
        }
    });
    action
}
