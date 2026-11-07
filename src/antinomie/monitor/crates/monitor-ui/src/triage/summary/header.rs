// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's header strip: the sample, the run, the tier tiles, the
//! family candidates the detections name and the behaviour tags. Observations
//! and where they came from; no verdict and no score.
use super::sample::{short_hash, size_text, SampleInfo};
use super::state::{tier_tiles, Built};
use super::{Act, Destination, RunFacts};
use crate::theme;
use crate::triage::{presentation, rules::Tier, ArchiveScan};
use eframe::egui::{self, RichText};

/// "ran for 14.2 s": the run's own words, without its leading capital.
fn lower_first(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_lowercase().chain(chars).collect())
        .unwrap_or_default()
}

/// A drawn dot of `color`, as tall as a line of text.
pub(super) fn dot(ui: &mut egui::Ui, color: egui::Color32) {
    let height = ui.text_style_height(&egui::TextStyle::Body);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(height * 0.7, height), egui::Sense::hover());
    ui.painter()
        .circle_filled(rect.center(), height * 0.22, color);
}

fn sample_line(ui: &mut egui::Ui, sample: Option<&SampleInfo>, fallback: &str) {
    let Some(sample) = sample else {
        ui.label(RichText::new(fallback).strong().color(theme::heading()));
        ui.label(
            RichText::new("Static analysis was not recorded for this run").color(theme::muted()),
        );
        return;
    };
    let name = if sample.name.is_empty() {
        fallback
    } else {
        &sample.name
    };
    ui.label(RichText::new(name).strong().color(theme::heading()));
    let mut parts: Vec<String> = Vec::new();
    if !sample.kind.is_empty() {
        parts.push(sample.kind.clone());
    }
    if let Some(linking) = sample.linking {
        parts.push(linking.to_owned());
    }
    if let Some(packer) = &sample.packer {
        parts.push(format!("{packer}-packed"));
    }
    if let Some(size) = sample.size {
        parts.push(size_text(size));
    }
    if !parts.is_empty() {
        ui.label(RichText::new(parts.join(" \u{b7} ")).color(theme::text()));
    }
    if let Some(hash) = &sample.sha256 {
        ui.label(
            RichText::new(format!("SHA-256 {}", short_hash(hash)))
                .monospace()
                .color(theme::muted()),
        )
        .on_hover_text(hash);
        if ui
            .small_button(egui_phosphor::regular::COPY)
            .on_hover_text("Copy the SHA-256")
            .clicked()
        {
            ui.ctx().copy_text(hash.clone());
            crate::toasts::notify(ui.ctx(), crate::activity::Level::Info, "SHA-256 copied");
        }
    }
}

/// What the header says besides the scan.
#[derive(Clone, Copy)]
pub(super) struct Facts<'a> {
    pub sample: Option<&'a SampleInfo>,
    pub run: &'a RunFacts,
    pub route: &'a crate::route_ui::RouteText,
    /// The program the run was asked to start: the name when no analysis has one.
    pub program: &'a str,
}

pub(super) fn show(
    ui: &mut egui::Ui,
    built: &Built,
    scan: &ArchiveScan,
    facts: &Facts<'_>,
    acts: &mut Vec<Act>,
) {
    let Facts {
        sample,
        run,
        route,
        program,
    } = *facts;

    presentation::frame().fill(theme::panel()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_wrapped(|ui| sample_line(ui, sample, program));
        ui.horizontal_wrapped(|ui| {
            let mut run_line: Vec<String> = Vec::new();
            if let Some(base) = &run.base {
                run_line.push(format!("Base {base}"));
            }
            if route.headline == crate::route_ui::NOT_RECORDED {
                run_line.push("route not recorded".to_owned());
            } else {
                run_line.push(format!("route {}", route.headline));
            }
            if let Some(state) = &route.run_state {
                run_line.push(lower_first(state));
            }
            if !run_line.is_empty() {
                ui.label(RichText::new(run_line.join(" \u{b7} ")).color(theme::text()));
            }
        });
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            for (tier, count) in tier_tiles(scan.counts.finding_tiers) {
                let label = if tier == Tier::Info {
                    "info".to_owned()
                } else {
                    tier.tag().to_uppercase()
                };
                let color = theme::tone(tier.tone());
                let button = egui::Button::new(
                    RichText::new(format!("{count} {label}"))
                        .strong()
                        .color(color),
                )
                .fill(color.gamma_multiply(0.12))
                .corner_radius(4);
                if ui
                    .add(button)
                    .on_hover_text(format!(
                        "Open Suspicious activity with only the {label} rows"
                    ))
                    .clicked()
                {
                    acts.push(Act::Tier(tier));
                }
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("Family candidates")
                    .small()
                    .color(theme::muted()),
            );
            if built.candidates.is_empty() {
                ui.label(
                    RichText::new("none named by a detection")
                        .small()
                        .color(theme::muted()),
                );
            }
            for candidate in &built.candidates {
                if ui
                    .link(RichText::new(&candidate.name).strong())
                    .on_hover_text(&candidate.source)
                    .clicked()
                {
                    acts.push(Act::Go(Destination::Detection(
                        antinomie_monitor_core::analysis::detection::Engine::Yara,
                    )));
                }
                ui.label(
                    RichText::new(format!("({})", candidate.source))
                        .small()
                        .color(theme::muted()),
                );
            }
        });
        if !built.tags.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Tags").small().color(theme::muted()));
                for tag in &built.tags {
                    presentation::badge(ui, tag, theme::neutral_accent()).on_hover_text(
                        "Seen in this run's rules and detections: an observation, not a verdict",
                    );
                }
            });
        }
    });
}
