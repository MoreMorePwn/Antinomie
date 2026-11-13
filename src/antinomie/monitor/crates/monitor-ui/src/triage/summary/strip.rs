// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's strip of a run's timed screenshots (ANT-T0487): small
//! pictures in a row with the run-relative time under each. Only the ones in
//! view are decoded (on threads, by [`Thumb`]); the others are dropped as soon
//! as they scroll away, so a long series holds a handful of textures. A click
//! opens the picture in Library > Screenshots, whose viewer steps through the
//! run with the arrow keys.
use super::thumb::Thumb;
use crate::theme;
use antinomie_monitor_core::timed_shots::{time_label, RunShot};
use eframe::egui::{self, RichText};
use std::{collections::HashMap, path::PathBuf};

/// How wide a picture is drawn, and the side it is decoded to.
const WIDTH: f32 = 132.0;
const SIDE: usize = 264;

#[derive(Default)]
pub(in crate::triage) struct Strip {
    thumbs: HashMap<PathBuf, Thumb>,
}

impl Strip {
    /// Draw the strip; the path of a clicked picture.
    pub(super) fn show(&mut self, ui: &mut egui::Ui, shots: &[RunShot]) -> Option<PathBuf> {
        let mut clicked = None;
        let mut drawn = Vec::new();
        egui::ScrollArea::horizontal()
            .id_salt("summary-timed-strip")
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.horizontal_top(|ui| {
                    for shot in shots {
                        ui.vertical(|ui| {
                            ui.set_width(WIDTH);
                            let height = WIDTH * 9.0 / 16.0;
                            let (rect, _) = ui.allocate_exact_size(
                                egui::vec2(WIDTH, height),
                                egui::Sense::hover(),
                            );
                            if ui.is_rect_visible(rect) {
                                drawn.push(shot.path.clone());
                                let thumb = self.thumbs.entry(shot.path.clone()).or_default();
                                let mut inner = ui.new_child(egui::UiBuilder::new().max_rect(rect));
                                if thumb.show_sized(&mut inner, &shot.path, WIDTH, SIDE) {
                                    clicked = Some(shot.path.clone());
                                }
                            }
                            ui.label(
                                RichText::new(time_label(shot.t_ms))
                                    .small()
                                    .color(theme::muted()),
                            );
                        });
                    }
                });
            });
        self.thumbs.retain(|path, _| drawn.contains(path));
        clicked
    }
}
