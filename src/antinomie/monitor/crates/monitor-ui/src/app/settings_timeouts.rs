// SPDX-License-Identifier: GPL-3.0-only
//! Settings > Analysis tools: the time each tool may run, one field per tool,
//! with a reset whose tooltip names the tool's default.
use super::*;
use antinomie_monitor_core::{
    analysis::detection::{EngineTime, EngineTimeouts},
    TimedTool, TIMEOUT_MAX_SECONDS,
};

impl MonitorApp {
    /// One tool's time: the number it has now (its default when none was
    /// set) and a reset that clears the choice; the default is in its tooltip.
    pub(super) fn timeout_row(&mut self, ui: &mut egui::Ui, tool: TimedTool) {
        let default = tool.default_seconds();
        let set = self.settings.analysis_limits.timeouts.get(tool);
        let mut shown = if set == 0 { default as u32 } else { set };
        ui.horizontal_wrapped(|ui| {
            ui.label("Time limit").on_hover_text(
                "How long this tool may run before it is stopped and its check is marked Timeout. \
                 It comes before the time limit for every tool below.",
            );
            let changed = ui
                .add(
                    egui::DragValue::new(&mut shown)
                        .range(10..=TIMEOUT_MAX_SECONDS)
                        .suffix(" s"),
                )
                .changed();
            if changed {
                let stored = if u64::from(shown) == default {
                    0
                } else {
                    shown
                };
                self.settings.analysis_limits.timeouts.set(tool, stored);
            }
            if ui
                .add_enabled(set != 0, egui::Button::new("Reset"))
                .on_hover_text(format!("Back to the default time ({default} s)"))
                .on_disabled_hover_text(format!("Already the default time ({default} s)"))
                .clicked()
            {
                self.settings.analysis_limits.timeouts.set(tool, 0);
            }
        });
    }

    /// The time of each detection engine (Settings > Detection rules), with
    /// its default and a Reset. The live settings are the Triage's; they reach
    /// the saved ones when the settings are saved.
    pub(super) fn detection_timeouts(&mut self, ui: &mut egui::Ui) {
        for engine in EngineTime::ALL {
            let default = engine.default_seconds();
            let set = self.triage.detection_settings().timeouts.get(engine);
            let mut shown = if set == 0 { default as u32 } else { set };
            ui.horizontal_wrapped(|ui| {
                ui.add_sized(
                    [ui.spacing().interact_size.x, 0.0],
                    egui::Label::new(engine.label()),
                );
                let changed = ui
                    .add(
                        egui::DragValue::new(&mut shown)
                            .range(10..=EngineTimeouts::MAX)
                            .suffix(" s"),
                    )
                    .changed();
                if changed {
                    let stored = if u64::from(shown) == default {
                        0
                    } else {
                        shown
                    };
                    self.triage
                        .detection_settings()
                        .timeouts
                        .set(engine, stored);
                }
                if ui
                    .add_enabled(set != 0, egui::Button::new("Reset"))
                    .on_hover_text(format!("Back to the default time ({default} s)"))
                    .on_disabled_hover_text(format!("Already the default time ({default} s)"))
                    .clicked()
                {
                    self.triage.detection_settings().timeouts.set(engine, 0);
                }
            });
        }
    }

    /// The tools that are not in the list of installable ones (binwalk and the
    /// built-in YARA scan) with their times.
    pub(super) fn built_in_timeouts(&mut self, ui: &mut egui::Ui) {
        for tool in TimedTool::ALL
            .into_iter()
            .filter(|tool| tool.package().is_none())
        {
            ui.separator();
            ui.label(RichText::new(tool.label()).strong().color(theme::text()));
            self.timeout_row(ui, tool);
        }
    }
}
