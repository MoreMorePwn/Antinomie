// SPDX-License-Identifier: MIT
//! Whole-run section totals, independent of table filters and preview pages.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Count {
    Pending,
    Unavailable,
    Ready(u64),
}

impl Count {
    pub(super) fn label(self) -> String {
        match self {
            Self::Pending => "…".into(),
            Self::Unavailable => "—".into(),
            Self::Ready(count) => antinomie_monitor_core::analysis::detection::group_digits(count),
        }
    }

    fn color(self, accent: bool) -> egui::Color32 {
        match self {
            Self::Ready(count) if count > 0 => {
                if accent {
                    theme::blue()
                } else {
                    theme::text()
                }
            }
            _ => theme::muted(),
        }
    }
}

/// One wrapping navigation unit, with a separate rounded count badge.
pub(super) fn tab(
    ui: &mut egui::Ui,
    selected: bool,
    title: &str,
    count: Count,
    accent: bool,
) -> bool {
    let label = count.label();
    let font = egui::TextStyle::Button.resolve(ui.style());
    let small = egui::TextStyle::Small.resolve(ui.style());
    let measure = |text: &str, font| {
        ui.fonts(|fonts| {
            fonts
                .layout_no_wrap(text.into(), font, theme::text())
                .size()
                .x
        })
    };
    let badge_width = measure(&label, small) + 14.0;
    let natural = measure(title, font) + ui.spacing().button_padding.x * 2.0 + badge_width + 4.0;
    let width = natural.min(ui.max_rect().width()).max(badge_width + 4.0);
    let height = ui.spacing().interact_size.y.max(30.0);
    let output = ui.allocate_ui_with_layout(
        egui::vec2(width, height),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            let clicked = ui
                .add_sized(
                    egui::vec2((width - badge_width - 4.0).max(0.0), height),
                    egui::Button::new(RichText::new(title).strong().color(if selected {
                        theme::palette().primary_text
                    } else {
                        theme::text()
                    }))
                    .selected(selected)
                    .truncate(),
                )
                .on_hover_text(title)
                .clicked();
            let color = count.color(accent);
            let badge = egui::Frame::new()
                .fill(color.gamma_multiply(0.12))
                .corner_radius(4)
                .inner_margin(egui::Margin::symmetric(7, 3))
                .show(ui, |ui| {
                    ui.label(RichText::new(label).small().strong().color(color));
                });
            let response =
                badge
                    .response
                    .interact(egui::Sense::click())
                    .on_hover_text(match count {
                        Count::Pending => "Updating the whole-run count",
                        Count::Unavailable => "No whole-run count is available",
                        Count::Ready(_) => "Whole-run count before table filters and pagination",
                    });
            clicked || response.clicked()
        },
    );
    output.inner
}

#[derive(Clone, Copy)]
enum Metric {
    Findings,
    Opened,
    Reads,
    Changed,
    /// An operation tab other than Opened and Read.
    File(FileTab),
    Ips,
    Hosts,
    Http,
    Dns,
}

impl TriageView {
    fn section_count(&self, metric: Metric) -> Count {
        if self.scan_rx.is_some() {
            return Count::Pending;
        }
        let Some(scan) = &self.scan else {
            return Count::Unavailable;
        };
        let count = match metric {
            Metric::Findings => scan.counts.findings,
            Metric::Opened => scan.counts.opened,
            Metric::Reads => scan.counts.reads,
            Metric::Changed => scan.counts.changed,
            Metric::File(tab) => scan.counts.tabs[tab.slot() - 8],
            Metric::Ips | Metric::Hosts | Metric::Http | Metric::Dns => {
                let Some((_, ips, hosts)) = scan.network_counts else {
                    return Count::Unavailable;
                };
                match metric {
                    Metric::Ips => ips,
                    Metric::Hosts => hosts,
                    Metric::Http => scan.counts.http,
                    Metric::Dns => scan.counts.dns,
                    _ => unreachable!(),
                }
            }
        };
        Count::Ready(count)
    }

    pub(super) fn process_tabs(&mut self, ui: &mut egui::Ui) {
        let count = self.section_count(Metric::Findings);
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.process, ProcessTab::Tree, "Process tree");
            if tab(
                ui,
                self.process == ProcessTab::Suspicious,
                "Suspicious activity",
                count,
                true,
            ) {
                self.process = ProcessTab::Suspicious;
            }
        });
    }

    pub(super) fn file_tabs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            for value in FileTab::ALL {
                let metric = match value {
                    FileTab::Opened => Metric::Opened,
                    FileTab::Read => Metric::Reads,
                    FileTab::Changed => Metric::Changed,
                    other => Metric::File(other),
                };
                if tab(
                    ui,
                    self.files == value,
                    value.title(),
                    self.section_count(metric),
                    false,
                ) {
                    self.files = value;
                }
            }
        });
    }

    pub(super) fn network_tabs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            for (value, title, metric) in [
                (NetTab::Ips, "IPs", Metric::Ips),
                (NetTab::Hosts, "Hosts", Metric::Hosts),
                (NetTab::Http, "HTTP", Metric::Http),
                (NetTab::Dns, "DNS", Metric::Dns),
            ] {
                if tab(
                    ui,
                    self.network == value,
                    title,
                    self.section_count(metric),
                    false,
                ) {
                    self.network = value;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests;
