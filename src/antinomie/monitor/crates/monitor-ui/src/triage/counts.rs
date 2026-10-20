// SPDX-License-Identifier: MIT
//! Whole-run section totals, independent of table filters and preview pages.
use super::*;
use crate::widgets::{self, TabItem, Tone};

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

    /// The badge tone: accent (or plain) when there is something to see.
    fn tone(self, accent: bool) -> Tone {
        match self {
            Self::Ready(count) if count > 0 => {
                if accent {
                    Tone::Accent
                } else {
                    Tone::Plain
                }
            }
            _ => Tone::Neutral,
        }
    }
}

/// One navigation unit: a thin-bordered tab with a count badge. Call it
/// inside `widgets::tab_row`.
pub(super) fn tab(
    ui: &mut egui::Ui,
    selected: bool,
    title: &str,
    count: Count,
    accent: bool,
) -> bool {
    let item = TabItem::new(title)
        .badge(count.label(), count.tone(accent))
        .tooltip(match count {
            Count::Pending => "Updating the whole-run count",
            Count::Unavailable => "No whole-run count is available",
            Count::Ready(_) => "Whole-run count before table filters and pagination",
        });
    widgets::tab(ui, selected, &item).clicked()
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
        widgets::tab_row(ui, |ui| {
            if widgets::tab(
                ui,
                self.process == ProcessTab::Tree,
                &TabItem::new("Process tree"),
            )
            .clicked()
            {
                self.process = ProcessTab::Tree;
            }
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
        widgets::tab_row(ui, |ui| {
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
        widgets::tab_row(ui, |ui| {
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
