// SPDX-License-Identifier: GPL-3.0-only
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
    Processes,
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
    Sessions,
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
            Metric::Processes => scan.process.len() as u64,
            Metric::Findings => scan.counts.findings,
            Metric::Opened => scan.counts.opened,
            Metric::Reads => scan.counts.reads,
            Metric::Changed => scan.counts.changed,
            Metric::File(tab) => scan.counts.tabs[tab.slot() - 8],
            Metric::Ips | Metric::Hosts | Metric::Http | Metric::Dns | Metric::Sessions => {
                let Some((_, ips, hosts)) = scan.network_counts else {
                    return Count::Unavailable;
                };
                match metric {
                    Metric::Ips => ips,
                    Metric::Hosts => hosts,
                    Metric::Http => scan.counts.http,
                    Metric::Dns => scan.counts.dns,
                    Metric::Sessions => scan.counts.sessions,
                    _ => unreachable!(),
                }
            }
        };
        Count::Ready(count)
    }

    /// Process tree, Suspicious activity and Graph, one segmented control.
    pub(super) fn process_tabs(&mut self, ui: &mut egui::Ui) {
        let processes = self.section_count(Metric::Processes);
        let findings = self.section_count(Metric::Findings);
        // Red with a HIGH row, amber with a MEDIUM row, neutral otherwise.
        let tiers = self.scan.as_ref().map(|scan| scan.counts.finding_tiers);
        let warn = match (findings, tiers) {
            (Count::Ready(count), Some(tiers)) if count > 0 && tiers[0] > 0 => Tone::Error,
            (Count::Ready(count), Some(tiers)) if count > 0 && tiers[1] > 0 => Tone::Warn,
            _ => Tone::Neutral,
        };
        let hover = self.scan.as_ref().map(|scan| {
            let tiers = scan.counts.finding_tiers;
            format!(
                "{} high · {} medium · {} low · {} info · {} hidden",
                tiers[0],
                tiers[1],
                tiers[2],
                tiers[3],
                scan.counts.findings_hidden + scan.counts.findings_suppressed
            )
        });
        widgets::segmented(
            ui,
            [
                (
                    ProcessTab::Tree,
                    TabItem::new("Process tree").badge(processes.label(), processes.tone(false)),
                ),
                (ProcessTab::Suspicious, {
                    let item = TabItem::new("Suspicious activity").badge(findings.label(), warn);
                    match hover {
                        Some(hover) => item.tooltip(hover),
                        None => item,
                    }
                }),
                (
                    ProcessTab::Graph,
                    TabItem::new("Graph").tooltip(
                        "The same findings on process swimlanes against time, with the severity curve, a category heat strip and the phases of the run",
                    ),
                ),
            ],
            &mut self.process,
        );
        ui.add_space(6.0);
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
                    self.files == value && !self.history_tab,
                    value.title(),
                    self.section_count(metric),
                    false,
                ) {
                    self.files = value;
                    self.history_tab = false;
                }
            }
            let item = TabItem::new("Per-file history").tooltip(
                "Every file the run touched, and for the chosen one its history as a graph with the processes involved and what was written where",
            );
            if widgets::tab(ui, self.history_tab, &item).clicked() {
                self.history_tab = true;
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
                (NetTab::Sessions, "Sessions", Metric::Sessions),
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
