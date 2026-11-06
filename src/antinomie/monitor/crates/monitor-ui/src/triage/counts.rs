// SPDX-License-Identifier: GPL-3.0-only
//! Whole-run section totals, independent of table filters and preview pages.
use super::*;
use crate::widgets::{self, TabItem, Tone};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Count {
    Pending,
    Unavailable,
    Ready(u64),
    /// A table with chips on: the rows it lists out of all the run has.
    Shown {
        shown: u64,
        total: u64,
    },
}

impl Count {
    pub(super) fn label(self) -> String {
        match self {
            Self::Pending => "…".into(),
            Self::Unavailable => "—".into(),
            Self::Ready(count) => antinomie_monitor_core::analysis::detection::group_digits(count),
            Self::Shown { shown, total } => {
                let group = antinomie_monitor_core::analysis::detection::group_digits;
                format!("{} / {}", group(shown), group(total))
            }
        }
    }

    /// The badge tone: accent (or plain) when there is something to see.
    fn tone(self, accent: bool) -> Tone {
        match self {
            Self::Ready(count) | Self::Shown { total: count, .. } if count > 0 => {
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

impl Count {
    /// The label with a count over 99 shortened to "99+", for a tab title.
    pub(super) fn capped_label(self) -> String {
        match self {
            Self::Ready(count) if count > 99 => "99+".into(),
            other => other.label(),
        }
    }

    /// The full wording for a hover text: "120 matched", "not scanned".
    fn named(self) -> String {
        match self {
            Self::Pending => "updating".into(),
            Self::Unavailable => "no count".into(),
            Self::Ready(_) | Self::Shown { .. } => format!("{} matched", self.label()),
        }
    }
}

/// The Detection tab: "Detection 3 · 0 · 99+", the matched rules of YARA, IDS
/// and Sigma in the badge style of the IOC tab, each capped at "99+". It has
/// no badge until an engine has a count.
pub(super) fn detection_tab(counts: [Count; 3]) -> TabItem {
    let item = TabItem::new("Detection");
    if counts.iter().all(|count| *count == Count::Unavailable) {
        return item;
    }
    let any = counts
        .iter()
        .any(|count| matches!(count, Count::Ready(found) if *found > 0));
    let text = counts.map(Count::capped_label).join(" · ");
    let tone = if any { Tone::Accent } else { Tone::Neutral };
    item.badge(text, tone).tooltip(format!(
        "Matched rules: YARA {} · IDS {} · Sigma {}",
        counts[0].named(),
        counts[1].named(),
        counts[2].named()
    ))
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
            Count::Shown { .. } => {
                "Rows listed with the Hide chips on, out of all the run recorded. Turn a chip off to list the hidden rows"
            }
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
    /// Per-file history: the files the run touched.
    History,
    /// An operation tab other than Opened and Read.
    File(FileTab),
}

impl TriageView {
    fn section_count(&self, metric: Metric) -> Count {
        if self.preparing() {
            return Count::Pending;
        }
        let Some(scan) = &self.scan else {
            return Count::Unavailable;
        };
        let visible = |tab: FileTab| {
            let count = scan.counts.visibility[file_visibility::visibility_slot(tab)];
            (count.total > 0 && count.shown != count.total).then_some(Count::Shown {
                shown: count.shown,
                total: count.total,
            })
        };
        let hidden = match metric {
            Metric::Opened => visible(FileTab::Opened),
            Metric::Reads => visible(FileTab::Read),
            Metric::Changed => visible(FileTab::Changed),
            Metric::File(tab) => visible(tab),
            _ => None,
        };
        if let Some(hidden) = hidden {
            return hidden;
        }
        let count = match metric {
            Metric::Processes => scan.process.len() as u64,
            Metric::Findings => scan.counts.findings,
            Metric::Opened => scan.counts.opened,
            Metric::Reads => scan.counts.reads,
            Metric::Changed => scan.counts.changed,
            Metric::History => {
                scan.file_activity.files.len() as u64 + scan.file_activity.omitted_files
            }
            Metric::File(tab) => scan.counts.tabs[tab.slot() - 8],
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
            // The per-file table leads, then the history of one file: they are
            // the way into every file the run touched, with how many there are.
            let count = self.section_count(Metric::History);
            let by_file = TabItem::new("By file")
                .badge(count.label(), count.tone(false))
                .tooltip(
                    "One row for each file the run touched: what happened to it, who did it, its size, type and SHA-256",
                );
            if widgets::tab(ui, self.by_file && !self.history_tab, &by_file).clicked() {
                self.by_file = true;
                self.history_tab = false;
            }
            let item = TabItem::new("Per-file history")
                .badge(count.label(), count.tone(false))
                .tooltip(
                    "Every file the run touched, and for the chosen one its history as a graph with the processes involved and what was written where",
                );
            if widgets::tab(ui, self.history_tab, &item).clicked() {
                self.history_tab = true;
                self.by_file = false;
            }
            for value in FileTab::ALL {
                let metric = match value {
                    FileTab::Opened => Metric::Opened,
                    FileTab::Read => Metric::Reads,
                    FileTab::Changed => Metric::Changed,
                    other => Metric::File(other),
                };
                if tab(
                    ui,
                    self.files == value && !self.history_tab && !self.by_file,
                    value.title(),
                    self.section_count(metric),
                    false,
                ) {
                    self.files = value;
                    self.history_tab = false;
                    self.by_file = false;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod detection_tab_tests {
    use super::*;

    fn painted(counts: [Count; 3]) -> String {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let mut texts = Vec::new();
        let output = ctx.run_ui(egui::RawInput::default(), |root| {
            egui::CentralPanel::default().show(root, |ui| {
                widgets::tab_row(ui, |ui| {
                    widgets::tab(ui, false, &detection_tab(counts));
                });
            });
        });
        fn walk(shape: &egui::epaint::Shape, texts: &mut Vec<String>) {
            match shape {
                egui::epaint::Shape::Text(text) => texts.push(text.galley.text().to_owned()),
                egui::epaint::Shape::Vec(shapes) => {
                    shapes.iter().for_each(|shape| walk(shape, texts));
                }
                _ => {}
            }
        }
        for shape in &output.shapes {
            walk(&shape.shape, &mut texts);
        }
        texts.join("|")
    }

    #[test]
    fn the_detection_tab_counts_each_engine_capped_at_99_plus() {
        let text = painted([Count::Ready(3), Count::Ready(0), Count::Ready(99)]);
        assert!(
            text.contains("Detection") && text.contains("3 · 0 · 99"),
            "{text}"
        );
        let text = painted([Count::Ready(100), Count::Pending, Count::Unavailable]);
        assert!(text.contains("99+ · … · —"), "{text}");
        assert!(!text.contains("100"), "{text}");
    }

    #[test]
    fn the_hover_names_each_engine_and_an_unscanned_run_has_no_badge() {
        let item = detection_tab([Count::Ready(120), Count::Ready(1), Count::Unavailable]);
        let tip = item.tooltip.unwrap();
        assert!(tip.contains("YARA 120 matched"), "{tip}");
        assert!(
            tip.contains("IDS 1 matched") && tip.contains("Sigma no count"),
            "{tip}"
        );
        assert!(detection_tab([Count::Unavailable; 3]).badge.is_none());
    }
}
