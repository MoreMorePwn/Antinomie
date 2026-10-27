// SPDX-License-Identifier: GPL-3.0-only
//! The Summary tab: verdict-level answers first, then the runs and what to
//! search for, then the reference material. One line per result, a link into
//! the window on the right, no narrative.
use super::{parts, *};
use crate::{
    sample_tags,
    widgets::{table, Tone},
};
use antinomie_monitor_core::{samples::TagKind, AnalysisKind, AnalysisSection};

/// Rows the string tables show before they say "Showing 6 of N".
const CAP: usize = 6;

/// What a click in the Summary asks of the app.
enum Go {
    /// Open the run in Triage (or Run History for a deleted folder).
    Run(usize),
    /// The static report on this tab.
    Report(AnalysisKind),
    AllRuns,
    Verify,
    /// Open the file viewer on the archived sample.
    View,
}

impl MonitorApp {
    pub(super) fn summary_tab(&mut self, ui: &mut egui::Ui, data: &Arc<Data>) {
        let mut go = None;
        let mut lineage_out = None;
        let mut output_act = None;
        let mut similar_open = None;
        let mut lineage = self
            .samples_page
            .detail
            .as_mut()
            .map(|detail| std::mem::take(&mut detail.lineage))
            .unwrap_or_default();
        let scroll_y = self
            .samples_page
            .detail
            .as_mut()
            .and_then(|detail| detail.scroll_y);
        let (scanned, verified, verifying, similar) = match self.samples_page.detail.as_ref() {
            Some(detail) => (
                Some(&detail.scanned),
                detail.verified.as_ref(),
                detail.verify.is_some(),
                Some(&detail.similar),
            ),
            None => (None, None, false, None),
        };
        let mut area = egui::ScrollArea::vertical()
            .id_salt("sample_summary")
            .auto_shrink([false, false]);
        if let Some(y) = scroll_y {
            area = area.vertical_scroll_offset(y);
        }
        area.show(ui, |ui| {
            ui.set_width(ui.available_width());
            verdict(ui, data);
            if let Some(number) =
                super::triage_parts::rules_matched(ui, data, self.settings.font_size)
            {
                go = Some(Go::Run(number));
            }
            super::triage_parts::techniques(ui, data);
            super::triage_parts::evasion(ui, data);
            recent_runs(ui, data, &mut go, self.settings.font_size);
            super::triage_parts::indicators(ui, data);
            if let Some(scanned) = scanned {
                strings(ui, data, scanned, &mut go, self.settings.font_size);
            }
            static_analysis(ui, data, scanned, &mut go);
            identity(ui, data, verified, verifying, &mut go);
            lineage_out = super::lineage::section(ui, &mut lineage, data);
            output_act = super::output_files::section(ui, data, self.settings.font_size);
            if let Some(state) = similar {
                similar_open = super::similar::section(ui, state, self.settings.font_size);
            }
            ui.add_space(16.0);
        });
        if let Some(detail) = &mut self.samples_page.detail {
            detail.lineage = lineage;
        }
        if let Some(sha) = similar_open {
            self.samples_page.open_detail(&sha);
            return;
        }
        match output_act {
            Some(super::output_files::Act::Open(number, kind)) => {
                if let Some(entry) = data.runs.iter().find(|entry| entry.number == number) {
                    self.open_sample_run(&entry.run, kind.target(), None);
                }
            }
            Some(super::output_files::Act::GoToRun(number)) => go = Some(Go::Run(number)),
            None => {}
        }
        match lineage_out {
            Some(super::lineage::Out::OpenSample(sha)) => {
                self.samples_page.open_detail(&sha);
                return;
            }
            Some(super::lineage::Out::OpenRun(number)) => go = Some(Go::Run(number)),
            Some(super::lineage::Out::Promote {
                path,
                sha256,
                writer,
                runs,
            }) => {
                let choices = data
                    .runs
                    .iter()
                    .filter(|entry| runs.contains(&entry.number))
                    .map(|entry| super::super::promote::RunChoice {
                        number: entry.number,
                        run_id: entry.run.id.clone(),
                        vm_id: entry.run.vm_id.clone(),
                        vm_name: vm_name(&entry.run),
                        directory: entry.run.directory.clone(),
                        dump: None,
                    })
                    .collect();
                self.samples_page.promote = Some(super::super::promote::Promote::new(
                    &self.options.data_dir,
                    path,
                    sha256,
                    data.record.sha256.clone(),
                    writer,
                    choices,
                ));
            }
            None => {}
        }
        let detail = &mut self.samples_page.detail;
        match go {
            Some(Go::Run(number)) => {
                if let Some(entry) = data.runs.iter().find(|entry| entry.number == number) {
                    self.open_sample_run(&entry.run, crate::workspace::Panel::Triage, None);
                }
            }
            Some(Go::Report(kind)) => {
                if let Some(reference) = &data.report {
                    self.open_sample_report(&reference.report, reference.directory.clone(), kind);
                }
            }
            Some(Go::AllRuns) => {
                if let Some(detail) = detail {
                    detail.tab = Tab::Runs;
                }
            }
            Some(Go::Verify) => {
                if let Some(detail) = detail {
                    detail.start_verify(ui.ctx(), &self.options.data_dir);
                }
            }
            Some(Go::View) => {
                if let Some(data) = self
                    .samples_page
                    .detail
                    .as_ref()
                    .and_then(|d| d.data.clone())
                {
                    self.samples_page
                        .open_viewer(ui.ctx(), &data.record, data.archive.clone());
                }
            }
            None => {}
        }
    }
}

/// Verdict and family: three fields in one box.
fn verdict(ui: &mut egui::Ui, data: &Data) {
    parts::section(ui, "Verdict and family", None, |ui| {
        egui::Frame::new()
            .fill(theme::palette().panel)
            .stroke(egui::Stroke::new(1.0_f32, theme::palette().line_soft))
            .corner_radius(6)
            .inner_margin(10)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.columns(3, |columns| {
                    let verdicts: Vec<&Tag> = data
                        .tags
                        .iter()
                        .filter(|tag| tag.kind == TagKind::Verdict)
                        .collect();
                    field(&mut columns[0], "Verdict", |ui| {
                        if verdicts.is_empty() {
                            ui.label(theme::hint_text("None set"));
                        }
                        for tag in verdicts {
                            sample_tags::tag(ui, tag);
                        }
                    });
                    columns[0].label(theme::hint_text("Your verdict tag"));
                    field(&mut columns[1], "Highest suspicion", |ui| {
                        super::triage_parts::highest(ui, data);
                    });
                    let family = data.record.family.trim();
                    field(&mut columns[2], "Family", |ui| {
                        if family.is_empty() {
                            ui.label(theme::hint_text("Unknown"));
                        } else {
                            ui.label(RichText::new(family).strong());
                        }
                    });
                    columns[2].label(theme::hint_text(family_source(data)));
                });
            });
    });
}

fn field(ui: &mut egui::Ui, label: &str, value: impl FnOnce(&mut egui::Ui)) {
    ui.label(RichText::new(label).small().color(theme::muted()));
    ui.horizontal_wrapped(value);
}

/// Where the family name came from, or why there is none.
fn family_source(data: &Data) -> String {
    use antinomie_monitor_core::samples::OriginKind;
    let family = data.record.family.trim();
    let downloaded = data
        .origins
        .iter()
        .find(|origin| origin.kind == OriginKind::Download);
    match (family.is_empty(), downloaded) {
        (false, Some(origin)) => format!("{} signature", origin.source),
        (false, None) => "Recorded with the sample".into(),
        (true, Some(origin)) => format!("{} gave no signature", origin.source),
        (true, None) => match data.origins.first() {
            Some(origin) => format!("{}, so no source signature", origin.kind.label()),
            None => "No source signature".into(),
        },
    }
}

/// The latest five runs, newest first; a row opens that run's Triage.
fn recent_runs(ui: &mut egui::Ui, data: &Data, go: &mut Option<Go>, font: f32) {
    parts::section(ui, "Runs", Some(data.runs.len()), |ui| {
        if data.runs.is_empty() {
            parts::muted_line(ui, "Never run.");
            return;
        }
        let shown = &data.runs[..data.runs.len().min(5)];
        let mut menu = None;
        parts::mini_table(ui, "sample_summary_runs")
            .sense(egui::Sense::click())
            .column(egui_extras::Column::exact(120.0))
            .column(egui_extras::Column::exact(150.0))
            .column(egui_extras::Column::exact(140.0))
            .column(egui_extras::Column::exact(100.0))
            .column(egui_extras::Column::remainder().at_least(100.0))
            .header(table::header_height(font), |mut header| {
                for title in ["Run", "Start", "VM", "Suspicion", "Outcome"] {
                    header.col(|ui| table::head(ui, title));
                }
            })
            .body(|body| {
                body.rows(table::row_height(font) + 4.0, shown.len(), |mut row| {
                    let entry = &shown[row.index()];
                    let run = &entry.run;
                    let exit = super::super::exit_label(run);
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(parts::run_name(entry.number)).strong().color(
                                    if entry.folder {
                                        theme::text()
                                    } else {
                                        theme::muted()
                                    },
                                ),
                            )
                            .selectable(false),
                        );
                        if !entry.folder {
                            widgets::chip(ui, "folder deleted", Tone::Neutral)
                                .on_hover_text("The run's folder is no longer on disk");
                        }
                    });
                    row.col(|ui| {
                        table::cell_click(ui, table::Cell::Mono, &parts::minute(run.started_ms));
                    });
                    row.col(|ui| {
                        table::cell_click(ui, table::Cell::Text, &vm_name(run));
                    });
                    row.col(|ui| super::triage_parts::run_suspicion(ui, entry));
                    row.col(|ui| {
                        widgets::chip(ui, &exit, parts::exit_tone(&exit));
                    });
                    let response = row.response().on_hover_text(if entry.folder {
                        format!("Open Triage for {}", parts::run_name(entry.number))
                    } else {
                        "The run's folder was deleted".into()
                    });
                    if response.clicked() && entry.folder {
                        *go = Some(Go::Run(entry.number));
                    }
                    response.context_menu(|ui| {
                        if ui
                            .add_enabled(entry.folder, egui::Button::new("Open Triage"))
                            .clicked()
                        {
                            menu = Some(entry.number);
                            ui.close_menu();
                        }
                        if entry.folder {
                            crate::evidence::menu(ui, &run.directory);
                        }
                    });
                });
            });
        if let Some(number) = menu {
            *go = Some(Go::Run(number));
        }
        if parts::more(ui, &format!("All runs ({}) ›", data.runs.len())).clicked() {
            *go = Some(Go::AllRuns);
        }
    });
}

/// The VM a run was on, as the run says it.
pub(super) fn vm_name(run: &RunSummary) -> String {
    run.environment
        .as_ref()
        .map(|environment| environment.vm_name.clone())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| run.vm_id.clone())
}

/// Interesting strings and Regex matches below them.
fn strings(ui: &mut egui::Ui, data: &Data, scanned: &Scanned, go: &mut Option<Go>, font: f32) {
    let reference = data.report.as_ref();
    parts::section(
        ui,
        "Interesting strings",
        match scanned {
            Scanned::Done(strings) => Some(strings.interesting.len()),
            _ => None,
        },
        |ui| match (scanned, reference) {
            (Scanned::None, _) | (_, None) => parts::muted_line(ui, "Not analysed."),
            (Scanned::Reading, _) => {
                theme::loading_weak(ui, "Reading the strings…");
            }
            (Scanned::Failed(error), _) => {
                ui.colored_label(theme::error(), error);
            }
            (Scanned::Done(strings), Some(reference)) => {
                string_table(
                    ui,
                    "sample_summary_strings",
                    &strings.interesting,
                    &["Type", "String", "Offset"],
                    font,
                    |row| vec![row.kind.clone(), row.shown.clone(), row.found_in.clone()],
                    "No URLs, IPs, domains, paths or keys.",
                );
                let total = strings_total(&reference.report);
                let label = format!(
                    "{}Strings ({total}) ›",
                    if strings.interesting.len() > CAP {
                        format!("Showing {CAP} of {} · ", strings.interesting.len())
                    } else {
                        String::new()
                    }
                );
                if parts::more(ui, &label).clicked() {
                    *go = Some(Go::Report(AnalysisKind::Strings));
                }
            }
        },
    );
    // The scan is of the report's strings: no report, no matches section.
    let (Scanned::Done(strings), Some(_)) = (scanned, reference) else {
        return;
    };
    parts::section(ui, "Regex matches", Some(strings.total as usize), |ui| {
        string_table(
            ui,
            "sample_summary_regex",
            &strings.matches,
            &["Category", "Type", "Match", "Found in", "Seen"],
            font,
            |row| {
                vec![
                    row.category.label().to_owned(),
                    row.kind.clone(),
                    row.shown.clone(),
                    row.found_in.clone(),
                    row.seen.to_string(),
                ]
            },
            "No regex matches.",
        );
        let label = format!(
            "{}Regex matches ({}) ›",
            if strings.total as usize > CAP && strings.matches.len() > CAP {
                format!("Showing {CAP} of {} · ", strings.total)
            } else {
                String::new()
            },
            strings.total
        );
        if parts::more(ui, &label).clicked() {
            *go = Some(Go::Report(AnalysisKind::Regex));
        }
    });
}

/// How many strings the report's Strings tab lists.
fn strings_total(report: &antinomie_monitor_core::AnalysisReport) -> u64 {
    report
        .sections
        .iter()
        .find(|section| section.kind == AnalysisKind::Strings)
        .map_or(0, counted)
}

fn counted(section: &AnalysisSection) -> u64 {
    section
        .listing
        .as_ref()
        .map_or(section.entries.len() as u64, |listing| listing.rows)
}

/// Up to [`CAP`] rows of text cells, the last column of a numeric table
/// right-aligned; one line each with the full text in the tooltip.
fn string_table(
    ui: &mut egui::Ui,
    id: &str,
    rows: &[antinomie_monitor_core::samples::StringRow],
    titles: &[&str],
    font: f32,
    cells: impl Fn(&antinomie_monitor_core::samples::StringRow) -> Vec<String>,
    empty: &str,
) {
    if rows.is_empty() {
        parts::muted_line(ui, empty);
        return;
    }
    let shown = &rows[..rows.len().min(CAP)];
    let wide = if titles.len() == 3 { 1 } else { 2 };
    let mut builder = parts::mini_table(ui, id);
    for (index, title) in titles.iter().enumerate() {
        builder = builder.column(if index == wide {
            egui_extras::Column::remainder().at_least(160.0).clip(true)
        } else if *title == "Seen" {
            egui_extras::Column::exact(60.0)
        } else if *title == "Found in" || *title == "Offset" {
            egui_extras::Column::exact(170.0)
        } else {
            egui_extras::Column::exact(130.0)
        });
    }
    builder
        .header(table::header_height(font), |mut header| {
            for title in titles {
                header.col(|ui| {
                    table::head_aligned(ui, title, table::numeric_align(*title == "Seen"))
                });
            }
        })
        .body(|body| {
            body.rows(table::row_height(font), shown.len(), |mut row| {
                let values = cells(&shown[row.index()]);
                for (index, value) in values.iter().enumerate() {
                    row.col(|ui| {
                        let kind = if index == wide {
                            table::Cell::Mono
                        } else if titles[index] == "Seen" {
                            table::Cell::Number
                        } else if titles[index] == "Found in" || titles[index] == "Offset" {
                            table::Cell::Mono
                        } else {
                            table::Cell::Text
                        };
                        let shown = table::cell_rich(
                            ui,
                            kind,
                            RichText::new(value).color(if index == wide {
                                theme::text()
                            } else {
                                theme::muted()
                            }),
                        );
                        shown.on_hover_text(value);
                    });
                }
            });
        });
}

/// What the static report has, one line per Static Analysis tab, each
/// opening that tab.
fn static_analysis(ui: &mut egui::Ui, data: &Data, scanned: Option<&Scanned>, go: &mut Option<Go>) {
    parts::section(ui, "Static analysis", None, |ui| {
        let Some(reference) = &data.report else {
            ui.label(RichText::new("Not analysed").strong());
            return;
        };
        let report = &reference.report;
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Report").color(theme::muted()));
            ui.label(RichText::new(short_id(&report.id)).monospace());
            if let Some(run) = data
                .runs
                .iter()
                .find(|entry| entry.number == reference.number)
            {
                ui.label(parts::minute(run.run.started_ms));
                ui.label(format!(
                    "{} · {}",
                    parts::run_name(run.number),
                    report
                        .specimen_source
                        .map_or("during the run", |source| source.label())
                ));
            }
            widgets::chip(ui, format!("{:?}", report.state), Tone::Good);
            if widgets::link(ui, "Static Analysis ›").clicked() {
                *go = Some(Go::Report(AnalysisKind::Metadata));
            }
        });
        let total = match scanned {
            Some(Scanned::Done(strings)) => Some(strings.total),
            _ => None,
        };
        for (kind, label, sub) in LINES {
            let Some(section) = report.sections.iter().find(|section| section.kind == *kind) else {
                continue;
            };
            let value = line_value(*kind, section, total);
            let response = ui
                .horizontal(|ui| {
                    ui.label(RichText::new(*label).strong());
                    if !sub.is_empty() {
                        ui.label(RichText::new(*sub).small().color(theme::muted()));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(RichText::new("›").color(theme::muted()));
                        ui.add(egui::Label::new(RichText::new(&value).monospace()).truncate());
                    });
                })
                .response
                .interact(egui::Sense::click())
                .on_hover_cursor(egui::CursorIcon::PointingHand);
            if response.clicked() {
                *go = Some(Go::Report(*kind));
            }
        }
    });
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// One line per Static Analysis tab, in the window's order.
const LINES: &[(AnalysisKind, &str, &str)] = &[
    (AnalysisKind::Metadata, "File Info", "Summary"),
    (AnalysisKind::Structures, "File Info", "Sections"),
    (AnalysisKind::Hardening, "File Info", "Hardening"),
    (AnalysisKind::Identification, "File Info", "Identification"),
    (AnalysisKind::Entropy, "File Info", "Entropy"),
    (AnalysisKind::Strings, "Strings", ""),
    (AnalysisKind::Regex, "Regex matches", ""),
    (AnalysisKind::Floss, "FLOSS", ""),
    (AnalysisKind::Embedded, "Binwalk", ""),
    (AnalysisKind::Unpacking, "Unpacking", ""),
    (AnalysisKind::Rules, "YARA", ""),
    (AnalysisKind::Capabilities, "Capa Matrix", ""),
    (AnalysisKind::Disassembly, "Disassembly", ""),
    (AnalysisKind::Decompilation, "Decompilation", ""),
];

/// The count or value the tab's badge shows.
fn line_value(kind: AnalysisKind, section: &AnalysisSection, regex_total: Option<u64>) -> String {
    match kind {
        AnalysisKind::Strings
        | AnalysisKind::Floss
        | AnalysisKind::Embedded
        | AnalysisKind::Rules
        | AnalysisKind::Capabilities => counted(section).to_string(),
        AnalysisKind::Regex => {
            regex_total.map_or_else(|| first_line(&section.summary), |n| n.to_string())
        }
        _ => first_line(&section.summary),
    }
}

fn first_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or_default().trim();
    if line.chars().count() > 60 {
        format!("{}…", line.chars().take(59).collect::<String>())
    } else if line.is_empty() {
        "–".into()
    } else {
        line.to_owned()
    }
}

/// Identity: description, tags, type, how it was added, every hash, the
/// archive and every name it went by.
fn identity(
    ui: &mut egui::Ui,
    data: &Data,
    verified: Option<&(bool, String)>,
    verifying: bool,
    go: &mut Option<Go>,
) {
    parts::section(ui, "Identity", None, |ui| {
        let record = &data.record;
        let palette = theme::palette();
        ui.columns(2, |columns| {
            let left = &mut columns[0];
            egui::Frame::new()
                .fill(palette.panel)
                .stroke(egui::Stroke::new(1.0_f32, palette.line_soft))
                .corner_radius(6)
                .inner_margin(10)
                .show(left, |ui| {
                    ui.set_width(ui.available_width());
                    if record.description.is_empty() {
                        ui.label(theme::hint_text("No description"));
                    } else {
                        ui.label(&record.description);
                    }
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        for tag in &data.tags {
                            sample_tags::tag(ui, tag);
                        }
                        if data.tags.is_empty() {
                            ui.label(theme::hint_text("No tags"));
                        }
                    });
                    ui.add_space(6.0);
                    egui::Grid::new("sample_identity_left")
                        .num_columns(2)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            let kind = if record.file_type.is_empty() {
                                "unknown".to_owned()
                            } else {
                                record.file_type.clone()
                            };
                            let arch = if record.arch.is_empty() {
                                String::new()
                            } else {
                                format!(
                                    " · {}",
                                    antinomie_monitor_core::samples::arch_label(&record.arch)
                                )
                            };
                            parts::row(
                                ui,
                                "Type",
                                format!("{kind}{arch} · {}", crate::values::file_size(record.size)),
                            );
                            for (index, origin) in data.origins.iter().enumerate() {
                                let when = parts::second(origin.at_ms);
                                parts::row(
                                    ui,
                                    if index == 0 { "Added" } else { "Also added" },
                                    format!(
                                        "{} · {when}{}",
                                        origin.kind.label(),
                                        if origin.before_custody {
                                            " · recorded before the custody log"
                                        } else {
                                            ""
                                        }
                                    ),
                                );
                                let source = [&origin.source, &origin.path, &origin.detail]
                                    .into_iter()
                                    .filter(|part| !part.is_empty())
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(" · ");
                                if !source.is_empty() {
                                    parts::row(ui, "Source", source);
                                }
                            }
                        });
                });
            let right = &mut columns[1];
            egui::Frame::new()
                .fill(palette.panel)
                .stroke(egui::Stroke::new(1.0_f32, palette.line_soft))
                .corner_radius(6)
                .inner_margin(10)
                .show(right, |ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new("sample_identity_hashes")
                        .num_columns(2)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            parts::copyable(ui, "SHA-256", &record.sha256);
                            parts::copyable(ui, "SHA-1", &record.sha1);
                            parts::copyable(ui, "MD5", &record.md5);
                            parts::copyable(ui, "TLSH", &record.tlsh);
                        });
                    ui.add_space(4.0);
                    // Not in the grid: a long path must wrap in the box, not
                    // widen its column.
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Archive").color(theme::muted()));
                        {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(data.archive.display().to_string()).monospace(),
                                )
                                .selectable(true),
                            );
                            if data.archived {
                                widgets::chip(ui, "archive present", Tone::Good)
                                    .on_hover_text("AES zip, password infected");
                            } else {
                                widgets::chip(ui, "✗ missing", Tone::Error);
                            }
                            if verifying {
                                theme::spinner(ui);
                            }
                            match verified {
                                Some((true, _)) => {
                                    widgets::chip(ui, "✓ SHA-256 matches", Tone::Good);
                                }
                                Some((false, why)) => {
                                    widgets::chip(ui, "✗ did not verify", Tone::Error)
                                        .on_hover_text(why);
                                }
                                None => {}
                            }
                            if ui
                                .add_enabled(
                                    data.archived && !verifying,
                                    egui::Button::new("Verify"),
                                )
                                .on_hover_text("Read the archive back and compare its SHA-256")
                                .clicked()
                            {
                                *go = Some(Go::Verify);
                            }
                            if ui
                                .add_enabled(data.archived, egui::Button::new("View content"))
                                .on_hover_text("Open the archived file in the viewer")
                                .on_disabled_hover_text("The archive was removed")
                                .clicked()
                            {
                                *go = Some(Go::View);
                            }
                        }
                    });
                });
        });
        ui.add_space(8.0);
        aliases(ui, data);
    });
}

/// Every file name the sample went by.
fn aliases(ui: &mut egui::Ui, data: &Data) {
    egui::Frame::new()
        .fill(theme::palette().panel)
        .stroke(egui::Stroke::new(1.0_f32, theme::palette().line_soft))
        .corner_radius(6)
        .inner_margin(10)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let names: std::collections::BTreeSet<&str> = data
                .aliases
                .iter()
                .map(|alias| alias.name.as_str())
                .collect();
            ui.horizontal(|ui| {
                ui.label(RichText::new("Aliases").strong());
                ui.label(
                    RichText::new(format!(
                        "{} name{}",
                        names.len(),
                        if names.len() == 1 { "" } else { "s" }
                    ))
                    .color(theme::muted()),
                );
            });
            if data.aliases.is_empty() {
                ui.label(theme::hint_text("–"));
                return;
            }
            egui::Grid::new("sample_aliases")
                .num_columns(3)
                .spacing([16.0, 4.0])
                .striped(true)
                .show(ui, |ui| {
                    for title in ["Name", "Path or source", "Where"] {
                        ui.label(RichText::new(title).small().color(theme::muted()));
                    }
                    ui.end_row();
                    for alias in &data.aliases {
                        ui.label(RichText::new(&alias.name).monospace().strong());
                        ui.label(RichText::new(&alias.path).monospace().color(theme::muted()));
                        ui.label(RichText::new(&alias.seen).color(theme::muted()));
                        ui.end_row();
                    }
                });
        });
}
