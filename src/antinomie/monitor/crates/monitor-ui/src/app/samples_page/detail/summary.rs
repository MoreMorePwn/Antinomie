// SPDX-License-Identifier: GPL-3.0-only
//! The Summary tab: verdict-level answers first, then the runs and what to
//! search for, then the reference material. One line per result, a link into
//! the window on the right, no narrative.
mod strings;

use self::strings::{counted, strings};
use super::{parts, *};
use crate::{
    sample_tags,
    widgets::{self, fit_table, Tone},
};
use antinomie_monitor_core::{
    samples::{StringRow, TagKind},
    strings_regex::Category,
    AnalysisKind, AnalysisSection,
};

/// What a click in the Summary asks of the app.
enum Go {
    /// Open the run in Triage (or Run History for a deleted folder).
    Run(usize),
    /// Open the run in Triage on one rule's hit (engine, rule id).
    Rule(usize, String, String),
    /// Run static analysis on the sample's archived copy.
    Analyze,
    /// The static report on this tab.
    Report(AnalysisKind),
    /// The static report on this tab, on one of its views.
    ReportView(AnalysisKind, crate::analysis::SubTab),
    AllRuns,
    Verify,
    /// Open the file viewer on the archived sample.
    View,
    /// The Notes tab.
    Notes,
    /// Edit or delete the latest note.
    Note(super::notes_tab::Act),
    /// Open the run in Syscall Trace with this filter (a check's evidence).
    Trace(usize, String),
}

impl MonitorApp {
    pub(super) fn summary_tab(&mut self, ui: &mut egui::Ui, data: &Arc<Data>) {
        let mut go = None;
        let mut lineage_out = None;
        let mut output_act = None;
        let mut files_act = None;
        let mut similar_open = None;
        let mut lineage = self
            .samples_page
            .detail
            .as_mut()
            .map(|detail| std::mem::take(&mut detail.lineage))
            .unwrap_or_default();
        // A note's chip named something on this tab: go to it.
        if let Some(reference) = self
            .samples_page
            .detail
            .as_mut()
            .and_then(|detail| detail.focus.take())
        {
            use antinomie_monitor_core::samples::RefKind;
            match reference.kind {
                RefKind::Lineage => {
                    lineage.focus_node(&reference.target);
                    parts::scroll_to_section(ui.ctx(), "Lineage");
                }
                RefKind::Artifact => parts::scroll_to_section(ui.ctx(), "Artifacts"),
                RefKind::Indicator => parts::scroll_to_section(ui.ctx(), "Indicators"),
                _ => {}
            }
        }
        let (scanned, verified, verifying, similar) = match self.samples_page.detail.as_ref() {
            Some(detail) => (
                Some(&detail.scanned),
                detail.verified.as_ref(),
                detail.verify.is_some(),
                Some(&detail.similar),
            ),
            None => (None, None, false, None),
        };
        egui::ScrollArea::vertical()
            .id_salt("sample_summary")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // Room for the scroll bar, so no table or box runs under it.
                ui.set_width((ui.available_width() - parts::SCROLL_GUTTER).max(0.0));
                verdict(ui, data);
                match super::notes_tab::latest(ui, data) {
                    Some(super::notes_tab::Act::Tab) => go = Some(Go::Notes),
                    Some(act) => go = Some(Go::Note(act)),
                    None => {}
                }
                if let Some((number, engine, rule)) =
                    super::triage_parts::rules_matched(ui, data, self.settings.font_size)
                {
                    go = Some(Go::Rule(number, engine, rule));
                }
                if let Some(number) = super::triage_parts::techniques(ui, data) {
                    go = Some(Go::Run(number));
                }
                if let Some((number, filter)) = super::triage_parts::evasion(ui, data) {
                    go = Some(Go::Trace(number, filter));
                }
                recent_runs(ui, data, &mut go, self.settings.font_size);
                super::triage_parts::indicators(ui, data);
                if let Some(scanned) = scanned {
                    strings(ui, data, scanned, &mut go, self.settings.font_size);
                }
                static_analysis(ui, data, scanned, &mut go);
                identity(
                    ui,
                    data,
                    verified,
                    verifying,
                    &mut go,
                    self.settings.font_size,
                );
                lineage_out = super::lineage::section(ui, &mut lineage, data);
                output_act = super::output_files::section(ui, data, self.settings.font_size);
                files_act = super::written_files::section(ui, data, self.settings.font_size);
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
        match files_act {
            Some(super::written_files::Act::History(number, path)) => {
                if let Some(entry) = data.runs.iter().find(|entry| entry.number == number) {
                    self.open_sample_file(&entry.run, &path, false);
                }
            }
            Some(super::written_files::Act::Export(number, path)) => {
                if let Some(entry) = data.runs.iter().find(|entry| entry.number == number) {
                    self.open_sample_file(&entry.run, &path, true);
                }
            }
            Some(super::written_files::Act::GoToRun(number)) => go = Some(Go::Run(number)),
            None => {}
        }
        match output_act {
            Some(super::output_files::Act::Open(number, kind)) => {
                self.open_output(data, number, kind);
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
            Some(Go::Trace(number, filter)) => {
                if let Some(entry) = data.runs.iter().find(|entry| entry.number == number) {
                    self.open_sample_run(&entry.run, crate::workspace::Panel::Trace, Some(filter));
                }
            }
            Some(Go::Rule(number, engine, rule)) => {
                if let Some(entry) = data.runs.iter().find(|entry| entry.number == number) {
                    self.open_sample_rule(&entry.run, &engine, &rule);
                }
            }
            Some(Go::Analyze) => {
                self.analyze_sample(ui.ctx(), &data.record, data.archive.clone());
            }
            Some(Go::Report(kind)) => {
                if let Some(reference) = &data.report {
                    self.open_sample_report(&reference.report, reference.directory.clone(), kind);
                }
            }
            Some(Go::ReportView(kind, sub)) => {
                if let Some(reference) = &data.report {
                    self.pending_sub_tab = Some((reference.report.id.clone(), kind, sub));
                    self.open_sample_report(&reference.report, reference.directory.clone(), kind);
                }
            }
            Some(Go::Note(act)) => self.apply_note_act(data, act),
            Some(Go::Notes) => {
                if let Some(detail) = detail {
                    detail.tab = Tab::Notes;
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
        parts::panel_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.columns(3, |columns| {
                let verdicts: Vec<&Tag> = data
                    .tags
                    .iter()
                    .filter(|tag| tag.kind == TagKind::Verdict)
                    .collect();
                field(&mut columns[0], "Verdict", |ui| {
                    if verdicts.is_empty() {
                        ui.label(theme::hint_text("No tag"));
                    }
                    for tag in verdicts {
                        sample_tags::tag(ui, tag);
                    }
                });
                field(&mut columns[1], "Highest suspicion", |ui| {
                    super::triage_parts::highest(ui, data);
                });
                field(&mut columns[2], "Family", |ui| family(ui, data));
                if let Some(source) = family_source(data) {
                    columns[2].label(RichText::new(source).small().color(theme::muted()));
                }
            });
        });
    });
}

fn field(ui: &mut egui::Ui, label: &str, value: impl FnOnce(&mut egui::Ui)) {
    ui.label(RichText::new(label).small().color(theme::muted()));
    ui.horizontal_wrapped(value);
}

/// The family a YARA rule that matched names, newest rule list first.
fn yara_family(data: &Data) -> Option<&antinomie_monitor_core::samples::RuleRow> {
    data.rollup
        .rules
        .iter()
        .find(|rule| rule.engine.eq_ignore_ascii_case("yara") && !rule.family.trim().is_empty())
}

/// The Family field: the family name (the download source's signature, else a
/// YARA rule's), else the sample's malware-category tags, else "Unknown".
fn family(ui: &mut egui::Ui, data: &Data) {
    let named = data.record.family.trim();
    if !named.is_empty() {
        ui.label(RichText::new(named).strong());
        return;
    }
    if let Some(rule) = yara_family(data) {
        ui.label(RichText::new(rule.family.trim()).strong());
        return;
    }
    let categories: Vec<&Tag> = data
        .tags
        .iter()
        .filter(|tag| tag.kind == TagKind::Category)
        .collect();
    if categories.is_empty() {
        ui.label(theme::hint_text("Unknown"));
    }
    for tag in categories {
        sample_tags::tag(ui, tag);
    }
}

/// Where the family name came from: the download source's signature, a YARA
/// rule, or both when they agree. Nothing when the field shows tags.
fn family_source(data: &Data) -> Option<String> {
    use antinomie_monitor_core::samples::OriginKind;
    let named = data.record.family.trim();
    let yara = yara_family(data);
    let downloaded = data
        .origins
        .iter()
        .find(|origin| origin.kind == OriginKind::Download);
    match (named.is_empty(), downloaded, yara) {
        (false, Some(origin), Some(rule)) if rule.family.trim().eq_ignore_ascii_case(named) => {
            Some(format!(
                "{} signature · YARA rule {}",
                origin.source, rule.rule
            ))
        }
        (false, Some(origin), _) => Some(format!("{} signature", origin.source)),
        (false, None, _) => Some("Recorded with the sample".into()),
        (true, _, Some(rule)) => Some(format!("YARA rule {}", rule.rule)),
        (true, _, None) => None,
    }
}

/// The outcome of a run in words that carry its state where the exit alone
/// would not ("Interrupted · Exit 0"), since the colour is never the only cue.
fn outcome_words(run: &RunSummary) -> String {
    let exit = super::super::exit_label(run);
    match run.state {
        RunState::FailedToStart | RunState::LaunchUnconfirmed => run_status(run).to_owned(),
        RunState::Interrupted | RunState::Finalized | RunState::Stopped => {
            format!("{} · {exit}", run_status(run))
        }
        _ if run.recording_error.is_some() && !run.state.never_recorded() => {
            format!("{exit} · incomplete")
        }
        _ => exit,
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
        parts::on_surface(ui, |ui| {
            parts::click_table(ui, "sample_summary_runs")
                .column(crate::widgets::fit_table::Col::fixed(120.0))
                .column(crate::widgets::fit_table::Col::fixed(150.0))
                .column(crate::widgets::fit_table::Col::fixed(140.0))
                .column(crate::widgets::fit_table::Col::fixed(100.0))
                .column(crate::widgets::fit_table::Col::rest(80.0).at_least(100.0))
                .header(fit_table::header_height(font), |mut header| {
                    for title in ["Run", "Start", "VM", "Suspicion", "Outcome"] {
                        header.col(|ui| fit_table::head(ui, title));
                    }
                })
                .body(|body| {
                    body.rows(fit_table::row_height(font) + 4.0, shown.len(), |mut row| {
                        let entry = &shown[row.index()];
                        let run = &entry.run;
                        let exit = outcome_words(run);
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
                            fit_table::cell_click(
                                ui,
                                fit_table::Cell::Mono,
                                &parts::minute(run.started_ms),
                            );
                        });
                        row.col(|ui| {
                            fit_table::cell_click(ui, fit_table::Cell::Text, &vm_name(run));
                        });
                        row.col(|ui| super::triage_parts::run_suspicion(ui, entry));
                        row.col(|ui| {
                            // One line; the whole outcome is the tooltip.
                            let detail = execution_detail(run);
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&exit).color(crate::run_state_line::color(run)),
                                )
                                .truncate()
                                .selectable(false),
                            )
                            .on_hover_text(if detail.is_empty() { &exit } else { &detail });
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

/// What the static report has, one line per Static analysis tab, each
/// opening that tab.
fn static_analysis(ui: &mut egui::Ui, data: &Data, scanned: Option<&Scanned>, go: &mut Option<Go>) {
    parts::section(ui, "Static analysis", None, |ui| {
        let Some(reference) = &data.report else {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Not analysed").strong());
                if parts::more_inline(ui, "Analyze ›")
                    .on_hover_text("Run static analysis on the archived sample")
                    .clicked()
                {
                    *go = Some(Go::Analyze);
                }
            });
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
            // The report's own state: green only when every check finished.
            let (word, tone) = report_state(report.state);
            widgets::chip(ui, word, tone);
            if ui
                .button("Open Static analysis")
                .on_hover_text("Open this report in the Static analysis tab")
                .clicked()
            {
                *go = Some(Go::Report(AnalysisKind::Metadata));
            }
        });
        let total = match scanned {
            Some(Scanned::Done(strings)) => Some(strings.total),
            _ => None,
        };
        let lines: Vec<(&AnalysisSection, &str, String, Option<String>)> = LINES
            .iter()
            .filter_map(|(kind, label)| {
                let section = report
                    .sections
                    .iter()
                    .find(|section| section.kind == *kind)?;
                let notice = section.reason().map(|(why, _)| why);
                Some((
                    section,
                    *label,
                    line_result(*kind, section, total, data),
                    notice,
                ))
            })
            .collect();
        let strong = egui::TextStyle::Body.resolve(ui.style());
        let name_width = parts::fitted_up_to(
            ui,
            &strong,
            lines.iter().map(|(_, label, ..)| (*label).to_owned()),
            200.0,
        ) + 6.0;
        let chip_width = state_width(ui);
        let button_width = ui.fonts(|fonts| {
            fonts
                .layout_no_wrap("Open".into(), strong.clone(), egui::Color32::PLACEHOLDER)
                .size()
                .x
        }) + ui.spacing().button_padding.x * 2.0;
        // Name, state, result and Open are columns of fixed widths, so every
        // Open button is in one column; the notice (why a check is not
        // complete) takes what is left, to the right of the button, and wraps
        // under itself. With no notice the result takes the rest.
        let gap = ui.spacing().item_spacing.x;
        let rest =
            (ui.available_width() - name_width - chip_width - button_width - 3.0 * gap).max(0.0);
        let any_notice = lines.iter().any(|(.., notice)| notice.is_some());
        let (result_width, notice_width) = if any_notice {
            let result = (rest * 0.55).max(120.0);
            (result, (rest - result - gap).max(120.0))
        } else {
            (rest.max(60.0), 0.0)
        };
        for (section, label, result, notice) in lines {
            let kind = section.kind;
            let mut open = false;
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(name_width, ui.spacing().interact_size.y),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.set_min_width(name_width);
                        ui.set_max_width(name_width);
                        ui.add(
                            egui::Label::new(RichText::new(label).strong())
                                .truncate()
                                .selectable(false),
                        )
                        .on_hover_text(label);
                    },
                );
                let (word, tone) = section_state(section.state);
                let chip = widgets::chip_wide(ui, word, tone, chip_width);
                if !section.summary.is_empty()
                    && section.state != antinomie_monitor_core::AnalysisSectionState::Complete
                {
                    chip.on_hover_text(&section.summary);
                }
                // The result wraps inside its own column, so none of it is cut
                // off and the button after it stays where it is.
                ui.allocate_ui_with_layout(
                    egui::vec2(result_width, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_width(result_width);
                        ui.add(egui::Label::new(&result).wrap().selectable(false))
                            .on_hover_text(&result);
                    },
                );
                open = ui
                    .button("Open")
                    .on_hover_text(format!("Open {label} in Static analysis"))
                    .clicked();
                if let Some(notice) = &notice {
                    ui.allocate_ui_with_layout(
                        egui::vec2(notice_width, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_width(notice_width);
                            ui.add(
                                egui::Label::new(
                                    RichText::new(notice).small().color(section_notice(section)),
                                )
                                .wrap()
                                .selectable(false),
                            )
                            .on_hover_text(notice);
                        },
                    );
                }
            });
            if open {
                *go = Some(if kind == AnalysisKind::Structures {
                    // The symbols when the file has them, else its sections.
                    let sub = if section.entries.iter().any(|entry| entry.label == "Symbol") {
                        crate::analysis::SubTab::Symbols
                    } else {
                        crate::analysis::SubTab::Sections
                    };
                    Go::ReportView(kind, sub)
                } else {
                    Go::Report(kind)
                });
            }
        }
    });
}

/// A static report's state as a word and a tone: green only for Complete.
fn report_state(state: antinomie_monitor_core::AnalysisState) -> (&'static str, Tone) {
    use antinomie_monitor_core::AnalysisState as S;
    match state {
        S::Complete => ("Complete", Tone::Good),
        S::Partial => ("Partial", Tone::Warn),
        S::Unavailable => ("Unavailable", Tone::Error),
        S::Cancelled => ("Cancelled", Tone::Neutral),
        S::Acquiring => ("Acquiring", Tone::Info),
        S::Queued => ("Queued", Tone::Neutral),
        S::Running => ("Running", Tone::Info),
    }
}

/// One category's state, as the Static analysis tab colours it.
fn section_state(state: antinomie_monitor_core::AnalysisSectionState) -> (&'static str, Tone) {
    use antinomie_monitor_core::AnalysisSectionState as S;
    match state {
        S::Complete => ("Complete", Tone::Good),
        S::Partial => ("Partial", Tone::Warn),
        S::Timeout => ("Timeout", Tone::Warn),
        S::Unavailable => ("Unavailable", Tone::Error),
        S::Pending => ("Pending", Tone::Neutral),
        S::Running => ("Running", Tone::Info),
    }
}

/// The colour of a check's notice: an error for a check that could not run, a
/// warning for a timeout or a partial result.
fn section_notice(section: &AnalysisSection) -> egui::Color32 {
    if section.state == antinomie_monitor_core::AnalysisSectionState::Unavailable {
        theme::error()
    } else {
        theme::warn()
    }
}

/// The width of a state chip, so the column of them lines up.
fn state_width(ui: &egui::Ui) -> f32 {
    widgets::chip_width(
        ui,
        &[
            "Complete",
            "Partial",
            "Timeout",
            "Unavailable",
            "Pending",
            "Running",
        ],
    )
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// One line per Static analysis tab, in the window's order.
const LINES: &[(AnalysisKind, &str)] = &[
    (AnalysisKind::Metadata, "File info"),
    (AnalysisKind::Identification, "Identification"),
    (AnalysisKind::Structures, "Structures"),
    (AnalysisKind::Hardening, "Hardening"),
    (AnalysisKind::Entropy, "Entropy"),
    (AnalysisKind::Strings, "Strings"),
    (AnalysisKind::Regex, "Regex matches"),
    (AnalysisKind::Floss, "FLOSS"),
    (AnalysisKind::Embedded, "Binwalk"),
    (AnalysisKind::Unpacking, "Unpacking"),
    (AnalysisKind::Rules, "YARA rules"),
    (AnalysisKind::Capabilities, "capa"),
    (AnalysisKind::Disassembly, "Disassembly"),
    (AnalysisKind::Decompilation, "Decompilation"),
];

/// What a check found, in plain words from its report section; why it is not
/// complete is the notice to the right of its Open button.
fn line_result(
    kind: AnalysisKind,
    section: &AnalysisSection,
    regex_total: Option<u64>,
    data: &Data,
) -> String {
    use antinomie_monitor_core::analysis::detection::group_digits;
    let plural = |n: usize, one: &str, many: &str| {
        format!(
            "{} {}",
            group_digits(n as u64),
            if n == 1 { one } else { many }
        )
    };
    let count = |labels: &[&str]| {
        section
            .entries
            .iter()
            .filter(|entry| labels.contains(&entry.label.as_str()))
            .count()
    };
    let names = |limit: usize| {
        let all: Vec<&str> = section.entries.iter().map(|e| e.label.as_str()).collect();
        let mut text = all
            .iter()
            .take(limit)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        if all.len() > limit {
            text.push_str(&format!(", +{} more", all.len() - limit));
        }
        text
    };
    match kind {
        AnalysisKind::Metadata => format!(
            "{}; hashes and object header ({} fields)",
            crate::values::file_size(data.record.size),
            section.entries.len()
        ),
        AnalysisKind::Identification => {
            let mut parts: Vec<String> = Vec::new();
            for entry in &section.entries {
                match entry.label.split_once(": ") {
                    Some(("format", _)) => parts.insert(0, entry.value.clone()),
                    Some((_, name)) => parts.push(name.to_owned()),
                    None => parts.push(entry.label.clone()),
                }
            }
            if parts.is_empty() {
                "Nothing identified".to_owned()
            } else {
                parts.join("; ")
            }
        }
        AnalysisKind::Structures => {
            let mut kinds = Vec::new();
            for (labels, word) in [
                (&["Section"][..], "sections"),
                (&["Segment"], "segments"),
                (&["Symbol"], "symbols"),
                (&["Import"], "imports"),
                (&["Export"], "exports"),
            ] {
                let n = count(labels);
                if n > 0 {
                    kinds.push(format!("{} {word}", group_digits(n as u64)));
                }
            }
            format!(
                "{} ({})",
                plural(counted(section) as usize, "row", "rows"),
                kinds.join(", ")
            )
        }
        AnalysisKind::Hardening => {
            let facts: Vec<String> = section
                .entries
                .iter()
                .filter(|entry| entry.value.len() < 120 && !entry.value.starts_with(' '))
                .map(|entry| {
                    let value = entry.value.split(';').next().unwrap_or_default().trim();
                    format!("{}: {value}", entry.label)
                })
                .collect();
            if facts.is_empty() {
                first_line(&section.summary)
            } else {
                facts.join("; ")
            }
        }
        AnalysisKind::Entropy => {
            let whole = section
                .entries
                .iter()
                .find(|entry| entry.label == "Whole file")
                .and_then(|entry| entry.value.parse::<f64>().ok());
            match whole {
                Some(bits) => format!(
                    "{bits:.2} bits/byte whole file, {} measured (not a packing verdict)",
                    plural(count(&["Measured region"]), "region", "regions")
                ),
                None => first_line(&section.summary),
            }
        }
        AnalysisKind::Strings => {
            let total = section
                .summary
                .split_whitespace()
                .next()
                .and_then(|word| word.parse::<u64>().ok());
            match (total, section.summary.split_once(" strings")) {
                (Some(total), Some((_, rest))) => {
                    format!("{} strings{rest}", group_digits(total))
                }
                _ => format!("{} strings", group_digits(counted(section))),
            }
        }
        AnalysisKind::Regex => match regex_total {
            Some(total) => plural(total as usize, "match", "matches"),
            None => "Matched over the strings when Regex matches is opened".to_owned(),
        },
        AnalysisKind::Rules => {
            let n = section.entries.len();
            if n == 0 {
                "No rule matched".to_owned()
            } else {
                format!(
                    "{}: {}",
                    plural(n, "rule matched", "rules matched"),
                    names(2)
                )
            }
        }
        AnalysisKind::Capabilities => {
            let n = section.entries.len();
            if n == 0 {
                first_line(&section.summary)
            } else {
                format!(
                    "{}, e.g. {}",
                    plural(n, "capability", "capabilities"),
                    names(3)
                )
            }
        }
        AnalysisKind::Floss => plural(
            counted(section) as usize,
            "string recovered",
            "strings recovered",
        ),
        AnalysisKind::Embedded => plural(
            counted(section) as usize,
            "embedded signature",
            "embedded signatures",
        ),
        _ => first_line(&section.summary),
    }
}

fn first_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or_default().trim();
    if line.is_empty() {
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
    font: f32,
) {
    parts::section(ui, "Identity", None, |ui| {
        let record = &data.record;
        // A gap between the two boxes, and boxes of one height.
        let spacing = ui.spacing().item_spacing.x;
        ui.spacing_mut().item_spacing.x = 16.0;
        let mut left_body = |ui: &mut egui::Ui| {
            if record.description.is_empty() {
                ui.label(theme::hint_text("No description"));
            } else {
                ui.add(egui::Label::new(&record.description).wrap());
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
            ui.add_space(8.0);
            let value_width = parts::value_width(
                ui,
                &[
                    "Type",
                    "Added",
                    "Also added",
                    "Source",
                    "SHA-256",
                    "SHA-1",
                    "Archive",
                ],
                0.0,
            );
            egui::Grid::new("sample_identity_left")
                .num_columns(2)
                .spacing([12.0, parts::ROW_GAP])
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
                    parts::row_in(
                        ui,
                        "Type",
                        format!("{kind}{arch} · {}", crate::values::short_size(record.size)),
                        value_width,
                    );
                    for (index, origin) in data.origins.iter().enumerate() {
                        let when = parts::second(origin.at_ms);
                        parts::row_in(
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
                            value_width,
                        );
                        let source = [&origin.source, &origin.path, &origin.detail]
                            .into_iter()
                            .filter(|part| !part.is_empty())
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" · ");
                        if !source.is_empty() {
                            parts::row_in(ui, "Source", source, value_width);
                        }
                    }
                    // The hashes and the archive share the label column of
                    // the facts above; a long value is cut in the middle (the
                    // whole of it on hover and in the copy button).
                    for (label, value) in [
                        ("SHA-256", record.sha256.as_str()),
                        ("SHA-1", record.sha1.as_str()),
                        ("MD5", record.md5.as_str()),
                        ("TLSH", record.tlsh.as_str()),
                    ] {
                        parts::copy_row_in(ui, label, value, value_width, "Not computed");
                    }
                    let archive = data.archive.display().to_string();
                    parts::copy_row_in(ui, "Archive", &archive, value_width, "–");
                    ui.label("");
                    archive_state(ui, data, verified, verifying, go, value_width);
                    ui.end_row();
                });
        };
        // The facts box and the aliases take the whole width, one above the
        // other, so neither is narrow or half empty.
        ui.spacing_mut().item_spacing.x = spacing;
        parts::panel_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            left_body(ui);
        });
        ui.add_space(8.0);
        aliases(ui, data, font);
    });
}

/// The archive's state chips and its Verify and View buttons, wrapped inside
/// `width`.
fn archive_state(
    ui: &mut egui::Ui,
    data: &Data,
    verified: Option<&(bool, String)>,
    verifying: bool,
    go: &mut Option<Go>,
    width: f32,
) {
    ui.scope(|ui| {
        ui.set_max_width(width);
        ui.horizontal_wrapped(|ui| {
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
                    widgets::chip(ui, "✗ did not verify", Tone::Error).on_hover_text(why);
                }
                None => {}
            }
            if ui
                .add_enabled(data.archived && !verifying, egui::Button::new("Verify"))
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
        });
    });
}

/// Every file name the sample went by.
fn aliases(ui: &mut egui::Ui, data: &Data, font: f32) {
    parts::panel_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        let names: std::collections::BTreeSet<&str> = data
            .aliases
            .iter()
            .map(|alias| alias.name.as_str())
            .collect();
        let heading = ui.horizontal(|ui| {
            ui.label(theme::section_title(ui, "Aliases"));
            ui.label(
                RichText::new(format!(
                    "{} name{}",
                    names.len(),
                    if names.len() == 1 { "" } else { "s" }
                ))
                .color(theme::muted()),
            );
        });
        parts::scroll_if_asked(ui, "Aliases", heading.response.rect);
        if data.aliases.is_empty() {
            ui.label(theme::hint_text("–"));
            return;
        }
        ui.add_space(4.0);
        let body = egui::TextStyle::Body.resolve(ui.style());
        let mono = egui::TextStyle::Monospace.resolve(ui.style());
        let name = parts::fitted_up_to(
            ui,
            &mono,
            std::iter::once("Name".to_owned()).chain(data.aliases.iter().map(|a| a.name.clone())),
            280.0,
        );
        let seen = parts::fitted_up_to(
            ui,
            &body,
            std::iter::once("Where".to_owned()).chain(data.aliases.iter().map(|a| a.seen.clone())),
            320.0,
        );
        // The path takes what is left and is cut; the tooltip has all of it.
        let narrow = ui.available_width() < name + seen + 200.0;
        let (name, seen) = if narrow {
            (name.min(150.0), seen.min(110.0))
        } else {
            (name, seen)
        };
        parts::on_surface(ui, |ui| {
            parts::mini_table(ui, "sample_aliases")
                .column(crate::widgets::fit_table::Col::fixed(name).clip(true))
                .column(
                    crate::widgets::fit_table::Col::rest(80.0)
                        .at_least(120.0)
                        .clip(true),
                )
                .column(crate::widgets::fit_table::Col::fixed(seen).clip(true))
                .header(fit_table::header_height(font), |mut header| {
                    for title in ["Name", "Path or source", "Where"] {
                        header.col(|ui| fit_table::head(ui, title));
                    }
                })
                .body(|body| {
                    body.rows(
                        fit_table::row_height(font) + 6.0,
                        data.aliases.len(),
                        |mut row| {
                            let alias = &data.aliases[row.index()];
                            row.col(|ui| {
                                let shown = fit_table::cell_rich(
                                    ui,
                                    fit_table::Cell::Mono,
                                    RichText::new(&alias.name).strong(),
                                );
                                shown.on_hover_text(&alias.name);
                            });
                            row.col(|ui| {
                                let shown = fit_table::cell_rich(
                                    ui,
                                    fit_table::Cell::Mono,
                                    RichText::new(&alias.path).color(theme::text()),
                                );
                                shown.on_hover_text(&alias.path);
                            });
                            row.col(|ui| {
                                fit_table::cell_rich(
                                    ui,
                                    fit_table::Cell::Text,
                                    RichText::new(&alias.seen).color(theme::text()),
                                );
                            });
                        },
                    );
                });
        });
    });
}
